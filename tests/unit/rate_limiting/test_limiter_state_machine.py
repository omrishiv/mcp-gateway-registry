"""Stateful property tests for the gateway rate limiter.

Pins two properties of ``registry.rate_limiting.limiter.RateLimiter``, which
enforces fixed-window counters: each gate allows at most ``max_requests`` per
``window_seconds`` window, where the window index is
``int(now) // window_seconds`` and a denied request consumes nothing on that
gate. First, while the datastore is healthy no caller, target or
caller-target key is allowed more than its configured limit in any window, and
every decision matches a reference model of the sequential
tightest-window-first algorithm. Second, the fail policy holds during a
datastore outage: with ``fail_open=False`` every request that has an applicable
gate is denied, and with ``quarantine_fail_closed=True`` every request is
denied once quarantine membership cannot be read.

The machine runs the production limiter, the production DocumentDB counter
backend and the production definitions and memberships repositories over an
in-memory collection, with a controllable clock. Repository read caches are
disabled (TTL 0), which models an outage that outlasts the cache TTL.
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from hypothesis import (
    settings,
)
from hypothesis import (
    strategies as st,
)
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    rule,
    run_state_machine_as_test,
)
from pymongo.errors import (
    DuplicateKeyError,
    ServerSelectionTimeoutError,
)

from registry.rate_limiting.definitions_repository import DefinitionsRepository
from registry.rate_limiting.documentdb_backend import DocumentDBRateLimiterBackend
from registry.rate_limiting.limiter import RateLimiter
from registry.rate_limiting.memberships_repository import MembershipsRepository
from registry.rate_limiting.models import (
    QUARANTINE_CALLER_GROUP,
    QUARANTINE_TARGET_GROUP,
    RateLimitDecision,
    RateLimitDefinition,
)

START_EPOCH_US: int = 1_700_000_000 * 1_000_000
MAX_ADVANCE_US: int = 25_000_000

BURST_WINDOW: int = 5
TARGET_WINDOW: int = 10
VOLUME_WINDOW: int = 20

TARGET_WITH_LIMIT: str = "srv-a"
TARGET_WITHOUT_LIMIT: str = "srv-b"
TARGETS: tuple[str, ...] = (TARGET_WITH_LIMIT, TARGET_WITHOUT_LIMIT)
TARGET_ENTITY_TYPE: str = "mcp_server"


@dataclass(frozen=True)
class _Caller:
    """A caller as the auth server passes it to ``RateLimiter.check``."""

    username: str | None
    client_id: str | None
    is_admin: bool
    membership_ids: tuple[str, ...]


CALLERS: dict[str, _Caller] = {
    "alice": _Caller("alice", None, False, ("user:alice",)),
    "bob": _Caller("bob", None, False, ("user:bob",)),
    "carol": _Caller("carol", None, False, ("user:carol",)),
    "bot": _Caller("svc-bot", "bot-client", False, ("user:svc-bot", "client:bot-client")),
    "root": _Caller("root", None, True, ("user:root",)),
}

BASE_GROUPS: dict[str, list[str]] = {
    "user:alice": ["devs"],
    "user:bob": ["devs", "ops"],
    "user:carol": [],
    "client:bot-client": ["devs"],
    "user:root": ["devs"],
}

MACHINE_SETTINGS = settings(
    max_examples=50,
    stateful_step_count=15,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)


class _Clock:
    """Controllable wall clock with microsecond resolution."""

    def __init__(self) -> None:
        self.micros = START_EPOCH_US

    def now(self) -> float:
        """Return the current epoch time in seconds."""
        return self.micros / 1_000_000


def _clock_datetime(
    clock: _Clock,
) -> type[datetime]:
    """Build a ``datetime`` subclass whose ``now`` reads ``clock``.

    Args:
        clock: The controllable clock.

    Returns:
        A datetime class to patch into the counter backend module.
    """

    class _ClockDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(clock.now(), tz)

    return _ClockDatetime


class _Store:
    """Health switches shared by every in-memory collection (one datastore)."""

    def __init__(self) -> None:
        self.counter_up = True
        self.metadata_up = True

    @property
    def healthy(self) -> bool:
        """Return True when every collection answers."""
        return self.counter_up and self.metadata_up


def _matches(
    doc: dict[str, Any],
    query: dict[str, Any],
) -> bool:
    """Evaluate the subset of MongoDB query syntax the repositories use.

    Supports equality (array fields match on membership), ``$in`` and ``$or``.

    Args:
        doc: Stored document.
        query: Query filter.

    Returns:
        True if ``doc`` satisfies ``query``.
    """
    for key, condition in query.items():
        if key == "$or":
            if not any(_matches(doc, clause) for clause in condition):
                return False
            continue
        value = doc.get(key)
        if isinstance(condition, dict) and "$in" in condition:
            if value not in condition["$in"]:
                return False
        elif isinstance(value, list):
            if condition not in value:
                return False
        elif value != condition:
            return False
    return True


class _AsyncCursor:
    """Async iterator over a snapshot of matching documents."""

    def __init__(
        self,
        docs: list[dict[str, Any]],
    ) -> None:
        self._docs = iter(docs)

    def __aiter__(self) -> "_AsyncCursor":
        return self

    async def __anext__(self) -> dict[str, Any]:
        try:
            return next(self._docs)
        except StopIteration:
            raise StopAsyncIteration from None


class _InMemoryCollection:
    """In-memory stand-in for a motor collection, failing while its store is down."""

    def __init__(
        self,
        store: _Store,
        is_counter: bool,
    ) -> None:
        self._store = store
        self._is_counter = is_counter
        self.docs: dict[str, dict[str, Any]] = {}

    def _check_up(self) -> None:
        """Raise the driver error a real outage produces."""
        up = self._store.counter_up if self._is_counter else self._store.metadata_up
        if not up:
            raise ServerSelectionTimeoutError("datastore unavailable")

    async def find_one_and_update(
        self,
        filter: dict[str, Any],
        update: dict[str, Any],
        upsert: bool = False,
        return_document: Any = None,
    ) -> dict[str, Any]:
        """Apply the backend's conditional ``$inc`` upsert with MongoDB semantics."""
        self._check_up()
        doc_id = filter["_id"]
        below = filter["count"]["$lt"]
        doc = self.docs.get(doc_id)
        if doc is None:
            doc = {"_id": doc_id, "count": 0, **update.get("$setOnInsert", {})}
            self.docs[doc_id] = doc
        elif doc["count"] >= below:
            raise DuplicateKeyError(f"E11000 duplicate key error: _id {doc_id}")
        doc["count"] += update["$inc"]["count"]
        return dict(doc)

    async def find_one(
        self,
        filter: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Return a copy of the first matching document, or None."""
        self._check_up()
        for doc in self.docs.values():
            if _matches(doc, filter):
                return dict(doc)
        return None

    def find(
        self,
        query: dict[str, Any],
    ) -> _AsyncCursor:
        """Return an async cursor over copies of the matching documents."""
        self._check_up()
        return _AsyncCursor([dict(doc) for doc in self.docs.values() if _matches(doc, query)])


@dataclass(frozen=True)
class _ModelGate:
    """One gate as the reference model sees it."""

    axis: str
    subject: str
    window: int
    limit: int
    fail_closed: bool


@dataclass(frozen=True)
class _Outcome:
    """What a request's caller observes: the decision, or an error treated as allow."""

    allowed: bool
    quarantined: bool
    axis: str | None
    limit: int | None
    reset_epoch: int
    retry_after: int
    error: str | None


def _outcome_from(
    decision: RateLimitDecision,
) -> _Outcome:
    """Project a limiter decision onto the fields the model predicts."""
    return _Outcome(
        allowed=decision.allowed,
        quarantined=decision.quarantined,
        axis=decision.axis,
        limit=decision.limit,
        reset_epoch=decision.reset_epoch,
        retry_after=decision.retry_after,
        error=None,
    )


def _check(
    limiter: RateLimiter,
    caller: _Caller,
    target: str,
) -> _Outcome:
    """Run one limiter check the way the auth server does.

    ``auth_server.server._enforce_rate_limit`` lets the request through when
    ``check`` raises, so an exception is reported as an allow carrying the error.

    Args:
        limiter: Limiter under test.
        caller: The validated caller.
        target: Classified MCP server target.

    Returns:
        The observed outcome.
    """
    try:
        decision = asyncio.run(
            limiter.check(
                username=caller.username,
                client_id=caller.client_id,
                is_admin=caller.is_admin,
                target_entity_type=TARGET_ENTITY_TYPE,
                target_name=target,
            )
        )
    except Exception as exc:
        return _Outcome(True, False, None, None, 0, 0, f"{type(exc).__name__}: {exc}")
    return _outcome_from(decision)


def _definition_docs(
    limits: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build the definition documents for one machine run.

    Caller-side definitions never set ``fail_closed`` so most-restrictive
    resolution has no tie on that flag; the target definition's flag is drawn.

    Args:
        limits: Drawn limit values.

    Returns:
        Documents ready to store, each with its ``_id``.
    """
    definitions = [
        RateLimitDefinition(
            axis="caller",
            entity_type="group",
            name="devs",
            user_max_requests=limits["devs_burst_user"],
            agent_max_requests=limits["devs_burst_agent"],
            window_seconds=BURST_WINDOW,
        ),
        RateLimitDefinition(
            axis="caller",
            entity_type="group",
            name="devs",
            user_max_requests=limits["devs_volume_user"],
            agent_max_requests=limits["devs_volume_agent"],
            window_seconds=VOLUME_WINDOW,
        ),
        RateLimitDefinition(
            axis="caller",
            entity_type="group",
            name="ops",
            user_max_requests=limits["ops_burst_user"],
            window_seconds=BURST_WINDOW,
        ),
        RateLimitDefinition(
            axis="caller_target",
            entity_type="group",
            name="devs",
            user_max_requests=limits["devs_pair_user"],
            agent_max_requests=limits["devs_pair_agent"],
            window_seconds=VOLUME_WINDOW,
        ),
        RateLimitDefinition(
            axis="target",
            entity_type=TARGET_ENTITY_TYPE,
            name=TARGET_WITH_LIMIT,
            max_requests=limits["target"],
            window_seconds=TARGET_WINDOW,
            fail_closed=limits["target_fail_closed"],
        ),
        RateLimitDefinition(
            axis="quarantine", entity_type="group", name=QUARANTINE_CALLER_GROUP, scope="caller"
        ),
        RateLimitDefinition(
            axis="quarantine", entity_type="group", name=QUARANTINE_TARGET_GROUP, scope="target"
        ),
    ]
    return [{"_id": d.build_id(), **d.model_dump()} for d in definitions]


LIMIT_STRATEGY = st.fixed_dictionaries(
    {
        "devs_burst_user": st.integers(1, 3),
        "devs_burst_agent": st.integers(1, 3),
        "devs_volume_user": st.integers(2, 6),
        "devs_volume_agent": st.integers(2, 6),
        "ops_burst_user": st.integers(1, 3),
        "devs_pair_user": st.integers(1, 4),
        "devs_pair_agent": st.integers(1, 4),
        "target": st.integers(1, 6),
        "target_fail_closed": st.booleans(),
    }
)


class _LimiterMachine(RuleBasedStateMachine):
    """Drive the limiter with requests, clock moves, outages and quarantines."""

    fail_open: bool = True
    quarantine_fail_closed: bool = False

    def __init__(self) -> None:
        super().__init__()
        self.clock = _Clock()
        self.store = _Store()
        self.counters = _InMemoryCollection(self.store, is_counter=True)
        self.definitions = _InMemoryCollection(self.store, is_counter=False)
        self.memberships = _InMemoryCollection(self.store, is_counter=False)
        self.limits: dict[str, Any] = {}
        self.quarantined_callers: set[str] = set()
        self.target_quarantined = False
        self.model_counts: dict[tuple[str, str, int, int], int] = defaultdict(int)
        self.observed_allowed: dict[tuple[str, str, int, int], int] = defaultdict(int)
        self.gate_limits: dict[tuple[str, str, int, int], int] = {}
        self._patches = [
            patch(
                "registry.rate_limiting.documentdb_backend.datetime",
                _clock_datetime(self.clock),
            ),
            patch(
                "registry.rate_limiting.limiter.time",
                SimpleNamespace(time=self.clock.now),
            ),
        ]
        for active in self._patches:
            active.start()

        backend = DocumentDBRateLimiterBackend()
        backend._collection = self.counters
        backend._indexes_created = True
        definitions = DefinitionsRepository(cache_ttl_seconds=0)
        definitions._collection = self.definitions
        memberships = MembershipsRepository(cache_ttl_seconds=0)
        memberships._collection = self.memberships
        self.limiter = RateLimiter(
            backend=backend,
            definitions=definitions,
            memberships=memberships,
            fail_open=self.fail_open,
            quarantine_fail_closed=self.quarantine_fail_closed,
        )

    def teardown(self) -> None:
        for active in reversed(self._patches):
            active.stop()

    def _write_membership(
        self,
        doc_id: str,
        groups: list[str],
    ) -> None:
        """Store a membership document as the admin API would."""
        subject_type, subject = doc_id.split(":", 1)
        self.memberships.docs[doc_id] = {
            "_id": doc_id,
            "subject_type": subject_type,
            "subject": subject,
            "groups": list(groups),
            "enabled": True,
        }

    @initialize(limits=LIMIT_STRATEGY)
    def configure(
        self,
        limits: dict[str, Any],
    ) -> None:
        self.limits = limits
        for doc in _definition_docs(limits):
            self.definitions.docs[doc["_id"]] = doc
        for doc_id, groups in BASE_GROUPS.items():
            self._write_membership(doc_id, groups)

    def _groups(
        self,
        caller: _Caller,
    ) -> list[str]:
        """Return the caller's rate-limit groups per the reference model."""
        groups: list[str] = []
        for doc_id in caller.membership_ids:
            for group in BASE_GROUPS.get(doc_id, []):
                if group not in groups:
                    groups.append(group)
        return groups

    def _gates(
        self,
        caller: _Caller,
        target: str,
    ) -> list[_ModelGate]:
        """Return the gates that apply, in enforcement order, per the reference model."""
        is_agent = caller.client_id is not None
        identity = caller.client_id or caller.username or ""
        gates: list[_ModelGate] = []
        if not caller.is_admin:
            groups = self._groups(caller)
            burst = []
            volume = []
            pair = []
            if "devs" in groups:
                burst.append(self.limits["devs_burst_agent" if is_agent else "devs_burst_user"])
                volume.append(self.limits["devs_volume_agent" if is_agent else "devs_volume_user"])
                pair.append(self.limits["devs_pair_agent" if is_agent else "devs_pair_user"])
            if "ops" in groups and not is_agent:
                burst.append(self.limits["ops_burst_user"])
            if burst:
                gates.append(_ModelGate("clr", identity, BURST_WINDOW, min(burst), False))
            if volume:
                gates.append(_ModelGate("clr", identity, VOLUME_WINDOW, min(volume), False))
            if pair:
                subject = f"{identity}|{target}"
                gates.append(_ModelGate("ctg", subject, VOLUME_WINDOW, min(pair), False))
        if target == TARGET_WITH_LIMIT:
            gates.append(
                _ModelGate(
                    "tgt",
                    target,
                    TARGET_WINDOW,
                    self.limits["target"],
                    self.limits["target_fail_closed"],
                )
            )
        return sorted(gates, key=lambda gate: gate.window)

    def _counter_id(
        self,
        gate: _ModelGate,
    ) -> tuple[str, str, int, int]:
        """Identify a gate's counter in the current fixed window."""
        return (gate.axis, gate.subject, gate.window, int(self.clock.now()) // gate.window)

    def _throttle(
        self,
        gate: _ModelGate,
    ) -> _Outcome:
        """Build the throttle outcome the model predicts for ``gate``."""
        now = int(self.clock.now())
        reset_epoch = (now // gate.window + 1) * gate.window
        return _Outcome(
            allowed=False,
            quarantined=False,
            axis=gate.axis,
            limit=gate.limit,
            reset_epoch=reset_epoch,
            retry_after=max(1, reset_epoch - now),
            error=None,
        )

    def _expected(
        self,
        name: str,
        target: str,
    ) -> _Outcome | bool:
        """Predict the outcome; a bare bool means only ``allowed`` is specified.

        Mutates the model counters exactly as the limiter's backend should.
        """
        caller = CALLERS[name]
        if not self.store.metadata_up:
            if self.quarantine_fail_closed:
                return _Outcome(False, True, "tgt", None, 0, 0, None)
            return self.fail_open
        if self.target_quarantined and target == TARGET_WITH_LIMIT:
            return _Outcome(False, True, "tgt", None, 0, 0, None)
        if not caller.is_admin and name in self.quarantined_callers:
            return _Outcome(False, True, "clr", None, 0, 0, None)
        for gate in self._gates(caller, target):
            if not self.store.counter_up:
                if gate.fail_closed or not self.fail_open:
                    return self._throttle(gate)
                continue
            counter = self._counter_id(gate)
            self.gate_limits[counter] = gate.limit
            if self.model_counts[counter] >= gate.limit:
                return self._throttle(gate)
            self.model_counts[counter] += 1
        return True

    @rule(name=st.sampled_from(sorted(CALLERS)), server=st.sampled_from(TARGETS))
    def request(
        self,
        name: str,
        server: str,
    ) -> None:
        healthy = self.store.healthy
        expected = self._expected(name, server)
        actual = _check(self.limiter, CALLERS[name], server)
        context = (
            f"caller={name} target={server} now={self.clock.now()} "
            f"counter_up={self.store.counter_up} metadata_up={self.store.metadata_up} "
            f"fail_open={self.fail_open} quarantine_fail_closed={self.quarantine_fail_closed}"
        )
        if isinstance(expected, bool):
            assert actual.allowed is expected, (
                f"expected allowed={expected}, got {actual}: {context}"
            )
        else:
            assert actual == expected, f"expected {expected}, got {actual}: {context}"
        if healthy and actual.allowed:
            for gate in self._gates(CALLERS[name], server):
                self.observed_allowed[self._counter_id(gate)] += 1

    @rule(micros=st.integers(0, MAX_ADVANCE_US))
    def advance_time(
        self,
        micros: int,
    ) -> None:
        self.clock.micros += micros

    @rule(counter_up=st.booleans(), metadata_up=st.booleans())
    def set_store_health(
        self,
        counter_up: bool,
        metadata_up: bool,
    ) -> None:
        self.store.counter_up = counter_up
        self.store.metadata_up = metadata_up

    @rule(name=st.sampled_from(sorted(CALLERS)), quarantined=st.booleans())
    def set_caller_quarantine(
        self,
        name: str,
        quarantined: bool,
    ) -> None:
        doc_id = CALLERS[name].membership_ids[0]
        groups = list(BASE_GROUPS.get(doc_id, []))
        if quarantined:
            groups.append(QUARANTINE_CALLER_GROUP)
            self.quarantined_callers.add(name)
        else:
            self.quarantined_callers.discard(name)
        self._write_membership(doc_id, groups)

    @rule(quarantined=st.booleans())
    def set_target_quarantine(
        self,
        quarantined: bool,
    ) -> None:
        doc_id = f"server:{TARGET_WITH_LIMIT}"
        self.target_quarantined = quarantined
        if quarantined:
            self._write_membership(doc_id, [QUARANTINE_TARGET_GROUP])
        else:
            self.memberships.docs.pop(doc_id, None)

    @invariant()
    def no_key_exceeds_its_limit(self) -> None:
        over = {
            counter: count
            for counter, count in self.observed_allowed.items()
            if count > self.gate_limits[counter]
        }
        assert not over, f"allowed more than the limit in a window: {over}"


def _machine_for(
    fail_open: bool,
    quarantine_fail_closed: bool,
) -> type[_LimiterMachine]:
    """Return a machine class bound to one limiter fail-policy configuration."""
    return type(
        f"LimiterMachine_open{fail_open}_qfc{quarantine_fail_closed}",
        (_LimiterMachine,),
        {"fail_open": fail_open, "quarantine_fail_closed": quarantine_fail_closed},
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("fail_open", "quarantine_fail_closed"),
    [
        pytest.param(True, False, id="fail_open-default"),
        pytest.param(True, True, id="fail_open-quarantine_fail_closed"),
        pytest.param(False, False, id="fail_closed"),
        pytest.param(False, True, id="fail_closed-quarantine_fail_closed"),
    ],
)
def test_limiter_state_machine(
    fail_open: bool,
    quarantine_fail_closed: bool,
) -> None:
    """Property: limits hold per key per window, and the fail policy holds in an outage."""
    run_state_machine_as_test(
        _machine_for(fail_open, quarantine_fail_closed),
        settings=MACHINE_SETTINGS,
    )


def _outage_limiter(
    fail_open: bool,
    quarantine_fail_closed: bool,
) -> _LimiterMachine:
    """Build a configured machine with its whole datastore down.

    Args:
        fail_open: Limiter ``fail_open`` policy.
        quarantine_fail_closed: Limiter ``quarantine_fail_closed`` policy.

    Returns:
        A machine instance; call ``teardown`` when done.
    """
    machine = _machine_for(fail_open, quarantine_fail_closed)()
    machine.configure(
        limits={
            "devs_burst_user": 1,
            "devs_burst_agent": 1,
            "devs_volume_user": 2,
            "devs_volume_agent": 2,
            "ops_burst_user": 1,
            "devs_pair_user": 1,
            "devs_pair_agent": 1,
            "target": 1,
            "target_fail_closed": False,
        }
    )
    machine.store.counter_up = False
    machine.store.metadata_up = False
    return machine


@pytest.mark.unit
@pytest.mark.parametrize("name", sorted(CALLERS))
def test_fail_closed_limiter_denies_during_outage(
    name: str,
) -> None:
    """Property: with fail_open False, a datastore outage denies a gated request."""
    machine = _outage_limiter(fail_open=False, quarantine_fail_closed=False)
    try:
        outcome = _check(machine.limiter, CALLERS[name], TARGET_WITH_LIMIT)
    finally:
        machine.teardown()
    assert outcome.allowed is False, f"request allowed during outage: {outcome}"


@pytest.mark.unit
@pytest.mark.parametrize("fail_open", [True, False])
@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("name", sorted(CALLERS))
def test_quarantine_fail_closed_denies_during_outage(
    name: str,
    target: str,
    fail_open: bool,
) -> None:
    """Property: with quarantine_fail_closed, an unreadable quarantine store denies everyone."""
    machine = _outage_limiter(fail_open=fail_open, quarantine_fail_closed=True)
    try:
        outcome = _check(machine.limiter, CALLERS[name], target)
    finally:
        machine.teardown()
    assert outcome.allowed is False
    assert outcome.quarantined is True
