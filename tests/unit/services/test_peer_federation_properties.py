"""Property tests for peer federation ingest and peer removal.

Pins three security properties of peer federation: a sync from peer P and the
removal of peer P only create, change or delete server or agent records whose
``sync_metadata.source_peer_id`` is P, so local registrations never change
because of federation; ownership of a synced record is set by local policy,
never by the ``registered_by`` value the peer sent; and the federation export
never sends a peer a private item or a group-restricted item outside the peer's
groups.
"""

import asyncio
import copy
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import (
    strategies as st,
)
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    rule,
    run_state_machine_as_test,
)

from registry.api import federation_export_routes as export_module
from registry.schemas.agent_models import AgentCard
from registry.services import peer_federation_service as pfs_module
from registry.services.peer_federation_service import PeerFederationService

PEER_IDS: tuple[str, ...] = ("peer-a", "peer-b")
LOCAL_PATHS: tuple[str, ...] = (
    "/x",
    "/y",
    "/local-z",
    "/peer-a/x",
    "/peer-a/y",
    "/peer-b/y",
)
PEER_ITEM_PATHS: tuple[str, ...] = ("/x", "/y", "x")
ITEM_NAMES: tuple[str, ...] = ("alpha", "beta", "gamma")
LOCAL_OWNER: str = "local-admin"
PEER_AGENT_URL: str = "https://peer.example.com/agent"
LOCAL_AGENT_URL: str = "https://local.example.com/agent"

# Marks "visibility key absent" in the generated server records.
MISSING: Any = object()
EXPORT_GROUPS: tuple[str, ...] = ("g1", "g2", "g3")
# Stored server visibility values, including legacy and malformed spellings.
SERVER_VISIBILITIES: tuple[Any, ...] = (
    "public",
    "private",
    "internal",
    "group-restricted",
    "Public",
    "PRIVATE",
    " private",
    "group",
    "",
    None,
    MISSING,
)
AGENT_VISIBILITIES: tuple[str, ...] = ("public", "private", "internal", "group-restricted")
PEER_CLIENT_ID: str = "peer-client"

PROPERTY_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)
STATEFUL_SETTINGS = settings(
    max_examples=50,
    stateful_step_count=15,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

FINDING_15_REASON = (
    "Known defect: peer sync and peer removal select records by the /<peer_id>/ "
    "path prefix, so a local record under that prefix is overwritten by sync and "
    "deleted with the peer."
)
FINDING_14_REASON = (
    "Known defect: peer sync stores the registered_by value chosen by the peer, "
    "so a peer can name a local user as owner of a synced item."
)


class _InMemoryServerService:
    """In-memory stand-in for ``server_service`` that records every mutation.

    Records are deep-copied on the way in and out, so callers can never alias
    stored state. Each mutation is logged with the actor that caused it.
    """

    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}
        self.mutations: list[dict[str, Any]] = []
        self.actor: str = "local"

    def _log(
        self,
        op: str,
        path: str,
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
    ) -> None:
        """Append one mutation entry attributed to the current actor.

        Args:
            op: Operation name (register, update or remove).
            path: Record path.
            before: Record before the mutation, or None.
            after: Record after the mutation, or None.
        """
        self.mutations.append(
            {
                "actor": self.actor,
                "op": op,
                "path": path,
                "before": copy.deepcopy(before),
                "after": copy.deepcopy(after),
            }
        )

    async def get_server_info(
        self,
        path: str,
        include_credentials: bool = False,
    ) -> dict[str, Any] | None:
        record = self.records.get(path)
        return copy.deepcopy(record) if record is not None else None

    async def get_all_servers(
        self,
        include_inactive: bool = False,
        include_credentials: bool = False,
    ) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self.records)

    async def register_server(
        self,
        server_info: dict[str, Any],
        is_version_registration: bool = False,
    ) -> dict[str, Any]:
        path = server_info["path"]
        if path in self.records:
            return {"success": False, "message": "path exists"}
        self.records[path] = copy.deepcopy(server_info)
        self._log("register", path, None, server_info)
        return {"success": True}

    async def update_server(
        self,
        path: str,
        server_info: dict[str, Any],
    ) -> bool:
        if path not in self.records:
            return False
        before = self.records[path]
        self.records[path] = copy.deepcopy(server_info)
        self._log("update", path, before, server_info)
        return True

    async def remove_server(
        self,
        path: str,
    ) -> bool:
        if path not in self.records:
            return False
        before = self.records.pop(path)
        self._log("remove", path, before, None)
        return True


class _InMemoryAgentService:
    """In-memory stand-in for ``agent_service`` keyed by agent path."""

    def __init__(self) -> None:
        self.records: dict[str, AgentCard] = {}

    async def get_agent_info(
        self,
        path: str,
    ) -> AgentCard | None:
        return self.records.get(path)

    async def get_all_agents(self) -> list[AgentCard]:
        return list(self.records.values())

    async def register_agent(
        self,
        agent_card: AgentCard,
    ) -> AgentCard:
        self.records[agent_card.path] = agent_card
        return agent_card

    async def update_agent(
        self,
        path: str,
        updates: dict[str, Any],
    ) -> AgentCard:
        self.records[path] = AgentCard(**updates)
        return self.records[path]

    async def delete_agent(
        self,
        path: str,
    ) -> bool:
        return self.records.pop(path, None) is not None


@contextmanager
def _federation_service(
    servers: _InMemoryServerService,
    agents: _InMemoryAgentService,
) -> Iterator[PeerFederationService]:
    """Yield a fresh PeerFederationService wired to in-memory stores.

    Args:
        servers: Fake used in place of ``server_service``.
        agents: Fake used in place of ``agent_service``.

    Yields:
        A new service instance with search indexing patched to a no-op.
    """
    PeerFederationService._instance = None
    try:
        with ExitStack() as stack:
            stack.enter_context(patch.object(pfs_module, "server_service", servers))
            stack.enter_context(patch.object(pfs_module, "agent_service", agents))
            service = PeerFederationService()
            stack.enter_context(
                patch.object(service, "_index_server_for_search", AsyncMock(return_value=None))
            )
            stack.enter_context(
                patch.object(service, "_index_agent_for_search", AsyncMock(return_value=None))
            )
            yield service
    finally:
        PeerFederationService._instance = None


def _local_record(
    path: str,
    name: str,
) -> dict[str, Any]:
    """Build a locally registered server record (no sync_metadata).

    Args:
        path: Server path.
        name: Server name.

    Returns:
        Server record dict as the local registration path stores it.
    """
    return {
        "id": f"local-{path.strip('/').replace('/', '-')}",
        "path": path,
        "server_name": name,
        "registered_by": LOCAL_OWNER,
        "visibility": "private",
        "proxy_pass_url": "http://local-backend:8000",
    }


def _source_peer(
    record: dict[str, Any] | None,
) -> str | None:
    """Return the peer a stored record came from, or None for local records.

    Args:
        record: Stored server record, or None.

    Returns:
        ``sync_metadata.source_peer_id`` or None.
    """
    if not record:
        return None
    return (record.get("sync_metadata") or {}).get("source_peer_id")


class FederationIngestMachine(RuleBasedStateMachine):
    """Local registrations interleaved with peer syncs and peer removals."""

    def __init__(self) -> None:
        super().__init__()
        self.servers = _InMemoryServerService()
        self.agents = _InMemoryAgentService()
        self.local_snapshots: dict[str, dict[str, Any]] = {}
        self._ctx = _federation_service(self.servers, self.agents)
        self.service = self._ctx.__enter__()

    def teardown(self) -> None:
        self._ctx.__exit__(None, None, None)

    @rule(
        path=st.sampled_from(LOCAL_PATHS),
        name=st.sampled_from(ITEM_NAMES),
    )
    def register_local(
        self,
        path: str,
        name: str,
    ) -> None:
        record = _local_record(path, name)
        self.servers.actor = "local"
        result = asyncio.run(self.servers.register_server(record))
        if result["success"]:
            self.local_snapshots[path] = copy.deepcopy(record)

    @rule(
        peer_id=st.sampled_from(PEER_IDS),
        items=st.lists(
            st.fixed_dictionaries(
                {
                    "path": st.sampled_from(PEER_ITEM_PATHS),
                    "server_name": st.sampled_from(ITEM_NAMES),
                }
            ),
            max_size=3,
        ),
    )
    def sync(
        self,
        peer_id: str,
        items: list[dict[str, Any]],
    ) -> None:
        self.servers.actor = peer_id
        asyncio.run(self.service._store_synced_servers(peer_id, items))

    @rule(peer_id=st.sampled_from(PEER_IDS))
    def remove_peer(
        self,
        peer_id: str,
    ) -> None:
        self.servers.actor = peer_id
        asyncio.run(self.service._cleanup_synced_servers(peer_id))
        asyncio.run(self.service._cleanup_synced_agents(peer_id))

    @invariant()
    def local_records_untouched(self) -> None:
        """Every local record is still present and byte-for-byte unchanged."""
        for path, snapshot in self.local_snapshots.items():
            assert path in self.servers.records, f"local record {path} was deleted"
            assert self.servers.records[path] == snapshot, (
                f"local record {path} was changed to {self.servers.records[path]!r}"
            )

    @invariant()
    def peer_touches_only_its_own_records(self) -> None:
        """A sync or removal of peer P only touches records sourced from P."""
        for mutation in self.servers.mutations:
            actor = mutation["actor"]
            if actor == "local":
                continue
            for side in ("before", "after"):
                record = mutation[side]
                if record is None:
                    continue
                assert _source_peer(record) == actor, (
                    f"{actor} {mutation['op']} at {mutation['path']} touched "
                    f"{side} record from source {_source_peer(record)!r}"
                )
        self.servers.mutations.clear()


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_15_REASON)
def test_federation_ingest_state_machine() -> None:
    """Property: peer sync and removal never change or delete local records."""
    run_state_machine_as_test(FederationIngestMachine, settings=STATEFUL_SETTINGS)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("local_path", "action", "peer_id", "peer_items"),
    [
        pytest.param(
            "/local-z",
            "sync",
            "peer-a",
            [{"path": "/x", "server_name": "alpha"}],
            id="sync-plain-local-path",
        ),
        pytest.param(
            "/local-z",
            "remove",
            "peer-a",
            [],
            id="remove-plain-local-path",
        ),
        pytest.param(
            "/peer-b/y",
            "sync",
            "peer-a",
            [{"path": "/y", "server_name": "alpha"}],
            id="sync-other-peer-prefix",
        ),
        pytest.param(
            "/peer-a/x",
            "sync",
            "peer-a",
            [{"path": "/x", "server_name": "alpha"}],
            id="sync-overwrites-local-under-prefix",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_15_REASON),
        ),
        pytest.param(
            "/peer-b/y",
            "remove",
            "peer-b",
            [],
            id="remove-deletes-local-under-prefix",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_15_REASON),
        ),
    ],
)
def test_local_record_survives_peer_action(
    local_path: str,
    action: str,
    peer_id: str,
    peer_items: list[dict[str, Any]],
) -> None:
    """Property: a local record is unchanged after any sync or removal of a peer."""
    servers = _InMemoryServerService()
    agents = _InMemoryAgentService()
    record = _local_record(local_path, "local")
    asyncio.run(servers.register_server(record))

    with _federation_service(servers, agents) as service:
        if action == "sync":
            asyncio.run(service._store_synced_servers(peer_id, peer_items))
        else:
            asyncio.run(service._cleanup_synced_servers(peer_id))

    assert servers.records.get(local_path) == record


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_14_REASON)
@PROPERTY_SETTINGS
@given(peer_owner=st.from_regex(r"[a-z]{3,10}", fullmatch=True))
@example(peer_owner="alice")
def test_synced_server_owner_not_chosen_by_peer(
    peer_owner: str,
) -> None:
    """Property: a synced server's registered_by never equals the peer-sent value."""
    servers = _InMemoryServerService()
    agents = _InMemoryAgentService()
    item = {"path": "/x", "server_name": "alpha", "registered_by": peer_owner}

    with _federation_service(servers, agents) as service:
        asyncio.run(service._store_synced_servers("peer-a", [item]))

    stored = servers.records.get("/peer-a/x")
    assert stored is not None, "synced server was not stored"
    assert stored.get("registered_by") != peer_owner


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_14_REASON)
@PROPERTY_SETTINGS
@given(peer_owner=st.from_regex(r"[a-z]{3,10}", fullmatch=True))
@example(peer_owner="alice")
def test_synced_agent_owner_not_chosen_by_peer(
    peer_owner: str,
) -> None:
    """Property: a synced agent's registered_by never equals the peer-sent value."""
    servers = _InMemoryServerService()
    agents = _InMemoryAgentService()
    item = {
        "path": "/x",
        "name": "Peer Agent",
        "description": "A peer agent",
        "version": "1.0.0",
        "url": PEER_AGENT_URL,
        "registered_by": peer_owner,
    }

    with _federation_service(servers, agents) as service:
        asyncio.run(service._store_synced_agents("peer-a", [item]))

    stored = agents.records.get("/peer-a/x")
    assert stored is not None, "synced agent was not stored"
    assert stored.registered_by != peer_owner


# ---------------------------------------------------------------------------
# Agent records in the ingest state machine
# ---------------------------------------------------------------------------


class _RecordingAgentService(_InMemoryAgentService):
    """In-memory ``agent_service`` that deep-copies cards and logs every mutation.

    Each mutation is logged as dict snapshots with the actor that caused it, so
    the invariants can compare ``sync_metadata.source_peer_id`` with the actor.
    """

    def __init__(self) -> None:
        super().__init__()
        self.mutations: list[dict[str, Any]] = []
        self.actor: str = "local"

    def _log(
        self,
        op: str,
        path: str,
        before: AgentCard | None,
        after: AgentCard | None,
    ) -> None:
        """Append one mutation entry attributed to the current actor.

        Args:
            op: Operation name (register, update or delete).
            path: Agent path.
            before: Card before the mutation, or None.
            after: Card after the mutation, or None.
        """
        self.mutations.append(
            {
                "actor": self.actor,
                "op": op,
                "path": path,
                "before": before.model_dump() if before is not None else None,
                "after": after.model_dump() if after is not None else None,
            }
        )

    async def get_agent_info(
        self,
        path: str,
    ) -> AgentCard | None:
        card = self.records.get(path)
        return card.model_copy(deep=True) if card is not None else None

    async def get_all_agents(self) -> list[AgentCard]:
        return [card.model_copy(deep=True) for card in self.records.values()]

    async def register_agent(
        self,
        agent_card: AgentCard,
    ) -> AgentCard:
        stored = agent_card.model_copy(deep=True)
        self.records[stored.path] = stored
        self._log("register", stored.path, None, stored)
        return stored.model_copy(deep=True)

    async def update_agent(
        self,
        path: str,
        updates: dict[str, Any],
    ) -> AgentCard:
        before = self.records.get(path)
        stored = AgentCard(**copy.deepcopy(updates))
        self.records[path] = stored
        self._log("update", path, before, stored)
        return stored.model_copy(deep=True)

    async def delete_agent(
        self,
        path: str,
    ) -> bool:
        before = self.records.pop(path, None)
        if before is None:
            return False
        self._log("delete", path, before, None)
        return True


def _local_agent(
    path: str,
    name: str,
) -> AgentCard:
    """Build a locally registered agent card (no sync_metadata).

    Args:
        path: Agent path.
        name: Agent name.

    Returns:
        AgentCard as the local registration path stores it.
    """
    return AgentCard(
        path=path,
        name=name,
        description="A local agent",
        version="1.0.0",
        url=LOCAL_AGENT_URL,
        registered_by=LOCAL_OWNER,
        visibility="private",
    )


_PEER_AGENT_ITEMS = st.lists(
    st.fixed_dictionaries(
        {
            "path": st.sampled_from(PEER_ITEM_PATHS),
            "name": st.sampled_from(ITEM_NAMES),
            "description": st.just("A peer agent"),
            "version": st.just("1.0.0"),
            "url": st.just(PEER_AGENT_URL),
        }
    ),
    max_size=3,
)


class FederationAgentIngestMachine(RuleBasedStateMachine):
    """Local agent registrations interleaved with peer agent syncs and peer removals."""

    def __init__(self) -> None:
        super().__init__()
        self.servers = _InMemoryServerService()
        self.agents = _RecordingAgentService()
        self.local_snapshots: dict[str, dict[str, Any]] = {}
        self._ctx = _federation_service(self.servers, self.agents)
        self.service = self._ctx.__enter__()

    def teardown(self) -> None:
        self._ctx.__exit__(None, None, None)

    @rule(
        path=st.sampled_from(LOCAL_PATHS),
        name=st.sampled_from(ITEM_NAMES),
    )
    def register_local_agent(
        self,
        path: str,
        name: str,
    ) -> None:
        if path in self.agents.records:
            return
        card = _local_agent(path, name)
        self.agents.actor = "local"
        asyncio.run(self.agents.register_agent(card))
        self.local_snapshots[path] = card.model_dump()

    @rule(peer_id=st.sampled_from(PEER_IDS), items=_PEER_AGENT_ITEMS)
    def sync_agents(
        self,
        peer_id: str,
        items: list[dict[str, Any]],
    ) -> None:
        self.agents.actor = peer_id
        asyncio.run(self.service._store_synced_agents(peer_id, items))

    @rule(peer_id=st.sampled_from(PEER_IDS))
    def remove_peer(
        self,
        peer_id: str,
    ) -> None:
        self.agents.actor = peer_id
        asyncio.run(self.service._cleanup_synced_servers(peer_id))
        asyncio.run(self.service._cleanup_synced_agents(peer_id))

    @invariant()
    def local_agents_untouched(self) -> None:
        """Every local agent is still present and unchanged."""
        for path, snapshot in self.local_snapshots.items():
            assert path in self.agents.records, f"local agent {path} was deleted"
            current = self.agents.records[path].model_dump()
            assert current == snapshot, f"local agent {path} was changed to {current!r}"

    @invariant()
    def peer_touches_only_its_own_agents(self) -> None:
        """A sync or removal of peer P only touches agents sourced from P."""
        for mutation in self.agents.mutations:
            actor = mutation["actor"]
            if actor == "local":
                continue
            for side in ("before", "after"):
                record = mutation[side]
                if record is None:
                    continue
                assert _source_peer(record) == actor, (
                    f"{actor} {mutation['op']} at {mutation['path']} touched "
                    f"{side} agent from source {_source_peer(record)!r}"
                )
        self.agents.mutations.clear()


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_15_REASON)
def test_federation_agent_ingest_state_machine() -> None:
    """Property: peer agent sync and removal never change or delete local agents."""
    run_state_machine_as_test(FederationAgentIngestMachine, settings=STATEFUL_SETTINGS)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("local_path", "action", "peer_id", "peer_path"),
    [
        pytest.param("/local-z", "sync", "peer-a", "/x", id="sync-plain-local-path"),
        pytest.param("/local-z", "remove", "peer-a", None, id="remove-plain-local-path"),
        pytest.param("/peer-b/y", "sync", "peer-a", "/y", id="sync-other-peer-prefix"),
        pytest.param(
            "/peer-a/x",
            "sync",
            "peer-a",
            "/x",
            id="sync-overwrites-local-under-prefix",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_15_REASON),
        ),
        pytest.param(
            "/peer-b/y",
            "remove",
            "peer-b",
            None,
            id="remove-deletes-local-under-prefix",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_15_REASON),
        ),
    ],
)
def test_local_agent_survives_peer_action(
    local_path: str,
    action: str,
    peer_id: str,
    peer_path: str | None,
) -> None:
    """Property: a local agent is unchanged after any sync or removal of a peer."""
    servers = _InMemoryServerService()
    agents = _RecordingAgentService()
    card = _local_agent(local_path, "local")
    asyncio.run(agents.register_agent(card))
    item = {
        "path": peer_path,
        "name": "alpha",
        "description": "A peer agent",
        "version": "1.0.0",
        "url": PEER_AGENT_URL,
    }

    with _federation_service(servers, agents) as service:
        if action == "sync":
            asyncio.run(service._store_synced_agents(peer_id, [item]))
        else:
            asyncio.run(service._cleanup_synced_agents(peer_id))

    stored = agents.records.get(local_path)
    assert stored is not None, f"local agent {local_path} was deleted"
    assert stored.model_dump() == card.model_dump()


# ---------------------------------------------------------------------------
# Export direction: what this registry sends a peer
# ---------------------------------------------------------------------------


def _peer_may_receive(
    visibility: Any,
    allowed_groups: Any,
    peer_groups: list[str],
) -> bool:
    """Return True when visibility policy lets a peer with `peer_groups` see an item.

    A missing visibility means public (the documented legacy default). Otherwise
    only a public item, or a group-restricted item that shares a group with the
    peer, may leave; private, internal and unrecognised values never do. Case
    and surrounding whitespace are ignored so a normalising fix also passes.

    Args:
        visibility: Stored visibility, or MISSING when the key is absent.
        allowed_groups: Stored allowed_groups value.
        peer_groups: Groups in the peer's federation token.

    Returns:
        Whether the item may be exported to that peer.
    """
    if visibility is MISSING:
        return True
    if not isinstance(visibility, str):
        return False
    normalized = visibility.strip().lower()
    if normalized == "public":
        return True
    if normalized == "group-restricted" and isinstance(allowed_groups, list):
        return bool(set(allowed_groups) & set(peer_groups))
    return False


def _peer_context(
    peer_groups: list[str],
) -> dict[str, Any]:
    """Build the user context federation_auth hands an export route.

    Args:
        peer_groups: Groups in the peer's federation token.

    Returns:
        A federation peer user context.
    """
    return {
        "username": "peer-registry",
        "client_id": PEER_CLIENT_ID,
        "scopes": ["federation-service"],
        "groups": list(peer_groups),
    }


@contextmanager
def _export_services(
    servers: dict[str, dict[str, Any]],
    agents: list[AgentCard],
    agent_states: dict[str, bool],
) -> Iterator[None]:
    """Patch the export routes' services with in-memory data.

    Args:
        servers: Server records keyed by path.
        agents: Agent cards.
        agent_states: Enabled flag per agent path.

    Yields:
        None, while the patches are active.
    """
    server_service = MagicMock()
    server_service.get_all_servers = AsyncMock(return_value=copy.deepcopy(servers))
    agent_service = MagicMock()
    agent_service.get_all_agents = AsyncMock(
        return_value=[card.model_copy(deep=True) for card in agents]
    )
    agent_service.get_all_agent_states = AsyncMock(return_value=dict(agent_states))
    audit_service = MagicMock(log_connection=AsyncMock(return_value=None))
    with (
        patch.object(export_module, "server_service", server_service),
        patch.object(export_module, "agent_service", agent_service),
        patch.object(export_module, "get_federation_audit_service", return_value=audit_service),
    ):
        yield


_GROUP_SUBSETS = st.lists(st.sampled_from(EXPORT_GROUPS), unique=True, max_size=3)


@st.composite
def _stored_servers(draw: st.DrawFn) -> dict[str, dict[str, Any]]:
    """Draw stored server records with arbitrary visibility and group settings."""
    servers: dict[str, dict[str, Any]] = {}
    for index in range(draw(st.integers(min_value=0, max_value=6))):
        path = f"/server-{index}"
        record: dict[str, Any] = {
            "path": path,
            "server_name": f"server-{index}",
            "is_enabled": draw(st.booleans()),
            "allowed_groups": draw(_GROUP_SUBSETS),
        }
        visibility = draw(st.sampled_from(SERVER_VISIBILITIES))
        if visibility is not MISSING:
            record["visibility"] = visibility
        servers[path] = record
    return servers


@st.composite
def _stored_agents(draw: st.DrawFn) -> list[AgentCard]:
    """Draw stored agent cards with every valid visibility and group setting."""
    agents: list[AgentCard] = []
    for index in range(draw(st.integers(min_value=0, max_value=6))):
        visibility = draw(st.sampled_from(AGENT_VISIBILITIES))
        min_groups = 1 if visibility == "group-restricted" else 0
        allowed_groups = draw(
            st.lists(st.sampled_from(EXPORT_GROUPS), unique=True, min_size=min_groups, max_size=3)
        )
        agents.append(
            AgentCard(
                path=f"/agent-{index}",
                name=f"agent-{index}",
                description="An exported agent",
                version="1.0.0",
                url=f"https://agents.example.com/agent-{index}",
                visibility=visibility,
                allowed_groups=allowed_groups,
            )
        )
    return agents


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(servers=_stored_servers(), peer_groups=_GROUP_SUBSETS)
@example(
    servers={
        "/secret": {"path": "/secret", "is_enabled": True, "visibility": "private"},
        "/team": {
            "path": "/team",
            "is_enabled": True,
            "visibility": "group-restricted",
            "allowed_groups": ["g2"],
        },
    },
    peer_groups=["g1"],
)
def test_server_export_never_leaks_restricted_items(
    servers: dict[str, dict[str, Any]],
    peer_groups: list[str],
) -> None:
    """Property: exported servers are a subset of what visibility policy lets the peer see."""
    with _export_services(servers, [], {}):
        response = asyncio.run(
            export_module.export_servers(
                limit=export_module.MAX_PAGE_LIMIT,
                offset=0,
                since_generation=None,
                user_context=_peer_context(peer_groups),
            )
        )

    for item in response.items:
        stored = servers[item["path"]]
        assert _peer_may_receive(
            stored.get("visibility", MISSING),
            stored.get("allowed_groups"),
            peer_groups,
        ), f"peer with groups {peer_groups} received server {stored!r}"


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(
    agents=_stored_agents(),
    enabled=st.booleans(),
    peer_groups=_GROUP_SUBSETS,
)
def test_agent_export_never_leaks_restricted_items(
    agents: list[AgentCard],
    enabled: bool,
    peer_groups: list[str],
) -> None:
    """Property: exported agents are a subset of what visibility policy lets the peer see."""
    states = {card.path: enabled for card in agents}
    with _export_services({}, agents, states):
        response = asyncio.run(
            export_module.export_agents(
                limit=export_module.MAX_PAGE_LIMIT,
                offset=0,
                since_generation=None,
                user_context=_peer_context(peer_groups),
            )
        )

    by_path = {card.path: card for card in agents}
    for item in response.items:
        stored = by_path[item["path"]]
        assert _peer_may_receive(stored.visibility, stored.allowed_groups, peer_groups), (
            f"peer with groups {peer_groups} received agent {stored.path} "
            f"({stored.visibility}, {stored.allowed_groups})"
        )
