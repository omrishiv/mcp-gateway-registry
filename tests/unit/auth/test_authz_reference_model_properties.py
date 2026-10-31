"""Differential properties of the registry and gateway authorization decision.

One reference model, ``_decide`` and ``_may_call``, states what a caller holding
a set of IdP groups may do under a scope table: the scopes those groups map to
(exact group-name match only), the merged ui_permissions, whether those make the
caller an administrator (an admin-conferring action granted the list element
``"all"``), and which servers and tools the caller may see and call. Every
production function that answers part of that question is diffed against the
model over generated scope tables served by a dict-backed scope repository, and
the registry's tool-list filter is diffed against the gateway's per-call
decision. Access must also be monotone in groups and scopes, independent of
their order and duplicates, deny-by-default, and fail closed when the scope
repository errors.
"""

import asyncio
import copy
import os
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import (
    Any,
    NamedTuple,
)
from unittest.mock import (
    AsyncMock,
    patch,
)

import pytest
from hypothesis import (
    assume,
    example,
    given,
    settings,
)
from hypothesis import strategies as st

os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-definitely-long-enough-32b")

# auth_server.server imports its siblings by flat name (the container layout),
# so its directory must be importable, as tests/auth_server/conftest.py arranges.
_AUTH_SERVER_DIR = str(Path(__file__).resolve().parents[3] / "auth_server")
if _AUTH_SERVER_DIR not in sys.path:
    sys.path.append(_AUTH_SERVER_DIR)

from auth_server.server import validate_server_tool_access  # noqa: E402
from registry.auth import dependencies  # noqa: E402
from registry.auth.asset_permissions import (  # noqa: E402
    _SCOPE_NAMES,
    accessible_resources_for,
    asset_scope_name,
    user_has_asset_permission,
)
from registry.auth.tool_filter import tool_allowed_for_user  # noqa: E402
from registry.repositories.documentdb.scope_repository import (  # noqa: E402
    DocumentDBScopeRepository,
    _grants_admin,
)

pytestmark = pytest.mark.unit

_PROPERTY = settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)

_TOOL_CALL = "tools/call"
_WILDCARDS = frozenset({"*", "all"})
# Only "*" names every server; "all" is a plain (reserved) server name.
_SERVER_WILDCARD = "*"
_EVERY_TOOL = frozenset({"*"})

# Restated admin rule: a mutating prefix, minus the per-type custom-entity and
# skill-management scopes, which gate one asset family rather than the registry.
_MUTATING_PREFIXES = ("register_", "modify_", "toggle_", "delete_", "publish_", "create_")
_NON_ADMIN_MUTATIONS = frozenset({"publish_skill", "modify_skill", "delete_skill", "toggle_skill"})
_ENTITY_SCOPE_RE = re.compile(r"\A(create|modify|delete)_.+_entity\Z")

_GROUP_POOL = ("eng", "ops", "sec", "qa")
_SCOPE_POOL = ("scope-a", "scope-b", "scope-c", "scope-d")
_ENTITY_TYPE = "dataset"
_ACTIONS = tuple(
    sorted(
        set(_SCOPE_NAMES.values())
        | {
            "list_dataset_entity",
            "create_dataset_entity",
            "delete_dataset_entity",
            "change_lifecycle_status",
            "create_virtual_server",
        }
    )
)
_RESOURCE_POOL = ("all", "github", "gitlab", "*", "All")
_ODD_UI_VALUES = ("all", "*", "All", "reinstall", None, 3, {"all": True})
_PROBE_RESOURCES = ("github", "gitlab", "*", "all")

_CANONICAL_SERVERS = ("github", "gitlab")
_SLASH_VARIANTS = ("/github/", "/github", "github/")
_TOOL_POOL = ("read", "write", "delete_repo", "*", "all")
_PROBE_TOOLS = ("read", "write", "delete_repo")
_METHOD_POOL = ("tools/call", "tools/list", "initialize", "*", "all")
_PROBE_METHODS = ("tools/call", "tools/list", "initialize")
# (gateway server name, registered server path) pairs probed on both sides.
_PROBE_SERVERS = (("github", "/github/"), ("gitlab", "/gitlab/"))
_ABSENT = object()

_REPO_READS = ("get_all_group_mappings", "get_ui_scopes_bulk", "get_server_scopes_bulk")


class _Decision(NamedTuple):
    """One caller's authorization as the reference model or production sees it."""

    scopes: frozenset[str]
    ui_permissions: dict[str, frozenset[str]]
    is_admin: bool
    servers: frozenset[str]
    tools: dict[str, frozenset[str]]


# Reference model.


def _confers_admin(action: str) -> bool:
    """Return True when holding ``action`` for every resource makes an administrator."""
    return (
        action.startswith(_MUTATING_PREFIXES)
        and action not in _NON_ADMIN_MUTATIONS
        and not _ENTITY_SCOPE_RE.match(action)
    )


def _allowlist(value: Any) -> frozenset[str]:
    """Return the tools a stored ``tools`` value names; ``{"*"}`` means every tool."""
    names = {value} if isinstance(value, str) else set(value) if isinstance(value, list) else set()
    return _EVERY_TOOL if names & _WILDCARDS else frozenset(names)


def _normalize_ui(ui: dict[str, Iterable[str]]) -> dict[str, frozenset[str]]:
    """Drop empty grants and collapse any grant holding ``"all"`` to ``{"all"}``."""
    return {a: frozenset({"all"}) if "all" in v else frozenset(v) for a, v in ui.items() if v}


def _decide(table: dict[str, dict], groups: Iterable[str]) -> _Decision:
    """Reference decision: what ``groups`` may do under ``table``."""
    held = set(groups)
    scopes = frozenset(name for name, doc in table.items() if held & set(doc["group_mappings"]))
    ui: dict[str, set[str]] = {}
    tools: dict[str, set[str]] = {}
    for scope in scopes:
        for action, value in table[scope]["ui_permissions"].items():
            if isinstance(value, list):
                ui.setdefault(action, set()).update(value)
        for rule in table[scope]["server_access"]:
            server = rule.get("server")
            if isinstance(server, str) and server:
                tools.setdefault(server, set()).update(_allowlist(rule.get("tools", [])))
    ui_permissions = _normalize_ui(ui)
    is_admin = any(_confers_admin(a) and "all" in r for a, r in ui_permissions.items())
    allowlists = {k: _EVERY_TOOL if "*" in v else frozenset(v) for k, v in tools.items()}
    return _Decision(scopes, ui_permissions, is_admin, frozenset(tools), allowlists)


def _may_call(
    table: dict[str, dict],
    groups: Iterable[str],
    server: str,
    method: str,
    tool: str | None,
    blocked: frozenset[str],
) -> bool:
    """Reference gateway decision for one MCP request on ``server``."""
    if method == _TOOL_CALL and tool in blocked:
        return False
    for scope in _decide(table, groups).scopes:
        for rule in table[scope]["server_access"]:
            name = rule.get("server")
            if not isinstance(name, str) or not name.strip("/"):
                continue
            if name != _SERVER_WILDCARD and name.strip("/") != server.strip("/"):
                continue
            allowed = _allowlist(rule.get("tools", []))
            if method == _TOOL_CALL:
                if "*" in allowed or tool in allowed:
                    return True
                continue
            methods = set(rule.get("methods") or [])
            if method in methods or methods & _WILDCARDS or "*" in allowed or method in allowed:
                return True
    return False


# Production harness.


class _TableScopeRepo:
    """Dict-backed scope repository over a scope table.

    Implements the reads the registry and gateway decisions make, with the
    DocumentDB repository's return shapes. Each read named in ``failing`` raises
    instead, standing in for an unreachable store.
    """

    def __init__(
        self,
        table: dict[str, dict],
        failing: Iterable[str] = (),
    ) -> None:
        self._table = copy.deepcopy(table)
        self._failing = frozenset(failing)

    def _check(self, read: str) -> None:
        if read in self._failing:
            raise RuntimeError(f"scope store unavailable during {read}")

    async def get_all_group_mappings(self) -> dict[str, list[str]]:
        self._check("get_all_group_mappings")
        return {name: list(doc["group_mappings"]) for name, doc in self._table.items()}

    async def get_ui_scopes_bulk(self, group_names: list[str]) -> dict[str, dict]:
        self._check("get_ui_scopes_bulk")
        found = {n: self._table[n]["ui_permissions"] for n in set(group_names) if n in self._table}
        return copy.deepcopy({n: ui for n, ui in found.items() if ui})

    async def get_server_scopes_bulk(self, scope_names: list[str]) -> dict[str, list[dict]]:
        self._check("get_server_scopes_bulk")
        found = {n: self._table[n]["server_access"] for n in set(scope_names) if n in self._table}
        return copy.deepcopy({n: rules for n, rules in found.items() if rules})

    async def get_server_scopes(self, scope_name: str) -> list[dict]:
        self._check("get_server_scopes")
        return copy.deepcopy(self._table.get(scope_name, {}).get("server_access", []))


async def _context_from_groups(
    repo: Any,
    groups: list[str],
) -> dict[str, Any]:
    """Derive the request-time user_context the way both auth paths do.

    Args:
        repo: Scope repository the registry reads.
        groups: The caller's IdP groups, in the order the IdP sent them.

    Returns:
        The context built by ``map_cognito_groups_to_scopes`` then ``_derive_user_context``.
    """
    with patch("registry.repositories.factory.get_scope_repository", return_value=repo):
        scopes = await dependencies.map_cognito_groups_to_scopes(groups)
        return await _derive(scopes, groups)


async def _derive(
    scopes: list[str],
    groups: list[str],
) -> dict[str, Any]:
    """Call ``_derive_user_context`` for a caller; the repository must already be patched.

    Args:
        scopes: The caller's scopes.
        groups: The caller's groups.

    Returns:
        The derived user_context.
    """
    return await dependencies._derive_user_context(
        username="caller",
        groups=groups,
        scopes=scopes,
        auth_method="oauth2",
        provider="keycloak",
    )


def _context(table: dict[str, dict], groups: list[str]) -> dict[str, Any]:
    """Return the production user_context for ``groups`` under ``table``."""
    return asyncio.run(_context_from_groups(_TableScopeRepo(table), groups))


def _context_for_scopes(table: dict[str, dict], scopes: list[str]) -> dict[str, Any]:
    """Return the production user_context for a caller holding exactly ``scopes``."""

    async def _run() -> dict[str, Any]:
        repo = _TableScopeRepo(table)
        with patch("registry.repositories.factory.get_scope_repository", return_value=repo):
            return await _derive(scopes, [])

    return asyncio.run(_run())


def _decision_of(ctx: dict[str, Any]) -> _Decision:
    """Project a production user_context onto the reference model's shape."""
    return _Decision(
        frozenset(ctx["scopes"]),
        _normalize_ui(ctx["ui_permissions"]),
        bool(ctx["is_admin"]),
        frozenset(ctx["accessible_servers"]),
        {k: frozenset(v) for k, v in ctx["accessible_tools"].items()},
    )


def _atoms(decision: _Decision) -> frozenset[tuple]:
    """Flatten a decision into individual grants, so inclusion means "no more access"."""
    atoms: set[tuple] = {("scope", s) for s in decision.scopes}
    atoms |= {("server", s) for s in decision.servers}
    if decision.is_admin:
        atoms.add(("admin",))
    for action, granted in decision.ui_permissions.items():
        atoms |= {("ui", action, r) for r in _PROBE_RESOURCES if "all" in granted or r in granted}
    for key, allow in decision.tools.items():
        atoms |= {("tool", key.strip("/"), t) for t in _PROBE_TOOLS if "*" in allow or t in allow}
    return frozenset(atoms)


def _visible_tools(ctx: dict[str, Any]) -> frozenset[tuple[str, str]]:
    """Return the (server, tool) probes the registry tool filter shows for ``ctx``."""
    return frozenset(
        (name, tool)
        for name, path in _PROBE_SERVERS
        for tool in _PROBE_TOOLS
        if tool_allowed_for_user(name, tool, ctx, server_path=path)
    )


def _gateway(
    table: dict[str, dict],
    scopes: list[str],
    requests: Iterable[tuple[str, str, str | None]],
    blocked: frozenset[str] = frozenset(),
) -> dict[tuple[str, str, str | None], bool]:
    """Run ``validate_server_tool_access`` for each (server, method, tool) request.

    Args:
        table: Scope table the gateway reads.
        scopes: The caller's scopes.
        requests: Requests to decide.
        blocked: Blocked tools on every server.

    Returns:
        The gateway's decision per request.
    """

    async def _run() -> dict[tuple[str, str, str | None], bool]:
        with (
            patch("auth_server.server.get_scope_repository", return_value=_TableScopeRepo(table)),
            patch("auth_server.server._get_blocked_tools", AsyncMock(return_value=set(blocked))),
        ):
            return {
                (server, method, tool): await validate_server_tool_access(
                    server, method, tool, list(scopes)
                )
                for server, method, tool in requests
            }

    return asyncio.run(_run())


def _tool_calls() -> list[tuple[str, str, str]]:
    """Return every probed ``tools/call`` request."""
    return [(name, _TOOL_CALL, tool) for name, _ in _PROBE_SERVERS for tool in _PROBE_TOOLS]


def _scope_doc(
    groups: list[str],
    rules: list[dict] | None = None,
    ui: dict | None = None,
) -> dict:
    """Build one scope document for a pinned example."""
    return {"group_mappings": groups, "ui_permissions": ui or {}, "server_access": rules or []}


def _call_rule(server: str, tools: Any) -> dict:
    """Build a server rule allowing ``tools/call`` with the given ``tools`` value."""
    return {"server": server, "methods": [_TOOL_CALL], "tools": tools}


def _outcome(predicate: Any, ui_permissions: dict) -> object:
    """Return a predicate's verdict, or the exception type it raised."""
    try:
        return bool(predicate(ui_permissions))
    except Exception as exc:
        return type(exc).__name__


# Strategies.

_list_tools = st.lists(st.sampled_from(_TOOL_POOL), max_size=3)
_WELL_FORMED_TOOLS = st.one_of(_list_tools, st.just(_ABSENT))
_ANY_TOOLS = st.one_of(
    _list_tools, st.just(_ABSENT), st.sampled_from(_TOOL_POOL), st.sampled_from([None, 3])
)
_ui_values = st.one_of(
    st.lists(st.sampled_from(_RESOURCE_POOL), max_size=3), st.sampled_from(_ODD_UI_VALUES)
)
_ui_tables = st.dictionaries(st.sampled_from(_ACTIONS), _ui_values, max_size=4)
_groups = st.lists(st.sampled_from((*_GROUP_POOL, "other")), max_size=4)


@st.composite
def _rule(draw: st.DrawFn, servers: tuple[str, ...], tools: st.SearchStrategy) -> dict:
    """Draw one server access rule.

    Args:
        draw: Hypothesis draw function.
        servers: Server names the rule may name.
        tools: Strategy for the ``tools`` value (``_ABSENT`` omits the key).

    Returns:
        A server rule dict.
    """
    rule: dict[str, Any] = {
        "server": draw(st.sampled_from(servers)),
        "methods": draw(st.lists(st.sampled_from(_METHOD_POOL), max_size=3)),
    }
    value = draw(tools)
    if value is not _ABSENT:
        rule["tools"] = value
    return rule


def _tables(
    servers: tuple[str, ...] = _CANONICAL_SERVERS + _SLASH_VARIANTS,
    tools: st.SearchStrategy = _WELL_FORMED_TOOLS,
    ui: st.SearchStrategy = _ui_tables,
) -> st.SearchStrategy[dict[str, dict]]:
    """Strategy for scope tables.

    Args:
        servers: Server names rules may name.
        tools: Strategy for each rule's ``tools`` value.
        ui: Strategy for each scope's ui_permissions.

    Returns:
        A strategy of scope name to scope document.
    """
    doc = st.fixed_dictionaries(
        {
            "group_mappings": st.lists(st.sampled_from(_GROUP_POOL), max_size=3),
            "ui_permissions": ui,
            "server_access": st.lists(_rule(servers, tools), max_size=3),
        }
    )
    return st.dictionaries(st.sampled_from(_SCOPE_POOL), doc, max_size=4)


_REGISTRY_TABLES = _tables(tools=_ANY_TOOLS)
_GATEWAY_TABLES = _tables(
    servers=(*_CANONICAL_SERVERS, *_SLASH_VARIANTS, "*", "all"), ui=st.just({})
)


@st.composite
def _reordered_groups(draw: st.DrawFn) -> tuple[dict, list[str], list[str]]:
    """Draw a table, a group list, and a permutation of it with duplicates added."""
    table = draw(_REGISTRY_TABLES)
    groups = draw(_groups)
    variant = list(draw(st.permutations(groups)))
    variant += draw(st.lists(st.sampled_from(groups), max_size=3)) if groups else []
    return table, groups, list(draw(st.permutations(variant)))


@st.composite
def _with_extra_group(draw: st.DrawFn, tables: st.SearchStrategy) -> tuple[dict, list, str]:
    """Draw a table, a group list, and one more group to add."""
    return draw(tables), draw(_groups), draw(st.sampled_from(_GROUP_POOL))


@st.composite
def _with_inserted_scope(draw: st.DrawFn, tables: st.SearchStrategy) -> tuple[dict, list, list]:
    """Draw a table, a scope list, and the same list with one scope inserted anywhere."""
    table = draw(tables)
    scopes = draw(st.lists(st.sampled_from(_SCOPE_POOL), max_size=3))
    extra = draw(st.sampled_from(_SCOPE_POOL))
    index = draw(st.integers(min_value=0, max_value=len(scopes)))
    return table, scopes, [*scopes[:index], extra, *scopes[index:]]


# Pinned examples.

_FIRST_KEY_WINS_TABLE = {
    "scope-a": _scope_doc(["eng"], [_call_rule("github", ["write"])]),
    "scope-b": _scope_doc(["ops"], [_call_rule("/github/", ["read"])]),
}
_LAST_NORMALIZED_KEY_TABLE = {
    "scope-a": _scope_doc(["eng"], [_call_rule("/github", ["read"])]),
    "scope-b": _scope_doc(["ops"], [_call_rule("github/", ["write"])]),
}
_NULL_TOOLS_TABLE = {
    "scope-a": _scope_doc(["eng"], [_call_rule("github", None)]),
    "scope-b": _scope_doc(["ops"], [_call_rule("github", ["read"])]),
}
_ALL_SERVER_TABLE = {"scope-a": _scope_doc(["eng"], [_call_rule("all", ["read"])])}
_STAR_SERVER_TABLE = {"scope-a": _scope_doc(["eng"], [_call_rule("*", ["read"])])}


# Reference diffs.


@_PROPERTY
@given(table=_REGISTRY_TABLES, groups=_groups)
def test_group_mapping_matches_reference(table: dict, groups: list[str]) -> None:
    """Property: map_cognito_groups_to_scopes returns exactly the reference scopes, once each."""

    async def _run() -> list[str]:
        with patch(
            "registry.repositories.factory.get_scope_repository",
            return_value=_TableScopeRepo(table),
        ):
            return await dependencies.map_cognito_groups_to_scopes(groups)

    scopes = asyncio.run(_run())
    assert len(scopes) == len(set(scopes)), f"duplicate scopes: {scopes}"
    assert set(scopes) == _decide(table, groups).scopes


@_PROPERTY
@given(table=_REGISTRY_TABLES, groups=_groups)
@example(
    table={"scope-a": _scope_doc(["eng"], ui={"register_service": ["github", "all"]})},
    groups=["eng"],
)
def test_derived_context_matches_reference(table: dict, groups: list[str]) -> None:
    """Property: the derived context's scopes, ui_permissions, is_admin, servers and tools equal the reference.

    Covers map_cognito_groups_to_scopes, get_ui_permissions_for_user,
    resolve_scope_access, _user_is_admin and _derive_user_context together,
    over tables with no cross-server rule (those are diffed against the
    gateway below).
    """
    assert _decision_of(_context(table, groups)) == _decide(table, groups)


_ASSET_PERMISSIONS = (*sorted(_SCOPE_NAMES), ("custom_entity", "list"), ("custom_entity", "create"))
_LIST_PROJECTIONS = (
    ("server", "accessible_services"),
    ("agent", "accessible_agents"),
    ("skill", "accessible_skills"),
)


@_PROPERTY
@given(table=_REGISTRY_TABLES, groups=_groups)
def test_asset_permissions_match_reference(table: dict, groups: list[str]) -> None:
    """Property: per-asset checks and list projections equal the reference decision.

    user_has_asset_permission allows iff the caller is admin or the action's
    grant holds the resource or ``"all"``; accessible_resources_for and the
    context's ``accessible_*`` lists project the list grant as ``["all"]`` or
    the named resources.
    """
    ctx = _context(table, groups)
    reference = _decide(table, groups)
    for family, action in _ASSET_PERMISSIONS:
        type_name = _ENTITY_TYPE if family == "custom_entity" else None
        key = asset_scope_name(family, action, type_name)
        granted = reference.ui_permissions.get(key, frozenset())
        for resource in _PROBE_RESOURCES:
            expected = reference.is_admin or "all" in granted or resource in granted
            allowed = user_has_asset_permission(family, action, resource, ctx, type_name=type_name)
            assert allowed == expected, (family, action, resource)
    for family, field in _LIST_PROJECTIONS:
        listed = reference.ui_permissions.get(asset_scope_name(family, "list"), frozenset())
        assert set(accessible_resources_for(family, ctx["ui_permissions"])) == set(listed)
        assert set(ctx[field]) == set(listed)


# Monotonicity, order and duplicates.


@_PROPERTY
@given(case=_with_extra_group(_REGISTRY_TABLES))
def test_context_monotone_in_groups(case: tuple[dict, list[str], str]) -> None:
    """Property: adding a group never removes a scope, ui grant, admin, server or tool grant."""
    table, groups, extra = case
    before = _atoms(_decision_of(_context(table, groups)))
    after = _atoms(_decision_of(_context(table, [*groups, extra])))
    assert before <= after, f"lost by adding {extra!r}: {sorted(before - after)}"


@_PROPERTY
@given(case=_with_inserted_scope(_REGISTRY_TABLES))
def test_context_monotone_in_scopes(case: tuple[dict, list[str], list[str]]) -> None:
    """Property: holding one more scope never removes a ui grant, admin, server or tool grant."""
    table, scopes, more = case
    before = _atoms(_decision_of(_context_for_scopes(table, scopes)))
    after = _atoms(_decision_of(_context_for_scopes(table, more)))
    assert before <= after, f"lost going {scopes} -> {more}: {sorted(before - after)}"


@_PROPERTY
@given(case=_with_extra_group(_REGISTRY_TABLES))
@example(case=(_FIRST_KEY_WINS_TABLE, ["eng"], "ops"))
def test_tool_visibility_monotone_in_groups(case: tuple[dict, list[str], str]) -> None:
    """Property: adding a group never hides a tool the registry tool filter showed."""
    table, groups, extra = case
    before = _visible_tools(_context(table, groups))
    after = _visible_tools(_context(table, [*groups, extra]))
    assert before <= after, f"hidden by adding {extra!r}: {sorted(before - after)}"


@_PROPERTY
@given(case=_with_inserted_scope(_tables(tools=_ANY_TOOLS, ui=st.just({}))))
@example(case=(_NULL_TOOLS_TABLE, ["scope-b"], ["scope-a", "scope-b"]))
def test_gateway_monotone_in_scopes(case: tuple[dict, list[str], list[str]]) -> None:
    """Property: holding one more scope never makes the gateway deny a request it allowed."""
    table, scopes, more = case
    requests = [(n, m, t) for n, _ in _PROBE_SERVERS for m in _PROBE_METHODS for t in _PROBE_TOOLS]
    before = _gateway(table, scopes, requests)
    after = _gateway(table, more, requests)
    lost = sorted(r for r in requests if before[r] and not after[r])
    assert not lost, f"denied after going {scopes} -> {more}: {lost}"


@_PROPERTY
@given(case=_reordered_groups())
def test_context_invariant_under_order_and_duplicates(
    case: tuple[dict, list[str], list[str]],
) -> None:
    """Property: reordering or repeating groups, or the scopes they map to, changes no grant."""
    table, groups, variant = case
    assert _decision_of(_context(table, groups)) == _decision_of(_context(table, variant))
    scopes = sorted(_decide(table, groups).scopes)
    shuffled = [*reversed(scopes), *scopes]
    assert _decision_of(_context_for_scopes(table, scopes)) == _decision_of(
        _context_for_scopes(table, shuffled)
    )


@_PROPERTY
@given(case=_reordered_groups())
@example(case=(_LAST_NORMALIZED_KEY_TABLE, ["eng", "ops"], ["ops", "eng"]))
def test_tool_visibility_invariant_under_group_order(
    case: tuple[dict, list[str], list[str]],
) -> None:
    """Property: reordering or repeating groups never changes which tools the filter shows."""
    table, groups, variant = case
    assert _visible_tools(_context(table, groups)) == _visible_tools(_context(table, variant))


# Deny-by-default and exact names.

_NON_CONFERRING_GRANTS = (
    pytest.param(["*"], id="list-star"),
    pytest.param(["All"], id="list-All"),
    pytest.param(["ALL"], id="list-ALL"),
    pytest.param([" all"], id="list-space-all"),
    pytest.param(["all "], id="list-all-space"),
    pytest.param([], id="list-empty"),
    pytest.param("*", id="bare-star"),
    pytest.param("All", id="bare-All"),
    pytest.param("all", id="bare-all"),
    pytest.param("reinstall", id="bare-reinstall"),
    pytest.param(None, id="null"),
    pytest.param(0, id="number"),
    pytest.param({"all": True}, id="dict-all"),
)


@pytest.mark.parametrize("action", ["register_service", "delete_agent", "create_virtual_server"])
@pytest.mark.parametrize("grant", _NON_CONFERRING_GRANTS)
def test_derived_context_admin_requires_list_all_grant(action: str, grant: Any) -> None:
    """Property: only the list element "all" on a conferring action makes the derived context admin."""
    table = {"scope-a": _scope_doc(["eng"], ui={action: grant})}
    assert _context(table, ["eng"])["is_admin"] is False


@pytest.mark.parametrize("action", ["register_service", "delete_agent", "create_virtual_server"])
@pytest.mark.parametrize("grant", _NON_CONFERRING_GRANTS)
def test_user_is_admin_requires_list_all_grant(action: str, grant: Any) -> None:
    """Property: _user_is_admin is true only for the list element "all" on a conferring action.

    Raising on a malformed value is treated as a denial here (fail closed).
    """
    assert _outcome(dependencies._user_is_admin, {action: grant}) is not True


@_PROPERTY
@given(groups=_groups)
def test_empty_table_grants_nothing(groups: list[str]) -> None:
    """Property: with no scope documents, any groups get no scope, grant, admin, server or tool."""
    ctx = _context({}, groups)
    assert _atoms(_decision_of(ctx)) == frozenset()
    assert _visible_tools(ctx) == frozenset()


def _name_variants(name: str) -> list[str]:
    """Return spellings of ``name`` that differ by case, whitespace, prefix or suffix."""
    return [
        name.upper(),
        name.title(),
        f" {name}",
        f"{name} ",
        f"{name}\n",
        f"x{name}",
        f"{name}x",
        name[:-1],
        f"/{name}",
    ]


@_PROPERTY
@given(
    table=_REGISTRY_TABLES,
    target=st.sampled_from(_GROUP_POOL),
    pick=st.integers(min_value=0, max_value=8),
)
def test_group_name_variants_get_nothing(table: dict, target: str, pick: int) -> None:
    """Property: a group that differs from every mapped name by case, whitespace, prefix or suffix gets nothing."""
    variant = _name_variants(target)[pick]
    assume(all(variant not in doc["group_mappings"] for doc in table.values()))
    ctx = _context(table, [variant])
    assert _atoms(_decision_of(ctx)) == frozenset()
    assert _visible_tools(ctx) == frozenset()


# Repository errors.


@_PROPERTY
@given(
    table=_REGISTRY_TABLES,
    groups=_groups,
    failing=st.sets(st.sampled_from(_REPO_READS), min_size=1),
)
def test_repository_error_never_widens_context(
    table: dict,
    groups: list[str],
    failing: set[str],
) -> None:
    """Property: when scope reads fail, derivation raises or grants a subset of the reference.

    When every read fails, a context that is returned grants nothing.
    """
    try:
        ctx = asyncio.run(_context_from_groups(_TableScopeRepo(table, failing), groups))
    except Exception:  # Refusing to build a context is failing closed.
        return
    granted = _atoms(_decision_of(ctx))
    assert granted <= _atoms(_decide(table, groups))
    if failing == set(_REPO_READS):
        assert granted == frozenset() and ctx["is_admin"] is False


class _FailingCollection:
    """Mongo collection stand-in whose every query fails."""

    def find(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("DocumentDB unreachable")

    async def find_one(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("DocumentDB unreachable")


@pytest.mark.parametrize("groups", [[], ["mcp-registry-admin"], ["registry-admins", "eng"]])
def test_documentdb_read_failure_yields_empty_context(groups: list[str]) -> None:
    """Property: a DocumentDB read error yields an empty context with is_admin False."""
    repo = DocumentDBScopeRepository()
    repo._collection = _FailingCollection()
    ctx = asyncio.run(_context_from_groups(repo, groups))
    assert ctx["is_admin"] is False
    assert _atoms(_decision_of(ctx)) == frozenset()
    assert _visible_tools(ctx) == frozenset()


_json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-2, max_value=2),
    st.sampled_from(["all", "*", "All", "reinstall", "github", ""]),
)
_json_values = st.recursive(
    _json_scalars,
    lambda inner: st.one_of(
        st.lists(inner, max_size=3),
        st.dictionaries(st.sampled_from(["all", "github"]), inner, max_size=2),
    ),
    max_leaves=4,
)


@_PROPERTY
@given(ui_permissions=st.dictionaries(st.sampled_from(_ACTIONS), _json_values, max_size=3))
@example(ui_permissions={"register_service": "reinstall"})
def test_grants_admin_agrees_with_user_is_admin(ui_permissions: dict) -> None:
    """Property: the write guard's _grants_admin and request-time _user_is_admin agree on every JSON value."""
    assert _outcome(_grants_admin, ui_permissions) == _outcome(
        dependencies._user_is_admin, ui_permissions
    )


# Gateway and list filter.


def _assert_gateway_matches_reference(
    table: dict,
    groups: list[str],
    blocked: frozenset[str],
) -> None:
    """Assert validate_server_tool_access equals ``_may_call`` on every probed request."""
    scopes = sorted(_decide(table, groups).scopes)
    requests = [(n, _TOOL_CALL, t) for n, _ in _PROBE_SERVERS for t in _PROBE_TOOLS]
    requests += [(n, m, None) for n, _ in _PROBE_SERVERS for m in _PROBE_METHODS[1:]]
    decided = _gateway(table, scopes, requests, blocked)
    wrong = sorted(
        (r, decided[r])
        for r in requests
        if decided[r] != _may_call(table, groups, r[0], r[1], r[2], blocked)
    )
    assert not wrong, f"gateway (request, verdict) differing from reference: {wrong}"


_blocked = st.frozensets(st.sampled_from(_PROBE_TOOLS), max_size=1)


@_PROPERTY
@given(
    table=_tables(servers=(*_CANONICAL_SERVERS, *_SLASH_VARIANTS, "*"), ui=st.just({})),
    groups=_groups,
    blocked=_blocked,
)
def test_gateway_matches_reference_without_all_server(
    table: dict,
    groups: list[str],
    blocked: frozenset[str],
) -> None:
    """Property: with no ``server: "all"`` rule, the gateway decision equals the reference."""
    _assert_gateway_matches_reference(table, groups, blocked)


@_PROPERTY
@given(table=_GATEWAY_TABLES, groups=_groups, blocked=_blocked)
@example(table=_ALL_SERVER_TABLE, groups=["eng"], blocked=frozenset())
def test_gateway_matches_reference(
    table: dict,
    groups: list[str],
    blocked: frozenset[str],
) -> None:
    """Property: the gateway decision equals the reference, ``server: "all"`` included."""
    _assert_gateway_matches_reference(table, groups, blocked)


def _assert_list_matches_call(table: dict, groups: list[str]) -> None:
    """Assert a tool is in the registry's filtered list iff the gateway allows calling it."""
    ctx = _context(table, groups)
    assert ctx["is_admin"] is False
    visible = _visible_tools(ctx)
    callable_ = {
        (n, t) for (n, _, t), ok in _gateway(table, ctx["scopes"], _tool_calls()).items() if ok
    }
    assert visible == callable_, (
        f"listed but not callable: {sorted(visible - callable_)}; "
        f"callable but not listed: {sorted(callable_ - visible)}"
    )


@_PROPERTY
@given(table=_tables(servers=_CANONICAL_SERVERS, ui=st.just({})), groups=_groups)
def test_list_filter_matches_gateway_for_canonical_names(table: dict, groups: list[str]) -> None:
    """Property: for non-admin callers whose rules name each server one way, list and call agree."""
    _assert_list_matches_call(table, groups)


@_PROPERTY
@given(table=_GATEWAY_TABLES, groups=_groups)
@example(table=_ALL_SERVER_TABLE, groups=["eng"])
@example(table=_STAR_SERVER_TABLE, groups=["eng"])
@example(table=_FIRST_KEY_WINS_TABLE, groups=["eng", "ops"])
def test_list_filter_matches_gateway(table: dict, groups: list[str]) -> None:
    """Property: for non-admin callers, a tool is listed iff the gateway allows ``tools/call`` on it.

    Admins are out of scope: the registry filter shows them every tool by
    design (``filter_tools_for_user`` docstring), while the gateway still
    requires a server rule.
    """
    _assert_list_matches_call(table, groups)


@pytest.mark.parametrize(
    ("table", "groups"),
    [
        pytest.param(_ALL_SERVER_TABLE, ["eng"], id="server-all-is-wildcard-in-registry-only"),
        pytest.param(_STAR_SERVER_TABLE, ["eng"], id="server-star-ignores-tools-in-registry"),
        pytest.param(_FIRST_KEY_WINS_TABLE, ["eng", "ops"], id="first-slash-spelling-wins"),
    ],
)
def test_list_filter_matches_gateway_pinned(table: dict, groups: list[str]) -> None:
    """Property: each pinned list-versus-call case lists exactly what is callable."""
    _assert_list_matches_call(table, groups)
