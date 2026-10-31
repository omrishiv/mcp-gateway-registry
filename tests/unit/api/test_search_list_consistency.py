"""Semantic search never shows a caller more than the list endpoints do.

``POST /api/search/semantic`` is a second read path over the same servers,
tools, agents, skills, virtual servers and custom entities that the list
endpoints (``GET /api/servers``, ``/api/agents``, ``/api/skills``,
``/api/virtual-servers``, ``/api/custom/{type}``) return. The security property
pinned here: for any user context derived from a generated scope table, with
the vector search mocked to return every stored entity, the search results for
each entity type are a subset of what the same caller's list endpoint returns
for that type, and no search result carries a backend address, credential or
other sensitive field that the list endpoint withholds from that caller.
"""

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any
from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.api import (
    agent_routes,
    custom_entity_routes,
    search_routes,
    server_routes,
    skill_routes,
    virtual_server_routes,
)
from registry.auth.dependencies import (
    _derive_user_context,
    nginx_proxied_auth,
)
from registry.core.config import (
    DeploymentMode,
    RegistryMode,
)
from registry.core.config import (
    settings as registry_settings,
)
from registry.schemas.agent_models import AgentCard
from registry.schemas.custom_entity_models import CustomEntityRecord
from registry.schemas.proxy_mixin import CustomHeaderEncrypted
from registry.schemas.skill_models import SkillCard
from registry.schemas.virtual_server_models import VirtualServerInfo
from registry.services.agent_service import agent_service
from registry.services.server_service import server_service
from registry.services.skill_service import SkillService

_SECRET_MARK: str = "SENTINEL-SECRET"
_BACKEND_HOST: str = "backend.internal.invalid"
_BACKEND_URL: str = f"http://{_BACKEND_HOST}:9000"
_CUSTOM_TYPE: str = "prompt"
_USERS: tuple[str, ...] = ("alice", "bob")
_GROUPS: tuple[str, ...] = ("team-a", "team-b")
_TOOLS: tuple[str, ...] = ("search", "delete")

# (path, display name). /docs is displayed as "jira", the technical name of /jira.
_SERVERS: tuple[tuple[str, str], ...] = (
    ("/github", "GitHub"),
    ("/jira", "Jira"),
    ("/docs", "jira"),
)
_AGENT_PATHS: tuple[str, ...] = ("/agents/triage", "/agents/billing", "/agents/deploy")
_SKILL_NAMES: tuple[str, ...] = ("pdf", "report", "deploy")
_VIRTUAL_SERVERS: tuple[tuple[str, str], ...] = (
    ("/virtual/vs1", "Virtual One"),
    ("/virtual/vs2", "Virtual Two"),
)
_CUSTOM_IDS: tuple[str, ...] = (
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
)

_SERVER_GRANTS: tuple[str, ...] = ("github", "/jira", "jira", "docs", "/virtual/vs1", "*", "all")
_TOOL_GRANTS: tuple[list[str], ...] = (["all"], ["search"], [])
_UI_GRANTS: dict[str, tuple[str, ...]] = {
    "list_service": ("github", "jira", "docs", "all"),
    "list_agents": (*_AGENT_PATHS, "all"),
    "list_skills": (*_SKILL_NAMES, "all"),
    "list_virtual_server": ("/virtual/vs1", "all"),
    f"list_{_CUSTOM_TYPE}_entity": (
        "all",
        _CUSTOM_TYPE,
        f"/{_CUSTOM_TYPE}/{_CUSTOM_IDS[0]}",
    ),
}
_ADMIN_SCOPE: str = "registry-admin-scope"
_ADMIN_SCOPE_RULES: list[dict[str, Any]] = [{"server": "*", "tools": ["all"]}]
_ADMIN_SCOPE_UI: dict[str, list[str]] = {
    "modify_service": ["all"],
    **{permission: ["all"] for permission in _UI_GRANTS},
}
_SCOPE_NAMES: tuple[str, ...] = ("scope-a", "scope-b")

_AGENT_VISIBILITIES: tuple[str, ...] = ("public", "private", "group-restricted")
_SKILL_VISIBILITIES: tuple[str, ...] = ("public", "private", "group")
_CUSTOM_VISIBILITIES: tuple[str, ...] = ("public", "private", "group-restricted")

_ENTITY_TYPES: list[str] = [
    "mcp_server",
    "tool",
    "a2a_agent",
    "skill",
    "virtual_server",
    _CUSTOM_TYPE,
]
_LIST_LIMIT: int = 2000

# Keys that carry a backend address the gateway hides from non-admin callers.
_BACKEND_KEYS: frozenset[str] = frozenset(
    {
        "proxy_pass_url",
        "proxyPassUrl",
        "mcp_endpoint",
        "mcpEndpoint",
        "sse_endpoint",
        "sseEndpoint",
        "proxy_target_url",
        "proxyTargetUrl",
        "proxy_target_host",
        "proxyTargetHost",
        "proxy_resolved_ips",
        "proxyResolvedIps",
    }
)
# Normalized (lowercase, separators removed) key fragments that name a secret.
_CREDENTIAL_KEY_FRAGMENTS: tuple[str, ...] = (
    "secret",
    "password",
    "passwd",
    "credential",
    "apikey",
    "privatekey",
    "authorization",
    "customheaders",
)
_TOKEN_ENDPOINT_SUFFIXES: tuple[str, ...] = ("url", "uri", "endpoint")
_UNINFORMATIVE_VALUES: tuple[Any, ...] = (None, "", [], {})
_BACKEND_CATEGORY: str = "backend address"
_CREDENTIAL_CATEGORY: str = "credential"

_SETTINGS_FOR_SWEEP = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)


# One scope-table entry: (scope name, (server rules as (server, tools), ui as (key, values))).
_ScopeEntry = tuple[str, tuple[tuple[Any, ...], tuple[tuple[str, tuple[str, ...]], ...]]]


@dataclass(frozen=True)
class _User:
    """A caller described by the scopes it holds in a generated scope table.

    Attributes:
        username: The caller's username.
        groups: The caller's IdP groups.
        held: Names of the scopes the caller holds.
        table: Scope name to (server access rules, ui_permissions).
    """

    username: str
    groups: tuple[str, ...]
    held: tuple[str, ...]
    table: tuple[_ScopeEntry, ...]

    def rules(
        self,
    ) -> dict[str, list[dict[str, Any]]]:
        """Return each scope's server access rules."""
        return {
            name: [{"server": server, "tools": list(tools)} for server, tools in rules]
            for name, (rules, _) in self.table
        }

    def ui(
        self,
    ) -> dict[str, dict[str, list[str]]]:
        """Return each scope's ui_permissions."""
        return {name: {key: list(values) for key, values in ui} for name, (_, ui) in self.table}


def _user(
    username: str,
    groups: tuple[str, ...],
    rules: list[tuple[str, list[str]]],
    ui: dict[str, list[str]],
    admin: bool = False,
) -> _User:
    """Build a caller holding one scope with ``rules`` and ``ui``, plus admin if asked."""
    table = [
        (
            "scope-a",
            (
                tuple((server, tuple(tools)) for server, tools in rules),
                tuple((key, tuple(values)) for key, values in ui.items()),
            ),
        )
    ]
    held = ["scope-a"]
    if admin:
        table.append(_admin_entry())
        held.append(_ADMIN_SCOPE)
    return _User(username=username, groups=groups, held=tuple(held), table=tuple(table))


def _admin_entry() -> _ScopeEntry:
    """Return the scope-table entry of a registry admin scope."""
    return (
        _ADMIN_SCOPE,
        (
            tuple((rule["server"], tuple(rule["tools"])) for rule in _ADMIN_SCOPE_RULES),
            tuple((key, tuple(values)) for key, values in _ADMIN_SCOPE_UI.items()),
        ),
    )


@st.composite
def _users(
    draw: st.DrawFn,
) -> _User:
    """Draw a caller and a scope table over the shared server, tool and UI grants."""
    table = []
    for name in _SCOPE_NAMES:
        rules = draw(
            st.lists(
                st.tuples(
                    st.sampled_from(_SERVER_GRANTS),
                    st.sampled_from(_TOOL_GRANTS).map(tuple),
                ),
                max_size=3,
            )
        )
        ui = tuple(
            (key, tuple(draw(st.lists(st.sampled_from(values), max_size=2, unique=True))))
            for key, values in _UI_GRANTS.items()
        )
        table.append((name, (tuple(rules), ui)))
    held = list(draw(st.lists(st.sampled_from(_SCOPE_NAMES), unique=True)))
    if draw(st.booleans()):
        table.append(_admin_entry())
        held.append(_ADMIN_SCOPE)
    return _User(
        username=draw(st.sampled_from(_USERS)),
        groups=tuple(draw(st.lists(st.sampled_from(_GROUPS), unique=True, max_size=2))),
        held=tuple(held),
        table=tuple(table),
    )


@dataclass(frozen=True)
class _Visibility:
    """Visibility metadata of one stored record.

    Attributes:
        visibility: Stored visibility value.
        owner: Owner (registered_by for agents).
        allowed_groups: Groups granted access when group-restricted.
    """

    visibility: str
    owner: str
    allowed_groups: tuple[str, ...]


@dataclass(frozen=True)
class _World:
    """Visibility of every agent, skill and custom record in the store.

    Attributes:
        agents: One entry per ``_AGENT_PATHS`` element.
        skills: One entry per ``_SKILL_NAMES`` element.
        custom: One entry per ``_CUSTOM_IDS`` element.
    """

    agents: tuple[_Visibility, ...]
    skills: tuple[_Visibility, ...]
    custom: tuple[_Visibility, ...]


def _visibility(
    visibilities: tuple[str, ...],
) -> st.SearchStrategy[_Visibility]:
    """Draw visibility metadata; group-restricted records always name a group."""
    return st.builds(
        _Visibility,
        visibility=st.sampled_from(visibilities),
        owner=st.sampled_from(_USERS),
        allowed_groups=st.lists(st.sampled_from(_GROUPS), min_size=1, max_size=2, unique=True).map(
            tuple
        ),
    )


def _worlds() -> st.SearchStrategy[_World]:
    """Draw the visibility of every stored agent, skill and custom record."""
    return st.builds(
        _World,
        agents=st.tuples(*[_visibility(_AGENT_VISIBILITIES) for _ in _AGENT_PATHS]),
        skills=st.tuples(*[_visibility(_SKILL_VISIBILITIES) for _ in _SKILL_NAMES]),
        custom=st.tuples(*[_visibility(_CUSTOM_VISIBILITIES) for _ in _CUSTOM_IDS]),
    )


_ALL_PUBLIC = _World(
    agents=tuple(_Visibility("public", "bob", ("team-b",)) for _ in _AGENT_PATHS),
    skills=tuple(_Visibility("public", "bob", ("team-b",)) for _ in _SKILL_NAMES),
    custom=tuple(_Visibility("public", "bob", ("team-b",)) for _ in _CUSTOM_IDS),
)
_SERVER_GRANT_WITHOUT_LIST_SERVICE = _user("alice", (), [("github", ["all"])], {})
_VIRTUAL_GRANT_WITHOUT_LIST_VIRTUAL = _user("alice", (), [("/virtual/vs1", ["all"])], {})
_DISPLAY_NAME_GRANT = _user("alice", (), [("jira", ["all"])], {"list_service": ["jira", "docs"]})
_PLAIN_USER_WITH_AGENT_GRANT = _user("alice", ("team-a",), [], {"list_agents": ["all"]})
_ADMIN_USER = _user("alice", (), [], {}, admin=True)


def _secret(
    label: str,
) -> str:
    """Return a sentinel secret value."""
    return f"{_SECRET_MARK}-{label}"


def _server_documents() -> dict[str, dict[str, Any]]:
    """Build every stored server with backend and credential fields."""
    return {
        path: {
            "id": f"server-{index}",
            "path": path,
            "server_name": name,
            "description": f"{name} tools",
            "tags": ["tools"],
            "num_tools": len(_TOOLS),
            "tool_list": [{"name": tool, "description": f"{tool} things"} for tool in _TOOLS],
            "is_enabled": True,
            "is_active": True,
            "visibility": "public",
            "proxy_pass_url": f"{_BACKEND_URL}{path}",
            "mcp_endpoint": f"{_BACKEND_URL}{path}/mcp",
            "sse_endpoint": f"{_BACKEND_URL}{path}/sse",
            "supported_transports": ["streamable-http"],
            "auth_scheme": "bearer",
            "auth_credential_encrypted": _secret(f"server-{index}"),
            "registered_by": "bob",
        }
        for index, (path, name) in enumerate(_SERVERS)
    }


def _agent_cards(
    world: _World,
) -> dict[str, AgentCard]:
    """Build every stored agent as a reverse-proxied card with upstream headers."""
    cards = {}
    for index, (path, state) in enumerate(zip(_AGENT_PATHS, world.agents, strict=True)):
        backend = f"{_BACKEND_URL}{path}"
        card = AgentCard(
            name=f"agent-{index}",
            path=path,
            url=f"https://gateway.example.com{path}",
            version="1.0.0",
            protocol_version="1.0",
            description="An agent",
            proxy_pass_url=backend,
            visibility=state.visibility,
            registered_by=state.owner,
            allowed_groups=list(state.allowed_groups),
            is_enabled=True,
        )
        cards[path] = card.model_copy(
            update={
                "is_proxied": True,
                "proxy_target_url": backend,
                "proxy_target_host": _BACKEND_HOST,
                "proxy_resolved_ips": ["10.0.0.8"],
                "custom_headers_encrypted": [
                    CustomHeaderEncrypted(
                        name="X-Tenant", value_encrypted=_secret(f"agent-{index}")
                    )
                ],
            }
        )
    return cards


def _skill_documents(
    world: _World,
) -> dict[str, dict[str, Any]]:
    """Build every stored skill as a proxied record with a credential."""
    return {
        f"/skills/{name}": {
            "id": f"skill-{index}",
            "path": f"/skills/{name}",
            "name": name,
            "description": f"{name} skill",
            "skill_md_url": f"https://skills.example.com/{name}/SKILL.md",
            "visibility": state.visibility,
            "owner": state.owner,
            "allowed_groups": list(state.allowed_groups),
            "is_enabled": True,
            "registry_name": "local",
            "auth_scheme": "bearer",
            "auth_credential_encrypted": _secret(f"skill-{index}"),
            "is_proxied": True,
            "proxy_target_url": f"{_BACKEND_URL}/skills/{name}",
        }
        for index, (name, state) in enumerate(zip(_SKILL_NAMES, world.skills, strict=True))
    }


def _custom_records(
    world: _World,
) -> dict[str, CustomEntityRecord]:
    """Build every stored custom-entity record."""
    records = {}
    for index, (record_id, state) in enumerate(zip(_CUSTOM_IDS, world.custom, strict=True)):
        path = f"/{_CUSTOM_TYPE}/{record_id}"
        records[path] = CustomEntityRecord(
            path=path,
            entity_type=_CUSTOM_TYPE,
            name=f"prompt-{index}",
            visibility=state.visibility,
            owner=state.owner,
            allowed_groups=list(state.allowed_groups),
        )
    return records


class _FakeServerRepository:
    """In-memory server repository for ``server_service`` and ``tool_blocks``."""

    def __init__(
        self,
        documents: dict[str, dict[str, Any]],
    ) -> None:
        self._documents = documents

    def _copy(
        self,
        paths: list[str],
    ) -> dict[str, dict[str, Any]]:
        return {path: json.loads(json.dumps(self._documents[path])) for path in paths}

    async def list_all(
        self,
        exclude_tool_list: bool = False,
    ) -> dict[str, dict[str, Any]]:
        """Return every server."""
        return self._copy(list(self._documents))

    async def list_paginated(
        self,
        skip: int = 0,
        limit: int = 100,
        exclude_tool_list: bool = False,
        metadata_paths: list[str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Return one page of servers."""
        return self._copy(list(self._documents)[skip : skip + limit])

    async def count(self) -> int:
        """Return the number of servers."""
        return len(self._documents)

    async def list_by_ids(
        self,
        ids: list[str],
    ) -> dict[str, dict[str, Any]]:
        """Return the servers whose path is in ``ids``."""
        return self._copy([path for path in self._documents if path in set(ids)])

    async def get(
        self,
        path: str,
    ) -> dict[str, Any] | None:
        """Return one server, or None."""
        return self._copy([path])[path] if path in self._documents else None

    async def get_tool_overrides(
        self,
        path: str,
    ) -> dict[str, Any]:
        """Return no per-tool overrides (no tool is blocked)."""
        return {}


class _FakeAgentRepository:
    """In-memory agent repository for ``agent_service``."""

    def __init__(
        self,
        cards: dict[str, AgentCard],
    ) -> None:
        self._cards = cards

    async def list_all(self) -> list[AgentCard]:
        """Return every agent."""
        return [card.model_copy(deep=True) for card in self._cards.values()]

    async def list_paginated(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> list[AgentCard]:
        """Return one page of agents."""
        return (await self.list_all())[skip : skip + limit]

    async def count(self) -> int:
        """Return the number of agents."""
        return len(self._cards)

    async def get(
        self,
        path: str,
    ) -> AgentCard | None:
        """Return one agent, or None."""
        card = self._cards.get(path)
        return card.model_copy(deep=True) if card else None


class _FakeSkillRepository:
    """In-memory skill repository for ``SkillService`` and the search overlay."""

    def __init__(
        self,
        documents: dict[str, dict[str, Any]],
    ) -> None:
        self._documents = documents

    async def list_filtered(
        self,
        include_disabled: bool = False,
        tag: str | None = None,
        visibility: str | None = None,
        registry_name: str | None = None,
        limit: int | None = None,
    ) -> list[SkillCard]:
        """Mirror the database query the DocumentDB repository builds."""
        cards = []
        for document in self._documents.values():
            if not include_disabled and document.get("is_enabled") is not True:
                continue
            if tag and tag not in document.get("tags", []):
                continue
            if visibility and document.get("visibility") != visibility:
                continue
            if registry_name and document.get("registry_name") != registry_name:
                continue
            cards.append(SkillCard(**document))
        return cards[:limit] if limit is not None else cards

    async def list_paginated(
        self,
        skip: int = 0,
        limit: int = 100,
    ) -> list[SkillCard]:
        """Return one page of skills."""
        return (await self.list_filtered(include_disabled=True))[skip : skip + limit]

    async def count(self) -> int:
        """Return the number of skills."""
        return len(self._documents)

    async def list_by_paths(
        self,
        paths: list[str],
        fields: list[str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Return the requested fields of the skills at ``paths``."""
        return {
            path: {field: self._documents[path].get(field) for field in fields or []}
            for path in paths
            if path in self._documents
        }


def _mongo_match(
    document: dict[str, Any],
    condition: dict[str, Any] | None,
) -> bool:
    """Evaluate the subset of MongoDB query syntax the custom-entity list builds."""
    if not condition:
        return True
    for key, expected in condition.items():
        if key == "$or":
            if not any(_mongo_match(document, branch) for branch in expected):
                return False
            continue
        if key == "$and":
            if not all(_mongo_match(document, branch) for branch in expected):
                return False
            continue
        actual = document.get(key)
        if isinstance(expected, dict) and "$in" in expected:
            options = expected["$in"]
            values = actual if isinstance(actual, list) else [actual]
            if not any(value in options for value in values):
                return False
            continue
        if isinstance(actual, list):
            if expected not in actual:
                return False
        elif actual != expected:
            return False
    return True


class _FakeCustomEntityRepository:
    """In-memory custom-entity record repository; ``_id`` is the record path."""

    def __init__(
        self,
        records: dict[str, CustomEntityRecord],
    ) -> None:
        self._records = records

    def _matching(
        self,
        type_name: str,
        condition: dict[str, Any] | None,
    ) -> list[CustomEntityRecord]:
        found = []
        for path, record in self._records.items():
            document = {**record.model_dump(mode="json"), "_id": path}
            if record.entity_type == type_name and _mongo_match(document, condition):
                found.append(record)
        return found

    async def list_paginated(
        self,
        type_name: str,
        skip: int,
        limit: int,
        condition: dict[str, Any] | None = None,
    ) -> list[CustomEntityRecord]:
        """Return one page of matching records."""
        return self._matching(type_name, condition)[skip : skip + limit]

    async def count(
        self,
        type_name: str,
        condition: dict[str, Any] | None = None,
    ) -> int:
        """Return the number of matching records."""
        return len(self._matching(type_name, condition))


class _FakeVirtualServerService:
    """Virtual-server service stand-in for the list route and the search route."""

    async def list_virtual_servers(self) -> list[VirtualServerInfo]:
        """Return every virtual server."""
        return [
            VirtualServerInfo(path=path, server_name=name, is_enabled=True)
            for path, name in _VIRTUAL_SERVERS
        ]

    async def get_virtual_server(
        self,
        path: str,
    ) -> None:
        """Return no tool-mapping config, so no virtual tool is treated as blocked."""
        return None


class _FakeSearchRepository:
    """Vector search stand-in that returns every stored entity with a score."""

    def __init__(
        self,
        world: _World,
    ) -> None:
        self._world = world

    async def search(
        self,
        **_: Any,
    ) -> dict[str, list[dict[str, Any]]]:
        """Return every entity, shaped like the DocumentDB search repository's hits."""
        servers = _server_documents()
        skills = _skill_documents(self._world)
        records = _custom_records(self._world)
        matching = [
            {"tool_name": tool, "description": f"{tool} things", "relevance_score": 0.8}
            for tool in _TOOLS
        ]
        return {
            "servers": [
                {
                    "path": path,
                    "server_name": document["server_name"],
                    "description": document["description"],
                    "tags": document["tags"],
                    "is_enabled": True,
                    "relevance_score": 0.9,
                    "matching_tools": matching,
                    "proxy_pass_url": document["proxy_pass_url"],
                    "mcp_endpoint": document["mcp_endpoint"],
                    "sse_endpoint": document["sse_endpoint"],
                    "supported_transports": document["supported_transports"],
                }
                for path, document in servers.items()
            ],
            "tools": [
                {
                    "server_path": path,
                    "server_name": document["server_name"],
                    "tool_name": tool,
                    "description": f"{tool} things",
                    "inputSchema": {},
                    "relevance_score": 0.8,
                }
                for path, document in servers.items()
                for tool in _TOOLS
            ],
            "agents": [
                {"path": path, "relevance_score": 0.7, "agent_card": {}} for path in _AGENT_PATHS
            ],
            "skills": [
                {
                    "path": path,
                    "skill_name": document["name"],
                    "description": document["description"],
                    "tags": [],
                    "visibility": document["visibility"],
                    "allowed_groups": document["allowed_groups"],
                    "owner": document["owner"],
                    "is_enabled": True,
                    "status": "active",
                    "relevance_score": 0.6,
                }
                for path, document in skills.items()
            ],
            "virtual_servers": [
                {
                    "path": path,
                    "server_name": name,
                    "description": "",
                    "tags": [],
                    "is_enabled": True,
                    "relevance_score": 0.5,
                    "matching_tools": [],
                }
                for path, name in _VIRTUAL_SERVERS
            ],
            "custom": [
                {
                    "entity_type": record.entity_type,
                    "path": path,
                    "name": record.name,
                    "description": None,
                    "tags": [],
                    "visibility": record.visibility,
                    "owner": record.owner,
                    "allowed_groups": record.allowed_groups,
                    "is_enabled": True,
                    "relevance_score": 0.4,
                }
                for path, record in records.items()
            ],
        }


class _FakeScopeRepository:
    """Scope repository backed by a ``_User``'s scope table."""

    def __init__(
        self,
        user: _User,
    ) -> None:
        self._rules = user.rules()
        self._ui = user.ui()

    async def get_server_scopes_bulk(
        self,
        scopes: list[str],
    ) -> dict[str, list[dict[str, Any]]]:
        """Return the server access rules of each known scope."""
        return {scope: self._rules[scope] for scope in scopes if scope in self._rules}

    async def get_ui_scopes_bulk(
        self,
        scopes: list[str],
    ) -> dict[str, dict[str, list[str]]]:
        """Return the ui_permissions of each known scope."""
        return {scope: self._ui[scope] for scope in scopes if scope in self._ui}


def _context_for(
    user: _User,
) -> dict[str, Any]:
    """Derive the request user_context the auth layer would build for ``user``."""
    with patch(
        "registry.repositories.factory.get_scope_repository",
        return_value=_FakeScopeRepository(user),
    ):
        return asyncio.run(
            _derive_user_context(
                username=user.username,
                groups=list(user.groups),
                scopes=list(user.held),
                auth_method="oauth2",
                provider="keycloak",
            )
        )


class _ContextStack:
    """Enter and exit a list of context managers as one."""

    def __init__(
        self,
        managers: list[Any],
    ) -> None:
        self._managers = managers

    def __enter__(self) -> None:
        for manager in self._managers:
            manager.__enter__()

    def __exit__(self, *exc_info: Any) -> None:
        for manager in reversed(self._managers):
            manager.__exit__(*exc_info)


def _app(
    context: dict[str, Any],
    world: _World,
) -> FastAPI:
    """Mount the search and list routers at the prefixes ``registry.main`` uses."""
    app = FastAPI()
    app.include_router(server_routes.router, prefix="/api")
    app.include_router(agent_routes.router, prefix="/api")
    app.include_router(skill_routes.router, prefix="/api")
    app.include_router(virtual_server_routes.router, prefix="/api")
    app.include_router(custom_entity_routes.router, prefix="/api")
    app.include_router(search_routes.router, prefix="/api/search")
    app.dependency_overrides[nginx_proxied_auth] = lambda: context
    app.dependency_overrides[search_routes.get_search_repo] = lambda: _FakeSearchRepository(world)
    return app


def _patched_registry(
    world: _World,
) -> _ContextStack:
    """Back every list and search dependency with in-memory fakes for ``world``."""
    servers = _FakeServerRepository(_server_documents())
    skills = _FakeSkillRepository(_skill_documents(world))
    skill_service = SkillService()
    skill_service._repo = skills
    custom_service = custom_entity_routes.CustomEntityService()
    custom_service._entities = _FakeCustomEntityRepository(_custom_records(world))
    custom_service._types = MagicMock()
    custom_service._types.cache.get_for_read = AsyncMock(return_value=object())
    virtual = _FakeVirtualServerService()
    scans = MagicMock()
    scans.get_scan_summaries = AsyncMock(return_value={})
    health = MagicMock()
    health._get_service_health_data.return_value = {"status": "healthy", "last_checked_iso": None}
    return _ContextStack(
        [
            patch.object(server_service, "_repo", servers),
            patch.object(agent_service, "_repo", _FakeAgentRepository(_agent_cards(world))),
            patch("registry.services.tool_blocks.get_server_repository", return_value=servers),
            patch("registry.api.server_routes.security_scanner_service", scans),
            patch("registry.services.agent_scanner.agent_scanner_service", scans),
            patch("registry.services.skill_scanner.skill_scanner_service", scans),
            patch("registry.health.service.health_service", health),
            patch("registry.api.skill_routes.get_skill_service", return_value=skill_service),
            patch("registry.api.search_routes.get_skill_repository", return_value=skills),
            patch.object(custom_entity_routes, "_get_service", return_value=custom_service),
            patch(
                "registry.api.virtual_server_routes.get_virtual_server_service",
                return_value=virtual,
            ),
            patch("registry.api.search_routes.get_virtual_server_service", return_value=virtual),
            patch(
                "registry.repositories.stats_repository.increment_search_counter",
                AsyncMock(return_value=None),
            ),
            patch("registry.audit.sink.emit_audit_event", MagicMock()),
            patch.object(registry_settings, "deployment_mode", DeploymentMode.WITH_GATEWAY),
            patch.object(registry_settings, "registry_mode", RegistryMode.FULL),
            patch.object(registry_settings, "custom_entity_types_enabled", True),
        ]
    )


@dataclass(frozen=True)
class _Views:
    """What one caller sees for one entity type through search and through the list.

    Attributes:
        search: Search result items keyed by identity.
        listed: List endpoint items keyed by identity.
    """

    search: dict[Any, Any]
    listed: dict[Any, Any]


def _get(
    client: TestClient,
    url: str,
    key: str,
) -> list[dict[str, Any]]:
    """GET a list endpoint and return its records, or none on a 404."""
    response = client.get(url)
    if response.status_code == 404:
        return []
    assert response.status_code == 200, f"{url} returned {response.status_code}: {response.text}"
    return response.json()[key]


def _views(
    user: _User,
    world: _World,
    entity: str,
) -> _Views:
    """Collect the search and list views of ``entity`` for ``user`` over ``world``."""
    context = _context_for(user)
    with _patched_registry(world):
        client = TestClient(_app(context, world))
        response = client.post(
            "/api/search/semantic",
            json={"query": "anything", "entity_types": _ENTITY_TYPES, "max_results": 50},
        )
        assert response.status_code == 200, response.text
        found = response.json()
        if entity in ("servers", "tools"):
            servers = _get(client, f"/api/servers?limit={_LIST_LIMIT}", "servers")
            if entity == "servers":
                listed = {server["path"]: server for server in servers}
            else:
                # A tool row is compared with its parent server row, which carries
                # the server's endpoint fields on the list side.
                listed = {
                    (server["path"], tool["name"]): {"tool": tool, "server": server}
                    for server in servers
                    for tool in server["tool_list"]
                }
        elif entity == "agents":
            agents = _get(client, f"/api/agents?limit={_LIST_LIMIT}", "agents")
            listed = {agent["path"]: agent for agent in agents}
        elif entity == "skills":
            skills = _get(client, f"/api/skills?limit={_LIST_LIMIT}", "skills")
            listed = {skill["path"]: skill for skill in skills}
        elif entity == "virtual_servers":
            virtual = _get(client, "/api/virtual-servers", "virtual_servers")
            listed = {server["path"]: server for server in virtual}
        else:
            records = _get(client, f"/api/custom/{_CUSTOM_TYPE}?limit=1000", "records")
            listed = {record["path"]: record for record in records}
    if entity == "tools":
        search = {(tool["server_path"], tool["tool_name"]): tool for tool in found["tools"]}
    else:
        search = {item["path"]: item for item in found[entity]}
    return _Views(search=search, listed=listed)


def _walk(
    value: Any,
) -> list[tuple[str, Any]]:
    """Return (key, value) for every mapping entry at every depth."""
    entries: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            entries.append((str(key), item))
            entries.extend(_walk(item))
    elif isinstance(value, list):
        for item in value:
            entries.extend(_walk(item))
    return entries


def _is_credential_key(
    key: str,
) -> bool:
    """Return True if ``key`` names a secret, a token or custom header values."""
    normalized = re.sub(r"[^a-z]", "", key.lower())
    if any(fragment in normalized for fragment in _CREDENTIAL_KEY_FRAGMENTS):
        return True
    return "token" in normalized and not normalized.endswith(_TOKEN_ENDPOINT_SUFFIXES)


def _sensitive(
    item: Any,
) -> dict[str, set[str]]:
    """Group the backend-address and credential content ``item`` carries by category.

    Categories rather than single keys are compared, because the two surfaces
    shape records differently: an admin's list row shows ``proxy_pass_url`` but
    has no ``sse_endpoint`` column, while the search row has both.

    Returns:
        Category name (``backend address`` or ``credential``) to the fields and
        sentinel values found; a category is absent when nothing was found.
    """
    found: dict[str, set[str]] = {}
    for key, value in _walk(item):
        if value in _UNINFORMATIVE_VALUES:
            continue
        if key in _BACKEND_KEYS:
            found.setdefault(_BACKEND_CATEGORY, set()).add(f"key {key}")
        if _is_credential_key(key):
            found.setdefault(_CREDENTIAL_CATEGORY, set()).add(f"key {key}")
    text = json.dumps(item)
    if _BACKEND_HOST in text:
        found.setdefault(_BACKEND_CATEGORY, set()).add("backend host value")
    if _SECRET_MARK in text:
        found.setdefault(_CREDENTIAL_CATEGORY, set()).add("sentinel secret value")
    return found


@pytest.mark.parametrize(
    "entity",
    [
        "servers",
        "tools",
        "agents",
        "skills",
        "virtual_servers",
        "custom",
    ],
)
@_SETTINGS_FOR_SWEEP
@given(user=_users(), world=_worlds())
@example(user=_SERVER_GRANT_WITHOUT_LIST_SERVICE, world=_ALL_PUBLIC)
@example(user=_DISPLAY_NAME_GRANT, world=_ALL_PUBLIC)
@example(user=_VIRTUAL_GRANT_WITHOUT_LIST_VIRTUAL, world=_ALL_PUBLIC)
def test_search_results_are_a_subset_of_list_results(
    entity: str,
    user: _User,
    world: _World,
) -> None:
    """Property: per entity type, search returns only records the caller's list returns."""
    views = _views(user, world, entity)
    extra = sorted(set(views.search) - set(views.listed), key=str)
    assert extra == [], (
        f"search returned {entity} the list endpoint hides from {user.username} "
        f"(held={list(user.held)}): {extra}"
    )


@pytest.mark.parametrize(
    "entity",
    [
        "servers",
        "tools",
        "agents",
        "skills",
        "virtual_servers",
        "custom",
    ],
)
@_SETTINGS_FOR_SWEEP
@given(user=_users(), world=_worlds())
@example(user=_PLAIN_USER_WITH_AGENT_GRANT, world=_ALL_PUBLIC)
@example(user=_ADMIN_USER, world=_ALL_PUBLIC)
def test_search_results_carry_nothing_the_list_withholds(
    entity: str,
    user: _User,
    world: _World,
) -> None:
    """Property: a search result carries backend-address or credential content only
    when the caller's list endpoint shows that kind of content for the same record.
    """
    views = _views(user, world, entity)
    leaks = {}
    for identity, item in views.search.items():
        if identity not in views.listed:
            continue
        shown = _sensitive(views.listed[identity])
        withheld = {
            category: sorted(details)
            for category, details in _sensitive(item).items()
            if category not in shown
        }
        if withheld:
            leaks[str(identity)] = withheld
    assert leaks == {}, f"search {entity} carry content the list withholds: {leaks}"
