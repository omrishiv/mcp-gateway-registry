"""Anonymous reads expose only public, enabled records and nothing internal.

The ARD catalog (``/.well-known/ai-catalog.json``), the registry card and the
per-record public endpoints (``/api/public/servers/{leaf}/server.json``,
``/api/public/agents/{leaf}``, ``/api/public/skills/{leaf}``) answer requests
that carry no identity. The security property pinned here: over any population
of servers, agents and skills with every visibility and enabled state, an
anonymous response names only records whose visibility is exactly ``public``
and that are enabled; no response carries a backend URL, a credential or the
owner and group metadata of a record; every spelling of a ``{leaf}`` either
404s or resolves to the record its canonical spelling resolves to; and every
catalog entry's URL dereferences to the record that entry describes.
"""

import asyncio
import copy
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from unittest.mock import patch
from urllib.parse import (
    quote,
    unquote,
    urlsplit,
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
    public_record_routes,
    wellknown_routes,
)
from registry.core.config import (
    DeploymentMode,
)
from registry.core.config import (
    settings as registry_settings,
)
from registry.schemas.agent_models import AgentCard
from registry.schemas.skill_models import SkillCard
from registry.services.ard_mapping import _sanitize_name

_SECRET_MARK: str = "SENTINEL-SECRET"
_BACKEND_HOST: str = "backend.internal.invalid"
_BACKEND_URL: str = f"http://{_BACKEND_HOST}:9000"
_GATEWAY_URL: str = "https://gateway.example.com"
_OWNER: str = "owner-user@example.com"
_GROUP: str = "team-a"
_PUBLISHER: str = "registry.example.com"

_KINDS: tuple[str, ...] = ("server", "agent", "skill")
_LEAVES: tuple[str, ...] = ("github", "jira", "GitHub")
_PREFIXES: dict[str, tuple[str, ...]] = {
    "server": ("", "/team-a", "/peer-1"),
    "agent": ("", "/team-a", "/peer-1"),
    "skill": ("/skills", "/skills/team-a"),
}
_RAW_VISIBILITIES: tuple[str | None, ...] = (
    "public",
    "private",
    "group-restricted",
    "group",
    "internal",
    "Public",
    None,
)
_SKILL_VISIBILITIES: tuple[str, ...] = ("public", "private", "group")
# None stands for a stored document with no is_enabled key at all.
_ENABLED_STATES: tuple[bool | None, ...] = (True, False, None)

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
# A key containing "token" names a token unless it is the URL of a token endpoint.
_TOKEN_ENDPOINT_SUFFIXES: tuple[str, ...] = ("url", "uri", "endpoint")
# Owner, group-list and auth-scheme metadata that the public routes promise to strip.
_INTERNAL_KEYS: frozenset[str] = frozenset(
    {
        "registered_by",
        "registeredBy",
        "owner",
        "allowed_groups",
        "allowedGroups",
        "auth_scheme",
        "authScheme",
        "auth_header_name",
        "authHeaderName",
        "security_schemes",
        "securitySchemes",
    }
)
_UNINFORMATIVE_VALUES: tuple[Any, ...] = (None, "", "none", [], {})

_ID_RE: re.Pattern[str] = re.compile(r"00000000-0000-4000-8000-\d{12}")
_PUBLIC_PREFIX: dict[str, str] = {
    "server": "/api/public/servers",
    "agent": "/api/public/agents",
    "skill": "/api/public/skills",
}
_EQUIVALENT_SPELLINGS: tuple[str, ...] = (
    "percent_encoded",
    "trailing_slash",
    "leading_double_slash",
    "dot_segment_prefix",
    "dot_segment_suffix",
    "encoded_dot_segment",
)
_SETTINGS_FOR_SWEEP = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)


@dataclass(frozen=True)
class _Record:
    """One stored record of the generated population.

    Attributes:
        kind: ``server``, ``agent`` or ``skill``.
        path: Stored path (the repository key).
        record_id: Unique id embedded in the stored document.
        name: Unique display name embedded in the stored document.
        visibility: Raw stored visibility, None when the key is absent.
        enabled: Raw stored is_enabled, None when the key is absent.
        federated: True when the record came from a peer registry.
    """

    kind: str
    path: str
    record_id: str
    name: str
    visibility: str | None
    enabled: bool | None
    federated: bool

    @property
    def leaf(self) -> str:
        """Return the canonical public-URL leaf of this record."""
        return _sanitize_name(self.path)

    @property
    def anonymous_visible(self) -> bool:
        """Oracle: an anonymous caller may see only public and enabled records."""
        return self.visibility == "public" and self.enabled is True


def _matches(
    document: dict[str, Any],
    filter_dict: dict[str, Any],
) -> bool:
    """Apply MongoDB top-level equality semantics; a missing key never matches."""
    missing = object()
    return all(document.get(key, missing) == value for key, value in filter_dict.items())


class _FakeDocumentRepository:
    """In-memory stand-in for the server and agent repositories.

    Returns deep copies, as a database round trip would, so a route that
    mutates a returned document cannot corrupt the store.
    """

    def __init__(
        self,
        documents: dict[str, dict[str, Any]],
    ) -> None:
        self._documents = documents

    async def find_with_filter(
        self,
        filter_dict: dict[str, Any],
        *,
        limit: int | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Return documents matching ``filter_dict`` in insertion order."""
        matched = {
            path: copy.deepcopy(document)
            for path, document in self._documents.items()
            if _matches(document, filter_dict)
        }
        if limit is not None:
            matched = dict(list(matched.items())[:limit])
        return matched


class _FakeSkillRepository:
    """In-memory stand-in for the skill repository's ``list_filtered``."""

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
        query: dict[str, Any] = {}
        if not include_disabled:
            query["is_enabled"] = True
        if tag:
            query["tags"] = tag
        if visibility:
            query["visibility"] = visibility
        if registry_name:
            query["registry_name"] = registry_name
        cards = [
            SkillCard(**copy.deepcopy(document))
            for document in self._documents.values()
            if _matches(document, query)
        ]
        return cards[:limit] if limit is not None else cards


class _FakeRegistryCardRepository:
    """In-memory registry card store that starts empty."""

    def __init__(self) -> None:
        self._card = None

    async def get(self):
        """Return the stored card, or None before initialization."""
        return self._card

    async def save(self, card):
        """Store and return ``card``."""
        self._card = card
        return card


def _secret(
    label: str,
    index: int,
) -> str:
    """Return a unique sentinel secret value."""
    return f"{_SECRET_MARK}-{label}-{index}"


def _apply_state(
    document: dict[str, Any],
    record: _Record,
) -> dict[str, Any]:
    """Write the raw visibility and enabled state onto a stored document."""
    document.pop("visibility", None)
    document.pop("is_enabled", None)
    if record.visibility is not None:
        document["visibility"] = record.visibility
    if record.enabled is not None:
        document["is_enabled"] = record.enabled
    if record.federated:
        document["registry_name"] = "peer-1"
        document["sync_metadata"] = {"is_federated": True, "source_peer_id": "peer-1"}
    else:
        document["registry_name"] = "local"
    return document


def _server_document(
    record: _Record,
    index: int,
) -> dict[str, Any]:
    """Build a stored server document carrying every backend and credential field."""
    backend = f"{_BACKEND_URL}/server-{index}"
    document: dict[str, Any] = {
        "id": record.record_id,
        "server_name": record.name,
        "description": "Issue tracker tools. Search and triage.",
        "tags": ["issues"],
        "num_tools": 1,
        "tool_list": [{"name": "search_issues", "description": "Search issues"}],
        "proxy_pass_url": backend,
        "mcp_endpoint": f"{backend}/mcp",
        "sse_endpoint": f"{backend}/sse",
        "supported_transports": ["streamable-http"],
        "versions": [{"version": "v2", "proxy_pass_url": f"{backend}/v2", "status": "stable"}],
        "allowed_groups": [_GROUP],
        "registered_by": _OWNER,
        "auth_scheme": "bearer",
        "auth_header_name": "X-Api-Key",
        "auth_credential_encrypted": _secret("server-credential", index),
        "custom_headers_encrypted": [
            {"name": "X-Tenant", "value_encrypted": _secret("server-header", index)}
        ],
        "custom_header_names": ["X-Tenant"],
        "backend_oauth": {
            "token_url": "https://idp.example.com/oauth2/token",
            "client_id": "backend-client",
            "client_secret_encrypted": _secret("server-backend-oauth", index),
            "scopes": ["read"],
        },
        "oauth_discovery": {
            "enabled": True,
            "oauth": {
                "client_id": "discovery-client",
                "client_secret_encrypted": _secret("server-discovery", index),
            },
            "user_id": _OWNER,
        },
        "egress_oauth": {
            "client_id": "egress-client",
            "client_secret_encrypted": _secret("server-egress", index),
        },
        "is_proxied": True,
        "proxy_target_url": backend,
        "proxy_target_host": _BACKEND_HOST,
        "proxy_resolved_ips": ["10.0.0.7"],
        "version": "1.0.0",
    }
    return _apply_state(document, record)


def _agent_document(
    record: _Record,
    index: int,
) -> dict[str, Any]:
    """Build a stored agent document for a reverse-proxied A2A agent."""
    backend = f"{_BACKEND_URL}/agent-{index}"
    card = AgentCard(
        id=record.record_id,
        name=record.name,
        path=record.path,
        url=f"{_GATEWAY_URL}{record.path}",
        version="1.0.0",
        protocol_version="1.0",
        description="Triage agent. Routes issues.",
        tags=["issues"],
        proxy_pass_url=backend,
        supported_interfaces=[
            {"url": backend, "protocol_binding": "JSONRPC", "protocol_version": "1.0"},
            {
                "url": f"{_BACKEND_HOST}:50051",
                "protocol_binding": "GRPC",
                "protocol_version": "1.0",
            },
        ],
        security_schemes={"bearer": {"type": "http", "scheme": "bearer"}},
        security=[{"bearer": []}],
        registered_by=_OWNER,
        visibility="group-restricted",
        allowed_groups=[_GROUP],
    )
    document = card.model_dump(mode="json")
    document.pop("path", None)
    document.update(
        {
            "auth_credential_encrypted": _secret("agent-credential", index),
            "custom_headers_encrypted": [
                {"name": "X-Tenant", "value_encrypted": _secret("agent-header", index)}
            ],
            "custom_header_names": ["X-Tenant"],
            "is_proxied": True,
            "proxy_target_url": backend,
            "proxy_target_host": _BACKEND_HOST,
            "proxy_resolved_ips": ["10.0.0.8"],
        }
    )
    return _apply_state(document, record)


def _skill_document(
    record: _Record,
    index: int,
) -> dict[str, Any]:
    """Build a stored skill document carrying credential and proxy fields."""
    document: dict[str, Any] = {
        "id": record.record_id,
        "path": record.path,
        "name": record.name,
        "description": "Summarize issues. Weekly report.",
        "skill_md_url": "https://skills.example.com/issues/SKILL.md",
        "tags": ["issues"],
        "allowed_groups": [_GROUP],
        "owner": _OWNER,
        "auth_scheme": "bearer",
        "auth_header_name": "X-Api-Key",
        "auth_credential_encrypted": _secret("skill-credential", index),
        "custom_headers_encrypted": [
            {"name": "X-Tenant", "value_encrypted": _secret("skill-header", index)}
        ],
        "custom_header_names": ["X-Tenant"],
        "is_proxied": True,
        "proxy_target_url": f"{_BACKEND_URL}/skill-{index}",
        "proxy_target_host": _BACKEND_HOST,
        "proxy_resolved_ips": ["10.0.0.9"],
    }
    _apply_state(document, record)
    document.setdefault("is_enabled", False)
    document.setdefault("visibility", "private")
    return document


@dataclass(frozen=True)
class _Population:
    """A generated registry population and its fake repositories' contents.

    Attributes:
        records: Every stored record, in insertion order.
        servers: Server documents keyed by path.
        agents: Agent documents keyed by path.
        skills: Skill documents keyed by path.
    """

    records: tuple[_Record, ...]
    servers: dict[str, dict[str, Any]]
    agents: dict[str, dict[str, Any]]
    skills: dict[str, dict[str, Any]]

    def by_name(
        self,
        name: str,
    ) -> _Record | None:
        """Return the record with display name ``name``, if any."""
        return next((record for record in self.records if record.name == name), None)


_RecordSpec = tuple[str, str, str, str | None, bool | None, bool]


def _build_population(
    specs: list[_RecordSpec],
) -> _Population:
    """Turn record specs into stored documents; later duplicates of a path are dropped.

    Args:
        specs: Tuples of (kind, prefix, leaf, visibility, enabled, federated).

    Returns:
        The population with one document per distinct (kind, path).
    """
    builders = {"server": _server_document, "agent": _agent_document, "skill": _skill_document}
    stores: dict[str, dict[str, dict[str, Any]]] = {kind: {} for kind in _KINDS}
    records: list[_Record] = []
    for kind, prefix, leaf, visibility, enabled, federated in specs:
        path = f"{prefix}/{leaf}"
        if path in stores[kind]:
            continue
        index = len(records)
        if kind == "skill" and visibility not in _SKILL_VISIBILITIES:
            visibility = "private"
        if kind == "skill" and enabled is None:
            enabled = False
        record = _Record(
            kind=kind,
            path=path,
            record_id=f"00000000-0000-4000-8000-{index:012d}",
            name=f"{kind}-name-{index}",
            visibility=visibility,
            enabled=enabled,
            federated=federated,
        )
        stores[kind][path] = builders[kind](record, index)
        records.append(record)
    return _Population(
        records=tuple(records),
        servers=stores["server"],
        agents=stores["agent"],
        skills=stores["skill"],
    )


@st.composite
def _populations(
    draw: st.DrawFn,
) -> _Population:
    """Draw a population of servers, agents and skills over every visibility state."""
    spec = st.sampled_from(_KINDS).flatmap(
        lambda kind: st.tuples(
            st.just(kind),
            st.sampled_from(_PREFIXES[kind]),
            st.sampled_from(_LEAVES),
            st.sampled_from(_RAW_VISIBILITIES),
            st.sampled_from(_ENABLED_STATES),
            st.booleans(),
        )
    )
    return _build_population(draw(st.lists(spec, min_size=1, max_size=8)))


def _public(
    kind: str,
    prefix: str,
    leaf: str,
) -> _RecordSpec:
    """Return a spec for a local, public and enabled record."""
    return (kind, prefix, leaf, "public", True, False)


_COLLIDING_SERVERS: list[_RecordSpec] = [
    _public("server", "/team-a", "github"),
    _public("server", "", "github"),
]
_PEER_SHADOWS_LOCAL_SERVER: list[_RecordSpec] = [
    ("server", "/peer-1", "github", "public", True, True),
    _public("server", "", "github"),
]
_COLLIDING_AGENTS: list[_RecordSpec] = [
    _public("agent", "/team-a", "github"),
    _public("agent", "", "github"),
]
_EVERY_STATE: list[_RecordSpec] = [
    (
        kind,
        prefix,
        leaf,
        _RAW_VISIBILITIES[index % len(_RAW_VISIBILITIES)],
        _ENABLED_STATES[index % len(_ENABLED_STATES)],
        False,
    )
    for kind in _KINDS
    for index, (prefix, leaf) in enumerate(
        (prefix, leaf) for prefix in _PREFIXES[kind] for leaf in _LEAVES
    )
]


def _canonical_url(
    kind: str,
    leaf: str,
) -> str:
    """Return the public record URL path for ``leaf``."""
    suffix = "/server.json" if kind == "server" else ""
    return f"{_PUBLIC_PREFIX[kind]}/{leaf}{suffix}"


@dataclass(frozen=True)
class _Response:
    """One anonymous response.

    Attributes:
        label: The request that produced it.
        status: HTTP status code.
        body: Parsed JSON body, None when the body is not JSON.
    """

    label: str
    status: int
    body: Any


def _patched_registry(
    population: _Population,
    deployment_mode: DeploymentMode,
):
    """Return a context manager that serves ``population`` to the public routes."""
    servers = _FakeDocumentRepository(population.servers)
    agents = _FakeDocumentRepository(population.agents)
    skills = _FakeSkillRepository(population.skills)
    cards = _FakeRegistryCardRepository()
    stack = [
        patch("registry.api.public_record_routes.get_server_repository", return_value=servers),
        patch("registry.api.public_record_routes.get_agent_repository", return_value=agents),
        patch("registry.api.public_record_routes.get_skill_repository", return_value=skills),
        patch("registry.services.ard_service.get_server_repository", return_value=servers),
        patch("registry.services.ard_service.get_agent_repository", return_value=agents),
        patch("registry.services.ard_service.get_skill_repository", return_value=skills),
        patch("registry.api.wellknown_routes.get_registry_card_repository", return_value=cards),
        patch.object(registry_settings, "deployment_mode", deployment_mode),
        patch.object(registry_settings, "enable_wellknown_discovery", True),
        patch.object(registry_settings, "ard_catalog_enabled", True),
        patch.object(registry_settings, "ard_publisher_domain", _PUBLISHER),
        patch.object(registry_settings, "ard_catalog_default_namespace", ""),
    ]
    return _ContextStack(stack)


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


def _app() -> FastAPI:
    """Mount the anonymous routers at the prefixes ``registry.main`` uses.

    The full application adds audit middleware that writes to a real database,
    so the routers are mounted on a bare app instead.
    """
    app = FastAPI()
    app.include_router(wellknown_routes.router, prefix="/.well-known")
    app.include_router(public_record_routes.router, prefix="/api")
    return app


def _client() -> TestClient:
    """Return an anonymous TestClient on the public routers (no lifespan)."""
    return TestClient(_app())


def _json_or_none(
    response: Any,
) -> Any:
    """Parse a response body as JSON, or return None."""
    try:
        return response.json()
    except ValueError:
        return None


async def _asgi_get(
    raw_path: str,
) -> tuple[int, Any]:
    """Send a GET whose path reaches the app exactly as uvicorn would deliver it.

    HTTP clients resolve dot segments before sending, so this drives the ASGI
    app directly: ``raw_path`` is percent-decoded into ``scope["path"]`` and
    nothing else is normalized.

    Args:
        raw_path: The request target as it appears on the wire.

    Returns:
        The status code and the parsed JSON body (None when not JSON).
    """
    app = _app()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": unquote(raw_path),
        "raw_path": raw_path.encode("ascii"),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    status: list[int] = []
    chunks: list[bytes] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            status.append(message["status"])
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    try:
        body = json.loads(b"".join(chunks) or b"null")
    except ValueError:
        body = None
    return status[0], body


def _anonymous_responses(
    population: _Population,
) -> list[_Response]:
    """Fetch the catalog, the registry card and every record URL anonymously.

    Every leaf of every stored record is requested, visible or not, so a route
    that returned a hidden record would show up here.
    """
    client = _client()
    responses: list[_Response] = []
    for label in ("/.well-known/ai-catalog.json", "/.well-known/registry-card"):
        response = client.get(label)
        responses.append(_Response(label, response.status_code, _json_or_none(response)))
    requested = sorted({(record.kind, record.leaf) for record in population.records})
    for kind, leaf in requested:
        url = _canonical_url(kind, leaf)
        response = client.get(url)
        responses.append(_Response(url, response.status_code, _json_or_none(response)))
    return responses


def _walk(
    value: Any,
    trail: str = "$",
) -> Iterator[tuple[str, str, Any]]:
    """Yield (trail, key, value) for every mapping entry at every depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield trail, str(key), item
            yield from _walk(item, f"{trail}.{key}")
    elif isinstance(value, list):
        for position, item in enumerate(value):
            yield from _walk(item, f"{trail}[{position}]")


def _is_credential_key(
    key: str,
) -> bool:
    """Return True if ``key`` names a secret, a token or custom header values."""
    normalized = re.sub(r"[^a-z]", "", key.lower())
    if any(fragment in normalized for fragment in _CREDENTIAL_KEY_FRAGMENTS):
        return True
    return "token" in normalized and not normalized.endswith(_TOKEN_ENDPOINT_SUFFIXES)


def _leaks(
    body: Any,
    deployment_mode: DeploymentMode,
) -> list[str]:
    """List every backend or credential field and value found in ``body``."""
    redact_backend = deployment_mode == DeploymentMode.WITH_GATEWAY
    found = []
    for trail, key, value in _walk(body):
        if _is_credential_key(key):
            found.append(f"credential key {trail}.{key}")
        if redact_backend and key in _BACKEND_KEYS:
            found.append(f"backend key {trail}.{key}")
    text = json.dumps(body)
    if _SECRET_MARK in text:
        found.append("sentinel secret value")
    if redact_backend and _BACKEND_HOST in text:
        found.append("backend host value")
    return found


def _ids_in(
    body: Any,
) -> set[str]:
    """Return every generated record id that appears anywhere in ``body``."""
    return set(_ID_RE.findall(json.dumps(body)))


@pytest.mark.parametrize(
    "deployment_mode",
    [DeploymentMode.WITH_GATEWAY, DeploymentMode.REGISTRY_ONLY],
    ids=["with-gateway", "registry-only"],
)
@_SETTINGS_FOR_SWEEP
@given(population=_populations())
@example(population=_build_population(_EVERY_STATE))
def test_anonymous_reads_name_only_public_enabled_records(
    deployment_mode: DeploymentMode,
    population: _Population,
) -> None:
    """Property: every record an anonymous response names is public and enabled."""
    visible_ids = {record.record_id for record in population.records if record.anonymous_visible}
    with _patched_registry(population, deployment_mode):
        responses = _anonymous_responses(population)
    hidden = {
        response.label: sorted(_ids_in(response.body) - visible_ids) for response in responses
    }
    hidden = {label: ids for label, ids in hidden.items() if ids}
    assert hidden == {}, f"anonymous responses named non-public or disabled records: {hidden}"

    catalog = next(r for r in responses if r.label.endswith("ai-catalog.json")).body
    for entry in catalog["entries"]:
        if entry["type"] == "application/ai-registry+json":
            continue
        record = population.by_name(entry["displayName"])
        assert record is not None and record.anonymous_visible, (
            f"catalog entry {entry['identifier']} describes a record that is not public and enabled"
        )


@pytest.mark.parametrize(
    "deployment_mode",
    [DeploymentMode.WITH_GATEWAY, DeploymentMode.REGISTRY_ONLY],
    ids=["with-gateway", "registry-only"],
)
@_SETTINGS_FOR_SWEEP
@given(population=_populations())
@example(population=_build_population(_EVERY_STATE))
def test_anonymous_bodies_carry_no_backend_or_credential_fields(
    deployment_mode: DeploymentMode,
    population: _Population,
) -> None:
    """Property: no anonymous body holds a credential, and none holds a backend
    address in with-gateway mode (registry-only mode has no gateway to hide it behind).
    """
    with _patched_registry(population, deployment_mode):
        responses = _anonymous_responses(population)
    leaks = {
        response.label: found
        for response in responses
        if response.status == 200 and (found := _leaks(response.body, deployment_mode))
    }
    assert leaks == {}, f"anonymous responses leaked internal fields: {leaks}"


def test_registry_card_carries_no_configured_secret() -> None:
    """Property: the auto-initialized registry card never echoes a configured secret."""
    secret_fields = [
        name
        for name, field in type(registry_settings).model_fields.items()
        if field.annotation in (str, str | None) and _is_credential_key(name)
    ]
    assert secret_fields, "expected Settings to declare at least one secret-named field"
    patches = [patch.object(registry_settings, name, _secret(name, 0)) for name in secret_fields]
    with _patched_registry(_build_population([]), DeploymentMode.WITH_GATEWAY):
        with _ContextStack(patches):
            response = _client().get("/.well-known/registry-card")
    assert response.status_code == 200
    assert _leaks(response.json(), DeploymentMode.WITH_GATEWAY) == []


def _internal_metadata(
    body: Any,
) -> list[str]:
    """List owner, group-list and auth-scheme keys that carry a real value."""
    return [
        f"{trail}.{key}={value!r}"
        for trail, key, value in _walk(body)
        if key in _INTERNAL_KEYS and value not in _UNINFORMATIVE_VALUES
    ]


@pytest.mark.parametrize(
    "kind",
    [
        "server",
        "agent",
        "skill",
    ],
)
@pytest.mark.parametrize("leaf", ["github"])
def test_anonymous_record_bodies_omit_owner_groups_and_auth_scheme(
    kind: str,
    leaf: str,
) -> None:
    """Property: an anonymous record body carries no owner, group list or auth scheme."""
    population = _build_population([_public(kind, _PREFIXES[kind][0], leaf)])
    with _patched_registry(population, DeploymentMode.WITH_GATEWAY):
        response = _client().get(_canonical_url(kind, leaf))
    assert response.status_code == 200, response.text
    found = _internal_metadata(response.json())
    assert found == [], f"anonymous {kind} body carries internal metadata: {found}"


def _respell(
    leaf: str,
    spelling: str,
    position: int,
) -> str:
    """Spell ``leaf`` differently in a way URL normalization maps back to ``leaf``.

    Args:
        leaf: Canonical leaf.
        spelling: One of ``_EQUIVALENT_SPELLINGS``.
        position: Index of the character to percent-encode.

    Returns:
        The raw request-target fragment that replaces the leaf.
    """
    if spelling == "percent_encoded":
        index = position % len(leaf)
        encoded = "".join(f"%{byte:02X}" for byte in leaf[index].encode())
        return leaf[:index] + encoded + leaf[index + 1 :]
    if spelling == "trailing_slash":
        return f"{leaf}/"
    if spelling == "leading_double_slash":
        return f"/{leaf}"
    if spelling == "dot_segment_prefix":
        return f"other/../{leaf}"
    if spelling == "dot_segment_suffix":
        return f"{leaf}/other/.."
    return f"%2E%2E/{quote(leaf)}"


def _flip_case(
    leaf: str,
    position: int,
) -> str | None:
    """Swap the case of the first cased character at or after ``position``."""
    for offset in range(len(leaf)):
        index = (position + offset) % len(leaf)
        if leaf[index].lower() != leaf[index].upper():
            return leaf[:index] + leaf[index].swapcase() + leaf[index + 1 :]
    return None


def _resolved_ids(
    kind: str,
    raw_leaf: str,
) -> tuple[int, set[str]]:
    """GET a public record by a raw leaf through the ASGI app; return status and ids."""
    status, body = asyncio.run(_asgi_get(_canonical_url(kind, raw_leaf)))
    return status, (_ids_in(body) if status == 200 else set())


@_SETTINGS_FOR_SWEEP
@given(
    population=_populations(),
    choice=st.integers(min_value=0, max_value=64),
    spelling=st.sampled_from(_EQUIVALENT_SPELLINGS),
    position=st.integers(min_value=0, max_value=16),
)
@example(
    population=_build_population([_public("agent", "", "github")]),
    choice=0,
    spelling="dot_segment_prefix",
    position=0,
)
def test_equivalent_leaf_spellings_never_resolve_to_another_record(
    population: _Population,
    choice: int,
    spelling: str,
    position: int,
) -> None:
    """Property: a dot-segment, percent-encoded, trailing-slash or double-slash
    spelling of a leaf is either 404 or resolves to the canonical spelling's record.
    """
    record = population.records[choice % len(population.records)]
    raw = _respell(record.leaf, spelling, position)
    with _patched_registry(population, DeploymentMode.WITH_GATEWAY):
        canonical_status, canonical_ids = _resolved_ids(record.kind, record.leaf)
        status, ids = _resolved_ids(record.kind, raw)
    assert status in (200, 404, 405), f"unexpected status {status} for {raw!r}"
    if status == 200:
        assert canonical_status == 200 and ids == canonical_ids, (
            f"{record.kind} leaf {raw!r} resolved to {sorted(ids)}, "
            f"canonical {record.leaf!r} resolved to {sorted(canonical_ids)}"
        )


@_SETTINGS_FOR_SWEEP
@given(
    population=_populations(),
    choice=st.integers(min_value=0, max_value=64),
    position=st.integers(min_value=0, max_value=16),
)
@example(
    population=_build_population([_public("server", "", "github")]),
    choice=0,
    position=0,
)
def test_case_changed_leaf_never_case_folds_onto_a_record(
    population: _Population,
    choice: int,
    position: int,
) -> None:
    """Property: a case-changed leaf resolves only to a record whose own leaf is
    exactly that spelling, never to a record by case-insensitive match.
    """
    record = population.records[choice % len(population.records)]
    flipped = _flip_case(record.leaf, position)
    if flipped is None:
        return
    with _patched_registry(population, DeploymentMode.WITH_GATEWAY):
        status, ids = _resolved_ids(record.kind, flipped)
    exact = {
        candidate.record_id
        for candidate in population.records
        if candidate.kind == record.kind and candidate.leaf == flipped
    }
    if status == 200:
        assert ids and ids <= exact, (
            f"{record.kind} leaf {flipped!r} resolved to {sorted(ids)}, "
            f"records with that exact leaf: {sorted(exact)}"
        )


@_SETTINGS_FOR_SWEEP
@given(population=_populations())
@example(population=_build_population(_COLLIDING_SERVERS))
@example(population=_build_population(_PEER_SHADOWS_LOCAL_SERVER))
@example(population=_build_population(_COLLIDING_AGENTS))
def test_catalog_entry_urls_dereference_to_the_described_record(
    population: _Population,
) -> None:
    """Property: each catalog entry's URL serves the record the entry describes."""
    with _patched_registry(population, DeploymentMode.WITH_GATEWAY):
        client = _client()
        catalog = client.get("/.well-known/ai-catalog.json").json()
        mismatches = []
        for entry in catalog["entries"]:
            if entry["type"] == "application/ai-registry+json":
                continue
            record = population.by_name(entry["displayName"])
            assert record is not None, f"catalog entry {entry} names no stored record"
            response = client.get(urlsplit(entry["url"]).path)
            served = _ids_in(_json_or_none(response)) if response.status_code == 200 else set()
            if served != {record.record_id}:
                mismatches.append(
                    f"{entry['url']} describes {record.path} ({record.record_id}) "
                    f"but served {sorted(served)} with status {response.status_code}"
                )
    assert mismatches == [], f"catalog URLs resolve to the wrong record: {mismatches}"
