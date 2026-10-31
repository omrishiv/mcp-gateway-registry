"""Property tests: generated generic and registrant locations stay inside their guard.

Pins three security properties of nginx config generation. First, the
render-time guard ``_safe_generic_block`` only emits a generic-proxy block when
neither the registered path nor the target contains a canonical nginx
metacharacter (``contains_nginx_metacharacters``), because both are
interpolated into ``location``, ``set`` and ``proxy_pass``. Second, every
``$name`` variable a rendered generic block references comes from a fixed
allowlist, so registry data can never make nginx expand a client-controlled
variable such as ``$http_foo`` into the authorization key. Third, every
rendered location that proxies straight to a registrant-controlled backend
forwards none of the gateway's internal tokens or secrets and clears the
reserved credential headers the caller sent.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.constants import RESERVED_CUSTOM_HEADER_NAMES
from registry.core import nginx_service as nginx_module
from registry.core.nginx_service import (
    AGENT_ROUTE_PREFIX,
    NginxConfigService,
)
from registry.schemas.agent_models import AgentCard
from registry.schemas.virtual_server_models import (
    ToolMapping,
    VirtualServerConfig,
)
from registry.utils.url_guard import contains_nginx_metacharacters
from tests.unit.core.nginx_render_harness import (
    AUTH_SERVER_URL,
    HEALTHY,
    ROOT_PATH,
    TEMPLATES,
    RegistrySnapshot,
    iter_blocks,
    parse_config,
    render_config,
    render_settings,
)

_ASCII: tuple[str, ...] = tuple(chr(code) for code in range(128))

SAFE_ENTITY_TYPE: str = "skill"
SAFE_PATH: str = "/skills/demo"
SAFE_TARGET: str = "https://skill.example.com/ab"

# Every variable the generic block template in _create_generic_proxy_block
# references, read off its text:
#   - nginx core variables: host, remote_addr, proxy_add_x_forwarded_for,
#     scheme, request_uri, http_authorization, upstream_status;
#   - auth_request captures and the upstream response headers they read:
#     auth_subrequest_status, auth_entra_outage_marker, auth_internal_token_generic,
#     auth_user, auth_scopes and the matching upstream_http_x_* names;
#   - the generic markers the block sets: generic_backend_url,
#     generic_proxy_kind, entity_path, generic_streaming, generic_has_upstream_auth.
# Registry data (path, target, entity type) must never add a name to this set.
GENERIC_BLOCK_VARIABLES: frozenset[str] = frozenset(
    {
        "host",
        "remote_addr",
        "proxy_add_x_forwarded_for",
        "scheme",
        "request_uri",
        "http_authorization",
        "upstream_status",
        "auth_subrequest_status",
        "auth_entra_outage_marker",
        "upstream_http_x_entra_group_lookup_unavailable",
        "auth_internal_token_generic",
        "upstream_http_x_internal_token_generic",
        "auth_user",
        "upstream_http_x_user",
        "auth_scopes",
        "upstream_http_x_scopes",
        "generic_backend_url",
        "generic_proxy_kind",
        "entity_path",
        "generic_streaming",
        "generic_has_upstream_auth",
    }
)
_VARIABLE_PATTERN: re.Pattern[str] = re.compile(r"\$\{?([A-Za-z0-9_]+)")

# Variables carrying a gateway-minted token or secret. None may be forwarded to
# a registrant backend: $auth_internal_token* are /validate-minted JWTs,
# $internal_session_secret is SECRET_KEY, and $http_x_internal_token* is the
# signed token a Lua subrequest inherits.
_INTERNAL_SECRET_VARIABLE: re.Pattern[str] = re.compile(
    r"\$\{?(auth_internal_token\w*|internal_session_secret|http_x_internal_token\w*)"
)
# Reserved credential headers a registrant-backend location must clear: the
# ingress credentials and the signed internal-token headers from
# RESERVED_CUSTOM_HEADER_NAMES.
_INGRESS_CREDENTIAL_HEADERS: frozenset[str] = frozenset(
    {"authorization", "x-authorization", "proxy-authorization", "cookie"}
)
CREDENTIAL_HEADERS: frozenset[str] = frozenset(
    name
    for name in RESERVED_CUSTOM_HEADER_NAMES
    if name in _INGRESS_CREDENTIAL_HEADERS or name.startswith("x-internal-token")
)
# A2A trust model: the caller presents the target agent's own credential in
# Authorization, and /validate refuses an Authorization equal to the gateway
# credential, so agent routes forward Authorization by design.
AGENT_FORWARDED_HEADERS: frozenset[str] = frozenset({"authorization"})

# Pools the generated registries draw from. Registrant origins never share a
# host with the auth server or the registry, so the netloc classifies a location.
_SERVER_PATHS: tuple[str, ...] = ("/alpha", "/beta-svc", "/team/gamma")
_BACKEND_ORIGINS: tuple[str, ...] = (
    "http://alpha.example.com",
    "https://beta.example.net:8443",
    "http://backendsvc:9000",
)
_AGENT_ORIGINS: tuple[str, ...] = (
    "http://agent-a.example.com:9000",
    "https://agent-b.example.org",
    "http://agentsvc:7000",
)
_GENERIC_ENTITIES: tuple[tuple[str, str], ...] = (
    ("skill", "/skills/s1"),
    ("a2a_agent", "/agents/g1"),
    ("custom-type_1", "/custom-type_1/c1"),
)
_GENERIC_ORIGINS: tuple[str, ...] = ("https://skill-a.example.com", "https://custom.example.io")
_EGRESS_MODES: tuple[str, ...] = ("none", "pat", "oauth_user", "obo_exchange")
_TRANSPORTS: tuple[tuple[str, ...], ...] = (
    ("streamable-http",),
    ("sse",),
    ("streamable-http", "sse"),
)
_TOOL_NAME: str = "search"

PROPERTY_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    deadline=None,
)

GUARD_REASON: str = (
    "Known defect: _safe_generic_block checks its own short character list, "
    "so $, #, single quote and NUL in the path, and single quote, NUL and a "
    "trailing # in the target, reach the location, set and proxy_pass directives."
)
VARIABLE_REASON: str = (
    "Known defect: _safe_generic_block accepts $ in the path, so a path such as "
    "/x$http_foo makes nginx expand a client header into $entity_path and proxy_pass."
)
AGENT_CLEAR_REASON: str = (
    "Known defect: the A2A agent locations proxy to the registrant backend "
    "without clearing Proxy-Authorization or the X-Internal-Token headers a "
    "caller sends."
)


def _safe_block(
    entity_type: str,
    path: str,
    target: str,
    streaming: bool = False,
    has_upstream_auth: bool = False,
) -> str | None:
    """Run ``_safe_generic_block`` with the harness settings.

    Args:
        entity_type: Entity type token.
        path: Registered entity path.
        target: Backend target URL.
        streaming: Streaming variant flag.
        has_upstream_auth: Upstream-auth marker flag.

    Returns:
        The rendered block, or None if the guard skipped it.
    """
    with patch.object(nginx_module, "settings", render_settings()):
        return NginxConfigService()._safe_generic_block(
            entity_type, path, target, streaming, has_upstream_auth
        )


def _accepted_metacharacters(
    seed_before: str,
    seed_after: str,
    field_name: str,
) -> list[str]:
    """Return ASCII characters the guard accepts that the canonical predicate rejects.

    Args:
        seed_before: Text before the inserted character.
        seed_after: Text after the inserted character.
        field_name: ``"path"`` or ``"target"``.

    Returns:
        Each character ``c`` for which the guard produced a block for
        ``seed_before + c + seed_after`` although that value contains an nginx
        metacharacter.
    """
    accepted = []
    for char in _ASCII:
        value = seed_before + char + seed_after
        if field_name == "path":
            block = _safe_block(SAFE_ENTITY_TYPE, value, SAFE_TARGET)
        else:
            block = _safe_block(SAFE_ENTITY_TYPE, SAFE_PATH, value)
        if block is not None and contains_nginx_metacharacters(value):
            accepted.append(char)
    return accepted


def _block_variables(
    block: str,
) -> tuple[set[str] | None, str | None]:
    """Return the ``$name`` variables a rendered generic block references.

    The block is parsed with crossplane inside a minimal http/server wrapper,
    so comments and Lua block bodies are excluded and only directive arguments
    count.

    Args:
        block: Output of ``_safe_generic_block`` (with ``{{ROOT_PATH}}``).

    Returns:
        ``(names, None)``, or ``(None, error)`` when the block does not parse.
    """
    text = "http {\n server {\n" + block.replace("{{ROOT_PATH}}", ROOT_PATH) + "\n }\n}\n"
    tree, error = parse_config(text)
    if tree is None:
        return None, error
    names: set[str] = set()
    for location in iter_blocks(tree, "location"):
        names.update(_VARIABLE_PATTERN.findall(" ".join(location["args"])))
        for directive in location.get("block", []):
            if directive["directive"] == "#" or directive["directive"].endswith("_by_lua_block"):
                continue
            for arg in directive.get("args", []):
                names.update(_VARIABLE_PATTERN.findall(arg))
    return names, None


def _path_strategy() -> st.SearchStrategy[str]:
    """Registered entity paths: ``/skills/`` plus segments over ASCII and nginx syntax."""
    segment = st.text(
        alphabet=st.sampled_from(
            [*"abcz09-_.~", "$", "#", "'", '"', ";", "{", "}", "\\", " ", "\t", "\n", "\x00"]
        ),
        min_size=1,
        max_size=10,
    )
    return st.lists(segment, min_size=1, max_size=3).map(lambda parts: "/skills/" + "/".join(parts))


def _target_strategy() -> st.SearchStrategy[str]:
    """Target URLs: a public https origin plus a path over ASCII and nginx syntax."""
    tail = st.text(
        alphabet=st.sampled_from(
            [*"abcz09-_.~/?=&%", "$", "#", "'", '"', ";", "{", "}", "\\", " ", "\n", "\x00"]
        ),
        max_size=16,
    )
    return tail.map(lambda rest: "https://skill.example.com/" + rest)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field_name", "seed_before", "seed_after"),
    [
        pytest.param(
            "path",
            "/skills/de",
            "mo",
            id="path-inside-segment",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=GUARD_REASON),
        ),
        pytest.param(
            "path",
            "/skills/demo",
            "",
            id="path-suffix",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=GUARD_REASON),
        ),
        pytest.param(
            "target",
            "https://skill.example.com/a",
            "b",
            id="target-inside-path",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=GUARD_REASON),
        ),
        pytest.param(
            "target",
            "https://skill.example.com/ab",
            "",
            id="target-suffix",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=GUARD_REASON),
        ),
    ],
)
def test_generic_guard_rejects_every_canonical_metacharacter(
    field_name: str,
    seed_before: str,
    seed_after: str,
) -> None:
    """Property: inserting any ASCII metacharacter into a path or target drops the block.

    Exhaustive over all 128 ASCII characters: if ``_safe_generic_block``
    produces a block, ``contains_nginx_metacharacters`` is False for the value.
    """
    seed = seed_before + seed_after
    path, target = (seed, SAFE_TARGET) if field_name == "path" else (SAFE_PATH, seed)
    if _safe_block(SAFE_ENTITY_TYPE, path, target) is None:
        pytest.fail(f"seed {seed!r} must produce a block for the sweep to be meaningful")

    accepted = _accepted_metacharacters(seed_before, seed_after, field_name)

    assert accepted == [], f"guard accepted {field_name} {seed!r} with metacharacters {accepted!r}"


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=GUARD_REASON)
@PROPERTY_SETTINGS
@given(path=_path_strategy())
@example(path="/skills/x$http_foo")
def test_generated_paths_with_metacharacters_are_rejected(
    path: str,
) -> None:
    """Property: an accepted generic path never contains a canonical metacharacter.

    Pinned counterexample: ``/skills/x$http_foo``, which renders
    ``set $entity_path "skills/x$http_foo"`` and lets a client header become
    part of the authorization key.
    """
    block = _safe_block(SAFE_ENTITY_TYPE, path, SAFE_TARGET)

    assert block is None or not contains_nginx_metacharacters(path), (
        f"guard produced a block for path {path!r}"
    )


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=GUARD_REASON)
@PROPERTY_SETTINGS
@given(target=_target_strategy())
@example(target="https://skill.example.com/a'b")
def test_generated_targets_with_metacharacters_are_rejected(
    target: str,
) -> None:
    """Property: an accepted generic target never contains a canonical metacharacter.

    Pinned counterexample: ``https://skill.example.com/a'b``.
    """
    block = _safe_block(SAFE_ENTITY_TYPE, SAFE_PATH, target)

    assert block is None or not contains_nginx_metacharacters(target), (
        f"guard produced a block for target {target!r}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("streaming", [False, True])
@pytest.mark.parametrize("has_upstream_auth", [False, True])
@pytest.mark.parametrize("entity_type", ["skill", "a2a_agent", "custom-type_1"])
def test_safe_generic_block_references_only_allowlisted_variables(
    entity_type: str,
    streaming: bool,
    has_upstream_auth: bool,
) -> None:
    """Property: a block for safe inputs references only allowlisted variables.

    Exhaustive over the streaming and upstream-auth variants: the block parses
    and every ``$name`` in its directive arguments is in
    ``GENERIC_BLOCK_VARIABLES``.
    """
    block = _safe_block(
        entity_type, f"/{entity_type}/demo", SAFE_TARGET, streaming, has_upstream_auth
    )
    assert block is not None

    names, error = _block_variables(block)

    assert names is not None, error
    assert names <= GENERIC_BLOCK_VARIABLES, sorted(names - GENERIC_BLOCK_VARIABLES)


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=VARIABLE_REASON)
@PROPERTY_SETTINGS
@given(
    entity_type=st.sampled_from(["skill", "a2a_agent", "custom-type_1"]),
    path=_path_strategy(),
    target=_target_strategy(),
    streaming=st.booleans(),
    has_upstream_auth=st.booleans(),
)
@example(
    entity_type="skill",
    path="/skills/x$http_foo",
    target=SAFE_TARGET,
    streaming=False,
    has_upstream_auth=False,
)
def test_generated_generic_block_references_only_allowlisted_variables(
    entity_type: str,
    path: str,
    target: str,
    streaming: bool,
    has_upstream_auth: bool,
) -> None:
    """Property: registry data never adds a ``$name`` to a rendered generic block.

    Hypothesis over path, target and variant flags: whenever a block is
    produced it parses and references only ``GENERIC_BLOCK_VARIABLES``.
    Pinned counterexample: ``/skills/x$http_foo`` adds ``$http_foo``.
    """
    block = _safe_block(entity_type, path, target, streaming, has_upstream_auth)
    if block is None:
        return

    names, error = _block_variables(block)

    assert names is not None, f"block for {path!r} / {target!r} does not parse: {error}"
    assert names <= GENERIC_BLOCK_VARIABLES, (
        f"block for {path!r} / {target!r} references {sorted(names - GENERIC_BLOCK_VARIABLES)}"
    )


@dataclass(frozen=True)
class _GeneratedRegistry:
    """A generated registry and the backend origins its registrants control.

    Attributes:
        snapshot: Registry contents to render.
        registrant_netlocs: ``host[:port]`` of every registrant backend.
    """

    snapshot: RegistrySnapshot
    registrant_netlocs: frozenset[str]


def _make_registry(
    servers: list[tuple[int, int, str, tuple[str, ...], bool, bool]],
    virtual_backends: list[list[int]],
    agents: list[int],
    generics: list[tuple[int, int]],
) -> _GeneratedRegistry:
    """Assemble a registry from index choices into the fixed pools.

    Args:
        servers: Per server ``(path_index, origin_index, egress_mode,
            transports, append_mcp_path, healthy)``; duplicate paths collapse.
        virtual_backends: Per virtual server, indices into ``servers``.
        agents: Indices into ``_AGENT_ORIGINS``, one agent each.
        generics: ``(entity_index, origin_index)`` per generic entity.

    Returns:
        The generated registry.
    """
    docs: dict[str, dict[str, Any]] = {}
    health: dict[str, str] = {}
    netlocs: set[str] = set()
    for path_index, origin_index, egress_mode, transports, append_mcp, healthy in servers:
        path = _SERVER_PATHS[path_index]
        origin = _BACKEND_ORIGINS[origin_index]
        docs[path] = {
            "path": path,
            "server_name": path.strip("/"),
            "proxy_pass_url": f"{origin}/mcp",
            "is_enabled": True,
            "egress_auth_mode": egress_mode,
            "supported_transports": list(transports),
            "append_mcp_path": append_mcp,
            "tool_list": [{"name": _TOOL_NAME, "description": "Search"}],
        }
        health[path] = HEALTHY if healthy else "unhealthy: timeout"
        netlocs.add(urlparse(origin).netloc)
    server_paths = sorted(docs)
    virtual_servers = []
    for index, backend_indices in enumerate(virtual_backends):
        mappings = [
            ToolMapping(
                tool_name=_TOOL_NAME,
                alias=f"{_TOOL_NAME}-{position}",
                backend_server_path=server_paths[backend % len(server_paths)],
            )
            for position, backend in enumerate(backend_indices)
        ]
        virtual_servers.append(
            VirtualServerConfig(
                path=f"/virtual/vs{index}",
                server_name=f"Virtual {index}",
                tool_mappings=mappings,
                is_enabled=True,
            )
        )
    agent_cards = {}
    for index, origin_index in enumerate(agents):
        origin = _AGENT_ORIGINS[origin_index]
        path = f"/agent-{index}"
        agent_cards[path] = AgentCard(
            name=f"Agent {index}",
            description="Agent",
            url=f"{origin}/a2a",
            version="1.0",
            path=path,
            supported_protocol="a2a",
            health_status=HEALTHY,
        )
        netlocs.add(urlparse(origin).netloc)
    generic_resources = []
    for entity_index, origin_index in dict(generics).items():
        entity_type, path = _GENERIC_ENTITIES[entity_index]
        origin = _GENERIC_ORIGINS[origin_index]
        generic_resources.append(
            {"entity_type": entity_type, "path": path, "target_url": f"{origin}/api"}
        )
        netlocs.add(urlparse(origin).netloc)
    snapshot = RegistrySnapshot(
        server_docs=docs,
        enabled_servers=dict(docs),
        health=health,
        virtual_servers=virtual_servers,
        agents=agent_cards,
        generic_resources=generic_resources,
    )
    return _GeneratedRegistry(snapshot=snapshot, registrant_netlocs=frozenset(netlocs))


def _registry_strategy() -> st.SearchStrategy[_GeneratedRegistry]:
    """Registries of 1 to 3 servers, 0 to 2 virtual servers, agents and generic entities."""
    server = st.tuples(
        st.integers(0, len(_SERVER_PATHS) - 1),
        st.integers(0, len(_BACKEND_ORIGINS) - 1),
        st.sampled_from(_EGRESS_MODES),
        st.sampled_from(_TRANSPORTS),
        st.booleans(),
        st.booleans(),
    )
    return st.builds(
        _make_registry,
        st.lists(server, min_size=1, max_size=3),
        st.lists(st.lists(st.integers(0, 2), min_size=1, max_size=3), max_size=2),
        st.lists(st.integers(0, len(_AGENT_ORIGINS) - 1), max_size=2),
        st.lists(
            st.tuples(
                st.integers(0, len(_GENERIC_ENTITIES) - 1),
                st.integers(0, len(_GENERIC_ORIGINS) - 1),
            ),
            max_size=2,
        ),
    )


_PINNED_REGISTRY: _GeneratedRegistry = _make_registry(
    servers=[(0, 0, "none", ("streamable-http",), True, True)],
    virtual_backends=[[0]],
    agents=[0],
    generics=[(0, 0)],
)


def _proxy_netloc(
    location: dict[str, Any],
) -> str | None:
    """Return the ``host[:port]`` a location's ``proxy_pass`` dials, if any.

    A variable ``proxy_pass`` is resolved through the ``set`` directive in the
    same location that assigns it.

    Args:
        location: crossplane ``location`` directive.

    Returns:
        The upstream netloc, or None if the location has no ``proxy_pass``.
    """
    body = location.get("block", [])
    assignments = {
        directive["args"][0]: directive["args"][1]
        for directive in body
        if directive["directive"] == "set" and len(directive["args"]) == 2
    }
    for directive in body:
        if directive["directive"] == "proxy_pass":
            target = directive["args"][0]
            return urlparse(assignments.get(target, target)).netloc
    return None


def _registrant_locations(
    template: Path,
    registry: _GeneratedRegistry,
) -> list[dict[str, Any]]:
    """Render ``registry`` and return locations that proxy to a registrant backend.

    Args:
        template: nginx template file.
        registry: Generated registry.

    Returns:
        crossplane ``location`` directives whose upstream is a registrant origin.
    """
    tree, error = parse_config(render_config(template, registry.snapshot))
    if tree is None:
        raise RuntimeError(f"render of {template.name} does not parse: {error}")
    return [
        location
        for location in iter_blocks(tree, "location")
        if _proxy_netloc(location) in registry.registrant_netlocs
    ]


def _secret_forwarding(
    location: dict[str, Any],
) -> list[str]:
    """Return directives in ``location`` that reference an internal token or secret."""
    found = []
    for directive in location.get("block", []):
        for arg in directive.get("args", []):
            if _INTERNAL_SECRET_VARIABLE.search(arg):
                found.append(f"{directive['directive']} {' '.join(directive['args'])}")
    return found


def _uncleared_credentials(
    location: dict[str, Any],
) -> list[str]:
    """Return reserved credential headers ``location`` does not clear.

    A header counts as cleared only by ``proxy_set_header <Name> ""``. Agent
    routes may forward ``AGENT_FORWARDED_HEADERS`` by design.

    Args:
        location: crossplane ``location`` directive.

    Returns:
        Sorted lowercase header names left uncleared.
    """
    cleared = {
        directive["args"][0].lower()
        for directive in location.get("block", [])
        if directive["directive"] == "proxy_set_header"
        and len(directive["args"]) == 2
        and directive["args"][1] == ""
    }
    required = set(CREDENTIAL_HEADERS)
    if f"{ROOT_PATH}{AGENT_ROUTE_PREFIX}/" in location["args"][-1]:
        required -= AGENT_FORWARDED_HEADERS
    return sorted(required - cleared)


@pytest.mark.unit
@pytest.mark.parametrize("template", TEMPLATES, ids=lambda path: path.name)
def test_pinned_registry_has_registrant_locations(
    template: Path,
) -> None:
    """Property: the classifier finds the agent registrant locations, and no virtual backend.

    Guards the header properties against passing vacuously. Virtual-backend
    locations are not registrant locations: each relays to the auth-server
    mcp-proxy hop, overwrites X-Internal-Token with the Lua-set request value
    rather than passing a second copy, and clears every other credential header.
    """
    locations = _registrant_locations(template, _PINNED_REGISTRY)
    paths = [location["args"][-1] for location in locations]

    assert not any(path.startswith("/_vs_backend") for path in paths), paths
    assert any(f"{AGENT_ROUTE_PREFIX}/" in path for path in paths), paths

    tree, error = parse_config(render_config(template, _PINNED_REGISTRY.snapshot))
    assert tree is not None, error
    hops = [
        location
        for location in iter_blocks(tree, "location")
        if location["args"][-1].startswith("/_vs_backend")
    ]
    assert hops
    for hop in hops:
        proxy_targets = [
            directive["args"][0]
            for directive in hop.get("block", [])
            if directive["directive"] == "proxy_pass"
        ]
        assert len(proxy_targets) == 1, proxy_targets
        target = urlparse(proxy_targets[0])
        assert target.netloc == urlparse(AUTH_SERVER_URL).netloc, proxy_targets
        assert target.path.startswith("/mcp-proxy/"), proxy_targets
        token_headers = [
            directive["args"]
            for directive in hop.get("block", [])
            if directive["directive"] == "proxy_set_header"
            and directive["args"][0].lower() == "x-internal-token"
        ]
        assert token_headers == [["X-Internal-Token", "$http_x_internal_token"]]
        assert _uncleared_credentials(hop) == ["x-internal-token"]


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(template=st.sampled_from(TEMPLATES), registry=_registry_strategy())
def test_registrant_locations_forward_no_internal_secret(
    template: Path,
    registry: _GeneratedRegistry,
) -> None:
    """Property: no registrant-backend location references an internal token or secret.

    Hypothesis over registries of servers (every egress mode and transport),
    virtual servers, agents and generic entities: in every rendered location
    whose ``proxy_pass`` reaches a registrant origin, no directive references
    ``$auth_internal_token*``, ``$internal_session_secret`` or
    ``$http_x_internal_token*``.
    """
    leaks = {
        location["args"][-1]: found
        for location in _registrant_locations(template, registry)
        if (found := _secret_forwarding(location))
    }

    assert leaks == {}


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=AGENT_CLEAR_REASON)
@PROPERTY_SETTINGS
@given(template=st.sampled_from(TEMPLATES), registry=_registry_strategy())
@example(template=TEMPLATES[0], registry=_PINNED_REGISTRY)
def test_registrant_locations_clear_reserved_credentials(
    template: Path,
    registry: _GeneratedRegistry,
) -> None:
    """Property: every registrant-backend location clears the reserved credential headers.

    Hypothesis over the same registries: each such location sets
    ``proxy_set_header <Name> ""`` for Authorization, X-Authorization,
    Proxy-Authorization, Cookie and every X-Internal-Token header, except
    that agent routes forward Authorization under the A2A trust model.
    Pinned counterexample: one agent, whose card and JSON-RPC locations leave
    Proxy-Authorization and the X-Internal-Token headers uncleared.
    """
    uncleared = {
        location["args"][-1]: missing
        for location in _registrant_locations(template, registry)
        if (missing := _uncleared_credentials(location))
    }

    assert uncleared == {}
