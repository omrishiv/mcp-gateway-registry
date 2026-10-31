"""Property tests pinning which identity mcpgw uses when it calls the registry.

mcpgw sits behind the gateway, which authorizes one credential per request, and
then calls the registry on the caller's behalf. These tests pin three
properties: the token mcpgw forwards is the one the gateway authorized, what
mcpgw returns never exceeds what the registry shows the caller's own token, and
the FastMCP DNS-rebinding protection is off only when an operator lists "*".
"""

import asyncio
import itertools
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
)

import httpx
import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st
from starlette.datastructures import Headers

# The mcpgw server depends on `fastmcp` which is not installed in the main
# project venv. Stub it out before importing the server module.
# FastMCP.tool() is a decorator, so make it a passthrough to keep the original
# async functions callable.
if "fastmcp" not in sys.modules:
    _fastmcp_stub = types.ModuleType("fastmcp")
    _fastmcp_stub.Context = type("Context", (), {})
    _mock_mcp = MagicMock()
    _mock_mcp.tool.return_value = lambda fn: fn  # decorator is a no-op
    _fastmcp_stub.FastMCP = MagicMock(return_value=_mock_mcp)
    sys.modules["fastmcp"] = _fastmcp_stub

# Add servers/mcpgw to sys.path so that `from models import ...` works
_mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
if _mcpgw_path not in sys.path:
    sys.path.insert(0, _mcpgw_path)

# Import (not re-import) the server module: popping it from sys.modules here
# would break sibling test modules that already hold a reference to the
# previously imported module object, since patch() targets would then resolve
# to a different module than the tools under test came from.

from servers.mcpgw import server as mcpgw_server  # noqa: E402
from servers.mcpgw.server import (  # noqa: E402
    _get_registry_headers,
    _resolve_allowed_hosts,
    get_skill_content,
    list_services,
    search_registry,
)

# Captured before any test patches httpx.AsyncClient (the patch target is the
# shared httpx module attribute, so the fake factory needs the real class).
_REAL_ASYNC_CLIENT = httpx.AsyncClient

_BEARER_PREFIX = "bearer "

TOKEN_A = "caller-token-a"
TOKEN_B = "caller-token-b"

CALLER_TOKEN = "caller-token"
ADMIN_STATIC_TOKEN = "admin-static-token"
M2M_TOKEN = "m2m-service-token"

PUBLIC_SERVER = "/public"
ADMIN_ONLY_SERVER = "/admin-only"
UNRESTRICTED_ONLY_SERVER = "/unrestricted-only"

PUBLIC_SKILL = "public-skill"
RESTRICTED_SKILL = "restricted-skill"

# What the fake registry shows each token. The caller sees only public items;
# the static admin token and the M2M service account each see more.
_REGISTRY_VIEWS = {
    CALLER_TOKEN: {
        "servers": [PUBLIC_SERVER],
        "skills": [PUBLIC_SKILL],
    },
    ADMIN_STATIC_TOKEN: {
        "servers": [PUBLIC_SERVER, ADMIN_ONLY_SERVER],
        "skills": [PUBLIC_SKILL, RESTRICTED_SKILL],
    },
    M2M_TOKEN: {
        "servers": [PUBLIC_SERVER, UNRESTRICTED_ONLY_SERVER],
        "skills": [PUBLIC_SKILL, RESTRICTED_SKILL],
    },
}

_FORWARDED_TOKEN_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: mcpgw reads Authorization before X-Authorization, so it "
        "forwards a different credential than the one the gateway authorized."
    ),
)

_SHARED_IDENTITY_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: with a service credential configured, mcpgw queries the "
        "registry as that shared identity instead of as the caller."
    ),
)

_EMPTY_ALLOWLIST_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: an allowlist with no host entries turns DNS-rebinding "
        "protection off instead of keeping it on."
    ),
)


def _reference_bearer_token(
    headers,
) -> str | None:
    """Return the bearer token the gateway authorizes from a header mapping.

    Mirrors the non-A2A path of the gateway's /validate: X-Authorization wins
    when present, otherwise Authorization; the token is that header with a
    case-insensitive "Bearer " prefix removed and the remainder stripped.

    Args:
        headers: A case-insensitive header mapping with a ``get`` method.

    Returns:
        The bearer token, or None when the selected header is absent, uses
        another scheme, or carries an empty token.
    """
    selected = headers.get("x-authorization") or headers.get("authorization")
    if not selected or not selected.lower().startswith(_BEARER_PREFIX):
        return None
    token = selected[len(_BEARER_PREFIX) :].strip()
    return token or None


def _build_ctx(
    authorization: str | None,
    x_authorization: str | None,
) -> SimpleNamespace:
    """Build a FastMCP-like context carrying the given ingress headers.

    Args:
        authorization: Value of the Authorization header, or None to omit it.
        x_authorization: Value of the X-Authorization header, or None to omit it.

    Returns:
        A context object whose request headers are case-insensitive.
    """
    raw: dict[str, str] = {}
    if authorization is not None:
        raw["Authorization"] = authorization
    if x_authorization is not None:
        raw["X-Authorization"] = x_authorization
    request = SimpleNamespace(headers=Headers(headers=raw))
    return SimpleNamespace(request_context=SimpleNamespace(request=request))


def _client_factory(
    handler,
):
    """Return an httpx.AsyncClient replacement that routes to `handler`.

    Args:
        handler: Callable taking an httpx.Request and returning an httpx.Response.

    Returns:
        A factory with the AsyncClient call signature that builds a real client
        on top of an in-memory transport.
    """

    def _factory(*args, **kwargs):
        return _REAL_ASYNC_CLIENT(
            transport=httpx.MockTransport(handler),
            timeout=kwargs.get("timeout"),
        )

    return _factory


def _recording_handler(
    seen: list[httpx.Request],
):
    """Return a registry handler that records every request and answers empty.

    Args:
        seen: List each incoming request is appended to.

    Returns:
        A MockTransport handler.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"servers": []})

    return _handler


def _server_record(
    path: str,
) -> dict:
    """Return a minimal /api/servers record that parses as ServerInfo.

    Args:
        path: The server path.

    Returns:
        A registry server record.
    """
    return {"path": path, "display_name": path.strip("/"), "is_enabled": True}


def _fake_registry(
    request: httpx.Request,
) -> httpx.Response:
    """Answer a registry call with the view of whichever token mcpgw sent.

    Args:
        request: The outbound request mcpgw made.

    Returns:
        The response the registry gives that token; 401 for an unknown token.
    """
    view = _REGISTRY_VIEWS.get(_reference_bearer_token(request.headers))
    if view is None:
        return httpx.Response(401, json={"detail": "unauthenticated"})

    path = request.url.path
    if path == "/api/servers":
        return httpx.Response(
            200,
            json={"servers": [_server_record(p) for p in view["servers"]]},
        )
    if path == "/api/search/semantic":
        hits = [
            {"path": p, "server_name": p.strip("/"), "matching_tools": []} for p in view["servers"]
        ]
        return httpx.Response(200, json={"servers": hits})
    if path.startswith("/api/skills/") and path.endswith("/content"):
        skill_name = path.split("/")[3]
        if skill_name in view["skills"]:
            return httpx.Response(
                200,
                json={"content": f"# {skill_name}", "url": f"https://skills.example/{skill_name}"},
            )
        return httpx.Response(404, json={"detail": "not found"})
    return httpx.Response(404, json={"detail": "not found"})


async def _call_list_services(
    tool_ctx,
) -> set[str]:
    """Return the server paths list_services shows."""
    result = await list_services(ctx=tool_ctx)
    return {s["path"] for s in result["services"]}


async def _call_search_registry(
    tool_ctx,
) -> set[str]:
    """Return the server paths search_registry shows."""
    result = await search_registry(query="anything", ctx=tool_ctx)
    return {s["path"] for s in result.get("servers", [])}


async def _call_get_restricted_skill(
    tool_ctx,
) -> set[str]:
    """Return the restricted skill's name if get_skill_content hands it back."""
    result = await get_skill_content(skill_name=RESTRICTED_SKILL, ctx=tool_ctx)
    return {result["skill_name"]} if result["status"] == "success" else set()


# Per tool: how to call it, and which items the caller's own token may see.
_TOOLS = {
    "list_services": (_call_list_services, set(_REGISTRY_VIEWS[CALLER_TOKEN]["servers"])),
    "search_registry": (_call_search_registry, set(_REGISTRY_VIEWS[CALLER_TOKEN]["servers"])),
    "get_skill_content": (
        _call_get_restricted_skill,
        set(_REGISTRY_VIEWS[CALLER_TOKEN]["skills"]) & {RESTRICTED_SKILL},
    ),
}


def _credential_config(
    config: str,
) -> tuple[str, object | None]:
    """Return the (REGISTRY_API_TOKEN, _m2m_manager) pair for a mode name.

    Args:
        config: One of "passthrough", "static_token", "m2m".

    Returns:
        The module attribute values that select that credential mode.
    """
    if config == "static_token":
        return ADMIN_STATIC_TOKEN, None
    if config == "m2m":
        return "", SimpleNamespace(get_token=AsyncMock(return_value=M2M_TOKEN))
    return "", None


# ---------------------------------------------------------------------------
# The forwarded token is the token the gateway authorized
# ---------------------------------------------------------------------------

# Ingress header values as an ASGI server hands them over. (id, Authorization,
# X-Authorization); None means the header is absent.
_INGRESS_CASES = [
    pytest.param(None, None, id="none"),
    pytest.param(f"Bearer {TOKEN_A}", None, id="authorization_only"),
    pytest.param(None, f"Bearer {TOKEN_A}", id="x_authorization_only"),
    pytest.param(f"Bearer {TOKEN_A}", f"Bearer {TOKEN_A}", id="both_equal"),
    pytest.param(
        f"Bearer {TOKEN_B}",
        f"Bearer {TOKEN_A}",
        id="both_different",
        marks=_FORWARDED_TOKEN_XFAIL,
    ),
    pytest.param("Basic dXNlcjpwYXNz", None, id="non_bearer_authorization_only"),
    pytest.param(None, "Basic dXNlcjpwYXNz", id="non_bearer_x_authorization_only"),
    pytest.param(
        f"Bearer {TOKEN_B}",
        "Basic dXNlcjpwYXNz",
        id="non_bearer_x_authorization_with_bearer_authorization",
        marks=_FORWARDED_TOKEN_XFAIL,
    ),
    pytest.param(
        "Basic dXNlcjpwYXNz",
        f"Bearer {TOKEN_A}",
        id="non_bearer_authorization_with_bearer_x_authorization",
        marks=_FORWARDED_TOKEN_XFAIL,
    ),
    pytest.param(f"BEARER {TOKEN_A}", None, id="upper_case_scheme_authorization"),
    pytest.param(None, f"BEARER {TOKEN_A}", id="upper_case_scheme_x_authorization"),
    pytest.param(f"Bearer    {TOKEN_A}   ", None, id="extra_whitespace_authorization"),
    pytest.param(None, f"Bearer    {TOKEN_A}   ", id="extra_whitespace_x_authorization"),
    pytest.param(f"  Bearer {TOKEN_A}", None, id="leading_whitespace_authorization"),
]


async def _assert_forwards_authorized_token(
    authorization: str | None,
    x_authorization: str | None,
) -> None:
    """Assert mcpgw forwards exactly the gateway-authorized token, or nothing.

    Args:
        authorization: Ingress Authorization value, or None.
        x_authorization: Ingress X-Authorization value, or None.
    """
    tool_ctx = _build_ctx(authorization, x_authorization)
    expected = _reference_bearer_token(tool_ctx.request_context.request.headers)
    seen: list[httpx.Request] = []

    with (
        patch.object(mcpgw_server, "REGISTRY_API_TOKEN", ""),
        patch.object(mcpgw_server, "_m2m_manager", None),
        patch.object(mcpgw_server, "REGISTRY_EXTERNAL_URL", ""),
        patch.object(mcpgw_server.httpx, "AsyncClient", _client_factory(_recording_handler(seen))),
    ):
        try:
            outbound = await _get_registry_headers(tool_ctx)
        except ValueError:
            outbound = None
        await list_services(ctx=tool_ctx)

    forwarded = None if outbound is None else _reference_bearer_token(Headers(headers=outbound))
    sent = [_reference_bearer_token(r.headers) for r in seen]

    assert forwarded == expected, (
        f"gateway authorized {expected!r} but mcpgw would forward {forwarded!r} "
        f"(Authorization={authorization!r}, X-Authorization={x_authorization!r})"
    )
    if expected is None:
        assert seen == [], f"no authorized token, yet mcpgw called the registry with {sent!r}"
    else:
        assert sent == [expected], f"gateway authorized {expected!r} but registry received {sent!r}"


@pytest.mark.asyncio
@pytest.mark.parametrize(("authorization", "x_authorization"), _INGRESS_CASES)
async def test_passthrough_forwards_the_gateway_authorized_token(authorization, x_authorization):
    """In passthrough mode mcpgw forwards exactly the token the gateway authorized.

    When the gateway's rule yields no bearer token, mcpgw must refuse and make
    no registry call.
    """
    await _assert_forwards_authorized_token(authorization, x_authorization)


_TOKEN_STRATEGY = st.from_regex(r"\A[A-Za-z0-9._-]{1,40}\Z", fullmatch=True)


@_FORWARDED_TOKEN_XFAIL
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(authorization_token=_TOKEN_STRATEGY, x_authorization_token=_TOKEN_STRATEGY)
@example(authorization_token=TOKEN_B, x_authorization_token=TOKEN_A)
def test_forwarded_token_matches_gateway_for_any_header_pair(
    authorization_token,
    x_authorization_token,
):
    """For any pair of bearer tokens, mcpgw forwards the one the gateway authorized."""
    asyncio.run(
        _assert_forwards_authorized_token(
            f"Bearer {authorization_token}",
            f"Bearer {x_authorization_token}",
        )
    )


# ---------------------------------------------------------------------------
# mcpgw never shows more than the caller's own token could see
# ---------------------------------------------------------------------------

_VIEW_CASES = [
    pytest.param(tool_name, config, id=f"{tool_name}-{config}", marks=marks)
    for tool_name in _TOOLS
    for config, marks in (
        ("passthrough", ()),
        ("static_token", _SHARED_IDENTITY_XFAIL),
        ("m2m", _SHARED_IDENTITY_XFAIL),
    )
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("tool_name", "config"), _VIEW_CASES)
async def test_tool_output_is_within_the_callers_registry_view(tool_name, config):
    """Every credential mode returns a subset of what the caller's token sees.

    The fake registry answers each token with its own view; whatever credential
    mcpgw chooses, the items it returns must be ones the registry would return
    for the caller's own token.
    """
    call_tool, caller_view = _TOOLS[tool_name]
    static_token, m2m_manager = _credential_config(config)
    tool_ctx = _build_ctx(None, f"Bearer {CALLER_TOKEN}")

    with (
        patch.object(mcpgw_server, "REGISTRY_API_TOKEN", static_token),
        patch.object(mcpgw_server, "_m2m_manager", m2m_manager),
        patch.object(mcpgw_server, "REGISTRY_EXTERNAL_URL", ""),
        patch.object(mcpgw_server.httpx, "AsyncClient", _client_factory(_fake_registry)),
    ):
        shown = await call_tool(tool_ctx)

    assert shown <= caller_view, (
        f"{tool_name} in {config} mode returned {sorted(shown - caller_view)} "
        f"which the caller's own token cannot see"
    )
    if config == "passthrough":
        # Guards against a vacuous pass: passthrough must show the caller's view.
        assert shown == caller_view


# ---------------------------------------------------------------------------
# DNS-rebinding protection is off only when "*" is listed
# ---------------------------------------------------------------------------

_ALLOWLIST_ENTRIES = ["", " ", "*", "mcpgw-server", "a.b"]


def _allowlist_cases() -> list:
    """Enumerate comma-joined allowlists of 0 to 3 entries, deduplicated.

    Returns:
        pytest params; lists with neither a host nor "*" carry the xfail mark.
    """
    values: dict[str, None] = {}
    for length in range(4):
        for combo in itertools.product(_ALLOWLIST_ENTRIES, repeat=length):
            values.setdefault(",".join(combo), None)

    cases = []
    for raw_value in values:
        entries = [e.strip() for e in raw_value.split(",")]
        has_entry = any(entries)
        marks = () if has_entry else _EMPTY_ALLOWLIST_XFAIL
        cases.append(pytest.param(raw_value, id=repr(raw_value), marks=marks))
    return cases


@pytest.mark.parametrize("raw_value", _allowlist_cases())
def test_host_protection_is_off_only_for_a_wildcard(raw_value):
    """Host/origin protection is disabled if and only if "*" is an entry."""
    protection, _ = _resolve_allowed_hosts(raw_value)
    wildcard_listed = "*" in [e.strip() for e in raw_value.split(",")]

    assert protection is (not wildcard_listed), (
        f"MCPGW_HTTP_ALLOWED_HOSTS={raw_value!r}: protection={protection}, "
        f"wildcard listed={wildcard_listed}"
    )
