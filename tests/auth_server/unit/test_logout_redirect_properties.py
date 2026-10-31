"""Property tests for the logout redirect of providers without an IdP logout URL.

For a provider with no ``logout_url`` (GitHub, Google) the auth server answers
``/oauth2/logout/{provider}`` with a direct 302 to the caller-supplied
``redirect_uri``. These tests pin that a browser following that ``Location``
never leaves the registry origin, whatever ``redirect_uri`` the caller sends.
"""

import asyncio
import os
from unittest.mock import patch
from urllib.parse import (
    urlencode,
    urljoin,
    urlsplit,
)

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-definitely-long-enough-32b")

import auth_server.server as server_module  # noqa: E402

pytestmark = pytest.mark.unit

_PROVIDER = "github"
_REGISTRY_HOST = "testserver"
_REGISTRY_ORIGIN = f"http://{_REGISTRY_HOST}"
_REGISTRY_BASE = f"{_REGISTRY_ORIGIN}/"
_LOGOUT_PATH = f"/oauth2/logout/{_PROVIDER}"
_OAUTH2_CONFIG = {
    "providers": {_PROVIDER: {"client_id": "gateway-web", "enabled": True}},
    "registry": {"success_redirect": "/login"},
}
_REDIRECT_ENV_VARS = (
    "OAUTH2_ALLOWED_REDIRECT_URIS",
    "SESSION_COOKIE_DOMAIN",
    "AUTH_SERVER_EXTERNAL_URL",
    "REGISTRY_URL",
)
_REDIRECT_TOKENS = ["/", "\\", ".", "a", ":", "@", "%5C", "\t", "evil.com"]
_ASCII_TAB_OR_NEWLINE = "\t\n\r"
_C0_CONTROL_OR_SPACE = "".join(chr(code) for code in range(0x21))


def _browser_resolve(base: str, location: str) -> str:
    """Resolve a ``Location`` header against ``base`` the way a browser does.

    Applies the WHATWG URL parser steps that Python's ``urljoin`` does not:
    strip leading and trailing C0 control or space, remove every ASCII tab or
    newline, and treat a backslash as a slash (special schemes http/https).

    Args:
        base: The absolute URL of the page that received the redirect.
        location: The raw ``Location`` header value.

    Returns:
        The absolute URL the browser navigates to.
    """
    value = location.strip(_C0_CONTROL_OR_SPACE)
    value = "".join(ch for ch in value if ch not in _ASCII_TAB_OR_NEWLINE)
    value = value.replace("\\", "/")
    return urljoin(base, value)


async def _asgi_get(path: str, query: str) -> tuple[int, dict[str, str]]:
    """Send one GET straight through the ASGI app and capture the raw response.

    An HTTP client library would parse (and may reject) the ``Location`` value
    before the test sees it; a browser does not, so the header is read raw.

    Args:
        path: Request path on the auth server.
        query: Already-encoded query string.

    Returns:
        The response status code and its headers, decoded as latin-1.
    """
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": query.encode("ascii"),
        "root_path": "",
        "headers": [(b"host", _REGISTRY_HOST.encode("ascii"))],
        "client": ("127.0.0.1", 50000),
        "server": (_REGISTRY_HOST, 80),
    }
    start: dict = {}
    request_sent = False

    async def _receive() -> dict:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def _send(message: dict) -> None:
        if message["type"] == "http.response.start":
            start.update(message)

    await server_module.app(scope, _receive, _send)
    headers = {key.decode("latin-1"): value.decode("latin-1") for key, value in start["headers"]}
    return start["status"], headers


def _logout_location(redirect_uri: str) -> str:
    """Call the logout route and return the ``Location`` it answers with.

    Args:
        redirect_uri: The caller-supplied ``redirect_uri`` query value.

    Returns:
        The raw ``Location`` header of the 302 response.
    """
    with (
        patch.object(server_module, "OAUTH2_CONFIG", _OAUTH2_CONFIG),
        patch.dict(os.environ),
    ):
        for name in _REDIRECT_ENV_VARS:
            os.environ.pop(name, None)
        status, headers = asyncio.run(
            _asgi_get(_LOGOUT_PATH, urlencode({"redirect_uri": redirect_uri}))
        )
    assert status == 302, f"status={status} for redirect_uri={redirect_uri!r}"
    return headers["location"]


def _assert_same_origin(redirect_uri: str) -> None:
    """Assert the logout redirect for ``redirect_uri`` stays on the registry.

    Args:
        redirect_uri: The caller-supplied ``redirect_uri`` query value.
    """
    location = _logout_location(redirect_uri)
    resolved = urlsplit(_browser_resolve(_REGISTRY_BASE, location))
    base = urlsplit(_REGISTRY_BASE)
    assert (resolved.scheme, resolved.netloc) == (base.scheme, base.netloc), (
        f"redirect_uri={redirect_uri!r} -> Location={location!r} -> {resolved.geturl()!r}"
    )


@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(redirect_uri=st.lists(st.sampled_from(_REDIRECT_TOKENS), max_size=8).map("".join))
@example(redirect_uri="/\\evil.com")
@example(redirect_uri="\\\\evil.com")
@example(redirect_uri="/\t/evil.com")
@example(redirect_uri="//evil.com")
def test_logout_redirect_stays_on_registry_origin(redirect_uri: str) -> None:
    """Every logout ``Location`` resolves, in a browser, to the registry origin."""
    _assert_same_origin(redirect_uri)


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "/login",
        "/dashboard?tab=servers",
        "settings",
        f"{_REGISTRY_ORIGIN}/dashboard",
    ],
)
def test_logout_honours_same_origin_redirect(redirect_uri: str) -> None:
    """A same-origin relative or absolute ``redirect_uri`` is followed as given."""
    location = _logout_location(redirect_uri)
    assert location == redirect_uri
    _assert_same_origin(redirect_uri)
