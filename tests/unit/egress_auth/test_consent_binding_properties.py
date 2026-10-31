"""Consent binding property: a callback stores a token only for its live principal.

The egress OAuth callback writes the upstream token into the vault bucket of the
principal named in the signed consent state. That write is safe only when the
browser completing the callback is authenticated as that same principal;
otherwise a consent link minted by one user and opened by another stores the
second user's upstream token in the first user's bucket. These tests drive the
real ``/oauth2/egress/callback`` route and the real ``EgressAuthService`` over
every browser session state and pin which of them may write.
"""

from typing import NamedTuple
from unittest.mock import AsyncMock
from urllib.parse import (
    parse_qs,
    urlparse,
)

import pytest
from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    status,
)
from fastapi.testclient import TestClient

import registry.api.egress_auth_routes as routes
from registry.egress_auth import (
    oauth_engine,
    state_codec,
)
from registry.egress_auth.service import EgressAuthService
from registry.secrets.interfaces import SecretStoreBase
from registry.utils.credential_encryption import encrypt_credential

_CONSENTING_USER = "alice"
_OTHER_USER = "mallory"
_AUTH_METHOD = "oauth2"
_SERVER_PATH = "/github-mcp"
_UPSTREAM = "https://api.example.com/mcp"
_CALLBACK_BASE_URL = "https://gw.example"
_CONSENTING_COOKIE = "session-of-alice"
_OTHER_COOKIE = "session-of-mallory"
_EXPIRED_COOKIE = "session-expired"
_LIVE_SESSIONS: dict[str, dict] = {
    _CONSENTING_COOKIE: {
        "username": _CONSENTING_USER,
        "egress_user": _CONSENTING_USER,
        "auth_method": _AUTH_METHOD,
        "client_id": "web",
        "session_id": "sid-alice",
    },
    _OTHER_COOKIE: {
        "username": _OTHER_USER,
        "egress_user": _OTHER_USER,
        "auth_method": _AUTH_METHOD,
        "client_id": "web",
        "session_id": "sid-mallory",
    },
}
_NO_LIVE_SESSION_REASON = (
    "Known defect: the egress callback stores the token in the consent state's "
    "principal bucket when the browser has no live session (no cookie or an "
    "expired one) instead of failing closed."
)


class _BrowserState(NamedTuple):
    """How the browser that completes the provider redirect looks to the registry.

    Attributes:
        cookie: Session cookie the browser presents, or None for no cookie.
        same_browser: True when it is the browser that started the consent, so it
            also carries anything that browser was given at consent start.
        live_principal: The principal the cookie resolves to, or None when the
            cookie is missing or no longer resolves.
    """

    cookie: str | None
    same_browser: bool
    live_principal: str | None


_BROWSER_STATES = [
    pytest.param(
        _BrowserState(cookie=None, same_browser=False, live_principal=None),
        id="no-session-cookie",
        marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=_NO_LIVE_SESSION_REASON),
    ),
    pytest.param(
        _BrowserState(cookie=_EXPIRED_COOKIE, same_browser=False, live_principal=None),
        id="expired-session-cookie",
        marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=_NO_LIVE_SESSION_REASON),
    ),
    pytest.param(
        _BrowserState(
            cookie=_CONSENTING_COOKIE, same_browser=True, live_principal=_CONSENTING_USER
        ),
        id="live-as-consenting-user",
    ),
    pytest.param(
        _BrowserState(cookie=_OTHER_COOKIE, same_browser=False, live_principal=_OTHER_USER),
        id="live-as-other-user",
    ),
]


class _RecordingStore(SecretStoreBase):
    """In-memory SecretStore that records every token write."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, str]] = []
        self._data: dict[tuple[str, str, str, str, str], object] = {}

    async def put_token(self, auth_method, user_id, provider, server_path, token, *, purpose):
        self.writes.append((auth_method, user_id))
        self._data[(purpose, auth_method, user_id, provider, server_path)] = token

    async def get_token(self, auth_method, user_id, provider, server_path, *, purpose):
        return self._data.get((purpose, auth_method, user_id, provider, server_path))

    async def delete_token(self, auth_method, user_id, provider, server_path, *, purpose):
        self._data.pop((purpose, auth_method, user_id, provider, server_path), None)

    async def list_for_user(self, auth_method, user_id):
        return []


async def _resolve_session(
    request: Request,
    session: str | None = None,
) -> dict:
    """Stand-in for ``nginx_proxied_auth`` that resolves a session cookie.

    Args:
        request: The incoming request (cookie read from it when ``session`` is None).
        session: Session cookie value passed explicitly, as the callback route does.

    Returns:
        A copy of the user context for a live session cookie.

    Raises:
        HTTPException: 401 for a missing, unknown or expired cookie, matching the
            real dependency.
    """
    cookie = session
    if cookie is None:
        cookie = request.cookies.get(routes.settings.session_cookie_name)
    if cookie in _LIVE_SESSIONS:
        return dict(_LIVE_SESSIONS[cookie])
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session expired. Please login again via OAuth2.",
    )


async def _session_dependency(
    request: Request,
) -> dict:
    """FastAPI dependency form of :func:`_resolve_session` for the initiate route.

    Args:
        request: The incoming request.

    Returns:
        The user context for the request's session cookie.
    """
    return await _resolve_session(request)


async def _fake_post_token(
    cfg,
    data,
    headers,
) -> dict:
    """Provider token endpoint stub: every code exchange succeeds.

    Args:
        cfg: Provider config (unused).
        data: Form body (unused).
        headers: Request headers (unused).

    Returns:
        A token endpoint response body.
    """
    return {
        "access_token": "gho_upstream_token_of_whoever_consented",
        "refresh_token": "rt",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "repo",
    }


def _browser(
    app: FastAPI,
    cookie: str | None,
) -> TestClient:
    """Return a TestClient acting as one browser with its own cookie jar.

    Args:
        app: The app under test.
        cookie: Session cookie to hold, or None for none.

    Returns:
        A TestClient whose jar holds only that session cookie.
    """
    cookies = {routes.settings.session_cookie_name: cookie} if cookie is not None else None
    return TestClient(app, cookies=cookies)


def _extract_state(
    authorize_url: str,
) -> str:
    """Return the ``state`` query parameter of a provider authorize URL.

    Args:
        authorize_url: URL returned by the initiate route.

    Returns:
        The encoded consent state.
    """
    return parse_qs(urlparse(authorize_url).query)["state"][0]


@pytest.fixture(autouse=True)
def _reset_cipher():
    state_codec.reset_cipher_for_tests()
    yield
    state_codec.reset_cipher_for_tests()


@pytest.fixture
def consent_app(monkeypatch):
    """App with the real egress routes and service; IdP, provider and DB stubbed.

    Returns:
        Tuple of (app, recording store).
    """
    original_auth_dependency = routes.nginx_proxied_auth
    egress_oauth = {
        "provider": "github",
        "client_id": "Iv1.testclient",
        "client_secret_encrypted": encrypt_credential("ghs_testsecret"),
        "scopes": ["repo"],
    }
    server = {
        "path": _SERVER_PATH,
        "proxy_pass_url": _UPSTREAM,
        "egress_auth_mode": "oauth_user",
        "egress_oauth": egress_oauth,
    }
    store = _RecordingStore()
    svc = EgressAuthService(secret_store=store, callback_base_url=_CALLBACK_BASE_URL)

    monkeypatch.setattr(routes.settings, "egress_auth_enabled", True)
    monkeypatch.setattr(routes.server_service, "get_server_info", AsyncMock(return_value=server))
    monkeypatch.setattr(routes, "get_egress_auth_service", lambda: svc)
    # The callback calls nginx_proxied_auth directly (not via Depends).
    monkeypatch.setattr(routes, "nginx_proxied_auth", _resolve_session)
    monkeypatch.setattr(oauth_engine, "_post_token", _fake_post_token)

    app = FastAPI()
    app.include_router(routes.router, prefix="/api")
    app.dependency_overrides[original_auth_dependency] = _session_dependency
    app.dependency_overrides[routes.verify_csrf_token_flexible] = lambda: None
    return app, store


@pytest.mark.unit
@pytest.mark.parametrize("browser_state", _BROWSER_STATES)
def test_callback_writes_only_for_live_principal(consent_app, browser_state):
    """Property: the callback writes principal P's bucket iff the browser is live as P.

    The consenting user starts consent from their own browser; the provider
    redirect is then completed by a browser in each possible session state. A
    vault write may happen only when that browser is authenticated as the
    principal bound in the consent state, and then only into that principal's
    bucket.
    """
    app, store = consent_app
    consenting_browser = _browser(app, _CONSENTING_COOKIE)
    initiate = consenting_browser.post(
        "/api/egress-auth/initiate", json={"server_path": _SERVER_PATH}
    )
    assert initiate.status_code == 200, initiate.text
    state_blob = _extract_state(initiate.json()["authorize_url"])

    if browser_state.same_browser:
        completing_browser = consenting_browser
    else:
        completing_browser = _browser(app, browser_state.cookie)
    completing_browser.get(
        "/api/oauth2/egress/callback",
        params={"code": "provider-code", "state": state_blob},
    )

    expected_writes = (
        [(_AUTH_METHOD, _CONSENTING_USER)]
        if browser_state.live_principal == _CONSENTING_USER
        else []
    )
    assert store.writes == expected_writes, (
        f"consent state minted for {_CONSENTING_USER!r}, completing browser live as "
        f"{browser_state.live_principal!r}: vault writes {store.writes}, "
        f"expected {expected_writes}"
    )
