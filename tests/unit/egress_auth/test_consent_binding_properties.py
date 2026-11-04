"""Consent binding property: a callback stores a token only where the consent began.

The egress OAuth callback writes the upstream token into the vault bucket of the
principal named in the signed consent state. That write is safe only when the
browser completing the callback is the browser that started the consent, and
that browser is authenticated as that same principal. Without the principal
check, a consent link minted by one user and opened by another stores the
second user's upstream token in the first user's bucket. Without the browser
check, anyone holding a state bound to user V (an agent with V's bearer, or V's
browser history) finishes the provider step with their own account and makes
V's browser load the callback, so V's vault holds the attacker's account.

These tests drive the real ``/oauth2/egress/callback``, ``/egress-auth/initiate``
and ``/oauth2/egress/connect`` routes and the real ``EgressAuthService``. Each
``TestClient`` is one browser with its own cookie jar.
"""

from datetime import (
    UTC,
    datetime,
)
from typing import NamedTuple
from unittest.mock import AsyncMock
from urllib.parse import (
    parse_qs,
    urlparse,
)

import httpx
import pytest
from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    status,
)
from fastapi.testclient import TestClient

import registry.api.egress_auth_routes as routes
import registry.api.egress_oauth_facade_routes as facade
from registry.egress_auth import (
    oauth_engine,
    state_codec,
)
from registry.egress_auth.providers import resolve_provider
from registry.egress_auth.schemas import OAuthState
from registry.egress_auth.service import EgressAuthService
from registry.secrets.interfaces import SecretStoreBase
from registry.utils.credential_encryption import encrypt_credential

_CONSENTING_USER = "alice"
_OTHER_USER = "mallory"
_AUTH_METHOD = "oauth2"
_SERVER_PATH = "/github-mcp"
_UPSTREAM = "https://api.example.com/mcp"
# The TestClient origin. The callback base carries the /api prefix the test app
# mounts the router under, so the browser-visible callback path the consent
# cookie is scoped to is the path these tests request.
_CALLBACK_BASE_URL = "http://testserver/api"
_CALLBACK_PATH = "/api/oauth2/egress/callback"
_CONSENTING_COOKIE = "session-of-alice"
_OTHER_COOKIE = "session-of-mallory"
_EXPIRED_COOKIE = "session-expired"
_NO_PRINCIPAL_COOKIE = "session-of-static-key"
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
    # A live session that owns no per-user bucket: vault_principal is None.
    _NO_PRINCIPAL_COOKIE: {
        "username": _CONSENTING_USER,
        "egress_user": _CONSENTING_USER,
        "auth_method": "network-trusted",
        "client_id": "web",
        "session_id": "sid-static",
    },
}
# Cookies for which the callback refuses before the code exchange: no cookie, one
# that no longer resolves, and one that resolves to a caller with no principal.
_REFUSING_COOKIES = [
    pytest.param(None, id="no-session-cookie"),
    pytest.param(_EXPIRED_COOKIE, id="expired-session-cookie"),
    pytest.param(_NO_PRINCIPAL_COOKIE, id="session-without-principal"),
]
# The two routes a browser starts a consent at.
_CONSENT_STARTS = ["initiate", "connect"]


class _BrowserState(NamedTuple):
    """How the browser that completes the provider redirect looks to the registry.

    Attributes:
        cookie: Session cookie the browser presents, or None for no cookie.
        same_browser: True when it is the browser that started the consent, so it
            also carries the consent cookie that browser was given at consent start.
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
    ),
    pytest.param(
        _BrowserState(cookie=_EXPIRED_COOKIE, same_browser=False, live_principal=None),
        id="expired-session-cookie",
    ),
    pytest.param(
        _BrowserState(
            cookie=_CONSENTING_COOKIE, same_browser=True, live_principal=_CONSENTING_USER
        ),
        id="live-as-consenting-user",
    ),
    pytest.param(
        _BrowserState(
            cookie=_CONSENTING_COOKIE, same_browser=False, live_principal=_CONSENTING_USER
        ),
        id="other-browser-live-as-consenting-user",
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
        authorize_url: URL a consent start sent the browser to.

    Returns:
        The encoded consent state.
    """
    return parse_qs(urlparse(authorize_url).query)["state"][0]


def _start_consent(
    browser: TestClient,
    start: str,
) -> tuple[str, httpx.Response]:
    """Start a consent in ``browser`` and return its state and the start response.

    Args:
        browser: The browser that starts the consent.
        start: ``initiate`` (the Connected Accounts XHR) or ``connect`` (the
            elicitation front door, which 302s to the provider).

    Returns:
        The encoded consent state and the response that started it.
    """
    if start == "initiate":
        response = browser.post("/api/egress-auth/initiate", json={"server_path": _SERVER_PATH})
        assert response.status_code == 200, response.text
        return _extract_state(response.json()["authorize_url"]), response
    response = browser.get(
        "/oauth2/egress/connect", params={"server": _SERVER_PATH}, follow_redirects=False
    )
    assert response.status_code == 302, response.text
    return _extract_state(response.headers["location"]), response


def _complete(
    browser: TestClient,
    state_blob: str,
    code: str = "provider-code",
) -> httpx.Response:
    """Load the provider redirect to the callback in ``browser``.

    Args:
        browser: The browser the provider redirect lands in.
        state_blob: The consent state the provider echoes back.
        code: The authorization code the provider issued.

    Returns:
        The callback response.
    """
    return browser.get(_CALLBACK_PATH, params={"code": code, "state": state_blob})


def _consent_cookies(
    browser: TestClient,
) -> dict[str, str]:
    """Return every cookie in ``browser``'s jar other than the session cookie.

    Args:
        browser: The browser whose jar to read.

    Returns:
        Cookie name to value.
    """
    return {
        cookie.name: cookie.value
        for cookie in browser.cookies.jar
        if cookie.name != routes.settings.session_cookie_name
    }


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
    monkeypatch.setattr(routes.settings, "egress_oauth_callback_base_url", _CALLBACK_BASE_URL)
    monkeypatch.setattr(routes.server_service, "get_server_info", AsyncMock(return_value=server))
    monkeypatch.setattr(routes, "get_egress_auth_service", lambda: svc)
    monkeypatch.setattr(facade, "get_egress_auth_service", lambda: svc)
    # The callback and the connect route call nginx_proxied_auth directly.
    monkeypatch.setattr(routes, "nginx_proxied_auth", _resolve_session)
    monkeypatch.setattr(facade, "nginx_proxied_auth", _resolve_session)
    monkeypatch.setattr(oauth_engine, "_post_token", _fake_post_token)

    app = FastAPI()
    app.include_router(routes.router, prefix="/api")
    app.include_router(facade.router)
    app.dependency_overrides[original_auth_dependency] = _session_dependency
    app.dependency_overrides[routes.verify_csrf_token_flexible] = lambda: None
    return app, store


@pytest.mark.unit
@pytest.mark.parametrize("start", _CONSENT_STARTS)
@pytest.mark.parametrize("browser_state", _BROWSER_STATES)
def test_callback_writes_only_in_the_starting_browser_live_as_its_principal(
    consent_app, start, browser_state
):
    """Property: the callback writes P's bucket iff it runs in P's starting browser, live as P.

    The consenting user starts consent from their own browser; the provider
    redirect is then completed by a browser in each possible session state. A
    vault write may happen only when that browser is the one that started the
    consent and is authenticated as the principal bound in the consent state,
    and then only into that principal's bucket.
    """
    app, store = consent_app
    consenting_browser = _browser(app, _CONSENTING_COOKIE)
    state_blob, _ = _start_consent(consenting_browser, start)

    if browser_state.same_browser:
        completing_browser = consenting_browser
    else:
        completing_browser = _browser(app, browser_state.cookie)
    _complete(completing_browser, state_blob)

    may_write = browser_state.same_browser and browser_state.live_principal == _CONSENTING_USER
    expected_writes = [(_AUTH_METHOD, _CONSENTING_USER)] if may_write else []
    assert store.writes == expected_writes, (
        f"consent started at {start} for {_CONSENTING_USER!r}, completing browser "
        f"{browser_state}: vault writes {store.writes}, expected {expected_writes}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("start", _CONSENT_STARTS)
def test_account_injection_into_the_principals_browser_writes_nothing(consent_app, start):
    """An attacker's code paired with V's state, loaded in V's browser, writes nothing.

    The attacker holds V's credential outside V's browser (an agent with V's
    bearer), so the consent it starts is bound to V. It completes the provider
    step with its own account and makes V's live browser load the callback with
    its code. V's browser never started that consent, so it holds no consent
    cookie for it, and the callback must refuse before the code exchange.
    """
    app, store = consent_app
    attacker_client = _browser(app, _CONSENTING_COOKIE)
    state_blob, _ = _start_consent(attacker_client, start)
    victims_browser = _browser(app, _CONSENTING_COOKIE)

    refused = _complete(victims_browser, state_blob, code="code-for-the-attackers-account")

    assert refused.status_code == 400, refused.text
    assert store.writes == [], (
        f"V's browser completed a consent another client started; vault writes {store.writes}"
    )


@pytest.mark.unit
def test_consent_cookie_completes_only_its_own_consent(consent_app):
    """The cookie one consent set never completes a different consent.

    One browser holds the cookie of consent 1. It cannot complete consent 2 (or
    3), which another client started: neither as it is, nor with consent 1's
    cookie value presented under the name the other consent's cookie has.
    """
    app, store = consent_app
    browser = _browser(app, _CONSENTING_COOKIE)
    _, first = _start_consent(browser, "initiate")
    [first_value] = first.cookies.values()
    other_client = _browser(app, _CONSENTING_COOKIE)
    second_state, _ = _start_consent(other_client, "initiate")
    third_state, third = _start_consent(other_client, "initiate")
    [third_name] = third.cookies.keys()

    as_is = _complete(browser, second_state)
    browser.cookies.set(third_name, first_value, path=_CALLBACK_PATH)
    renamed = _complete(browser, third_state)

    assert (as_is.status_code, renamed.status_code) == (400, 400), (as_is.text, renamed.text)
    assert store.writes == [], f"consent 1's cookie completed another consent: {store.writes}"


@pytest.mark.unit
@pytest.mark.parametrize("start", _CONSENT_STARTS)
def test_parallel_consents_in_one_browser_both_complete(consent_app, start):
    """Two consents started in one browser both complete, in either order.

    Each consent sets its own cookie, so starting the second does not displace
    the first. Each callback clears the cookie of its own consent.
    """
    app, store = consent_app
    browser = _browser(app, _CONSENTING_COOKIE)
    first_state, _ = _start_consent(browser, start)
    second_state, _ = _start_consent(browser, start)
    assert len(_consent_cookies(browser)) == 2, _consent_cookies(browser)

    second = _complete(browser, second_state)
    first = _complete(browser, first_state)

    assert (first.status_code, second.status_code) == (200, 200), (first.text, second.text)
    assert store.writes == [(_AUTH_METHOD, _CONSENTING_USER)] * 2
    assert _consent_cookies(browser) == {}


@pytest.mark.unit
def test_state_without_a_browser_binding_is_refused(consent_app):
    """A consent state that binds no browser (minted before the upgrade) never writes.

    The state carries everything else a consent state needs and the browser is
    live as its principal; only the browser binding is missing. The refusal
    also burns the state.
    """
    app, store = consent_app
    unbound = state_codec.encode_state(
        OAuthState(
            user_id=_CONSENTING_USER,
            auth_method=_AUTH_METHOD,
            provider="github",
            server_path=_SERVER_PATH,
            nonce="pre-upgrade-nonce",
            issued_at=datetime.now(UTC).isoformat(),
            approved_upstreams=[_UPSTREAM],
            token_url=resolve_provider({"provider": "github"}).token_url,
        )
    )
    browser = _browser(app, _CONSENTING_COOKIE)

    refused = _complete(browser, unbound)

    assert refused.status_code == 400, refused.text
    assert store.writes == []


@pytest.mark.unit
@pytest.mark.parametrize("refusing_cookie", _REFUSING_COOKIES)
def test_refused_callback_burns_the_state(consent_app, refusing_cookie):
    """A code and state the callback refused cannot be replayed by the initiator.

    The refusing browser's history keeps ``?code=...&state=...``. If that URL is
    handed back to the user who minted the state, their own live browser passes
    the principal and browser checks, so the refusal must already have consumed
    the nonce.
    """
    app, store = consent_app
    consenting_browser = _browser(app, _CONSENTING_COOKIE)
    state_blob, _ = _start_consent(consenting_browser, "initiate")
    refused = _complete(_browser(app, refusing_cookie), state_blob, "code-of-the-refusing-browser")
    assert refused.status_code == 401, refused.text

    _complete(consenting_browser, state_blob, "code-of-the-refusing-browser")

    assert store.writes == [], (
        f"callback refused for cookie {refusing_cookie!r}, then the same code and "
        f"state replayed from {_CONSENTING_USER!r}'s browser wrote {store.writes}"
    )


@pytest.mark.unit
def test_browser_mismatch_burns_the_state(consent_app):
    """A callback refused for the wrong browser cannot be replayed in the right one.

    V's own browser starts the consent; the code and state are first loaded in
    another browser live as V, which is refused for the missing consent cookie.
    Replaying the same URL in V's starting browser must not write either.
    """
    app, store = consent_app
    consenting_browser = _browser(app, _CONSENTING_COOKIE)
    state_blob, _ = _start_consent(consenting_browser, "initiate")
    refused = _complete(_browser(app, _CONSENTING_COOKIE), state_blob)
    assert refused.status_code == 400, refused.text

    _complete(consenting_browser, state_blob)

    assert store.writes == []
