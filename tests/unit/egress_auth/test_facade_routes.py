"""Route-level tests for the OAuth AS-facade (egress_oauth_facade_routes.py).

TestClient over the router with the session read, server_service, the
EgressAuthService, the auth-server mint HTTP call, and the Mongo operational
repo (pending/code state) all stubbed. Verifies the discovery docs, DCR, the
session-gated /authorize (including the no-session -> Keycloak login bounce),
and the /token redemption -> mint delegation, plus the callback-resume bridge.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import registry.api.egress_oauth_facade_routes as facade
from registry.egress_auth.oauth_engine import generate_pkce_verifier, pkce_challenge_s256

REGISTRY_URL = "https://gw.example.com"
USER = {
    "username": "alice",
    "auth_method": "oauth2",
    "client_id": "web",
    "groups": ["mcp-registry-user"],
    "scopes": ["openid", "email"],
}
STATIC = {"username": "ci-bot", "auth_method": "network-trusted", "groups": [], "scopes": []}


def _server(**over) -> dict:
    base = {
        "path": "/github",
        "egress_auth_mode": "oauth_user",
        "egress_oauth": {
            "provider": "github",
            "client_id": "Iv1.x",
            "client_secret_encrypted": "enc",
            "scopes": ["repo"],
        },
    }
    base.update(over)
    return base


class _FakeRepo:
    """In-memory stand-in for EgressOperationalRepository's facade methods."""

    def __init__(self):
        self.pending: dict[str, str] = {}
        self.codes: dict[str, str] = {}

    async def put_pending(self, correlation_id, payload, ttl_seconds):
        self.pending[correlation_id] = payload

    async def take_pending(self, correlation_id):
        return self.pending.pop(correlation_id, None)  # single-use

    async def store_code(self, code, payload, ttl_seconds):
        self.codes[code] = payload

    async def consume_code(self, code):
        return self.codes.pop(code, None)  # single-use


@pytest.fixture
def repo(monkeypatch):
    r = _FakeRepo()
    monkeypatch.setattr(facade, "get_facade_operational_repo", lambda: r)
    return r


@pytest.fixture
def client(monkeypatch, repo):
    def _build(
        user_context=USER,
        *,
        server=None,
        consent_url="https://github.com/login/oauth/authorize?x=1",
        enabled=True,
    ):
        monkeypatch.setattr(facade.settings, "egress_auth_enabled", enabled)
        monkeypatch.setattr(facade.settings, "registry_url", REGISTRY_URL)

        async def _get_server_info(path, include_credentials=False):
            return server

        monkeypatch.setattr(facade.server_service, "get_server_info", _get_server_info)

        # /authorize reads the session via _optional_session -> nginx_proxied_auth
        # (called with session=<cookie>). None user_context simulates no gateway
        # session (login bounce).
        async def _session(request, session=None):
            if user_context is None:
                raise RuntimeError("no session")
            return user_context

        monkeypatch.setattr(facade, "nginx_proxied_auth", _session)

        class _Svc:
            def build_consent_url(self, **kwargs):
                _Svc.last_session_id = kwargs.get("session_id")
                return consent_url

        monkeypatch.setattr(facade, "get_egress_auth_service", lambda: _Svc())

        app = FastAPI()
        app.include_router(facade.router)
        c = TestClient(app, follow_redirects=False)
        c._svc = _Svc
        c._repo = repo
        return c

    return _build


@pytest.mark.unit
class TestOptionalSession:
    """Regression: _optional_session MUST read the session cookie off the request
    and pass it explicitly to nginx_proxied_auth. nginx_proxied_auth's `session`
    is a FastAPI Cookie(...) param only populated by dependency injection; calling
    it directly without passing the cookie always sees session=None -> the login
    loop (the live bug)."""

    async def test_passes_request_cookie_to_nginx_proxied_auth(self, monkeypatch):
        monkeypatch.setattr(facade.settings, "session_cookie_name", "mcp_gateway_session")
        seen = {}

        async def _fake(request, session=None):
            seen["session"] = session
            return {"username": "alice", "auth_method": "oauth2"}

        monkeypatch.setattr(facade, "nginx_proxied_auth", _fake)

        class _Req:
            cookies = {"mcp_gateway_session": "the-cookie-value"}

        ctx = await facade._optional_session(_Req())
        assert ctx["username"] == "alice"
        assert seen["session"] == "the-cookie-value"  # extracted + forwarded

    async def test_returns_none_when_auth_raises(self, monkeypatch):
        async def _raise(request, session=None):
            raise RuntimeError("no session")

        monkeypatch.setattr(facade, "nginx_proxied_auth", _raise)

        class _Req:
            cookies = {}

        assert await facade._optional_session(_Req()) is None


@pytest.mark.unit
class TestResourceParam:
    """RFC 8707 resource-param parsing (regression: the client echoes the PRM
    `resource` field, which is the server identifier, NOT the PRM doc URL)."""

    def test_parses_canonical_resource_identifier(self, monkeypatch):
        monkeypatch.setattr(facade.settings, "registry_url", REGISTRY_URL)
        assert facade._server_path_from_resource(f"{REGISTRY_URL}/github") == "/github"

    def test_parses_prm_document_url_form(self, monkeypatch):
        monkeypatch.setattr(facade.settings, "registry_url", REGISTRY_URL)
        url = f"{REGISTRY_URL}/.well-known/oauth-protected-resource/github"
        assert facade._server_path_from_resource(url) == "/github"

    def test_bare_path_accepted(self, monkeypatch):
        monkeypatch.setattr(facade.settings, "registry_url", REGISTRY_URL)
        assert facade._server_path_from_resource("/github") == "/github"

    def test_unrelated_resource_rejected(self, monkeypatch):
        monkeypatch.setattr(facade.settings, "registry_url", REGISTRY_URL)
        assert facade._server_path_from_resource("https://evil.com/github") == ""

    def test_empty_resource(self, monkeypatch):
        monkeypatch.setattr(facade.settings, "registry_url", REGISTRY_URL)
        assert facade._server_path_from_resource("") == ""


@pytest.mark.unit
class TestDiscoveryEndpoints:
    def test_prm_endpoint(self, client):
        c = client(server=_server())
        r = c.get("/.well-known/oauth-protected-resource/github")
        assert r.status_code == 200
        body = r.json()
        # `resource` is the MCP server URL the client accesses, NOT the PRM doc URL.
        assert body["resource"] == f"{REGISTRY_URL}/github"
        assert body["authorization_servers"] == [f"{REGISTRY_URL}/oauth2/egress"]
        assert body["scopes_supported"] == ["repo"]

    def test_as_metadata_endpoint(self, client):
        c = client()
        r = c.get("/.well-known/oauth-authorization-server/oauth2/egress")
        assert r.status_code == 200
        assert r.json()["token_endpoint"] == f"{REGISTRY_URL}/oauth2/egress/token"

    def test_discovery_404_when_disabled(self, client):
        c = client(enabled=False)
        assert c.get("/.well-known/oauth-authorization-server/oauth2/egress").status_code == 404


@pytest.mark.unit
class TestRegister:
    def test_register_loopback_ok(self, client):
        c = client()
        r = c.post("/oauth2/egress/register", json={"redirect_uris": ["http://127.0.0.1:5000/cb"]})
        assert r.status_code == 201
        assert r.json()["client_id"].startswith("egress-")

    def test_register_non_loopback_400(self, client):
        c = client()
        r = c.post("/oauth2/egress/register", json={"redirect_uris": ["https://evil.com/cb"]})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_redirect_uri"


def _authorize_params(challenge: str, **over) -> dict:
    p = {
        "response_type": "code",
        "client_id": "egress-abc",
        "redirect_uri": "http://127.0.0.1:5000/cb",
        "state": "cli-state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": f"{REGISTRY_URL}/.well-known/oauth-protected-resource/github",
    }
    p.update(over)
    return p


@pytest.mark.unit
class TestAuthorize:
    def test_authorize_redirects_to_provider(self, client):
        c = client(server=_server())
        challenge = pkce_challenge_s256(generate_pkce_verifier())
        r = c.get("/oauth2/egress/authorize", params=_authorize_params(challenge))
        assert r.status_code == 302
        assert r.headers["location"].startswith("https://github.com/login/oauth/authorize")
        # the facade threaded a facade-marked session_id into the provider leg
        assert c._svc.last_session_id.startswith(facade._FACADE_SESSION_PREFIX)
        # and persisted the pending record under the correlation id
        corr = c._svc.last_session_id[len(facade._FACADE_SESSION_PREFIX) :]
        assert corr in c._repo.pending

    def test_authorize_no_session_bounces_to_keycloak_login(self, client):
        c = client(user_context=None, server=_server())
        challenge = pkce_challenge_s256(generate_pkce_verifier())
        r = c.get("/oauth2/egress/authorize", params=_authorize_params(challenge))
        assert r.status_code == 302
        loc = r.headers["location"]
        assert loc.startswith(f"{REGISTRY_URL}/oauth2/login/keycloak")
        # returns to /authorize with its params preserved (urlencoded)
        assert "oauth2%2Fegress%2Fauthorize" in loc
        # no pending stored when we bounce to login
        assert c._repo.pending == {}

    def test_authorize_non_loopback_redirect_400(self, client):
        c = client(server=_server())
        challenge = pkce_challenge_s256(generate_pkce_verifier())
        r = c.get(
            "/oauth2/egress/authorize",
            params=_authorize_params(challenge, redirect_uri="https://evil.com/cb"),
        )
        assert r.status_code == 400

    def test_authorize_requires_s256(self, client):
        c = client(server=_server())
        r = c.get(
            "/oauth2/egress/authorize",
            params=_authorize_params("", code_challenge_method="plain"),
        )
        assert r.status_code == 302
        assert "error=invalid_request" in r.headers["location"]

    def test_authorize_non_per_user_denied(self, client):
        c = client(user_context=STATIC, server=_server())
        challenge = pkce_challenge_s256(generate_pkce_verifier())
        r = c.get("/oauth2/egress/authorize", params=_authorize_params(challenge))
        assert r.status_code == 302
        assert "error=access_denied" in r.headers["location"]

    def test_authorize_unconfigured_server_errors(self, client):
        c = client(server=_server(egress_auth_mode="none", egress_oauth=None))
        challenge = pkce_challenge_s256(generate_pkce_verifier())
        r = c.get("/oauth2/egress/authorize", params=_authorize_params(challenge))
        assert r.status_code == 302
        assert "error=invalid_request" in r.headers["location"]


@pytest.mark.unit
class TestTokenAndResume:
    async def test_full_authorize_resume_token_flow(self, client, monkeypatch):
        # 1) authorize -> persists pending under correlation id
        c = client(server=_server())
        verifier = generate_pkce_verifier()
        challenge = pkce_challenge_s256(verifier)
        c.get("/oauth2/egress/authorize", params=_authorize_params(challenge))
        session_id = c._svc.last_session_id
        assert facade.is_facade_session(session_id)

        # 2) provider callback completes -> resume issues client code+redirect
        redirect = await facade.issue_facade_code_redirect(
            state_session_id=session_id,
            callback_user_id="alice",
            callback_auth_method="oauth2",
        )
        assert redirect is not None
        loc = redirect.headers["location"]
        assert loc.startswith("http://127.0.0.1:5000/cb")
        assert "state=cli-state" in loc
        code = loc.split("code=")[1].split("&")[0]
        assert code in c._repo.codes  # persisted in the repo

        # 3) token: redeem code (PKCE) -> mint delegated to auth-server (mocked)
        async def _fake_mint(identity):
            assert identity.user_id == "alice"
            assert identity.scopes == ["openid", "email"]
            return "minted.jwt.token", 28800

        monkeypatch.setattr(facade, "_mint_user_token", _fake_mint)
        r = c.post(
            "/oauth2/egress/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1:5000/cb",
                "code_verifier": verifier,
                "client_id": "egress-abc",
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["access_token"] == "minted.jwt.token"
        assert body["expires_in"] == 28800
        assert code not in c._repo.codes  # single-use consumed

    def test_token_bad_code_invalid_grant(self, client):
        c = client(server=_server())
        r = c.post(
            "/oauth2/egress/token",
            data={
                "grant_type": "authorization_code",
                "code": "nope",
                "redirect_uri": "http://127.0.0.1:5000/cb",
                "code_verifier": "v",
            },
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_token_unsupported_grant(self, client):
        c = client(server=_server())
        r = c.post("/oauth2/egress/token", data={"grant_type": "password"})
        assert r.status_code == 400
        assert r.json()["error"] == "unsupported_grant_type"

    async def test_token_wrong_pkce_rejected(self, client, monkeypatch):
        # full happy authorize+resume, then redeem with the WRONG verifier
        c = client(server=_server())
        verifier = generate_pkce_verifier()
        c.get("/oauth2/egress/authorize", params=_authorize_params(pkce_challenge_s256(verifier)))
        redirect = await facade.issue_facade_code_redirect(
            state_session_id=c._svc.last_session_id
        )
        code = redirect.headers["location"].split("code=")[1].split("&")[0]
        r = c.post(
            "/oauth2/egress/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://127.0.0.1:5000/cb",
                "code_verifier": generate_pkce_verifier(),  # wrong
            },
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    async def test_resume_account_swap_refused(self, client):
        # identity captured as alice; a callback observing bob must NOT resume.
        c = client(server=_server())
        verifier = generate_pkce_verifier()
        c.get("/oauth2/egress/authorize", params=_authorize_params(pkce_challenge_s256(verifier)))
        redirect = await facade.issue_facade_code_redirect(
            state_session_id=c._svc.last_session_id,
            callback_user_id="bob",
            callback_auth_method="oauth2",
        )
        assert redirect is None

    async def test_resume_unknown_correlation_returns_none(self, client):
        client(server=_server())
        assert (
            await facade.issue_facade_code_redirect(
                state_session_id=facade._FACADE_SESSION_PREFIX + "unknown"
            )
            is None
        )

    async def test_resume_retries_on_duplicate_code(self, client, monkeypatch):
        # An astronomically-rare auth-code collision must retry with a fresh code,
        # never 500 the callback (kiro cold-review nit).
        from pymongo.errors import DuplicateKeyError

        c = client(server=_server())
        verifier = generate_pkce_verifier()
        c.get("/oauth2/egress/authorize", params=_authorize_params(pkce_challenge_s256(verifier)))

        calls = {"n": 0}
        real_store = c._repo.store_code

        async def _flaky_store(code, payload, ttl):
            calls["n"] += 1
            if calls["n"] == 1:
                raise DuplicateKeyError("dup")  # first code collides
            await real_store(code, payload, ttl)

        monkeypatch.setattr(c._repo, "store_code", _flaky_store)
        redirect = await facade.issue_facade_code_redirect(
            state_session_id=c._svc.last_session_id
        )
        assert redirect is not None
        assert calls["n"] == 2  # retried once
        code = redirect.headers["location"].split("code=")[1].split("&")[0]
        assert code in c._repo.codes
