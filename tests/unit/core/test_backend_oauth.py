"""Backend OAuth (client_credentials) token cache tests.

Covers the registry-self backend-auth resolver: caching per server path,
config-fingerprint invalidation, single-flight acquisition, and fail-open-to-None
behavior on misconfig / token-endpoint failure.
"""

import pytest

from registry.core import backend_oauth
from registry.egress_auth import oauth_engine
from registry.egress_auth.schemas import StoredToken


def _server_info(**overrides) -> dict:
    bo = {
        "token_url": "https://idp.example/token",
        "client_id": "cid",
        "client_secret_encrypted": "enc-secret",
        "scopes": ["api:read"],
        "token_auth_style": "post_body",
    }
    bo.update(overrides.pop("backend_oauth", {}))
    si = {"auth_scheme": "oauth", "service_path": "/example", "backend_oauth": bo}
    si.update(overrides)
    return si


@pytest.fixture(autouse=True)
def _clear_cache():
    backend_oauth._cache.clear()
    backend_oauth._locks.clear()
    yield
    backend_oauth._cache.clear()
    backend_oauth._locks.clear()


@pytest.fixture(autouse=True)
def _stub_decrypt(monkeypatch):
    # The resolver decrypts client_secret_encrypted; stub it to a known plaintext.
    monkeypatch.setattr(backend_oauth, "decrypt_credential", lambda c: "plain-secret")


def _token(access="tok", expires_at=None) -> StoredToken:
    return StoredToken(
        access_token=access,
        token_type="Bearer",
        expires_at=expires_at,
        scopes=[],
        status="active",
        client_id="cid",
    )


@pytest.mark.unit
class TestResolveBearer:
    async def test_non_oauth_scheme_returns_none_without_calling_engine(self, monkeypatch):
        called = False

        async def fake_grant(*a, **k):
            nonlocal called
            called = True
            return _token()

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        assert await backend_oauth.resolve_bearer({"auth_scheme": "bearer"}) is None
        assert called is False

    async def test_missing_config_returns_none(self, monkeypatch):
        monkeypatch.setattr(oauth_engine, "client_credentials_token", lambda *a, **k: _token())
        si = _server_info(backend_oauth={"token_url": "", "client_id": ""})
        assert await backend_oauth.resolve_bearer(si) is None

    async def test_acquires_and_returns_token(self, monkeypatch):
        async def fake_grant(cfg, client_id, secret, scopes):
            assert client_id == "cid"
            assert secret == "plain-secret"
            assert scopes == ["api:read"]
            return _token(access="fresh")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        assert await backend_oauth.resolve_bearer(_server_info()) == "fresh"

    async def test_second_call_uses_cache(self, monkeypatch):
        calls = {"n": 0}

        async def fake_grant(*a, **k):
            calls["n"] += 1
            # No expiry hint -> default short TTL, but well within it for two calls.
            return _token(access=f"t{calls['n']}")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        first = await backend_oauth.resolve_bearer(_server_info())
        second = await backend_oauth.resolve_bearer(_server_info())
        assert first == second == "t1"
        assert calls["n"] == 1

    async def test_config_change_invalidates_cache(self, monkeypatch):
        calls = {"n": 0}

        async def fake_grant(*a, **k):
            calls["n"] += 1
            return _token(access=f"t{calls['n']}")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        await backend_oauth.resolve_bearer(_server_info())
        # Different client_id -> different fingerprint -> re-acquire.
        changed = await backend_oauth.resolve_bearer(
            _server_info(backend_oauth={"client_id": "cid2"})
        )
        assert changed == "t2"
        assert calls["n"] == 2

    async def test_engine_failure_returns_none(self, monkeypatch):
        async def fake_grant(*a, **k):
            raise oauth_engine.OAuthEngineError("token endpoint unreachable")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        assert await backend_oauth.resolve_bearer(_server_info()) is None

    async def test_invalidate_forces_reacquire(self, monkeypatch):
        calls = {"n": 0}

        async def fake_grant(*a, **k):
            calls["n"] += 1
            return _token(access=f"t{calls['n']}")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        await backend_oauth.resolve_bearer(_server_info())
        backend_oauth.invalidate("/example")
        await backend_oauth.resolve_bearer(_server_info())
        assert calls["n"] == 2


@pytest.mark.unit
class TestWithBearer:
    async def test_stashes_token_under_key(self, monkeypatch):
        monkeypatch.setattr(
            oauth_engine, "client_credentials_token", lambda *a, **k: _token(access="X")
        )

        async def fake_grant(*a, **k):
            return _token(access="X")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        si = await backend_oauth.with_bearer(_server_info())
        assert si[backend_oauth.RESOLVED_BEARER_KEY] == "X"

    async def test_noop_for_non_oauth(self):
        si = {"auth_scheme": "bearer"}
        assert await backend_oauth.with_bearer(si) is si


def _disc_server_info(**overrides) -> dict:
    si = {
        "auth_scheme": "none",
        "service_path": "/tableau-hosted",
        "path": "/tableau-hosted",
        # Registered upstream: the discovery borrow binds the vaulted token to
        # this server's own endpoint base (destination binding).
        "proxy_pass_url": "https://tableau.example.com/mcp",
        # Self-contained backend-auth discovery config (no top-level egress_oauth).
        "oauth_discovery": {
            "enabled": True,
            "oauth": {"provider": "custom", "client_id": "https://x/.well-known/oauth-client"},
            "auth_method": "oauth2",
            "user_id": "u-1",
        },
    }
    si.update(overrides)
    return si


class _FakeEgressSvc:
    def __init__(self, token=None, raises=False):
        self._token = token
        self._raises = raises
        self.calls = []

    async def get_valid_token(
        self, *, auth_method, user_id, server_path, egress_oauth, requested_upstream
    ):
        self.calls.append((auth_method, user_id, server_path, requested_upstream))
        if self._raises:
            raise RuntimeError("vault down")
        return self._token


@pytest.mark.unit
class TestDiscoveryBorrow:
    def _patch_svc(self, monkeypatch, svc):
        import registry.egress_auth.factory as factory

        monkeypatch.setattr(factory, "get_egress_auth_service", lambda: svc)

    async def test_borrows_designated_principal_token(self, monkeypatch):
        svc = _FakeEgressSvc(token="BORROWED")
        self._patch_svc(monkeypatch, svc)
        assert await backend_oauth.resolve_discovery_bearer(_disc_server_info()) == "BORROWED"
        assert svc.calls == [("oauth2", "u-1", "/tableau-hosted", "https://tableau.example.com")]

    async def test_disabled_returns_none_without_calling(self, monkeypatch):
        svc = _FakeEgressSvc(token="X")
        self._patch_svc(monkeypatch, svc)
        si = _disc_server_info(
            oauth_discovery={"enabled": False, "auth_method": "oauth2", "user_id": "u"}
        )
        assert await backend_oauth.resolve_discovery_bearer(si) is None
        assert svc.calls == []

    async def test_missing_oauth_config_returns_none(self, monkeypatch):
        svc = _FakeEgressSvc(token="X")
        self._patch_svc(monkeypatch, svc)
        # oauth_discovery present + enabled but without its own oauth provider config.
        si = _disc_server_info(
            oauth_discovery={"enabled": True, "auth_method": "oauth2", "user_id": "u-1"}
        )
        assert await backend_oauth.resolve_discovery_bearer(si) is None
        assert svc.calls == []

    async def test_missing_principal_returns_none(self, monkeypatch):
        svc = _FakeEgressSvc(token="X")
        self._patch_svc(monkeypatch, svc)
        si = _disc_server_info(
            oauth_discovery={
                "enabled": True,
                "oauth": {"provider": "custom", "client_id": "x"},
                "auth_method": "",
                "user_id": "",
            }
        )
        assert await backend_oauth.resolve_discovery_bearer(si) is None
        assert svc.calls == []

    async def test_vault_miss_returns_none(self, monkeypatch):
        # Identity not connected / refresh dead -> get_valid_token returns None.
        self._patch_svc(monkeypatch, _FakeEgressSvc(token=None))
        assert await backend_oauth.resolve_discovery_bearer(_disc_server_info()) is None

    async def test_vault_exception_degrades_to_none(self, monkeypatch):
        self._patch_svc(monkeypatch, _FakeEgressSvc(raises=True))
        assert await backend_oauth.resolve_discovery_bearer(_disc_server_info()) is None

    async def test_with_bearer_stashes_borrowed_token(self, monkeypatch):
        self._patch_svc(monkeypatch, _FakeEgressSvc(token="BORROWED"))
        si = await backend_oauth.with_bearer(_disc_server_info())
        assert si[backend_oauth.RESOLVED_BEARER_KEY] == "BORROWED"

    async def test_client_credentials_precedence_over_discovery(self, monkeypatch):
        # auth_scheme 'oauth' resolves via client_credentials; discovery not consulted.
        disc_svc = _FakeEgressSvc(token="BORROWED")
        self._patch_svc(monkeypatch, disc_svc)

        async def fake_cc(server_info):
            return "CC-TOKEN"

        monkeypatch.setattr(backend_oauth, "resolve_bearer", fake_cc)
        si = _disc_server_info(auth_scheme="oauth")
        out = await backend_oauth.with_bearer(si)
        assert out[backend_oauth.RESOLVED_BEARER_KEY] == "CC-TOKEN"
        assert disc_svc.calls == []


def _obo_server_info(**overrides) -> dict:
    si = {
        "auth_scheme": "none",
        "service_path": "/obo-echo",
        "path": "/obo-echo",
        "egress_auth_mode": "obo_exchange",
        "egress_oauth": {"target_audience": "api://internal-mcp", "scopes": []},
    }
    si.update(overrides)
    return si


@pytest.fixture
def _entra_gateway(monkeypatch):
    """Configure the gateway's own Entra IdP client + egress feature on."""
    for attr, val in (
        ("egress_auth_enabled", True),
        ("auth_provider", "entra"),
        ("entra_client_id", "gw-client"),
        ("entra_client_secret", "gw-secret"),
        ("entra_tenant_id", "tenant-1"),
        ("entra_login_base_url", "https://login.microsoftonline.com"),
        # No operator allowlist -> shape heuristic accepts api:// targets.
        ("egress_obo_allowed_audiences", ""),
    ):
        monkeypatch.setattr(backend_oauth.settings, attr, val, raising=False)


@pytest.mark.unit
class TestResolveOboDiscoveryBearer:
    async def test_mints_cc_token_audienced_to_target(self, monkeypatch, _entra_gateway):
        captured = {}

        async def fake_grant(cfg, client_id, secret, scopes):
            captured["token_url"] = cfg.token_url
            captured["client_id"] = client_id
            captured["secret"] = secret
            captured["scopes"] = scopes
            return _token(access="OBO-DISC")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        assert await backend_oauth.resolve_obo_discovery_bearer(_obo_server_info()) == "OBO-DISC"
        assert captured["client_id"] == "gw-client"
        assert captured["secret"] == "gw-secret"
        assert captured["scopes"] == ["api://internal-mcp/.default"]
        assert (
            captured["token_url"] == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
        )

    async def test_egress_disabled_returns_none(self, monkeypatch, _entra_gateway):
        monkeypatch.setattr(backend_oauth.settings, "egress_auth_enabled", False, raising=False)
        called = False

        async def fake_grant(*a, **k):
            nonlocal called
            called = True
            return _token()

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        assert await backend_oauth.resolve_obo_discovery_bearer(_obo_server_info()) is None
        assert called is False

    async def test_non_obo_mode_returns_none(self, monkeypatch, _entra_gateway):
        called = False

        async def fake_grant(*a, **k):
            nonlocal called
            called = True
            return _token()

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        si = _obo_server_info(egress_auth_mode="oauth_user")
        assert await backend_oauth.resolve_obo_discovery_bearer(si) is None
        assert called is False

    async def test_missing_target_returns_none(self, monkeypatch, _entra_gateway):
        monkeypatch.setattr(oauth_engine, "client_credentials_token", lambda *a, **k: _token())
        si = _obo_server_info(egress_oauth={"target_audience": "", "scopes": []})
        assert await backend_oauth.resolve_obo_discovery_bearer(si) is None

    async def test_disallowed_first_party_target_returns_none(self, monkeypatch, _entra_gateway):
        called = False

        async def fake_grant(*a, **k):
            nonlocal called
            called = True
            return _token()

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        # A shared first-party resource URL is rejected by the audience control.
        si = _obo_server_info(
            egress_oauth={"target_audience": "https://graph.microsoft.com", "scopes": []}
        )
        assert await backend_oauth.resolve_obo_discovery_bearer(si) is None
        assert called is False

    async def test_gateway_client_unconfigured_returns_none(self, monkeypatch, _entra_gateway):
        monkeypatch.setattr(backend_oauth.settings, "entra_client_secret", "", raising=False)
        called = False

        async def fake_grant(*a, **k):
            nonlocal called
            called = True
            return _token()

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        assert await backend_oauth.resolve_obo_discovery_bearer(_obo_server_info()) is None
        assert called is False

    async def test_second_call_uses_cache(self, monkeypatch, _entra_gateway):
        calls = {"n": 0}

        async def fake_grant(*a, **k):
            calls["n"] += 1
            return _token(access=f"t{calls['n']}")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        first = await backend_oauth.resolve_obo_discovery_bearer(_obo_server_info())
        second = await backend_oauth.resolve_obo_discovery_bearer(_obo_server_info())
        assert first == second == "t1"
        assert calls["n"] == 1

    async def test_target_change_reacquires(self, monkeypatch, _entra_gateway):
        calls = {"n": 0}

        async def fake_grant(*a, **k):
            calls["n"] += 1
            return _token(access=f"t{calls['n']}")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        await backend_oauth.resolve_obo_discovery_bearer(_obo_server_info())
        changed = await backend_oauth.resolve_obo_discovery_bearer(
            _obo_server_info(egress_oauth={"target_audience": "api://other-mcp", "scopes": []})
        )
        assert changed == "t2"
        assert calls["n"] == 2

    async def test_engine_failure_returns_none(self, monkeypatch, _entra_gateway):
        async def fake_grant(*a, **k):
            raise oauth_engine.OAuthEngineError("token endpoint unreachable")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        assert await backend_oauth.resolve_obo_discovery_bearer(_obo_server_info()) is None

    async def test_keycloak_sends_no_default_scope(self, monkeypatch, _entra_gateway):
        # Keycloak binds audience via a server-side mapper (follow-on): no .default
        # scope is sent, and the token endpoint is the realm token URL.
        for attr, val in (
            ("auth_provider", "keycloak"),
            ("keycloak_url", "https://kc.example.com"),
            ("keycloak_realm", "mcp-gateway"),
            ("keycloak_client_id", "kc-client"),
            ("keycloak_client_secret", "kc-secret"),
        ):
            monkeypatch.setattr(backend_oauth.settings, attr, val, raising=False)
        captured = {}

        async def fake_grant(cfg, client_id, secret, scopes):
            captured["token_url"] = cfg.token_url
            captured["scopes"] = scopes
            return _token(access="KC")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        assert await backend_oauth.resolve_obo_discovery_bearer(_obo_server_info()) == "KC"
        assert captured["scopes"] == []
        assert (
            captured["token_url"]
            == "https://kc.example.com/realms/mcp-gateway/protocol/openid-connect/token"
        )

    async def test_with_bearer_uses_obo_discovery_for_obo_server(self, monkeypatch, _entra_gateway):
        # Pure obo server: no auth_scheme=oauth, no oauth_discovery -> falls through
        # to the machine client_credentials path.
        async def fake_grant(*a, **k):
            return _token(access="OBO-DISC")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        si = await backend_oauth.with_bearer(_obo_server_info())
        assert si[backend_oauth.RESOLVED_BEARER_KEY] == "OBO-DISC"

    async def test_discovery_borrow_precedence_over_obo(self, monkeypatch, _entra_gateway):
        # A server configured with BOTH a connected discovery identity and
        # obo_exchange resolves via the borrowed vault token; the machine CC path
        # is not consulted.
        import registry.egress_auth.factory as factory

        monkeypatch.setattr(
            factory, "get_egress_auth_service", lambda: _FakeEgressSvc(token="BORROWED")
        )

        async def fail_grant(*a, **k):
            raise AssertionError("obo discovery CC must not run when the borrow succeeds")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fail_grant)
        si = _obo_server_info(
            proxy_pass_url="https://internal.example.com/mcp",
            oauth_discovery={
                "enabled": True,
                "oauth": {"provider": "custom", "client_id": "x"},
                "auth_method": "oauth2",
                "user_id": "u-1",
            },
        )
        out = await backend_oauth.with_bearer(si)
        assert out[backend_oauth.RESOLVED_BEARER_KEY] == "BORROWED"

    async def test_explicit_auth_scheme_bows_out(self, monkeypatch, _entra_gateway):
        # An operator-configured backend discovery credential (e.g. a bearer scan
        # token) must win; the derived machine token is only a fallback.
        called = False

        async def fake_grant(*a, **k):
            nonlocal called
            called = True
            return _token()

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fake_grant)
        si = _obo_server_info(auth_scheme="bearer")
        assert await backend_oauth.resolve_obo_discovery_bearer(si) is None
        assert called is False

    async def test_with_bearer_does_not_shadow_static_scheme(self, monkeypatch, _entra_gateway):
        # obo server + a static bearer: with_bearer must NOT stash a resolved
        # bearer, so the sync header builder uses the operator's static credential.
        async def fail_grant(*a, **k):
            raise AssertionError("obo discovery CC must not run when a scheme is set")

        monkeypatch.setattr(oauth_engine, "client_credentials_token", fail_grant)
        si = _obo_server_info(auth_scheme="bearer", auth_credential_encrypted="enc")
        out = await backend_oauth.with_bearer(si)
        assert backend_oauth.RESOLVED_BEARER_KEY not in out
