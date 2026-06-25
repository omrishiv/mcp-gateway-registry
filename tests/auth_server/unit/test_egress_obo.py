"""Unit tests for the OBO hop-1 token-exchange engine (auth_server/egress_obo.py).

Covers:
- Entra jwt-bearer request body shape (grant_type, assertion, scope, on_behalf_of).
- .default scope synthesis vs explicit scopes.
- IdP error-code -> typed exception mapping.
- Keycloak path raises (Phase 4 stub).
- No caching: two calls hit the token endpoint twice.
- Missing gateway credentials -> config error.
"""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from auth_server import egress_obo
from auth_server.egress_obo import (
    OboConfigError,
    OboConsentRequired,
    OboReauthRequired,
    OboUnsupportedIdpError,
    obo_exchange,
)


class _FakeEntraProvider:
    """Minimal stand-in for EntraIdProvider (class name carries the 'entra' kind)."""

    def __init__(self):
        self.client_id = "gw-client"
        self.client_secret = "gw-secret"
        self.token_url = "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"


class _FakeKeycloakProvider:
    def __init__(self):
        self.client_id = "gw-client"
        self.client_secret = "gw-secret"
        self.token_url = "https://kc.example/realms/r/protocol/openid-connect/token"


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self):
        return self._payload


def _patch_post(monkeypatch, response, capture: dict):
    """Patch httpx.AsyncClient so .post records its args and returns `response`.

    `capture` is filled with {"url":..., "data":..., "calls": n}.
    """
    capture["calls"] = 0

    async def _post(url, data=None, **kwargs):
        capture["calls"] += 1
        capture["url"] = url
        capture["data"] = data
        return response

    @asynccontextmanager
    async def _fake_client(*args, **kwargs):
        client = MagicMock()
        client.post = AsyncMock(side_effect=_post)
        yield client

    monkeypatch.setattr(egress_obo.httpx, "AsyncClient", _fake_client)


@pytest.mark.unit
class TestEntraExchangeBody:
    @pytest.mark.asyncio
    async def test_jwt_bearer_body_shape(self, monkeypatch):
        cap: dict = {}
        _patch_post(monkeypatch, _FakeResponse(200, {"access_token": "obo-tok"}), cap)

        token = await obo_exchange(
            _FakeEntraProvider(),
            subject_token="ingress-jwt",
            target_audience="api://outlook-mcp-server",
            scopes=[],
        )

        assert token == "obo-tok"
        body = cap["data"]
        assert body["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
        assert body["assertion"] == "ingress-jwt"
        assert body["client_id"] == "gw-client"
        assert body["client_secret"] == "gw-secret"
        assert body["requested_token_use"] == "on_behalf_of"
        # No explicit scopes -> synthesize <target>/.default
        assert body["scope"] == "api://outlook-mcp-server/.default"

    @pytest.mark.asyncio
    async def test_explicit_scopes_passed_verbatim(self, monkeypatch):
        cap: dict = {}
        _patch_post(monkeypatch, _FakeResponse(200, {"access_token": "t"}), cap)

        await obo_exchange(
            _FakeEntraProvider(),
            subject_token="j",
            target_audience="api://srv",
            scopes=["api://srv/Mail.Read", "api://srv/Files.Read"],
        )
        assert cap["data"]["scope"] == "api://srv/Mail.Read api://srv/Files.Read"

    @pytest.mark.asyncio
    async def test_no_cache_two_calls_hit_endpoint_twice(self, monkeypatch):
        cap: dict = {}
        _patch_post(monkeypatch, _FakeResponse(200, {"access_token": "t"}), cap)
        p = _FakeEntraProvider()
        await obo_exchange(p, subject_token="j", target_audience="api://srv")
        await obo_exchange(p, subject_token="j", target_audience="api://srv")
        assert cap["calls"] == 2


@pytest.mark.unit
class TestErrorMapping:
    @pytest.mark.asyncio
    async def test_invalid_grant_maps_to_reauth(self, monkeypatch):
        cap: dict = {}
        _patch_post(
            monkeypatch,
            _FakeResponse(400, {"error": "invalid_grant", "error_description": "expired"}),
            cap,
        )
        with pytest.raises(OboReauthRequired, match="expired"):
            await obo_exchange(_FakeEntraProvider(), subject_token="j", target_audience="api://srv")

    @pytest.mark.asyncio
    async def test_interaction_required_maps_to_consent(self, monkeypatch):
        cap: dict = {}
        _patch_post(
            monkeypatch,
            _FakeResponse(400, {"error": "interaction_required", "error_description": "consent"}),
            cap,
        )
        with pytest.raises(OboConsentRequired):
            await obo_exchange(_FakeEntraProvider(), subject_token="j", target_audience="api://srv")

    @pytest.mark.asyncio
    async def test_invalid_client_maps_to_config(self, monkeypatch):
        cap: dict = {}
        _patch_post(
            monkeypatch,
            _FakeResponse(401, {"error": "invalid_client"}),
            cap,
        )
        with pytest.raises(OboConfigError):
            await obo_exchange(_FakeEntraProvider(), subject_token="j", target_audience="api://srv")


@pytest.mark.unit
class TestUnsupportedAndConfig:
    @pytest.mark.asyncio
    async def test_keycloak_raises_not_implemented(self, monkeypatch):
        # Keycloak path is a Phase 4 stub; it must raise cleanly, not silently pass.
        with pytest.raises(OboUnsupportedIdpError, match="Keycloak"):
            await obo_exchange(
                _FakeKeycloakProvider(), subject_token="j", target_audience="srv-client"
            )

    @pytest.mark.asyncio
    async def test_unknown_provider_raises_unsupported(self, monkeypatch):
        class _Cognito:
            client_id = "x"
            client_secret = "y"
            token_url = "https://z/token"

        with pytest.raises(OboUnsupportedIdpError):
            await obo_exchange(_Cognito(), subject_token="j", target_audience="a")

    @pytest.mark.asyncio
    async def test_missing_credentials_raises_config(self, monkeypatch):
        class _NoCreds:
            client_id = ""
            client_secret = ""
            token_url = ""

        with pytest.raises(OboConfigError):
            await obo_exchange(_NoCreds(), subject_token="j", target_audience="a")
