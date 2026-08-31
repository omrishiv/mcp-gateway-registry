"""#993 consumer: the registry advertises CIMD support in its RFC 8414
authorization-server metadata so MCP clients present a CIMD-URL client_id to the
upstream IdP. The registry is NOT the authorization server and does NOT fetch or
validate the CIMD document itself -- the IdP does. In-process, no network."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from registry.api.wellknown_routes import router as wellknown_router

pytestmark = [pytest.mark.integration]

AS_PATH = "/.well-known/oauth-authorization-server"


class _StubProvider:
    """Stands in for the configured IdP provider; returns a minimal RFC 8414 doc
    whose endpoints point at the IdP (the passthrough the registry advertises)."""

    def authorization_server_metadata(self) -> dict:
        return {
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
        }


def _app(monkeypatch, *, cimd_consumer_enabled: bool) -> FastAPI:
    from registry.api import wellknown_routes as wkr

    class _Settings:
        pass

    stub_settings = _Settings()
    stub_settings.cimd_consumer_enabled = cimd_consumer_enabled
    monkeypatch.setattr(wkr, "settings", stub_settings)
    monkeypatch.setattr(wkr, "_get_active_auth_provider", lambda: _StubProvider())

    app = FastAPI()
    app.include_router(wellknown_router, prefix="/.well-known")
    return app


def test_cimd_support_advertised_when_enabled(monkeypatch):
    """With the consumer flag on, the AS metadata carries
    client_id_metadata_document_supported=true, and the IdP passthrough is intact."""
    client = TestClient(_app(monkeypatch, cimd_consumer_enabled=True))

    doc = client.get(AS_PATH).json()

    assert doc["client_id_metadata_document_supported"] is True
    # The registry only ADDS the flag; the IdP's endpoints pass through unchanged
    # (the registry is not the AS and stays out of the token path).
    assert doc["issuer"] == "https://idp.example.com"
    assert doc["token_endpoint"] == "https://idp.example.com/token"


def test_cimd_support_absent_when_disabled(monkeypatch):
    """Default off: the flag must not appear, so clients don't attempt CIMD
    against an IdP that hasn't been confirmed to support it."""
    client = TestClient(_app(monkeypatch, cimd_consumer_enabled=False))

    doc = client.get(AS_PATH).json()

    assert "client_id_metadata_document_supported" not in doc
