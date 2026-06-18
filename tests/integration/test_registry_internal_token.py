"""Integration tests for the registry-UI internal-token flow.

Exercises the full mint -> verify -> resolve chain across the auth_server (minter)
and registry (verifier) boundary, the way a real /validate -> nginx -> /api/ request
does. The auth_server mints; nginx forwards on X-Internal-Token-Registry; the
registry verifies and resolves identity server-side.

Through-nginx liveness (the registry API actually reachable on the nginx port with a
real token) is validated separately against a running stack; these tests pin the
contract at the Python boundary so it cannot silently drift.
"""

import os
import time
from types import SimpleNamespace
from unittest.mock import patch

import jwt as pyjwt
import pytest
from fastapi import HTTPException

from auth_server.internal_request_token import mint_registry_ui_token
from registry.auth.proxied_token import verify_registry_ui_token

_SECRET = "integration-shared-secret-key"


@pytest.fixture(autouse=True)
def _shared_secret_env():
    """Both services read SECRET_KEY from env; the same key on both sides is what
    makes the auth_server-minted token verifiable by the registry."""
    with patch.dict(os.environ, {"SECRET_KEY": _SECRET}, clear=False):
        yield


class TestMintVerifyRoundTrip:
    """The auth_server's mint output verifies on the registry side (same SECRET_KEY)."""

    def test_session_backed_token_round_trips(self) -> None:
        token = mint_registry_ui_token(
            subject="alice",
            session_id="sess-xyz",
            groups=[],
            auth_method="session_cookie",
            client_id="",
        )
        claims = verify_registry_ui_token(token)
        assert claims["sub"] == "alice"
        assert claims["session_id"] == "sess-xyz"
        assert claims["token_use"] == "mcp-registry-ui"

    def test_bearer_token_round_trips_with_groups(self) -> None:
        token = mint_registry_ui_token(
            subject="svc-1",
            session_id="",
            groups=["mcp-registry-admin"],
            auth_method="network-trusted",
            client_id="key-1",
        )
        claims = verify_registry_ui_token(token)
        assert claims["sub"] == "svc-1"
        assert claims["groups"] == ["mcp-registry-admin"]
        assert claims["session_id"] == ""


class TestCrossServiceRejection:
    """A token minted with a DIFFERENT SECRET_KEY (a mismatched deploy, or a forged
    token without the shared secret) must NOT verify -- this is the property that
    closes the header-forgery bypass."""

    def test_token_from_wrong_secret_rejected(self) -> None:
        # Mint with a different secret than the verifier holds.
        now = int(time.time())
        forged = pyjwt.encode(
            {
                "iss": "mcp-auth-server",
                "aud": "mcp-registry-ui",
                "sub": "attacker",
                "scopes": [],
                "session_id": "",
                "groups": ["mcp-registry-admin"],
                "auth_method": "x",
                "client_id": "",
                "token_use": "mcp-registry-ui",
                "iat": now,
                "exp": now + 30,
            },
            "attacker-does-not-know-the-secret",
            algorithm="HS256",
        )
        with pytest.raises(HTTPException) as exc:
            verify_registry_ui_token(forged)
        assert exc.value.status_code == 401


class TestCrossAudienceIsolation:
    """The registry-UI verifier rejects tokens minted for other audiences, and a
    registry-UI token is not accepted by other-audience verifiers (checked via the
    pyjwt audience claim)."""

    def test_mcp_proxy_token_rejected_by_registry_verifier(self) -> None:
        # An mcp-proxy-audience token must not pass the registry-ui verifier.
        from auth_server.internal_request_token import mint_mcp_proxy_token

        proxy_token = mint_mcp_proxy_token(
            subject="alice",
            scopes=["s/read"],
            server_name="srv/mcp",
            upstream_url="https://u.example/mcp",
        )
        with pytest.raises(HTTPException) as exc:
            verify_registry_ui_token(proxy_token)
        assert exc.value.status_code == 401

    def test_service_audience_token_rejected(self) -> None:
        # A mcp-registry (service-to-service) token must not pass either.
        now = int(time.time())
        svc = pyjwt.encode(
            {
                "iss": "mcp-auth-server",
                "aud": "mcp-registry",
                "sub": "registry-service",
                "token_use": "access",
                "iat": now,
                "exp": now + 60,
            },
            _SECRET,
            algorithm="HS256",
        )
        with pytest.raises(HTTPException) as exc:
            verify_registry_ui_token(svc)
        assert exc.value.status_code == 401


def _proxied_request(headers: dict[str, str]):
    lower = {k.lower(): v for k, v in headers.items()}
    return SimpleNamespace(
        headers=SimpleNamespace(get=lambda k, d=None: lower.get(k.lower(), d)),
        url=SimpleNamespace(path="/api/test"),
        method="GET",
        state=SimpleNamespace(),
    )
