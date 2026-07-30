"""Tests for cross-gateway token security boundaries.

These tests validate the INTENT of the cross-gateway routing security model:
- Credential isolation between gateway paths (a token for one path cannot
  authorize a different path)
- Fail-closed behavior when the system is in an invalid state
- The actual system boundaries (FastAPI dependencies) reject invalid tokens,
  not just that the JWT library does

Tests are written from the perspective of an attacker or misconfiguration,
not from the perspective of "does the function produce correct output."
"""

import os
import time
from unittest.mock import MagicMock

import jwt as pyjwt
import pytest
from fastapi import HTTPException

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests-32chars!")

from auth_server.internal_request_token import (
    CROSS_GATEWAY_AUDIENCE,
    CROSS_GATEWAY_TOKEN_USE,
    mint_cross_gateway_token,
    mint_mcp_proxy_token,
    mint_registry_ui_token,
    verify_cross_gateway_token,
    verify_mcp_proxy_token,
)


def _build_request(token: str | None = None, path_params: dict | None = None):
    """Build a mock FastAPI Request with an internal token header."""
    request = MagicMock()
    request.headers = {"X-Internal-Token": token} if token else {}
    request.path_params = path_params or {}
    request.state = MagicMock()
    return request


class TestCrossGatewayTokenCannotAccessLocalResources:
    """An attacker who obtains a cross-gateway token (intended for routing to
    a peer) must not be able to use it to execute tools on local MCP servers
    or access the registry API."""

    @pytest.mark.asyncio
    async def test_replayed_on_mcp_proxy_path_is_rejected(self):
        """Scenario: attacker intercepts a cross-gateway token and replays it
        on the /mcp-proxy/{server} path to execute a local tool.

        Expected: the mcp-proxy verification dependency rejects it because
        the audience is wrong — the attacker cannot reach any local tool."""
        cross_gw_token = mint_cross_gateway_token(
            subject="user:attacker@evil.com",
            scopes=["mcp:execute"],
            peer_id="peer-b",
            target_path="/billing-tools",
        )
        request = _build_request(
            token=cross_gw_token,
            path_params={"server_name": "local-secret-server/mcp"},
        )

        with pytest.raises(HTTPException) as exc:
            await verify_mcp_proxy_token(request)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_mcp_proxy_token_replayed_on_cross_gateway_path_is_rejected(self):
        """Scenario: attacker obtains a local mcp-proxy token (which grants
        access to a specific local server) and replays it on the cross-gateway
        proxy path to route calls to a peer.

        Expected: the cross-gateway verification dependency rejects it because
        the audience is wrong — the attacker cannot impersonate a peer call."""
        proxy_token = mint_mcp_proxy_token(
            subject="user:legitimate@company.com",
            scopes=["mcp:execute"],
            server_name="internal-server",
            upstream_url="http://internal:8080",
        )
        request = _build_request(token=proxy_token)

        with pytest.raises(HTTPException) as exc:
            await verify_cross_gateway_token(request)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_registry_ui_token_replayed_on_cross_gateway_path_is_rejected(self):
        """Scenario: attacker obtains a registry-ui token (for /api/* access)
        and replays it on the cross-gateway proxy path.

        Expected: rejected — a registry API token cannot authorize outbound
        calls to peer gateways."""
        ui_token = mint_registry_ui_token(
            subject="user:admin@company.com",
            session_id="abc123",
            groups=["mcp-registry-admin"],
            auth_method="oidc",
            client_id="my-client",
        )
        request = _build_request(token=ui_token)

        with pytest.raises(HTTPException) as exc:
            await verify_cross_gateway_token(request)
        assert exc.value.status_code == 401


class TestCrossGatewayProxyFailsClosed:
    """When the system is in an invalid state (missing config, expired creds,
    corrupted tokens), the cross-gateway proxy must DENY rather than allow
    a potentially unauthenticated request through."""

    @pytest.mark.asyncio
    async def test_no_token_at_all_denies_request(self):
        """Scenario: nginx misconfiguration fails to forward the internal token.

        Expected: 401 — the proxy never makes an outbound call without
        verifying the caller's identity first."""
        request = _build_request(token=None)

        with pytest.raises(HTTPException) as exc:
            await verify_cross_gateway_token(request)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_token_denies_even_if_claims_look_valid(self):
        """Scenario: a token was valid 2 minutes ago but has expired. The
        claims (peer_id, target_path, subject) are all correct.

        Expected: 401 — time-based expiry is enforced regardless of claim
        correctness. A stale token from a previous request cannot be replayed."""
        secret = os.environ["SECRET_KEY"]
        stale_token = pyjwt.encode(
            {
                "iss": "mcp-auth-server",
                "aud": CROSS_GATEWAY_AUDIENCE,
                "sub": "user:legitimate@company.com",
                "peer_id": "registry-b",
                "target_path": "/billing-tools",
                "token_use": CROSS_GATEWAY_TOKEN_USE,
                "scopes": ["mcp:read"],
                "iat": int(time.time()) - 120,
                "exp": int(time.time()) - 60,  # expired 60s ago
            },
            secret,
            algorithm="HS256",
        )
        request = _build_request(token=stale_token)

        with pytest.raises(HTTPException) as exc:
            await verify_cross_gateway_token(request)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_token_signed_with_wrong_key_denies(self):
        """Scenario: an attacker mints a token with their own key, setting
        all the right claims (peer_id, target_path, audience, token_use).

        Expected: 401 — signature verification fails. The attacker cannot
        forge tokens without the SECRET_KEY."""
        forged_token = pyjwt.encode(
            {
                "iss": "mcp-auth-server",
                "aud": CROSS_GATEWAY_AUDIENCE,
                "sub": "user:attacker@evil.com",
                "peer_id": "registry-b",
                "target_path": "/billing-tools",
                "token_use": CROSS_GATEWAY_TOKEN_USE,
                "scopes": ["mcp:admin"],
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
            },
            "attacker-controlled-secret-key-not-the-real-one",
            algorithm="HS256",
        )
        request = _build_request(token=forged_token)

        with pytest.raises(HTTPException) as exc:
            await verify_cross_gateway_token(request)
        assert exc.value.status_code == 401


class TestCrossGatewayTokenBindsPeerAndTarget:
    """The cross-gateway token binds the request to a specific peer and target
    at mint time. This prevents a token intended for one peer/resource from
    being used to reach a different peer/resource."""

    @pytest.mark.asyncio
    async def test_token_missing_peer_binding_is_rejected(self):
        """Scenario: a bug in /validate mints a token without peer_id.

        Expected: the verify dependency rejects it — an unbound token could
        be used to call any peer, which violates least-privilege."""
        secret = os.environ["SECRET_KEY"]
        unbound_token = pyjwt.encode(
            {
                "iss": "mcp-auth-server",
                "aud": CROSS_GATEWAY_AUDIENCE,
                "sub": "user:test",
                "target_path": "/billing-tools",
                "token_use": CROSS_GATEWAY_TOKEN_USE,
                "iat": int(time.time()),
                "exp": int(time.time()) + 30,
                # peer_id deliberately omitted
            },
            secret,
            algorithm="HS256",
        )
        request = _build_request(token=unbound_token)

        with pytest.raises(HTTPException) as exc:
            await verify_cross_gateway_token(request)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_token_missing_target_binding_is_rejected(self):
        """Scenario: a bug in /validate mints a token without target_path.

        Expected: rejected — an unbound token could be used to access any
        resource on the peer, which violates least-privilege."""
        secret = os.environ["SECRET_KEY"]
        unbound_token = pyjwt.encode(
            {
                "iss": "mcp-auth-server",
                "aud": CROSS_GATEWAY_AUDIENCE,
                "sub": "user:test",
                "peer_id": "registry-b",
                "token_use": CROSS_GATEWAY_TOKEN_USE,
                "iat": int(time.time()),
                "exp": int(time.time()) + 30,
                # target_path deliberately omitted
            },
            secret,
            algorithm="HS256",
        )
        request = _build_request(token=unbound_token)

        with pytest.raises(HTTPException) as exc:
            await verify_cross_gateway_token(request)
        assert exc.value.status_code == 401

    def test_minting_rejects_empty_peer_id(self):
        """Scenario: a code path tries to mint a token for cross-gateway
        routing but doesn't know which peer to target.

        Expected: ValueError at mint time — we never produce a token that
        could route to an undefined destination."""
        with pytest.raises(ValueError):
            mint_cross_gateway_token(
                subject="user:test",
                scopes=[],
                peer_id="",
                target_path="/target",
            )

    def test_minting_rejects_empty_target_path(self):
        """Scenario: a code path tries to mint a token for cross-gateway
        routing but doesn't know what resource to access.

        Expected: ValueError at mint time — we never produce a token that
        grants access to "everything on the peer"."""
        with pytest.raises(ValueError):
            mint_cross_gateway_token(
                subject="user:test",
                scopes=[],
                peer_id="peer-b",
                target_path="",
            )

    def test_minting_rejects_anonymous_caller(self):
        """Scenario: /validate somehow reaches the minting code without
        establishing the caller's identity.

        Expected: ValueError — we never produce a token that makes an
        anonymous outbound call to a peer (unattributable action)."""
        with pytest.raises(ValueError):
            mint_cross_gateway_token(
                subject="",
                scopes=[],
                peer_id="peer-b",
                target_path="/target",
            )


class TestValidTokenProducesCorrectClaims:
    """When everything is correct, the verified claims must carry enough
    context for the proxy endpoint to make authorization decisions."""

    @pytest.mark.asyncio
    async def test_verified_claims_carry_identity_and_routing(self):
        """After successful verification, the proxy endpoint has access to
        who is calling, what they can do, and where the request should go."""
        token = mint_cross_gateway_token(
            subject="user:jane@acme.com",
            scopes=["billing:read", "billing:write"],
            peer_id="registry-b",
            target_path="/billing-tools",
            auth_method="oidc",
        )
        request = _build_request(token=token)

        await verify_cross_gateway_token(request)

        claims = request.state.cross_gateway_claims
        # The proxy endpoint uses these to decide:
        # - Who to attribute the outbound call to (audit)
        assert claims["sub"] == "user:jane@acme.com"
        # - Which peer to route to (must match the route path param)
        assert claims["peer_id"] == "registry-b"
        # - What resource on the peer (path validation)
        assert claims["target_path"] == "/billing-tools"
        # - How the caller authenticated (context for the peer)
        assert claims["auth_method"] == "oidc"
        # - What the caller is allowed to do (for future per-scope authz)
        assert claims["scopes"] == ["billing:read", "billing:write"]
