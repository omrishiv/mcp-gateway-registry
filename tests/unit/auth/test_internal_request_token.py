"""Unit tests for auth_server/internal_request_token.py.

Covers the /validate-minted internal JWT: mint round-trips, the verify
dependency's accept/reject paths (missing / expired / tampered / wrong-audience
/ wrong-token_use / missing upstream / server-claim-path mismatch),
the fail-open opt-out semantics, the sub-path-append parity that the bound upstream_url
relies on, and the audience-parameterization seam the registry fast-follow reuses.
"""

import os
import time
from types import SimpleNamespace
from unittest.mock import patch

import jwt as pyjwt
import pytest
from fastapi import HTTPException

from auth_server.internal_request_token import (
    MCP_PROXY_AUDIENCE,
    _decode_internal_token,
    _mint_internal_token,
    mint_mcp_proxy_token,
    verify_mcp_proxy_token,
)

_SECRET = "test-secret-key-for-testing-only"


def _request(headers: dict[str, str], server_name: str = "airegistry-tools/mcp"):
    """Build a minimal stand-in for a FastAPI Request with the bits the
    dependency reads: .headers, .path_params, and a mutable .state."""
    lower = {k.lower(): v for k, v in headers.items()}
    return SimpleNamespace(
        headers=SimpleNamespace(get=lambda k, default=None: lower.get(k.lower(), default)),
        path_params={"server_name": server_name},
        state=SimpleNamespace(),
    )


@pytest.fixture(autouse=True)
def _secret_env():
    with patch.dict(os.environ, {"SECRET_KEY": _SECRET}, clear=False):
        yield


# --------------------------------------------------------------------------- #
# Mint
# --------------------------------------------------------------------------- #


class TestMint:
    def test_mint_roundtrips_expected_claims(self) -> None:
        token = mint_mcp_proxy_token(
            subject="alice",
            scopes=["mcp-servers-unrestricted/read"],
            server_name="airegistry-tools/mcp",
            upstream_url="https://upstream.example/mcp",
        )
        claims = _decode_internal_token(token, audience=MCP_PROXY_AUDIENCE)
        assert claims["sub"] == "alice"
        assert claims["scopes"] == ["mcp-servers-unrestricted/read"]
        assert claims["server"] == "airegistry-tools"  # first segment only
        assert claims["upstream_url"] == "https://upstream.example/mcp"
        assert claims["token_use"] == "mcp-proxy"
        assert claims["aud"] == "mcp-proxy"
        assert claims["iss"] == "mcp-auth-server"

    def test_mint_empty_subject_raises(self) -> None:
        # An empty subject would mint an anonymous-but-valid token; refuse so the
        # proxy fails closed instead of trusting "".
        with pytest.raises(ValueError, match="empty subject"):
            mint_mcp_proxy_token("", [], "srv", "https://u.example")

    def test_mint_without_secret_raises(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="SECRET_KEY"):
                mint_mcp_proxy_token("alice", [], "srv", "https://u.example")


# --------------------------------------------------------------------------- #
# Verify dependency
# --------------------------------------------------------------------------- #


class TestVerify:
    @pytest.mark.asyncio
    async def test_valid_token_passes_and_stashes_claims(self) -> None:
        token = mint_mcp_proxy_token(
            "alice", ["s/read"], "airegistry-tools/mcp", "https://u.example/mcp"
        )
        req = _request({"X-Internal-Token": token}, server_name="airegistry-tools/mcp")
        await verify_mcp_proxy_token(req)
        assert req.state.mcp_proxy_claims["sub"] == "alice"
        assert req.state.mcp_proxy_claims["upstream_url"] == "https://u.example/mcp"

    @pytest.mark.asyncio
    async def test_missing_token_enforced_raises_401(self) -> None:
        with patch.dict(os.environ, {"MCP_PROXY_SIG_ENFORCE": "true"}, clear=False):
            req = _request({})
            with pytest.raises(HTTPException) as exc:
                await verify_mcp_proxy_token(req)
            assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_token_not_enforced_allows_legacy_path(self) -> None:
        with patch.dict(os.environ, {"MCP_PROXY_SIG_ENFORCE": "false"}, clear=False):
            req = _request({})
            await verify_mcp_proxy_token(req)
            assert req.state.mcp_proxy_claims is None  # handler uses legacy headers

    @pytest.mark.asyncio
    async def test_invalid_token_rejected_even_when_not_enforced(self) -> None:
        # A tampered/invalid token signals a malicious caller, so it 401s even
        # under the enforce=false opt-out (only a *missing* token falls back).
        with patch.dict(os.environ, {"MCP_PROXY_SIG_ENFORCE": "false"}, clear=False):
            req = _request({"X-Internal-Token": "not.a.jwt"})
            with pytest.raises(HTTPException) as exc:
                await verify_mcp_proxy_token(req)
            assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self) -> None:
        # Mint with a tiny TTL, wait past it + leeway.
        with patch.dict(
            os.environ,
            {"MCP_PROXY_SIG_TTL_SECONDS": "5", "MCP_PROXY_SIG_LEEWAY_SECONDS": "0"},
            clear=False,
        ):
            now = int(time.time())
            token = pyjwt.encode(
                {
                    "iss": "mcp-auth-server",
                    "aud": "mcp-proxy",
                    "sub": "alice",
                    "scopes": [],
                    "server": "airegistry-tools",
                    "upstream_url": "https://u.example",
                    "token_use": "mcp-proxy",
                    "iat": now - 100,
                    "exp": now - 50,
                },
                _SECRET,
                algorithm="HS256",
            )
            req = _request({"X-Internal-Token": token})
            with pytest.raises(HTTPException) as exc:
                await verify_mcp_proxy_token(req)
            assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_signing_key_rejected(self) -> None:
        now = int(time.time())
        token = pyjwt.encode(
            {
                "iss": "mcp-auth-server",
                "aud": "mcp-proxy",
                "sub": "alice",
                "scopes": [],
                "server": "airegistry-tools",
                "upstream_url": "https://u.example",
                "token_use": "mcp-proxy",
                "iat": now,
                "exp": now + 30,
            },
            "WRONG-KEY-but-long-enough-to-satisfy-hmac-length-check",
            algorithm="HS256",
        )
        req = _request({"X-Internal-Token": token})
        with pytest.raises(HTTPException) as exc:
            await verify_mcp_proxy_token(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_audience_rejected(self) -> None:
        # A service-to-service internal token (aud=mcp-registry) cannot be
        # replayed at mcp_proxy.
        token = _mint_internal_token(
            audience="mcp-registry",
            subject="registry-service",
            scopes=[],
            extra_claims={
                "token_use": "mcp-proxy",
                "upstream_url": "https://u.example",
                "server": "airegistry-tools",
            },
        )
        req = _request({"X-Internal-Token": token})
        with pytest.raises(HTTPException) as exc:
            await verify_mcp_proxy_token(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_token_use_rejected(self) -> None:
        token = _mint_internal_token(
            audience=MCP_PROXY_AUDIENCE,
            subject="alice",
            scopes=[],
            extra_claims={
                "token_use": "something-else",
                "upstream_url": "https://u.example",
                "server": "airegistry-tools",
            },
        )
        req = _request({"X-Internal-Token": token})
        with pytest.raises(HTTPException) as exc:
            await verify_mcp_proxy_token(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_upstream_claim_rejected(self) -> None:
        token = _mint_internal_token(
            audience=MCP_PROXY_AUDIENCE,
            subject="alice",
            scopes=[],
            extra_claims={
                "token_use": "mcp-proxy",
                "upstream_url": "",
                "server": "airegistry-tools",
            },
        )
        req = _request({"X-Internal-Token": token})
        with pytest.raises(HTTPException) as exc:
            await verify_mcp_proxy_token(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_server_claim_path_mismatch_rejected(self) -> None:
        # Token minted for server "airegistry-tools" but request path is for "github-mcp".
        token = mint_mcp_proxy_token("alice", [], "airegistry-tools/mcp", "https://u.example/mcp")
        req = _request({"X-Internal-Token": token}, server_name="github-mcp/mcp")
        with pytest.raises(HTTPException) as exc:
            await verify_mcp_proxy_token(req)
        assert exc.value.status_code == 401
        assert "mismatch" in exc.value.detail.lower()


# --------------------------------------------------------------------------- #
# Sub-path-append parity
# --------------------------------------------------------------------------- #


def _apply_subpath_append(upstream_url: str, server_name: str) -> str:
    """Mirror mcp_proxy's append logic (auth_server/server.py) so the test pins
    the contract: bound (pre-append) upstream_url + sub_path == outbound URL."""
    if "/" in server_name:
        sub_path = server_name.split("/", 1)[1].lstrip("/")
        if sub_path and not upstream_url.rstrip("/").endswith("/" + sub_path):
            upstream_url = upstream_url.rstrip("/") + "/" + sub_path
    return upstream_url


class TestSubPathAppendParity:
    def test_append_adds_subpath(self) -> None:
        # Bound claim is the pre-append upstream; proxy appends "extra".
        assert (
            _apply_subpath_append("https://docs.example/mcp", "cloudflare-docs/extra")
            == "https://docs.example/mcp/extra"
        )

    def test_append_early_out_when_already_ends_with_subpath(self) -> None:
        # The "URL already ends with sub-path" early-out must not double-append.
        assert (
            _apply_subpath_append("https://docs.example/mcp", "cloudflare-docs/mcp")
            == "https://docs.example/mcp"
        )

    def test_no_subpath_when_no_segment(self) -> None:
        assert _apply_subpath_append("https://u.example", "airegistry-tools") == "https://u.example"


# --------------------------------------------------------------------------- #
# Audience-parameterization seam (registry fast-follow reuses this)
# --------------------------------------------------------------------------- #


class TestAudienceParameterization:
    def test_token_minted_for_one_audience_fails_another(self) -> None:
        token = _mint_internal_token(audience="mcp-registry-ui", subject="alice", scopes=["x"])
        # Decoding against a different audience must fail.
        with pytest.raises(pyjwt.InvalidTokenError):
            _decode_internal_token(token, audience="mcp-proxy")
        # But succeeds against the minted audience.
        claims = _decode_internal_token(token, audience="mcp-registry-ui")
        assert claims["sub"] == "alice"
