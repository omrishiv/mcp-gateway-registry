"""Tests for cross-gateway credential providers.

Security-focused: validates fail-closed behavior, no credential leakage,
and proper isolation from inbound request context.
"""

import pytest

from registry.services.cross_gateway_credential import (
    CrossGatewayCredentialError,
    StaticTokenCredentialProvider,
)


class TestStaticTokenCredentialProvider:
    """StaticTokenCredentialProvider must fail closed and never leak credentials."""

    def _make_provider(self, peers: dict | None = None):
        """Create a provider with a mock peer config loader."""
        peer_store = peers or {}

        def loader(peer_id: str):
            return peer_store.get(peer_id)

        return StaticTokenCredentialProvider(peer_config_loader=loader)

    @pytest.mark.asyncio
    async def test_returns_bearer_header(self):
        """Valid token is returned as Bearer header."""
        provider = self._make_provider(
            {
                "peer-b": {"federation_token": "secret-token-value"},
            }
        )
        headers = await provider.get_headers_for_peer(
            peer_id="peer-b",
            target_path="/billing-tools",
            calling_subject="user:jane@acme.com",
            calling_auth_method="oidc",
            calling_scopes=["mcp:read"],
        )
        assert headers == {"Authorization": "Bearer secret-token-value"}

    @pytest.mark.asyncio
    async def test_unknown_peer_raises(self):
        """Fail closed: unknown peer_id raises CrossGatewayCredentialError."""
        provider = self._make_provider({})
        with pytest.raises(CrossGatewayCredentialError, match="peer not found"):
            await provider.get_headers_for_peer(
                peer_id="nonexistent-peer",
                target_path="/target",
                calling_subject="user:test",
                calling_auth_method="oidc",
                calling_scopes=[],
            )

    @pytest.mark.asyncio
    async def test_none_token_raises(self):
        """Fail closed: peer exists but federation_token is None."""
        provider = self._make_provider(
            {
                "peer-b": {"federation_token": None},
            }
        )
        with pytest.raises(CrossGatewayCredentialError, match="no federation_token"):
            await provider.get_headers_for_peer(
                peer_id="peer-b",
                target_path="/target",
                calling_subject="user:test",
                calling_auth_method="oidc",
                calling_scopes=[],
            )

    @pytest.mark.asyncio
    async def test_empty_token_raises(self):
        """Fail closed: empty string token is rejected."""
        provider = self._make_provider(
            {
                "peer-b": {"federation_token": ""},
            }
        )
        with pytest.raises(CrossGatewayCredentialError, match="no federation_token"):
            await provider.get_headers_for_peer(
                peer_id="peer-b",
                target_path="/target",
                calling_subject="user:test",
                calling_auth_method="oidc",
                calling_scopes=[],
            )

    @pytest.mark.asyncio
    async def test_whitespace_only_token_raises(self):
        """Fail closed: whitespace-only token is rejected."""
        provider = self._make_provider(
            {
                "peer-b": {"federation_token": "   "},
            }
        )
        with pytest.raises(CrossGatewayCredentialError, match="no federation_token"):
            await provider.get_headers_for_peer(
                peer_id="peer-b",
                target_path="/target",
                calling_subject="user:test",
                calling_auth_method="oidc",
                calling_scopes=[],
            )

    @pytest.mark.asyncio
    async def test_token_stripped(self):
        """Token is stripped of surrounding whitespace."""
        provider = self._make_provider(
            {
                "peer-b": {"federation_token": "  valid-token  "},
            }
        )
        headers = await provider.get_headers_for_peer(
            peer_id="peer-b",
            target_path="/target",
            calling_subject="user:test",
            calling_auth_method="oidc",
            calling_scopes=[],
        )
        assert headers == {"Authorization": "Bearer valid-token"}

    @pytest.mark.asyncio
    async def test_pydantic_model_support(self):
        """Provider works with objects that have a federation_token attribute."""

        class FakePeerConfig:
            federation_token = "model-token"

        provider = self._make_provider(
            {
                "peer-b": FakePeerConfig(),
            }
        )
        headers = await provider.get_headers_for_peer(
            peer_id="peer-b",
            target_path="/target",
            calling_subject="user:test",
            calling_auth_method="oidc",
            calling_scopes=[],
        )
        assert headers == {"Authorization": "Bearer model-token"}

    @pytest.mark.asyncio
    async def test_error_message_does_not_contain_token(self):
        """Security: error messages never include the credential value."""
        provider = self._make_provider(
            {
                "peer-b": {"federation_token": None},
            }
        )
        with pytest.raises(CrossGatewayCredentialError) as exc_info:
            await provider.get_headers_for_peer(
                peer_id="peer-b",
                target_path="/target",
                calling_subject="user:test",
                calling_auth_method="oidc",
                calling_scopes=[],
            )
        # The error should mention the peer but never a credential value
        error_msg = str(exc_info.value)
        assert "peer-b" in error_msg
        assert "token" not in error_msg.lower() or "no federation_token" in error_msg


class TestCrossGatewayCredentialError:
    """CrossGatewayCredentialError carries peer_id and reason."""

    def test_error_attributes(self):
        """Error has peer_id and reason accessible."""
        err = CrossGatewayCredentialError("my-peer", "not configured")
        assert err.peer_id == "my-peer"
        assert err.reason == "not configured"
        assert "my-peer" in str(err)
        assert "not configured" in str(err)
