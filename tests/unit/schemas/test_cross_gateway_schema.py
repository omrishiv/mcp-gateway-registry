"""Tests for cross-gateway routing fields on PeerRegistryConfig.

Security-focused: validates that the schema rejects unsafe configurations
and never leaks sensitive fields in responses.
"""

import pytest

from registry.schemas.peer_federation_schema import (
    PeerRegistryConfig,
    PeerRegistryConfigResponse,
)


class TestGatewayEndpointValidation:
    """gateway_endpoint must be HTTPS, SSRF-safe, and properly formatted."""

    def _base_config(self, **overrides) -> dict:
        """Return a minimal valid peer config with overrides applied."""
        base = {
            "peer_id": "test-peer",
            "name": "Test Peer",
            "endpoint": "https://peer.example.com",
        }
        base.update(overrides)
        return base

    def test_valid_https_endpoint(self):
        """Accept a valid HTTPS gateway endpoint."""
        config = PeerRegistryConfig(
            **self._base_config(
                gateway_endpoint="https://gateway.example.com",
                gateway_enabled=True,
            )
        )
        assert config.gateway_endpoint == "https://gateway.example.com"
        assert config.gateway_enabled is True

    def test_none_endpoint_allowed(self):
        """None gateway_endpoint is valid (feature not configured)."""
        config = PeerRegistryConfig(
            **self._base_config(
                gateway_endpoint=None,
                gateway_enabled=False,
            )
        )
        assert config.gateway_endpoint is None

    def test_http_rejected(self):
        """Reject HTTP — credentials would be sent in cleartext."""
        with pytest.raises(ValueError, match="must use HTTPS"):
            PeerRegistryConfig(
                **self._base_config(
                    gateway_endpoint="http://gateway.example.com",
                )
            )

    def test_no_scheme_rejected(self):
        """Reject URLs without a scheme."""
        with pytest.raises(ValueError):
            PeerRegistryConfig(
                **self._base_config(
                    gateway_endpoint="gateway.example.com",
                )
            )

    def test_userinfo_in_url_rejected(self):
        """Reject URLs with credentials embedded (security anti-pattern)."""
        with pytest.raises(ValueError, match="must not contain credentials"):
            PeerRegistryConfig(
                **self._base_config(
                    gateway_endpoint="https://user:pass@gateway.example.com",
                )
            )

    def test_empty_string_becomes_none(self):
        """Empty/whitespace-only string treated as None."""
        config = PeerRegistryConfig(
            **self._base_config(
                gateway_endpoint="   ",
                gateway_enabled=False,
            )
        )
        assert config.gateway_endpoint is None

    def test_trailing_slash_stripped(self):
        """Trailing slash normalized away."""
        config = PeerRegistryConfig(
            **self._base_config(
                gateway_endpoint="https://gateway.example.com/",
            )
        )
        assert config.gateway_endpoint == "https://gateway.example.com"

    def test_gateway_enabled_without_endpoint_rejected(self):
        """Fail closed: gateway_enabled=True requires gateway_endpoint."""
        with pytest.raises(ValueError, match="requires gateway_endpoint"):
            PeerRegistryConfig(
                **self._base_config(
                    gateway_endpoint=None,
                    gateway_enabled=True,
                )
            )

    def test_private_ip_rejected(self):
        """Reject private/internal IPs — SSRF guard (literal IP check)."""
        with pytest.raises(ValueError, match="security validation"):
            PeerRegistryConfig(
                **self._base_config(
                    gateway_endpoint="https://10.0.0.1:8443",
                )
            )

    def test_loopback_rejected(self):
        """Reject loopback — SSRF guard."""
        with pytest.raises(ValueError, match="security validation"):
            PeerRegistryConfig(
                **self._base_config(
                    gateway_endpoint="https://127.0.0.1:8443",
                )
            )

    def test_metadata_ip_rejected(self):
        """Reject cloud metadata endpoint — never allowlistable."""
        with pytest.raises(ValueError, match="security validation"):
            PeerRegistryConfig(
                **self._base_config(
                    gateway_endpoint="https://169.254.169.254",
                )
            )

    def test_link_local_rejected(self):
        """Reject link-local addresses."""
        with pytest.raises(ValueError, match="security validation"):
            PeerRegistryConfig(
                **self._base_config(
                    gateway_endpoint="https://169.254.1.1",
                )
            )


class TestPeerTlsCaCertWriteOnly:
    """peer_tls_ca_cert must never appear in API responses."""

    def test_cert_not_in_response(self):
        """Response model exposes has_peer_tls_ca_cert but not the cert value."""
        config = PeerRegistryConfig(
            peer_id="test-peer",
            name="Test Peer",
            endpoint="https://peer.example.com",
            gateway_endpoint="https://gateway.example.com",
            gateway_enabled=True,
            peer_tls_ca_cert="-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
        )
        response = PeerRegistryConfigResponse.from_config(config)

        # The cert value must never be in the response
        assert not hasattr(response, "peer_tls_ca_cert")
        response_dict = response.model_dump()
        assert "peer_tls_ca_cert" not in response_dict

        # But the boolean indicator is present
        assert response.has_peer_tls_ca_cert is True

    def test_no_cert_shows_false(self):
        """has_peer_tls_ca_cert is False when not configured."""
        config = PeerRegistryConfig(
            peer_id="test-peer",
            name="Test Peer",
            endpoint="https://peer.example.com",
            peer_tls_ca_cert=None,
        )
        response = PeerRegistryConfigResponse.from_config(config)
        assert response.has_peer_tls_ca_cert is False


class TestGatewayFieldsInResponse:
    """Non-sensitive gateway fields appear correctly in responses."""

    def test_gateway_fields_in_response(self):
        """gateway_endpoint and gateway_enabled are non-sensitive and returned."""
        config = PeerRegistryConfig(
            peer_id="test-peer",
            name="Test Peer",
            endpoint="https://peer.example.com",
            gateway_endpoint="https://gateway.example.com",
            gateway_enabled=True,
        )
        response = PeerRegistryConfigResponse.from_config(config)
        assert response.gateway_endpoint == "https://gateway.example.com"
        assert response.gateway_enabled is True
