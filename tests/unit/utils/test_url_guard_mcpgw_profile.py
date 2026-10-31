"""Unit tests for MCPGW_GATEWAY_PROFILE's origin lock in registry/utils/url_guard.py.

mcpgw's gateway/registry traffic is locked to the origin (scheme, host, port)
of REGISTRY_BASE_URL via ``_Profile.allowed_origin_factory`` /
``_mcpgw_gateway_origin``, enforced in ``validate_url`` ahead of every other
branch. These tests pin:

- the allowlist/origin factories' own validation of REGISTRY_BASE_URL,
- same-origin acceptance and host/port/scheme mismatch rejection,
- that the origin check fires on EVERY branch of ``validate_url`` under this
  profile: an IP-literal candidate, a ``resolve=False`` call, a
  resolved-hostname call (proven by the resolver never being invoked), and a
  redirect hop through the guarded transport.

``MCPGW_GATEWAY_PROFILE`` already appears in
``test_url_guard_forward_proxy.py``'s credential-bearing-profile parametrize
list; this file does not duplicate that check.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from registry.exceptions import UrlValidationError
from registry.utils import url_guard


def _stub_async_dns(*ips: str):
    """Patch the event loop's resolver, leaving the real classifier in place.

    Must be called from inside a running event loop (an async test), matching
    the equivalent helper in test_url_guard_forward_proxy.py.
    """
    return patch.object(
        asyncio.get_running_loop(),
        "getaddrinfo",
        new=AsyncMock(return_value=[(2, 1, 6, "", (ip, 443)) for ip in ips]),
    )


@pytest.fixture(autouse=True)
def _clear_forward_proxy_cache():
    """Forward-proxy config is lru_cached; keep this file isolated from it."""
    url_guard._forward_proxy_config.cache_clear()
    yield
    url_guard._forward_proxy_config.cache_clear()


# ---------------------------------------------------------------------------
# _mcpgw_gateway_allowlist / _mcpgw_gateway_origin: REGISTRY_BASE_URL parsing
# ---------------------------------------------------------------------------


class TestMcpgwGatewayAllowlist:
    def test_missing_registry_base_url_raises(self, monkeypatch):
        monkeypatch.delenv("REGISTRY_BASE_URL", raising=False)

        with pytest.raises(UrlValidationError, match="REGISTRY_BASE_URL is not set"):
            url_guard._mcpgw_gateway_allowlist()

    def test_ip_literal_registry_base_url_raises(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://127.0.0.1:8080")

        with pytest.raises(UrlValidationError, match="must be a hostname, not an IP literal"):
            url_guard._mcpgw_gateway_allowlist()

    def test_registry_base_url_with_userinfo_raises(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://user:pass@registry:8080")

        with pytest.raises(UrlValidationError, match="userinfo"):
            url_guard._mcpgw_gateway_allowlist()

    def test_registry_base_url_with_query_string_raises(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry:8080/path?x=1")

        with pytest.raises(UrlValidationError, match="query string"):
            url_guard._mcpgw_gateway_allowlist()

    def test_trusts_exactly_the_registry_base_url_host(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry.internal:8080")

        allowlist = url_guard._mcpgw_gateway_allowlist()

        assert allowlist.allows_host("registry.internal")
        assert not allowlist.allows_host("other.internal")


class TestMcpgwGatewayOrigin:
    def test_missing_registry_base_url_raises(self, monkeypatch):
        monkeypatch.delenv("REGISTRY_BASE_URL", raising=False)

        with pytest.raises(UrlValidationError, match="REGISTRY_BASE_URL is not set"):
            url_guard._mcpgw_gateway_origin()

    def test_default_http_port_is_80(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry")

        assert url_guard._mcpgw_gateway_origin() == "http://registry:80"

    def test_default_https_port_is_443(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "https://registry")

        assert url_guard._mcpgw_gateway_origin() == "https://registry:443"

    def test_explicit_port_and_path_is_ignored(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry:8080/some/base/path")

        assert url_guard._mcpgw_gateway_origin() == "http://registry:8080"


# ---------------------------------------------------------------------------
# validate_url: same-origin passes, any mismatch fails
# ---------------------------------------------------------------------------


class TestValidateUrlOriginLock:
    def test_same_origin_url_passes(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry:8080")

        result = url_guard.validate_url(
            "http://registry:8080/api/servers",
            profile=url_guard.MCPGW_GATEWAY_PROFILE,
            resolve=False,
        )

        assert result == []

    @pytest.mark.parametrize(
        "candidate_url",
        [
            "http://other-host:8080/api/servers",  # different host
            "http://registry:9090/api/servers",  # different port
            "https://registry:8080/api/servers",  # different scheme
        ],
        ids=["different-host", "different-port", "different-scheme"],
    )
    def test_origin_mismatch_is_rejected(self, monkeypatch, candidate_url):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry:8080")

        with pytest.raises(UrlValidationError, match="allowed origin"):
            url_guard.validate_url(
                candidate_url, profile=url_guard.MCPGW_GATEWAY_PROFILE, resolve=False
            )

    def test_origin_lock_fires_for_an_ip_literal_candidate(self, monkeypatch):
        """An IP-literal candidate would otherwise reach only the private-IP
        check and return immediately with no further validation; the origin
        lock must still catch a wrong-origin literal first."""
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry:8080")

        with pytest.raises(UrlValidationError, match="allowed origin"):
            url_guard.validate_url(
                "http://93.184.216.34:8080/api/servers",
                profile=url_guard.MCPGW_GATEWAY_PROFILE,
            )

    def test_origin_lock_fires_on_a_resolve_false_call(self, monkeypatch):
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry:8080")

        with pytest.raises(UrlValidationError, match="allowed origin"):
            url_guard.validate_url(
                "http://evil.example:8080/api/servers",
                profile=url_guard.MCPGW_GATEWAY_PROFILE,
                resolve=False,
            )

    def test_origin_lock_fires_before_dns_resolution_is_ever_attempted(self, monkeypatch):
        """Proves ordering: a hostname that would resolve just fine is still
        denied, and the resolver is never even called."""
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry:8080")
        mock_resolve = MagicMock(return_value=["93.184.216.34"])

        with patch.object(url_guard, "_resolve_public_ips", mock_resolve):
            with pytest.raises(UrlValidationError, match="allowed origin"):
                url_guard.validate_url(
                    "http://evil.example:8080/api/servers",
                    profile=url_guard.MCPGW_GATEWAY_PROFILE,
                    resolve=True,
                )

        mock_resolve.assert_not_called()


# ---------------------------------------------------------------------------
# The origin lock also fires on a redirect hop through the guarded transport.
# ---------------------------------------------------------------------------


class TestGuardedTransportRedirectHop:
    async def test_origin_lock_fires_on_a_redirect_hop_to_the_wrong_origin(self, monkeypatch):
        """httpx re-invokes the transport per redirect hop (simulated here by
        routing two requests through the same transport instance): hop 1
        on-origin succeeds, hop 2 off-origin must still be denied."""
        monkeypatch.setenv("REGISTRY_BASE_URL", "http://registry:8080")
        transport = url_guard.GuardedAsyncTransport(guard_profile=url_guard.MCPGW_GATEWAY_PROFILE)

        with _stub_async_dns("93.184.216.34"):
            first = await transport._route_request_async(
                httpx.Request("GET", "http://registry:8080/api/servers")
            )
        assert first.proxy_url is None  # forward proxy is off by default

        with pytest.raises(UrlValidationError, match="allowed origin"):
            await transport._route_request_async(
                httpx.Request("GET", "http://evil.example:8080/api/servers")
            )
