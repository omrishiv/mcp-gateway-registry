"""Unit tests for servers/mcpgw/gateway_client.py.

gateway_client is the one place mcpgw builds the caller's identity, opens its
one guarded egress client, bounds how much of a response body it ever holds
in memory, and maps an exception to a message safe to hand back to an MCP
client. Unlike server.py, this module imports no ``fastmcp``, so it needs no
stub -- only ``servers/mcpgw`` on ``sys.path`` so ``import gateway_client``
resolves the same module object server.py's ``from gateway_client import
...`` already uses.
"""

import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

_mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
if _mcpgw_path not in sys.path:
    sys.path.insert(0, _mcpgw_path)

import gateway_client  # noqa: E402

from registry.exceptions import UrlValidationError  # noqa: E402


def _make_ctx(headers: dict[str, str] | None):
    """Build a minimal object matching the FastMCP Context duck type."""
    request = SimpleNamespace(headers=headers if headers is not None else {})
    request_context = SimpleNamespace(request=request)
    return SimpleNamespace(request_context=request_context)


# ---------------------------------------------------------------------------
# caller_headers / _caller_bearer_token
# ---------------------------------------------------------------------------


class TestCallerHeaders:
    def test_prefers_x_authorization_over_authorization(self):
        ctx = _make_ctx({"x-authorization": "Bearer first-token", "authorization": "Bearer second"})
        headers = gateway_client.caller_headers(ctx)
        assert headers["X-Authorization"] == "Bearer first-token"

    def test_falls_back_to_authorization(self):
        ctx = _make_ctx({"authorization": "Bearer only-token"})
        headers = gateway_client.caller_headers(ctx)
        assert headers["X-Authorization"] == "Bearer only-token"

    def test_no_ctx_raises(self):
        with pytest.raises(gateway_client.CallerIdentityError, match="Context is None"):
            gateway_client.caller_headers(None)

    def test_no_header_raises(self):
        ctx = _make_ctx({})
        with pytest.raises(gateway_client.CallerIdentityError, match="Bearer token not found"):
            gateway_client.caller_headers(ctx)

    def test_malformed_header_raises(self):
        ctx = _make_ctx({"authorization": "Basic dXNlcjpwYXNz"})
        with pytest.raises(gateway_client.CallerIdentityError, match="Bearer token not found"):
            gateway_client.caller_headers(ctx)

    def test_oidc_enabled_refuses_regardless_of_header(self, monkeypatch):
        monkeypatch.setattr(gateway_client, "OIDC_ENABLED", True)
        ctx = _make_ctx({"x-authorization": "Bearer fine-token"})
        with pytest.raises(gateway_client.CallerIdentityError, match="OIDC_ENABLED=true"):
            gateway_client.caller_headers(ctx)

    def test_oidc_enabled_refuses_even_with_no_ctx(self, monkeypatch):
        monkeypatch.setattr(gateway_client, "OIDC_ENABLED", True)
        with pytest.raises(gateway_client.CallerIdentityError, match="issue #895"):
            gateway_client.caller_headers(None)


# ---------------------------------------------------------------------------
# _forwarded_host_headers / caller_headers forwarding
# ---------------------------------------------------------------------------


class TestForwardedHostHeaders:
    def test_empty_when_external_url_unset(self, monkeypatch):
        monkeypatch.setattr(gateway_client, "REGISTRY_EXTERNAL_URL", "")
        assert gateway_client._forwarded_host_headers() == {}

    def test_empty_when_external_url_has_no_hostname(self, monkeypatch):
        monkeypatch.setattr(gateway_client, "REGISTRY_EXTERNAL_URL", "not-a-url")
        assert gateway_client._forwarded_host_headers() == {}

    def test_set_when_external_url_has_a_hostname(self, monkeypatch):
        monkeypatch.setattr(
            gateway_client, "REGISTRY_EXTERNAL_URL", "https://external.example:9443/base"
        )
        headers = gateway_client._forwarded_host_headers()
        assert headers == {
            "X-Forwarded-Host": "external.example:9443",
            "X-Forwarded-Proto": "https",
        }

    def test_caller_headers_includes_forwarded_host_when_set(self, monkeypatch):
        monkeypatch.setattr(
            gateway_client, "REGISTRY_EXTERNAL_URL", "https://external.example/base"
        )
        ctx = _make_ctx({"x-authorization": "Bearer t"})
        headers = gateway_client.caller_headers(ctx)
        assert headers["X-Forwarded-Host"] == "external.example"
        assert headers["X-Forwarded-Proto"] == "https"

    def test_caller_headers_omits_forwarded_host_by_default(self, monkeypatch):
        monkeypatch.setattr(gateway_client, "REGISTRY_EXTERNAL_URL", "")
        ctx = _make_ctx({"x-authorization": "Bearer t"})
        headers = gateway_client.caller_headers(ctx)
        assert "X-Forwarded-Host" not in headers
        assert "X-Forwarded-Proto" not in headers


# ---------------------------------------------------------------------------
# gateway_http_client
# ---------------------------------------------------------------------------


class TestGatewayHttpClient:
    def test_builds_guarded_client_with_profile_and_no_redirects(self, monkeypatch):
        mock_factory = MagicMock(return_value="client-sentinel")
        monkeypatch.setattr(gateway_client, "guarded_async_client", mock_factory)

        result = gateway_client.gateway_http_client(12.5, headers={"X-Authorization": "Bearer t"})

        assert result == "client-sentinel"
        mock_factory.assert_called_once_with(
            profile=gateway_client.MCPGW_GATEWAY_PROFILE,
            timeout=12.5,
            headers={"X-Authorization": "Bearer t"},
            follow_redirects=False,
        )


# ---------------------------------------------------------------------------
# read_bounded
# ---------------------------------------------------------------------------


class TestReadBounded:
    async def test_accepts_body_at_the_limit(self):
        body = b"x" * 100
        response = httpx.Response(200, content=body)

        result = await gateway_client.read_bounded(response, limit=100)

        assert result == body

    async def test_rejects_declared_content_length_over_limit(self):
        response = httpx.Response(200, content=b"short", headers={"content-length": "1000"})

        with pytest.raises(gateway_client.ResponseTooLargeError, match="declared Content-Length"):
            await gateway_client.read_bounded(response, limit=100)

    async def test_rejects_actual_bytes_over_limit_with_no_declared_length(self):
        async def _gen():
            yield b"a" * 60
            yield b"b" * 60

        response = httpx.Response(200, content=_gen())
        assert response.headers.get("content-length") is None

        with pytest.raises(gateway_client.ResponseTooLargeError, match="exceeds the"):
            await gateway_client.read_bounded(response, limit=100)

    async def test_rejects_actual_bytes_over_limit_when_declared_length_lies(self):
        # Declares well under the limit; the real body is well over it. httpx
        # serves whatever bytes were given regardless of the header value, so
        # this is the "lying Content-Length" case read_bounded must still catch.
        response = httpx.Response(200, content=b"z" * 150, headers={"content-length": "10"})

        with pytest.raises(gateway_client.ResponseTooLargeError, match="exceeds the"):
            await gateway_client.read_bounded(response, limit=100)


# ---------------------------------------------------------------------------
# request_json_bounded
# ---------------------------------------------------------------------------


class TestRequestJsonBounded:
    async def test_returns_parsed_json_on_success(self):
        def handler(request):
            return httpx.Response(200, json={"servers": []})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            data = await gateway_client.request_json_bounded(
                client, "GET", "http://registry.internal/api/servers"
            )

        assert data == {"servers": []}

    async def test_raises_http_status_error_before_parsing_on_non_2xx(self):
        # A non-JSON body: if the code ever tried json.loads before raising for
        # status, this would surface as a JSONDecodeError instead.
        def handler(request):
            return httpx.Response(500, text="Internal Server Error (not json)")

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(httpx.HTTPStatusError) as exc_info:
                await gateway_client.request_json_bounded(
                    client, "GET", "http://registry.internal/api/servers"
                )

        assert exc_info.value.response.status_code == 500


# ---------------------------------------------------------------------------
# redact_exception_text
# ---------------------------------------------------------------------------


class TestRedactExceptionText:
    def test_redacts_the_url_on_a_url_validation_error(self):
        exc = UrlValidationError(
            "http://evil.example/leak?token=TOPSECRET123",
            "targets blocked/private IP 10.0.0.1",
        )

        text = gateway_client.redact_exception_text(exc)

        assert "TOPSECRET123" not in text
        # Host/path stay, for debugging; only the query string (the secret) is gone.
        assert "evil.example" in text
        assert "/leak" in text
        assert "targets blocked/private IP 10.0.0.1" in text

    def test_passes_through_a_plain_message_for_other_exception_types(self):
        exc = ValueError("plain validation message")

        text = gateway_client.redact_exception_text(exc)

        assert text == "ValueError: plain validation message"


# ---------------------------------------------------------------------------
# public_error
# ---------------------------------------------------------------------------


class TestPublicError:
    def test_http_status_error(self):
        request = httpx.Request("GET", "http://registry.internal/api/servers")
        response = httpx.Response(503, request=request)
        exc = httpx.HTTPStatusError("boom", request=request, response=response)

        assert gateway_client.public_error(exc) == "The registry rejected the request (HTTP 503)."

    def test_timeout_exception(self):
        exc = httpx.TimeoutException("timed out")

        assert gateway_client.public_error(exc) == "The registry did not answer in time."

    def test_transport_error(self):
        exc = httpx.TransportError("connection failed")

        assert gateway_client.public_error(exc) == "The registry could not be reached."

    def test_url_validation_error(self):
        exc = UrlValidationError("http://10.0.0.5/", "targets blocked/private IP 10.0.0.5")

        assert gateway_client.public_error(exc) == "The request was refused by the egress guard."

    def test_generic_exception(self):
        exc = RuntimeError("something unexpected")

        assert gateway_client.public_error(exc) == "Unexpected error; see the mcpgw log."

    def test_url_validation_error_with_a_secret_looking_url_never_leaks_it(self):
        exc = UrlValidationError(
            "http://internal.example/?api_key=sk-TOPSECRET",
            "targets blocked/private IP 10.0.0.5",
        )

        message = gateway_client.public_error(exc)

        assert "sk-TOPSECRET" not in message
        assert "internal.example" not in message
        assert message == "The request was refused by the egress guard."


# ---------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------


class TestDeadline:
    def test_remaining_counts_down_from_total_seconds(self):
        deadline = gateway_client.Deadline(10.0)

        remaining = deadline.remaining()

        assert 0.0 < remaining <= 10.0
        assert deadline.expired() is False

    def test_zero_total_seconds_is_immediately_expired(self):
        deadline = gateway_client.Deadline(0.0)

        assert deadline.remaining() == 0.0
        assert deadline.expired() is True

    def test_negative_total_seconds_floors_remaining_at_zero(self):
        deadline = gateway_client.Deadline(-5.0)

        assert deadline.remaining() == 0.0
        assert deadline.expired() is True

    def test_remaining_decreases_over_real_time(self):
        deadline = gateway_client.Deadline(1.0)
        first = deadline.remaining()
        time.sleep(0.05)
        second = deadline.remaining()

        assert second < first
