"""Unit tests for the registration webhook notification service."""

import logging
from unittest.mock import (
    AsyncMock,
    patch,
)

import httpx
import pytest

from registry.services.webhook_service import (
    _build_auth_headers,
    send_registration_webhook,
)

SAMPLE_CARD = {
    "name": "test-server",
    "path": "test/server",
    "description": "A test server",
}


class TestBuildAuthHeaders:
    """Tests for _build_auth_headers."""

    def test_authorization_header_prepends_bearer(self):
        """Bearer prefix is added when header is Authorization."""
        with patch("registry.services.webhook_service.settings") as mock_settings:
            mock_settings.registration_webhook_auth_token = "my-secret-token"
            mock_settings.registration_webhook_auth_header = "Authorization"

            headers = _build_auth_headers()

            assert headers == {"Authorization": "Bearer my-secret-token"}

    def test_custom_header_sends_token_as_is(self):
        """Custom header names send the token without Bearer prefix."""
        with patch("registry.services.webhook_service.settings") as mock_settings:
            mock_settings.registration_webhook_auth_token = "my-api-key"
            mock_settings.registration_webhook_auth_header = "X-API-Key"

            headers = _build_auth_headers()

            assert headers == {"X-API-Key": "my-api-key"}

    def test_no_token_returns_empty_dict(self):
        """No auth headers when token is not configured."""
        with patch("registry.services.webhook_service.settings") as mock_settings:
            mock_settings.registration_webhook_auth_token = None
            mock_settings.registration_webhook_auth_header = "Authorization"

            headers = _build_auth_headers()

            assert headers == {}

    def test_authorization_header_case_insensitive(self):
        """Bearer prefix added regardless of Authorization casing."""
        with patch("registry.services.webhook_service.settings") as mock_settings:
            mock_settings.registration_webhook_auth_token = "tok"
            mock_settings.registration_webhook_auth_header = "AUTHORIZATION"

            headers = _build_auth_headers()

            assert headers == {"AUTHORIZATION": "Bearer tok"}


class TestSendRegistrationWebhook:
    """Tests for send_registration_webhook."""

    @pytest.mark.asyncio
    async def test_registration_event_payload(self):
        """Webhook is called with correct payload for a registration event."""
        mock_response = AsyncMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("registry.services.webhook_service.settings") as mock_settings,
            patch("registry.services.webhook_service.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.registration_webhook_url = "https://example.com/webhook"
            mock_settings.registration_webhook_auth_token = None
            mock_settings.registration_webhook_auth_header = "Authorization"
            mock_settings.registration_webhook_timeout_seconds = 10

            await send_registration_webhook(
                event_type="registration",
                registration_type="server",
                card_data=SAMPLE_CARD,
                performed_by="alice",
            )

            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args
            payload = call_kwargs.kwargs["json"]

            assert payload["event_type"] == "registration"
            assert payload["registration_type"] == "server"
            assert payload["performed_by"] == "alice"
            assert payload["card"] == SAMPLE_CARD
            assert "timestamp" in payload

    @pytest.mark.asyncio
    async def test_deletion_event_payload(self):
        """Webhook is called with correct payload for a deletion event."""
        mock_response = AsyncMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("registry.services.webhook_service.settings") as mock_settings,
            patch("registry.services.webhook_service.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.registration_webhook_url = "https://example.com/webhook"
            mock_settings.registration_webhook_auth_token = None
            mock_settings.registration_webhook_auth_header = "Authorization"
            mock_settings.registration_webhook_timeout_seconds = 10

            await send_registration_webhook(
                event_type="deletion",
                registration_type="agent",
                card_data=SAMPLE_CARD,
                performed_by="bob",
            )

            call_kwargs = mock_client.post.call_args
            payload = call_kwargs.kwargs["json"]

            assert payload["event_type"] == "deletion"
            assert payload["registration_type"] == "agent"
            assert payload["performed_by"] == "bob"

    @pytest.mark.asyncio
    async def test_failure_does_not_propagate(self):
        """Webhook HTTP errors are logged but not raised."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("registry.services.webhook_service.settings") as mock_settings,
            patch("registry.services.webhook_service.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.registration_webhook_url = "https://example.com/webhook"
            mock_settings.registration_webhook_auth_token = None
            mock_settings.registration_webhook_auth_header = "Authorization"
            mock_settings.registration_webhook_timeout_seconds = 10

            await send_registration_webhook(
                event_type="registration",
                registration_type="server",
                card_data=SAMPLE_CARD,
            )

    @pytest.mark.asyncio
    async def test_timeout_does_not_propagate(self):
        """Webhook timeout is logged but not raised."""
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("registry.services.webhook_service.settings") as mock_settings,
            patch("registry.services.webhook_service.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.registration_webhook_url = "https://example.com/webhook"
            mock_settings.registration_webhook_auth_token = None
            mock_settings.registration_webhook_auth_header = "Authorization"
            mock_settings.registration_webhook_timeout_seconds = 5

            await send_registration_webhook(
                event_type="registration",
                registration_type="skill",
                card_data=SAMPLE_CARD,
            )

    @pytest.mark.asyncio
    async def test_no_url_configured_skips_webhook(self):
        """Webhook is not called when URL is not configured."""
        with patch("registry.services.webhook_service.settings") as mock_settings:
            mock_settings.registration_webhook_url = None

            with patch("registry.services.webhook_service.httpx.AsyncClient") as mock_async:
                await send_registration_webhook(
                    event_type="registration",
                    registration_type="server",
                    card_data=SAMPLE_CARD,
                )

                mock_async.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_url_skips_webhook(self):
        """Webhook is not called when URL is empty string."""
        with patch("registry.services.webhook_service.settings") as mock_settings:
            mock_settings.registration_webhook_url = ""

            with patch("registry.services.webhook_service.httpx.AsyncClient") as mock_async:
                await send_registration_webhook(
                    event_type="registration",
                    registration_type="server",
                    card_data=SAMPLE_CARD,
                )

                mock_async.assert_not_called()

    @pytest.mark.asyncio
    async def test_http_url_logs_warning(self, caplog):
        """A WARNING is logged when webhook URL uses HTTP instead of HTTPS."""
        mock_response = AsyncMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("registry.services.webhook_service.settings") as mock_settings,
            patch("registry.services.webhook_service.httpx.AsyncClient", return_value=mock_client),
            caplog.at_level(logging.WARNING, logger="registry.services.webhook_service"),
        ):
            mock_settings.registration_webhook_url = "http://example.com/webhook"
            mock_settings.registration_webhook_auth_token = None
            mock_settings.registration_webhook_auth_header = "Authorization"
            mock_settings.registration_webhook_timeout_seconds = 10

            await send_registration_webhook(
                event_type="registration",
                registration_type="server",
                card_data=SAMPLE_CARD,
            )

            assert any("HTTP (not HTTPS)" in record.message for record in caplog.records)

    @pytest.mark.asyncio
    async def test_invalid_url_scheme_rejected(self, caplog):
        """URLs with non-http(s) schemes are rejected and logged as error."""
        with (
            patch("registry.services.webhook_service.settings") as mock_settings,
            caplog.at_level(logging.ERROR, logger="registry.services.webhook_service"),
        ):
            mock_settings.registration_webhook_url = "ftp://example.com/webhook"

            with patch("registry.services.webhook_service.httpx.AsyncClient") as mock_async:
                await send_registration_webhook(
                    event_type="registration",
                    registration_type="server",
                    card_data=SAMPLE_CARD,
                )

                mock_async.assert_not_called()
                assert any(
                    "Invalid webhook URL scheme" in record.message for record in caplog.records
                )

    @pytest.mark.asyncio
    async def test_local_runtime_env_redacted_in_payload(self):
        """local_runtime.env values must be masked before being
        sent to the external webhook endpoint, mirroring the registration gate
        sanitizer."""
        from unittest.mock import AsyncMock

        local_card = {
            "server_name": "local-server",
            "deployment": "local",
            "local_runtime": {
                "type": "npx",
                "package": "@acme/mcp",
                "env": {"LOG_LEVEL": "info", "API_KEY": "${API_KEY}"},
                "args": ["--api-key", "sk-realsecret"],
                "required_env": ["API_KEY"],
            },
            "auth_credential": "should-be-stripped",
        }

        captured_payload = {}

        async def _capture_post(url, json, headers):
            captured_payload.update(json)
            response = MagicMock()
            response.status_code = 200
            return response

        with patch("registry.services.webhook_service.settings") as mock_settings:
            mock_settings.registration_webhook_url = "https://hooks.example.com/recv"
            mock_settings.registration_webhook_auth_header_name = ""
            mock_settings.registration_webhook_auth_token = ""
            mock_settings.registration_webhook_timeout_seconds = 10

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value.post = _capture_post
            mock_client.__aexit__.return_value = None

            with patch(
                "registry.services.webhook_service.httpx.AsyncClient",
                return_value=mock_client,
            ):
                await send_registration_webhook(
                    event_type="registration",
                    registration_type="server",
                    card_data=local_card,
                )

        sent_card = captured_payload["card"]
        # Top-level credential fields stripped (existing behavior).
        assert "auth_credential" not in sent_card
        # local_runtime.env values masked, keys preserved.
        rt = sent_card["local_runtime"]
        assert set(rt["env"].keys()) == {"LOG_LEVEL", "API_KEY"}
        assert all(v == "<redacted>" for v in rt["env"].values())
        # args fully masked.
        assert rt["args"] == ["<redacted>", "<redacted>"]
        # Non-sensitive fields pass through.
        assert rt["package"] == "@acme/mcp"
        assert rt["required_env"] == ["API_KEY"]
