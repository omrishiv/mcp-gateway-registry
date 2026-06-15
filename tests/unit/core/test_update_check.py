"""Unit tests for the update-check module (issue #1218)."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from registry.core import update_check
from registry.core.update_check import (
    UpdateCheckState,
    _is_dev_build,
    _parse_release_tag,
    _run_check_once,
    get_state,
)


class TestParseReleaseTag:
    def test_parses_plain_version(self):
        v = _parse_release_tag("1.24.4")
        assert v is not None
        assert str(v) == "1.24.4"

    def test_strips_v_prefix(self):
        v = _parse_release_tag("v1.24.4")
        assert v is not None
        assert str(v) == "1.24.4"

    def test_returns_none_for_garbage(self):
        assert _parse_release_tag("not-a-version") is None

    def test_returns_none_for_empty(self):
        assert _parse_release_tag("") is None


class TestIsDevBuild:
    def test_no_build_version_is_dev(self, monkeypatch):
        monkeypatch.delenv("BUILD_VERSION", raising=False)
        assert _is_dev_build() is True

    def test_with_build_version_is_not_dev(self, monkeypatch):
        monkeypatch.setenv("BUILD_VERSION", "1.24.4")
        assert _is_dev_build() is False

    def test_empty_build_version_is_dev(self, monkeypatch):
        monkeypatch.setenv("BUILD_VERSION", "")
        assert _is_dev_build() is True


@pytest.fixture
def reset_state():
    """Restore the module-level state after each test."""
    original = update_check._state
    update_check._state = UpdateCheckState()
    yield
    update_check._state = original


class TestRunCheckOnce:
    @pytest.mark.asyncio
    async def test_skips_when_disabled(self, monkeypatch, reset_state):
        monkeypatch.setenv("BUILD_VERSION", "1.24.4")
        with patch("registry.core.update_check.settings") as mock_settings:
            mock_settings.update_check_enabled = False
            await _run_check_once()
        assert get_state().latest is None
        assert get_state().update_available is False

    @pytest.mark.asyncio
    async def test_skips_on_dev_build(self, monkeypatch, reset_state):
        monkeypatch.delenv("BUILD_VERSION", raising=False)
        with patch("registry.core.update_check.settings") as mock_settings:
            mock_settings.update_check_enabled = True
            await _run_check_once()
        assert get_state().latest is None

    @pytest.mark.asyncio
    async def test_skips_when_current_version_unparseable(
        self, monkeypatch, reset_state
    ):
        monkeypatch.setenv("BUILD_VERSION", "1.24.4")
        with (
            patch("registry.core.update_check.settings") as mock_settings,
            patch("registry.core.update_check.__version__", "abc123-not-a-version"),
        ):
            mock_settings.update_check_enabled = True
            await _run_check_once()
        assert get_state().latest is None

    @pytest.mark.asyncio
    async def test_detects_update_available(self, monkeypatch, reset_state):
        monkeypatch.setenv("BUILD_VERSION", "1.24.3")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = (
            b'{"tag_name":"1.24.4","html_url":"https://github.com/x/y/releases/tag/1.24.4"}'
        )
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with (
            patch("registry.core.update_check.settings") as mock_settings,
            patch("registry.core.update_check.__version__", "1.24.3"),
            patch("registry.core.update_check.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.update_check_enabled = True
            await _run_check_once()

        state = get_state()
        assert state.latest == "1.24.4"
        assert state.update_available is True
        assert state.release_notes_url == "https://github.com/x/y/releases/tag/1.24.4"
        assert state.checked_at is not None

    @pytest.mark.asyncio
    async def test_no_update_when_equal(self, monkeypatch, reset_state):
        monkeypatch.setenv("BUILD_VERSION", "1.24.4")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = (
            b'{"tag_name":"1.24.4","html_url":"https://github.com/x/y/releases/tag/1.24.4"}'
        )
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with (
            patch("registry.core.update_check.settings") as mock_settings,
            patch("registry.core.update_check.__version__", "1.24.4"),
            patch("registry.core.update_check.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.update_check_enabled = True
            await _run_check_once()

        assert get_state().update_available is False

    @pytest.mark.asyncio
    async def test_no_update_when_ahead(self, monkeypatch, reset_state):
        # Running version is newer than the released "latest" — never nudge.
        monkeypatch.setenv("BUILD_VERSION", "2.0.0")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = (
            b'{"tag_name":"1.24.4","html_url":"https://github.com/x/y/releases/tag/1.24.4"}'
        )
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with (
            patch("registry.core.update_check.settings") as mock_settings,
            patch("registry.core.update_check.__version__", "2.0.0"),
            patch("registry.core.update_check.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.update_check_enabled = True
            await _run_check_once()

        assert get_state().update_available is False

    @pytest.mark.asyncio
    async def test_fail_silent_on_network_error(self, monkeypatch, reset_state):
        monkeypatch.setenv("BUILD_VERSION", "1.24.3")
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("network down")
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with (
            patch("registry.core.update_check.settings") as mock_settings,
            patch("registry.core.update_check.__version__", "1.24.3"),
            patch("registry.core.update_check.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.update_check_enabled = True
            # Must not raise.
            await _run_check_once()

        assert get_state().latest is None
        assert get_state().update_available is False

    @pytest.mark.asyncio
    async def test_fail_silent_on_non_200(self, monkeypatch, reset_state):
        monkeypatch.setenv("BUILD_VERSION", "1.24.3")
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.content = b"{}"
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with (
            patch("registry.core.update_check.settings") as mock_settings,
            patch("registry.core.update_check.__version__", "1.24.3"),
            patch("registry.core.update_check.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.update_check_enabled = True
            await _run_check_once()

        assert get_state().latest is None

    @pytest.mark.asyncio
    async def test_rejects_non_http_release_url(self, monkeypatch, reset_state):
        monkeypatch.setenv("BUILD_VERSION", "1.24.3")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = (
            b'{"tag_name":"1.24.4","html_url":"javascript:alert(1)"}'
        )
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with (
            patch("registry.core.update_check.settings") as mock_settings,
            patch("registry.core.update_check.__version__", "1.24.3"),
            patch("registry.core.update_check.httpx.AsyncClient", return_value=mock_client),
        ):
            mock_settings.update_check_enabled = True
            await _run_check_once()

        assert get_state().latest is None
        assert get_state().release_notes_url is None


class TestStateSerialization:
    def test_to_dict_includes_check_enabled(self, reset_state):
        state = update_check._state
        state.latest = "1.24.4"
        state.update_available = True
        state.release_notes_url = "https://example.com/release"
        with patch("registry.core.update_check.settings") as mock_settings:
            mock_settings.update_check_enabled = True
            d = state.to_dict()
        assert d["latest"] == "1.24.4"
        assert d["update_available"] is True
        assert d["check_enabled"] is True
        assert "current" in d
        assert d["release_notes_url"] == "https://example.com/release"
