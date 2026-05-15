"""Unit tests for EntraIdProvider Graph group-overage handling (#929)."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from auth_server.providers.entra import EntraIdProvider


class TestHasGroupOverage:
    """has_group_overage classifies the two indicator formats Entra uses."""

    def test_hasgroups_true_is_overage(self):
        assert EntraIdProvider.has_group_overage({"hasgroups": True}) is True

    def test_hasgroups_false_is_not_overage(self):
        assert EntraIdProvider.has_group_overage({"hasgroups": False}) is False

    def test_claim_names_groups_is_overage(self):
        claims = {"_claim_names": {"groups": "https://graph.microsoft.com/..."}}
        assert EntraIdProvider.has_group_overage(claims) is True

    def test_claim_names_without_groups_is_not_overage(self):
        claims = {"_claim_names": {"src1": "https://example.com"}}
        assert EntraIdProvider.has_group_overage(claims) is False

    def test_no_indicators_is_not_overage(self):
        assert EntraIdProvider.has_group_overage({"groups": ["g1"]}) is False

    def test_empty_claims_is_not_overage(self):
        assert EntraIdProvider.has_group_overage({}) is False


def _mock_response(payload: dict, status_code: int = 200):
    """Build a httpx.Response-shaped mock that supports raise_for_status + json."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    if status_code >= 400:
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"{status_code}", request=MagicMock(), response=response
        )
    else:
        response.raise_for_status.return_value = None
    return response


class TestFetchGroupsViaGraph:
    """fetch_groups_via_graph paginates, filters, dedupes, and degrades safely."""

    @pytest.mark.asyncio
    async def test_returns_only_group_object_ids(self):
        page = {
            "value": [
                {"@odata.type": "#microsoft.graph.group", "id": "g-1"},
                {"@odata.type": "#microsoft.graph.directoryRole", "id": "role-1"},
                {"@odata.type": "#microsoft.graph.group", "id": "g-2"},
            ]
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_mock_response(page))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            ids = await EntraIdProvider.fetch_groups_via_graph("token")

        assert ids == ["g-1", "g-2"]

    @pytest.mark.asyncio
    async def test_pagination_combines_pages(self):
        page1 = {
            "value": [{"@odata.type": "#microsoft.graph.group", "id": "g-1"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/memberOf?$skiptoken=foo",
        }
        page2 = {"value": [{"@odata.type": "#microsoft.graph.group", "id": "g-2"}]}

        responses = [_mock_response(page1), _mock_response(page2)]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=responses)
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            ids = await EntraIdProvider.fetch_groups_via_graph("token")

        assert ids == ["g-1", "g-2"]
        assert mock_client.get.await_count == 2

    @pytest.mark.asyncio
    async def test_dedupes_repeated_ids_across_pages(self):
        page1 = {
            "value": [{"@odata.type": "#microsoft.graph.group", "id": "g-1"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/memberOf?$skiptoken=foo",
        }
        page2 = {
            "value": [
                {"@odata.type": "#microsoft.graph.group", "id": "g-1"},
                {"@odata.type": "#microsoft.graph.group", "id": "g-2"},
            ]
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[_mock_response(page1), _mock_response(page2)])
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            ids = await EntraIdProvider.fetch_groups_via_graph("token")

        assert ids == ["g-1", "g-2"]

    @pytest.mark.asyncio
    async def test_403_returns_empty_list(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_mock_response({"error": "forbidden"}, 403))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            ids = await EntraIdProvider.fetch_groups_via_graph("token")

        assert ids == []

    @pytest.mark.asyncio
    async def test_network_error_returns_empty_list(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("dns failed"))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            ids = await EntraIdProvider.fetch_groups_via_graph("token")

        assert ids == []

    @pytest.mark.asyncio
    async def test_hard_cap_truncates(self, monkeypatch):
        monkeypatch.setattr(EntraIdProvider, "GROUP_FETCH_HARD_CAP", 5)
        page = {
            "value": [
                {"@odata.type": "#microsoft.graph.group", "id": f"g-{i}"} for i in range(10)
            ]
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_mock_response(page))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            ids = await EntraIdProvider.fetch_groups_via_graph("token")

        assert len(ids) == 5
        assert ids == [f"g-{i}" for i in range(5)]

    @pytest.mark.asyncio
    async def test_url_inferred_from_login_base_url_us_gov(self, monkeypatch):
        """US Gov ENTRA_LOGIN_BASE_URL → graph.microsoft.us, no extra config."""
        monkeypatch.setenv("ENTRA_LOGIN_BASE_URL", "https://login.microsoftonline.us")
        monkeypatch.delenv("ENTRA_GRAPH_BASE_URL", raising=False)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_mock_response({"value": []}))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            await EntraIdProvider.fetch_groups_via_graph("token")

        url = mock_client.get.call_args[0][0]
        assert url.startswith("https://graph.microsoft.us/")

    @pytest.mark.asyncio
    async def test_explicit_graph_base_url_overrides_inference(self, monkeypatch):
        """Explicit ENTRA_GRAPH_BASE_URL beats the login-URL inference."""
        monkeypatch.setenv("ENTRA_LOGIN_BASE_URL", "https://login.microsoftonline.com")
        monkeypatch.setenv("ENTRA_GRAPH_BASE_URL", "https://graph.proxy.example.com")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_mock_response({"value": []}))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            await EntraIdProvider.fetch_groups_via_graph("token")

        url = mock_client.get.call_args[0][0]
        assert url.startswith("https://graph.proxy.example.com/")

    @pytest.mark.asyncio
    async def test_authorization_header_uses_bearer_token(self):
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_mock_response({"value": []}))
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None

        with patch("auth_server.providers.entra.httpx.AsyncClient", return_value=mock_client):
            await EntraIdProvider.fetch_groups_via_graph("the-access-token")

        mock_client.get.assert_awaited_once()
        _args, kwargs = mock_client.get.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer the-access-token"
