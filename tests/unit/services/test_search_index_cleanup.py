"""Unit tests for search_index_cleanup helper (issue #1145)."""

from unittest.mock import AsyncMock, patch

import pytest

from registry.services.search_index_cleanup import remove_from_search_index_with_retry


@pytest.mark.unit
class TestRemoveFromSearchIndexWithRetry:
    @pytest.mark.asyncio
    async def test_returns_true_on_first_success(self):
        search_repo = AsyncMock()
        search_repo.remove_entity.return_value = True

        result = await remove_from_search_index_with_retry(
            search_repo,
            "/server-a",
            entity_type="mcp_server",
            max_attempts=3,
            retry_delay_seconds=0,
        )

        assert result is True
        search_repo.remove_entity.assert_awaited_once_with("/server-a")

    @pytest.mark.asyncio
    async def test_retries_then_succeeds(self):
        search_repo = AsyncMock()
        search_repo.remove_entity.side_effect = [False, True]

        result = await remove_from_search_index_with_retry(
            search_repo,
            "/server-a",
            entity_type="mcp_server",
            max_attempts=3,
            retry_delay_seconds=0,
        )

        assert result is True
        assert search_repo.remove_entity.await_count == 2

    @pytest.mark.asyncio
    async def test_returns_false_and_increments_metric_after_exhausted_retries(self):
        search_repo = AsyncMock()
        search_repo.remove_entity.return_value = False

        with patch(
            "registry.services.search_index_cleanup._record_embedding_removal_failure"
        ) as mock_metric:
            result = await remove_from_search_index_with_retry(
                search_repo,
                "/server-a",
                entity_type="mcp_server",
                max_attempts=2,
                retry_delay_seconds=0,
            )

        assert result is False
        assert search_repo.remove_entity.await_count == 2
        mock_metric.assert_called_once_with("mcp_server")
