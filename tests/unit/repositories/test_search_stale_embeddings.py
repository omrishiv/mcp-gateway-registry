"""Unit tests for stale embedding detection and admin cleanup (issue #1145)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from registry.repositories.documentdb.search_repository import DocumentDBSearchRepository


def _make_repo() -> DocumentDBSearchRepository:
    repo = DocumentDBSearchRepository()
    repo._collection = AsyncMock()
    return repo


@pytest.mark.unit
class TestFindStaleEmbeddings:
    """Tests for find_stale_embeddings."""

    @pytest.mark.asyncio
    async def test_reports_orphaned_index_entries(self):
        repo = _make_repo()

        mock_source_col = MagicMock()
        mock_source_cursor = AsyncMock()
        mock_source_cursor.to_list = AsyncMock(return_value=[{"_id": "/server-a"}])
        mock_source_col.find.return_value = mock_source_cursor

        mock_embeddings_cursor = AsyncMock()
        mock_embeddings_cursor.to_list = AsyncMock(
            return_value=[
                {"_id": "/server-a", "entity_type": "mcp_server", "name": "A", "is_enabled": True},
                {"_id": "/ghost", "entity_type": "mcp_server", "name": "Ghost", "is_enabled": True},
            ]
        )
        mock_embeddings_col = MagicMock()
        mock_embeddings_col.find.return_value = mock_embeddings_cursor

        mock_db = MagicMock()
        mock_db.__getitem__ = MagicMock(return_value=mock_source_col)

        with (
            patch.object(repo, "_get_collection", new_callable=AsyncMock, return_value=mock_embeddings_col),
            patch(
                "registry.repositories.documentdb.search_repository.get_documentdb_client",
                new_callable=AsyncMock,
                return_value=mock_db,
            ),
            patch(
                "registry.repositories.documentdb.search_repository.get_collection_name",
                side_effect=lambda name: name,
            ),
        ):
            result = await repo.find_stale_embeddings()

        assert result["total_stale"] == 1
        assert result["stale"][0]["path"] == "/ghost"


@pytest.mark.unit
class TestRemoveStaleEmbeddings:
    """Tests for remove_stale_embeddings."""

    @pytest.mark.asyncio
    async def test_calls_remove_entity_per_path(self):
        repo = _make_repo()

        with patch.object(
            repo,
            "remove_entity",
            new_callable=AsyncMock,
            return_value=True,
        ) as mock_remove:
            result = await repo.remove_stale_embeddings(["/ghost-a", "/ghost-b"])

        assert result["success"] == 2
        assert result["failed"] == 0
        assert result["total"] == 2
        assert mock_remove.await_count == 2

    @pytest.mark.asyncio
    async def test_records_failure_when_remove_returns_false(self):
        repo = _make_repo()

        with patch.object(
            repo,
            "remove_entity",
            new_callable=AsyncMock,
            side_effect=[True, False],
        ):
            result = await repo.remove_stale_embeddings(["/ghost-a", "/ghost-b"])

        assert result["success"] == 1
        assert result["failed"] == 1
        assert result["details"][1]["status"] == "failed"


@pytest.mark.unit
class TestRemoveEntity:
    """Tests for remove_entity return value."""

    @pytest.mark.asyncio
    async def test_returns_true_when_deleted(self):
        repo = _make_repo()
        mock_collection = AsyncMock()
        mock_collection.delete_one.return_value = MagicMock(deleted_count=1)
        repo._collection = mock_collection

        with patch.object(repo, "_get_collection", AsyncMock(return_value=mock_collection)):
            assert await repo.remove_entity("/server-a") is True

    @pytest.mark.asyncio
    async def test_returns_true_when_not_found(self):
        repo = _make_repo()
        mock_collection = AsyncMock()
        mock_collection.delete_one.return_value = MagicMock(deleted_count=0)
        repo._collection = mock_collection

        with patch.object(repo, "_get_collection", AsyncMock(return_value=mock_collection)):
            assert await repo.remove_entity("/missing") is True

    @pytest.mark.asyncio
    async def test_returns_false_on_exception(self):
        repo = _make_repo()
        mock_collection = AsyncMock()
        mock_collection.delete_one.side_effect = RuntimeError("db down")
        repo._collection = mock_collection

        with patch.object(repo, "_get_collection", AsyncMock(return_value=mock_collection)):
            assert await repo.remove_entity("/server-a") is False
