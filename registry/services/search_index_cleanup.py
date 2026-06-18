"""Hardened search-index removal for entity deletes (issue #1145)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_MAX_ATTEMPTS = 3
_DEFAULT_RETRY_DELAY_SECONDS = 0.1


async def remove_from_search_index_with_retry(
    search_repo: Any,
    path: str,
    *,
    entity_type: str,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    retry_delay_seconds: float = _DEFAULT_RETRY_DELAY_SECONDS,
) -> bool:
    """Remove a path from the search index with retries.

    Used during entity deletion so embedding removal happens before the
    source document is deleted. A failure aborts the delete and increments
    ``embedding_removal_failures_total`` for alerting.

    Args:
        search_repo: Search repository instance.
        path: Entity path in the search index.
        entity_type: Metric label (e.g. ``mcp_server``, ``skill``).
        max_attempts: Number of removal attempts before giving up.
        retry_delay_seconds: Base delay between attempts (linear backoff).

    Returns:
        True when removal succeeded (including idempotent not-found).
        False when all attempts failed.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            result = await search_repo.remove_entity(path)
            if result is False:
                raise RuntimeError("remove_entity reported failure")
            return True
        except Exception as exc:
            logger.warning(
                "Search index removal attempt %d/%d failed for %s (%s): %s",
                attempt,
                max_attempts,
                path,
                entity_type,
                exc,
            )
            if attempt < max_attempts:
                await asyncio.sleep(retry_delay_seconds * attempt)

    _record_embedding_removal_failure(entity_type)
    logger.error(
        "Failed to remove %s from search index after %d attempts",
        path,
        max_attempts,
    )
    return False


def _record_embedding_removal_failure(entity_type: str) -> None:
    try:
        from registry.core.metrics import EMBEDDING_REMOVAL_FAILURES_TOTAL

        EMBEDDING_REMOVAL_FAILURES_TOTAL.labels(entity_type=entity_type).inc()
    except Exception as exc:
        logger.debug("embedding_removal_failures_total increment failed: %s", exc)
