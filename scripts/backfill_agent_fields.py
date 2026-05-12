"""One-time backfill: normalize supported_protocol, trust_level, and visibility on existing agents and servers."""

import logging
import os

from pymongo import MongoClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger(__name__)

# Allow override via MONGODB_CONNECTION_STRING (Atlas, externally-managed, etc.)
MONGODB_URI = os.getenv("MONGODB_CONNECTION_STRING") or "mongodb://localhost:27017"
DB_NAME = os.getenv("DOCUMENTDB_DATABASE", "mcp_registry")
AGENTS_COLLECTION = "mcp_agents_default"
SERVERS_COLLECTION = "mcp_servers_default"


def _backfill_supported_protocol(
    collection,
) -> None:
    """Set supported_protocol='other' on agents that don't have the field."""
    result = collection.update_many(
        {"supported_protocol": {"$exists": False}},
        {"$set": {"supported_protocol": "other"}},
    )
    logger.info(f"supported_protocol backfill: {result.modified_count} agents updated")


def _backfill_trust_level(
    collection,
) -> None:
    """Update trust_level from 'unverified' to 'community' for consistency."""
    result = collection.update_many(
        {"trust_level": "unverified"},
        {"$set": {"trust_level": "community"}},
    )
    logger.info(f"trust_level backfill: {result.modified_count} agents updated")


def _backfill_visibility(
    collection,
    collection_name: str = "agents",
) -> None:
    """Normalize visibility from 'internal' to 'private' for consistency.

    The canonical value is 'private'. Legacy documents may have 'internal'
    which is now treated as an alias.
    """
    result = collection.update_many(
        {"visibility": "internal"},
        {"$set": {"visibility": "private"}},
    )
    logger.info(
        f"visibility backfill ({collection_name}): {result.modified_count} documents updated (internal -> private)"
    )


def backfill_agent_fields() -> None:
    """Run all backfill operations on agents and servers."""
    # Only force directConnection=True for the local default; if the caller
    # provided their own URI, it owns topology (replica sets, SRV, etc.).
    if os.getenv("MONGODB_CONNECTION_STRING"):
        client = MongoClient(MONGODB_URI)
    else:
        client = MongoClient(MONGODB_URI, directConnection=True)
    db = client[DB_NAME]

    # Backfill agents collection
    agents = db[AGENTS_COLLECTION]
    logger.info(f"Backfilling agents collection: {AGENTS_COLLECTION}")
    _backfill_supported_protocol(agents)
    _backfill_trust_level(agents)
    _backfill_visibility(agents, collection_name="agents")

    # Backfill servers collection
    servers = db[SERVERS_COLLECTION]
    logger.info(f"Backfilling servers collection: {SERVERS_COLLECTION}")
    _backfill_visibility(servers, collection_name="servers")

    logger.info("Backfill complete")


if __name__ == "__main__":
    backfill_agent_fields()
