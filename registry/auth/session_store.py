"""Registry-side reader for the OAuth session store.

The auth server writes session records (see auth_server/session_store.py). The
registry only needs to read and delete them, so this module is a slim mirror.

Failure semantics: every operation returns None / False on failure. We never
raise from a transient store outage — callers translate that into 401.
"""

import logging
import os
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from motor.motor_asyncio import AsyncIOMotorCollection
from pymongo import ReadPreference, WriteConcern

from ..repositories.documentdb.client import get_collection_name, get_documentdb_client

logger = logging.getLogger(__name__)

COLLECTION_BASE_NAME: str = "oauth_sessions"
HKDF_INFO: bytes = b"mcp-gateway-session-id-token-encryption"

_collection: AsyncIOMotorCollection | None = None
_aesgcm: AESGCM | None = None


def _derive_token_encryption_key() -> bytes:
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY required for session token encryption")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    )
    return hkdf.derive(secret.encode("utf-8"))


def _get_aesgcm() -> AESGCM:
    global _aesgcm
    if _aesgcm is None:
        _aesgcm = AESGCM(_derive_token_encryption_key())
    return _aesgcm


def _decrypt_id_token(blob: bytes) -> str:
    nonce, ct = blob[:12], blob[12:]
    return _get_aesgcm().decrypt(nonce, ct, associated_data=None).decode("utf-8")


async def _get_collection() -> AsyncIOMotorCollection:
    """Get the oauth_sessions collection.

    Uses the registry's namespaced collection naming (`<base>_<namespace>`).
    Compatible with both AWS DocumentDB and MongoDB Community Edition. The
    auth server (writer) creates indexes on first access; the registry only
    reads and deletes, so it does not duplicate index management here.
    """
    global _collection
    if _collection is not None:
        return _collection
    db = await get_documentdb_client()
    _collection = db.get_collection(
        get_collection_name(COLLECTION_BASE_NAME),
        write_concern=WriteConcern(w="majority"),
        read_preference=ReadPreference.PRIMARY_PREFERRED,
    )
    return _collection


async def resolve_session(session_id: str) -> dict[str, Any] | None:
    """Hydrate a session record by id, decrypting id_token if present."""
    if not session_id:
        return None

    try:
        collection = await _get_collection()
        doc = await collection.find_one({"session_id": session_id})
    except Exception as e:
        logger.warning(f"Session store read failed: {e}")
        return None

    if not doc:
        return None

    expires_at = doc.get("expires_at")
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            return None

    result: dict[str, Any] = {
        "session_id": doc["session_id"],
        "username": doc.get("username"),
        "email": doc.get("email"),
        "name": doc.get("name"),
        "groups": doc.get("groups", []),
        "provider": doc.get("provider"),
        "auth_method": doc.get("auth_method"),
    }

    encrypted = doc.get("id_token_encrypted")
    if encrypted:
        try:
            result["id_token"] = _decrypt_id_token(encrypted)
        except Exception as e:
            logger.warning(f"Failed to decrypt id_token for session: {e}")

    return result


async def delete_session(session_id: str) -> bool:
    """Delete a session by id. Returns True if a document was removed."""
    if not session_id:
        return False
    try:
        collection = await _get_collection()
        result = await collection.delete_one({"session_id": session_id})
        return result.deleted_count > 0
    except Exception as e:
        logger.warning(f"Session store delete failed: {e}")
        return False
