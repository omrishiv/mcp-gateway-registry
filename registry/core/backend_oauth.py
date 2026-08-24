"""Backend OAuth (client_credentials) token acquisition + in-process cache.

Lets the REGISTRY authenticate to an OAuth-backed MCP server as an OAuth2
client (RFC 6749 §4.4 ``client_credentials`` grant) when it performs health
checks and tool discovery -- the machine-to-machine analogue of the static
``bearer`` / ``api_key`` backend-auth schemes. This is the registry's OWN
credential to reach the upstream; it is unrelated to the per-user egress vault
(``registry/egress_auth/``), which brokers END-USER tokens through the gateway.

Config lives on the server record under ``auth_scheme == "oauth"`` +
``backend_oauth`` (token_url, client_id, encrypted client_secret, scopes,
token_auth_style, resource). The client_secret is Fernet-encrypted with the
same key as every other backend credential.

The header builders in ``registry/core/mcp_client.py`` and
``registry/health/service.py`` are synchronous, but acquiring a token is an
async network call. So the async discovery/health entrypoints call
:func:`with_bearer` to resolve+cache the token and stash it on a shallow copy of
``server_info`` under :data:`RESOLVED_BEARER_KEY`; the sync builders read that
key for the ``oauth`` scheme. Resolution is cached per server path with a
single-flight lock so concurrent health checks don't stampede the token
endpoint, and is invalidated when the config fingerprint changes.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from registry.core.config import settings
from registry.egress_auth import oauth_engine
from registry.egress_auth.schemas import OAuthProviderConfig, TokenEndpointAuthStyle
from registry.utils.credential_encryption import decrypt_credential

logger = logging.getLogger(__name__)

# Key under which the resolved bearer token is stashed on a server_info copy for
# the synchronous header builders to consume.
RESOLVED_BEARER_KEY = "_backend_oauth_bearer"

# TTL applied when the token endpoint returns no expiry hint (no ``expires_in``
# and no JWT ``exp``). Short, so an opaque token is re-acquired each cycle rather
# than cached indefinitely.
_DEFAULT_TTL_SECONDS = 60


@dataclass
class _CacheEntry:
    access_token: str
    # Epoch seconds; None means "no expiry known" -> use the default short TTL.
    expires_at_epoch: float | None
    fingerprint: str
    # Wall-clock epoch when acquired (used only for the no-expiry default TTL).
    acquired_epoch: float


_cache: dict[str, _CacheEntry] = {}
_locks: dict[str, asyncio.Lock] = {}
_locks_guard = asyncio.Lock()


def _server_path(server_info: dict) -> str | None:
    return server_info.get("service_path") or server_info.get("path")


def _fingerprint(bo: dict, client_secret_encrypted: str | None) -> str:
    """Stable hash of the config so an edited config invalidates the cache.

    Includes the encrypted secret (ciphertext) so a rotated secret forces a
    re-acquire without ever hashing plaintext.
    """
    material = "|".join(
        [
            str(bo.get("token_url") or ""),
            str(bo.get("client_id") or ""),
            str(bo.get("token_auth_style") or "post_body"),
            str(bo.get("scope_separator") or " "),
            str(bo.get("resource") or ""),
            ",".join(bo.get("scopes") or []),
            client_secret_encrypted or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _to_epoch(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso).timestamp()
    except ValueError:
        return None


def _is_fresh(entry: _CacheEntry) -> bool:
    now = datetime.now(UTC).timestamp()
    skew = max(0, settings.egress_token_refresh_skew_seconds)
    if entry.expires_at_epoch is not None:
        return entry.expires_at_epoch - now > skew
    # No known expiry: honor the short default TTL.
    return now - entry.acquired_epoch < _DEFAULT_TTL_SECONDS


def _build_cfg(bo: dict) -> OAuthProviderConfig:
    token_url = bo.get("token_url") or ""
    style_raw = bo.get("token_auth_style") or TokenEndpointAuthStyle.POST_BODY.value
    try:
        style = TokenEndpointAuthStyle(style_raw)
    except ValueError:
        style = TokenEndpointAuthStyle.POST_BODY
    return OAuthProviderConfig(
        name="backend-client-credentials",
        display_name="Backend OAuth (client credentials)",
        # authorize_url is unused for client_credentials but the model requires a
        # value; mirror token_url so the config is self-consistent.
        authorize_url=token_url,
        token_url=token_url,
        scope_separator=bo.get("scope_separator") or " ",
        token_endpoint_auth_style=style,
        use_pkce=False,
        resource=bo.get("resource") or None,
        is_builtin=False,
    )


async def _lock_for(key: str) -> asyncio.Lock:
    async with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _locks[key] = lock
        return lock


async def resolve_bearer(server_info: dict) -> str | None:
    """Return a valid backend OAuth access token for ``server_info``, or None.

    Returns None (rather than raising) on any misconfiguration or token-endpoint
    failure so the caller simply omits the Authorization header -- the health
    check then fails/records unhealthy, which is the correct signal. Cached per
    server path with a single-flight lock and config-fingerprint invalidation.
    """
    if server_info.get("auth_scheme") != "oauth":
        return None
    bo = server_info.get("backend_oauth") or {}
    token_url = bo.get("token_url")
    client_id = bo.get("client_id")
    if not token_url or not client_id:
        logger.warning(
            "backend oauth misconfigured (missing token_url/client_id) path=%s",
            _server_path(server_info),
        )
        return None

    secret_encrypted = bo.get("client_secret_encrypted")
    fingerprint = _fingerprint(bo, secret_encrypted)
    key = _server_path(server_info) or fingerprint

    # Fast path: fresh cache hit for the current config.
    entry = _cache.get(key)
    if entry and entry.fingerprint == fingerprint and _is_fresh(entry):
        return entry.access_token

    lock = await _lock_for(key)
    async with lock:
        # Double-check under the lock: another waiter may have just acquired.
        entry = _cache.get(key)
        if entry and entry.fingerprint == fingerprint and _is_fresh(entry):
            return entry.access_token

        client_secret = decrypt_credential(secret_encrypted) if secret_encrypted else None
        cfg = _build_cfg(bo)
        scopes = bo.get("scopes") or []
        try:
            token = await oauth_engine.client_credentials_token(
                cfg, client_id, client_secret, scopes
            )
        except oauth_engine.OAuthEngineError as exc:
            logger.warning(
                "backend oauth token acquisition failed path=%s error=%s",
                _server_path(server_info),
                exc,
            )
            return None

        _cache[key] = _CacheEntry(
            access_token=token.access_token,
            expires_at_epoch=_to_epoch(token.expires_at),
            fingerprint=fingerprint,
            acquired_epoch=datetime.now(UTC).timestamp(),
        )
        logger.info(
            "backend oauth token acquired path=%s expires_at=%s",
            _server_path(server_info),
            token.expires_at,
        )
        return token.access_token


async def resolve_discovery_bearer(server_info: dict) -> str | None:
    """Borrow the designated per-user identity's vaulted token for headless
    discovery against an OAuth 2.1 (per-user) server. None when not configured,
    not connected, or the vaulted token is dead/near-expiry-unrefreshable.

    Uses the server's OWN backend-auth discovery config (``oauth_discovery.oauth``)
    -- independent of egress. Delegates to the shared OAuth vault
    (``get_valid_token``), which handles refresh, single-flight, and client-id
    rebinding.
    """
    disc = server_info.get("oauth_discovery") or {}
    if not disc.get("enabled"):
        return None
    oauth_cfg = disc.get("oauth")
    auth_method = disc.get("auth_method")
    user_id = disc.get("user_id")
    if not oauth_cfg or not auth_method or not user_id:
        logger.warning(
            "oauth discovery misconfigured (missing oauth config/principal) path=%s",
            _server_path(server_info),
        )
        return None
    server_path = _server_path(server_info)
    try:
        from registry.egress_auth.factory import get_egress_auth_service

        token = await get_egress_auth_service().get_valid_token(
            auth_method=auth_method,
            user_id=user_id,
            server_path=server_path,
            egress_oauth=oauth_cfg,
        )
    except Exception as exc:  # egress/vault/refresh failure -> degrade, don't crash discovery
        logger.warning(
            "oauth discovery token borrow failed path=%s error=%s",
            server_path,
            type(exc).__name__,
        )
        return None
    if not token:
        logger.info(
            "oauth discovery: no valid vaulted token for path=%s (identity not "
            "connected or refresh failed)",
            server_path,
        )
    return token


async def with_bearer(server_info: dict) -> dict:
    """Return ``server_info`` unchanged, or a shallow copy carrying a resolved
    OAuth bearer token under :data:`RESOLVED_BEARER_KEY`.

    Resolves, in order: (1) client_credentials (``auth_scheme == 'oauth'``), then
    (2) a borrowed per-user discovery-identity token (``oauth_discovery.enabled``).
    No-op when neither applies, so callers invoke it unconditionally before
    building request headers.
    """
    if not server_info:
        return server_info
    token: str | None = None
    if server_info.get("auth_scheme") == "oauth":
        token = await resolve_bearer(server_info)
    if token is None:
        token = await resolve_discovery_bearer(server_info)
    if not token:
        return server_info
    return {**server_info, RESOLVED_BEARER_KEY: token}


def invalidate(server_path: str) -> None:
    """Drop any cached token for a server path (call after a config change)."""
    _cache.pop(server_path, None)
