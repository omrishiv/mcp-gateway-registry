"""Cross-gateway credential providers for peer-to-peer runtime routing.

This module defines the pluggable interface for attaching credentials to
outbound cross-gateway calls, and the initial static-token implementation.

Security design:
- Credentials are NEVER logged (not even prefixes — a base64 JWT fragment
  is reconstructable; log only presence/absence and length).
- Credentials are NEVER forwarded from the caller's inbound request — they
  are resolved server-side from the peer configuration.
- The provider fails closed: a missing or empty credential raises rather
  than silently sending an unauthenticated request.
- The interface is deliberately narrow so future implementations (signed JWT,
  mTLS) can be swapped without touching the proxy endpoint.

Upgrade path:
- StaticTokenCredentialProvider → SignedJwtCredentialProvider (per-call signed JWT)
- The proxy endpoint calls get_headers_for_peer() and attaches whatever
  headers are returned. It does not know or care what credential type is used.
"""

import logging
from collections.abc import Callable
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class CrossGatewayCredentialError(Exception):
    """Raised when a credential cannot be resolved for a peer.

    The proxy endpoint catches this and returns 502 (bad gateway) — fail closed,
    never send an unauthenticated request.
    """

    def __init__(self, peer_id: str, reason: str):
        self.peer_id = peer_id
        self.reason = reason
        # Never include the credential value in the error message
        super().__init__(f"Cannot resolve credential for peer '{peer_id}': {reason}")


class CrossGatewayCredentialProvider(Protocol):
    """Protocol for providing credentials to outbound cross-gateway calls.

    Implementations resolve credentials for a specific peer and return HTTP
    headers to attach to the outbound request. The proxy endpoint is agnostic
    to the credential type — it attaches whatever headers are returned.

    Security contract:
    - MUST fail closed (raise CrossGatewayCredentialError) if no valid
      credential can be resolved. Never return empty headers silently.
    - MUST NOT log credential values.
    - MUST NOT include credentials from the inbound request.
    """

    async def get_headers_for_peer(
        self,
        peer_id: str,
        target_path: str,
        calling_subject: str,
        calling_auth_method: str,
        calling_scopes: list[str],
    ) -> dict[str, str]:
        """Return HTTP headers to attach to the outbound cross-gateway request.

        Args:
            peer_id: ID of the target peer registry.
            target_path: Resource path being accessed on the peer.
            calling_subject: Authenticated identity of the caller at our gateway.
            calling_auth_method: How the caller authenticated (oidc, api_key, etc).
            calling_scopes: Scopes the caller holds at our gateway.

        Returns:
            Dict of headers to merge into the outbound request.
            Typically {"Authorization": "Bearer <token>"}.

        Raises:
            CrossGatewayCredentialError: If no valid credential can be resolved.
                The proxy endpoint MUST NOT proceed without credentials.
        """
        ...


class StaticTokenCredentialProvider:
    """Provides the peer's configured federation_token as a Bearer credential.

    This is the initial implementation — reuses the same static token used for
    federation metadata sync. It will be replaced by a signed JWT credential
    provider once the federation keypair ships.

    Security properties:
    - Token is resolved from the stored peer config (never from the request).
    - Token presence and non-emptiness are validated (fail closed).
    - Token value is never logged.
    - If the peer has no token configured, raises immediately.
    """

    def __init__(
        self,
        peer_config_loader: Callable[[str], Any | None],
    ):
        """Initialize with a callable that loads peer config by peer_id.

        Args:
            peer_config_loader: Async or sync callable that returns a
                PeerRegistryConfig (or dict with federation_token) for a
                peer_id, or None if the peer is not found.
        """
        self._load_peer = peer_config_loader

    async def get_headers_for_peer(
        self,
        peer_id: str,
        target_path: str,
        calling_subject: str,
        calling_auth_method: str,
        calling_scopes: list[str],
    ) -> dict[str, str]:
        """Return Bearer token headers for the peer.

        Resolves the federation_token from the peer's stored configuration.
        Fails closed if the peer is unknown or has no token configured.
        """
        peer_config = self._load_peer(peer_id)
        if peer_config is None:
            raise CrossGatewayCredentialError(peer_id, "peer not found in configuration")

        # Extract token — support both Pydantic model and dict
        token: str | None = None
        if hasattr(peer_config, "federation_token"):
            token = peer_config.federation_token
        elif isinstance(peer_config, dict):
            token = peer_config.get("federation_token")

        # Fail closed: no token = no request
        if not token or not token.strip():
            raise CrossGatewayCredentialError(
                peer_id, "no federation_token configured for this peer"
            )

        logger.debug(
            "Resolved cross-gateway credential for peer '%s' "
            "(target=%s, caller=%s, type=static_token)",
            peer_id,
            target_path,
            calling_subject,
        )

        return {"Authorization": f"Bearer {token.strip()}"}
