"""EgressAuthService factory.

Builds the service singleton from settings + the SecretStore (mirrors the
repositories/secrets factory pattern). The replay guard and cross-replica
refresh lease are wired here in Phase 3; for now the service's in-process
defaults are used until those land.
"""

import logging

from registry.core.config import settings
from registry.egress_auth.service import EgressAuthService
from registry.secrets.factory import get_secret_store

logger = logging.getLogger(__name__)

_egress_service: EgressAuthService | None = None


def get_egress_auth_service() -> EgressAuthService:
    """Get the EgressAuthService singleton."""
    global _egress_service
    if _egress_service is not None:
        return _egress_service

    logger.info("Creating EgressAuthService (secret_store=%s)", settings.secret_store_backend)
    _egress_service = EgressAuthService(
        secret_store=get_secret_store(),
        callback_base_url=settings.egress_oauth_callback_base_url,
        refresh_skew_seconds=settings.egress_token_refresh_skew_seconds,
        state_ttl_seconds=settings.egress_state_ttl_seconds,
    )
    return _egress_service


def reset_egress_auth_service() -> None:
    """Reset the singleton. USE ONLY IN TESTS."""
    global _egress_service
    _egress_service = None
