"""
AuditLogger service for writing audit events to MongoDB.

This module provides the core audit logging service that writes
audit events to MongoDB for persistent storage and querying.
"""

import asyncio
import logging
from typing import TYPE_CHECKING, Optional, Union

from .models import MCPServerAccessRecord, RegistryApiAccessRecord, TokenMintAuditRecord

if TYPE_CHECKING:
    from ..repositories.audit_repository import AuditRepositoryBase

logger = logging.getLogger(__name__)


def _record_integrity_degradation(reason: str) -> None:
    """Increment the rate-alertable audit-integrity counter.

    Lazily imported (the `webhook_service` / `lifecycle_events` precedent) so
    that importing this module from the auth-server process -- which bootstraps
    its OWN meter provider in `auth_server.observability.meters` -- does not pull
    in a second one. Never raises: a metrics failure must not turn an audit
    problem into a request failure.

    `reason` is a code-supplied constant, never caller data, so the label
    cardinality stays bounded.
    """
    try:
        from ..observability.meters import audit_integrity_degraded_total

        audit_integrity_degraded_total.add(1, {"reason": reason})
    except Exception as exc:
        logger.warning("audit_integrity_degraded_total emit failed: %s", exc)


class NonDurableAuditError(RuntimeError):
    """Raised when audit logging would run without a durable sink and the
    deployment requires a durable audit trail.

    Fail-closed guard for the repudiation threat: best-effort JSON log lines are
    not a dependable audit trail (lost on restart, not queryable, rotated away).
    """


def enforce_durable_audit_sink(
    durable_sink_available: bool,
    require_durable: bool,
) -> None:
    """Enforce the durable-audit-sink policy, failing closed by default.

    Called during application startup after resolving whether a durable audit
    sink (MongoDB/DocumentDB) is actually available. When no durable sink is
    available:

    - if ``require_durable`` is True (the default deployment posture), raise
      :class:`NonDurableAuditError` so the application refuses to start rather
      than silently degrading to a non-durable audit trail;
    - if ``require_durable`` is False (explicit dev opt-out), emit a loud
      warning and allow startup to continue with best-effort log lines.

    Args:
        durable_sink_available: Whether a durable audit sink is available and
            wired up.
        require_durable: Whether the deployment requires a durable audit trail
            (``AUDIT_LOG_REQUIRE_DURABLE``).

    Raises:
        NonDurableAuditError: If no durable sink is available and
            ``require_durable`` is True.
    """
    if durable_sink_available:
        return

    if require_durable:
        logger.error(
            "Audit logging is enabled but no durable audit sink is available "
            "(MongoDB disabled or unreachable). Refusing to start with a "
            "non-durable audit trail. Provision the audit datastore, or set "
            "AUDIT_LOG_REQUIRE_DURABLE=false to explicitly accept a "
            "non-durable (best-effort log-line) audit trail."
        )
        raise NonDurableAuditError(
            "Non-durable audit trail refused: durable audit sink unavailable "
            "and AUDIT_LOG_REQUIRE_DURABLE is enabled. Provision the audit "
            "datastore or explicitly set AUDIT_LOG_REQUIRE_DURABLE=false."
        )

    logger.warning(
        "Audit logging is running WITHOUT a durable sink "
        "(AUDIT_LOG_REQUIRE_DURABLE=false). Audit records are best-effort log "
        "lines only and may be lost; this is unsafe for any repudiation-"
        "sensitive deployment. Enable MongoDB audit storage for a durable "
        "audit trail."
    )


class AuditWriteError(RuntimeError):
    """Raised by ``AuditLogger.log_event(..., fail_closed=True)`` when the
    durable audit write fails, so the caller can fail the request.
    """


class AuditLogger:
    """
    Async audit logger for MongoDB storage.

    Writes audit events to MongoDB for persistent storage. Events can be
    queried through the audit API endpoints.

    Attributes:
        stream_name: Name of the audit stream for categorization
        mongodb_enabled: Whether MongoDB logging is enabled
    """

    def __init__(
        self,
        log_dir: str = "logs/audit",
        rotation_hours: int = 1,
        rotation_max_mb: int = 100,
        local_retention_hours: int = 24,
        stream_name: str = "registry-api-access",
        mongodb_enabled: bool = False,
        audit_repository: Optional["AuditRepositoryBase"] = None,
    ):
        """
        Initialize the AuditLogger.

        Args:
            log_dir: Deprecated - no longer used (kept for backward compatibility)
            rotation_hours: Deprecated - no longer used (kept for backward compatibility)
            rotation_max_mb: Deprecated - no longer used (kept for backward compatibility)
            local_retention_hours: Deprecated - no longer used (kept for backward compatibility)
            stream_name: Name of the audit stream for categorization
            mongodb_enabled: Whether to write audit events to MongoDB
            audit_repository: Repository for MongoDB writes (required if mongodb_enabled)
        """
        self.stream_name = stream_name
        self.mongodb_enabled = mongodb_enabled
        self._audit_repository = audit_repository

        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

        if mongodb_enabled and audit_repository:
            logger.info(f"Audit logging enabled for stream: {stream_name} (MongoDB)")
        elif not mongodb_enabled:
            logger.warning(f"Audit logging disabled for stream: {stream_name}")

    async def log_event(
        self,
        record: Union[RegistryApiAccessRecord, "MCPServerAccessRecord", TokenMintAuditRecord],
        fail_closed: bool = False,
    ) -> None:
        """
        Write an audit record to the durable store (MongoDB).

        This method is thread-safe. If a durable sink is not available (audit
        disabled or MongoDB not wired up) the event is dropped: startup already
        fails closed on a missing durable sink when AUDIT_LOG_REQUIRE_DURABLE is
        set, so reaching this path means an operator explicitly opted into a
        non-durable trail.

        A failed durable write (transient MongoDB unavailability, etc.) is
        always logged as a distinct CRITICAL event and counted, so the loss is
        loud and alertable. With ``fail_closed`` the failure is then raised as
        :class:`AuditWriteError` so the caller fails the request: a mutating
        request must not succeed without its audit record. Without it (safe
        reads) the write stays best-effort and the request is not failed.

        Args:
            record: The audit record to log.
            fail_closed: Raise ``AuditWriteError`` when the durable write fails.

        Raises:
            AuditWriteError: If ``fail_closed`` and the durable write failed.
        """
        if not self.mongodb_enabled or not self._audit_repository:
            return

        async with self._lock:
            try:
                # The repository contract returns False when the insert failed
                # (DocumentDBAuditRepository logs and swallows the driver error).
                # Compare with "is False" so a repository returning None is not
                # mistaken for a failure.
                if await self._audit_repository.insert(record) is False:
                    raise AuditWriteError("audit repository reported a failed insert")
            except Exception as e:
                # Log only identifying context, never the full record (avoids
                # leaking any sensitive field the record may carry).
                logger.critical(
                    "AUDIT RECORD DROPPED: durable write failed (log_type=%s request_id=%s): %s",
                    getattr(record, "log_type", "unknown"),
                    getattr(record, "request_id", "unknown"),
                    e,
                )
                _record_integrity_degradation("record_dropped")
                if fail_closed:
                    raise AuditWriteError("durable audit write failed") from e

    async def update_outcome(
        self,
        record: RegistryApiAccessRecord,
    ) -> None:
        """
        Write the outcome of a request onto its already inserted audit record.

        Used for mutating requests, whose record is inserted (fail closed)
        before the handler runs. By the time this runs the change is committed
        and the attempt is durably recorded, so a failure never raises: it is
        logged as a CRITICAL dropped-record event and counted instead.

        Args:
            record: The completed audit record (same request_id and log_type
                as the inserted one).
        """
        if not self.mongodb_enabled or not self._audit_repository:
            return

        async with self._lock:
            try:
                # Same "is False" contract as insert(): False means no record
                # was updated (missing record or a swallowed driver error).
                if await self._audit_repository.update_outcome(record) is False:
                    raise AuditWriteError("audit repository reported a failed outcome update")
            except Exception as e:
                logger.critical(
                    "AUDIT RECORD DROPPED: outcome update failed; the record stays "
                    "pending (log_type=%s request_id=%s): %s",
                    record.log_type,
                    record.request_id,
                    e,
                )
                _record_integrity_degradation("record_dropped")

    async def close(self) -> None:
        """
        Close the audit logger.

        This method exists for backward compatibility and cleanup.
        """
        logger.debug(f"Audit logger closed for stream: {self.stream_name}")

    @property
    def current_file_path(self) -> str | None:
        """Deprecated - returns None (no local files)."""
        return None

    @property
    def is_open(self) -> bool:
        """Check if the audit logger is operational."""
        return self.mongodb_enabled and self._audit_repository is not None
