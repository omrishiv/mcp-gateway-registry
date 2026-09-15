"""Single source of truth for "is this record owned by a peer registry".

A record synced from a peer is content-owned by its source: the local registry
re-``$set``s every peer-supplied field on each sync, so a local write either
diverges silently or is reverted later. Every write path -- API mutation routes
AND background writers such as the health monitor's tool refresh -- must ask this
question the same way, so the rule lives here in a leaf module that the api,
services and health layers can all import.

NOT the same question as ``proxy_mixin._is_federated``: that one gates whether a
record may become a live gateway route and deliberately ignores a local detach,
because peer-supplied data must never reach the proxy chain no matter what an
operator flipped. This one gates local MUTABILITY, which an operator CAN take
over (see ``POST /api/peers/local-override``).
"""

from typing import Any

UNKNOWN_PEER = "unknown peer registry"


def is_locally_detached(doc: dict[str, Any] | None) -> bool:
    """Return True when an operator has detached this record from its source.

    ``sync_metadata.local_overrides`` is set by
    ``PeerFederationService.set_local_override``
    (``POST /api/peers/local-override``) and has two inseparable halves, which is
    why both live behind this one predicate: peer sync SKIPS a detached record
    (``PeerFederationService.is_locally_overridden``), and *because* sync skips it
    a local write is durable, so ``peer_owned_source`` hands ownership back to the
    local registry. Reading the flag in only one of the two places would either
    revert local edits on the next sync or freeze a record nothing will refresh.

    Any truthy value detaches: the flag has been stored as a bool and (via the
    same route) as a dict of overridden fields. Malformed ``sync_metadata`` reads
    as "not detached", which keeps the record peer-owned and in step with its
    source rather than silently unlocking it.
    """
    if not doc:
        return False
    sync_metadata = doc.get("sync_metadata")
    if not isinstance(sync_metadata, dict):
        return False
    return bool(sync_metadata.get("local_overrides"))


def peer_owned_source(doc: dict[str, Any] | None) -> str | None:
    """Return the source peer id when this record is owned by a peer registry.

    A record is peer-owned when ``sync_metadata`` marks it ``is_federated`` or
    ``is_read_only`` -- UNLESS an operator detached it with ``local_overrides``
    (``PeerFederationService.set_local_override``, exposed as
    ``POST /api/peers/local-override``). Sync SKIPS a detached record, so local
    edits to it are durable and cannot silently diverge from the source.

    Args:
        doc: The stored record (server document, or an agent's ``model_dump()``
            / any mapping carrying ``sync_metadata``). ``None`` is treated as
            locally owned; callers handle existence separately.

    Returns:
        The source peer id (``UNKNOWN_PEER`` when the record is flagged but the
        peer id was not stored) for a peer-owned record; ``None`` when the record
        is locally owned.
    """
    if not doc:
        return None
    if is_locally_detached(doc):
        return None
    sync_metadata = doc.get("sync_metadata")
    if not isinstance(sync_metadata, dict):
        return None
    if sync_metadata.get("is_federated") or sync_metadata.get("is_read_only"):
        return sync_metadata.get("source_peer_id") or UNKNOWN_PEER
    return None


def caller_owns_record(doc: dict[str, Any], username: str | None) -> bool:
    """Return True when ``username`` is positively established as the registrant.

    Fail-closed object-ownership rule shared by the server and agent mutation
    families: a blank/absent stored ``registered_by`` or a blank/absent caller
    ``username`` denies, so two empty identities can never compare equal. This
    matters because federation ingest stores ``registered_by = ""`` on a synced
    record (a peer must not name local owners) and a token minted without ``sub``
    yields ``username == ""``.

    Admin bypass is deliberately NOT here: callers decide whether an admin may
    bypass ownership for their operation.

    Args:
        doc: The stored record.
        username: The caller's username.

    Returns:
        True only if both identities are non-empty and equal.
    """
    registered_by = doc.get("registered_by")
    return bool(registered_by) and bool(username) and registered_by == username
