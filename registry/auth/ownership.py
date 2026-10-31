"""Record ownership keyed on the immutable ``owner_id`` identity.

``username`` is a display name derived from mutable or non-unique IdP claims
(GitHub ``login``, Auth0 ``nickname``, email, ...), so two principals can share
one. Ownership is therefore decided on ``owner_id``, which the auth server
derives injectively from the token's verified ``(issuer, subject)`` and the
registry carries in ``user_context["owner_id"]``. The value is opaque here and
compared by equality only.

Records created before ``owner_id`` existed carry only their username field
(``registered_by`` for servers and agents, ``owner`` for skills and custom
entities). Such a legacy record is owned by a caller whose non-empty username
equals that field, provided the caller has a non-empty ``owner_id``; the first
owner-authorized write then binds the record to the caller's ``owner_id``
(trust on first use, see :func:`legacy_owner_id_claim`), after which the
username no longer matters.

A falsy identity on either side never owns: a caller without ``owner_id``
owns nothing, and a record whose owner fields are all empty (for example a
record synced from a federation peer) is owned by nobody, so only admins can
manage it.
"""

import logging
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)

OWNER_ID_FIELD: str = "owner_id"
REGISTERED_BY_FIELD: str = "registered_by"
OWNER_FIELD: str = "owner"

# Returned by _identity for a value that is present but not a usable identity
# (a non-string, or a whitespace-only string). It never equals anything.
_INVALID: object = object()


def _identity(
    value: Any,
) -> Any:
    """Normalize an identity value.

    Args:
        value: A raw ``owner_id`` or username value.

    Returns:
        The string when it is non-empty and not whitespace-only, None when the
        value is absent (None or ""), and ``_INVALID`` for any other value.
    """
    if value is None or value == "":
        return None
    if isinstance(value, str) and value.strip():
        return value
    return _INVALID


def _field(
    record: Any,
    name: str,
) -> Any:
    """Read one field from a dict record or a model record.

    Args:
        record: A mapping or an object with attributes.
        name: The field name.

    Returns:
        The field value, or None when absent.
    """
    if record is None:
        return None
    if isinstance(record, Mapping):
        return record.get(name)
    return getattr(record, name, None)


def normalize_identity(
    value: Any,
) -> str | None:
    """Return ``value`` when it is a usable identity (``owner_id`` or username).

    Args:
        value: A raw identity from a token claim, session, context or record.

    Returns:
        The non-empty, non-whitespace string, else None.
    """
    identity = _identity(value)
    return identity if isinstance(identity, str) else None


def user_owner_id(
    user_context: Mapping[str, Any] | None,
) -> str | None:
    """Return the caller's ``owner_id`` when it is a usable identity.

    Args:
        user_context: The authenticated user context.

    Returns:
        The non-empty ``owner_id`` string, else None.
    """
    return normalize_identity((user_context or {}).get(OWNER_ID_FIELD))


def owner_query_clauses(
    user_context: Mapping[str, Any] | None,
    *,
    legacy_field: str = REGISTERED_BY_FIELD,
) -> list[dict[str, Any]]:
    """Return Mongo clauses matching exactly the records :func:`is_owner` grants.

    For list filters that must stay in lockstep with :func:`is_owner`: one
    clause for records bound to the caller's ``owner_id`` and one for legacy
    records (``owner_id`` null, absent or "") whose username field equals the
    caller's username. Combine each clause with the caller's other conditions.

    Args:
        user_context: The authenticated user context.
        legacy_field: The record's username field.

    Returns:
        The clauses; empty when the caller has no ``owner_id`` (owns nothing).
    """
    owner_id = user_owner_id(user_context)
    if owner_id is None:
        return []
    clauses: list[dict[str, Any]] = [{OWNER_ID_FIELD: owner_id}]
    username = normalize_identity((user_context or {}).get("username"))
    if username is not None:
        clauses.append({OWNER_ID_FIELD: {"$in": [None, ""]}, legacy_field: username})
    return clauses


def _owns_legacy(
    record: Any,
    user_context: Mapping[str, Any],
    legacy_field: str,
) -> bool:
    """Decide ownership of a record that has no ``owner_id``.

    Args:
        record: The record.
        user_context: The user context (its ``owner_id`` already checked).
        legacy_field: The record's username field.

    Returns:
        True when the record's username field and the caller's username are
        both usable and equal.
    """
    record_username = _identity(_field(record, legacy_field))
    user_username = _identity(user_context.get("username"))
    return isinstance(record_username, str) and record_username == user_username


def is_owner(
    record: Any,
    user_context: Mapping[str, Any] | None,
    *,
    legacy_field: str = REGISTERED_BY_FIELD,
) -> bool:
    """Return True when the caller owns ``record``.

    Ownership requires a non-empty caller ``owner_id`` and either an equal
    non-empty record ``owner_id``, or, for a legacy record with no
    ``owner_id``, an equal non-empty username in ``legacy_field``. A record
    ``owner_id`` that is present but not a non-empty string fails closed.
    Admin status is not considered here.

    Args:
        record: The stored record (dict or model).
        user_context: The authenticated user context.
        legacy_field: The record's username field: ``registered_by`` for
            servers and agents, ``owner`` for skills and custom entities.

    Returns:
        Whether the caller owns the record.
    """
    caller_owner_id = user_owner_id(user_context)
    if caller_owner_id is None:
        return False
    record_owner_id = _identity(_field(record, OWNER_ID_FIELD))
    if record_owner_id is _INVALID:
        return False
    if record_owner_id is not None:
        return record_owner_id == caller_owner_id
    return _owns_legacy(record, user_context, legacy_field)


def legacy_owner_id_claim(
    record: Any,
    user_context: Mapping[str, Any] | None,
    *,
    kind: str,
    path: str,
    legacy_field: str = REGISTERED_BY_FIELD,
) -> str | None:
    """Return the ``owner_id`` an owner-authorized write must bind to a legacy record.

    Call this only after the write has been authorized because the caller owns
    the record. When the record has no ``owner_id`` and the caller owns it by
    username, the caller's ``owner_id`` is returned for the caller to persist
    together with (or right after) its write, and the binding is logged. Any
    other case returns None and nothing is persisted.

    Args:
        record: The stored record before the write.
        user_context: The authenticated user context.
        kind: Record kind for the log line (``server``, ``agent``, ...).
        path: Record path for the log line.
        legacy_field: The record's username field.

    Returns:
        The caller's ``owner_id`` to persist, or None.
    """
    if _identity(_field(record, OWNER_ID_FIELD)) is not None:
        return None
    if not is_owner(record, user_context, legacy_field=legacy_field):
        return None
    owner_id = user_owner_id(user_context)
    logger.info(
        "Ownership backfill (trust on first use): binding legacy %s %s owned by "
        "%s=%r to owner_id=%r",
        kind,
        path,
        legacy_field,
        _field(record, legacy_field),
        owner_id,
    )
    return owner_id


def legacy_owner_id_update(
    record: Any,
    user_context: Mapping[str, Any] | None,
    *,
    kind: str,
    path: str,
    legacy_field: str = REGISTERED_BY_FIELD,
) -> dict[str, str]:
    """Return the ``$set`` fields binding a legacy record to its owner, if any.

    For write paths that persist a partial update dict: merge the result into
    the update after the ownership gate. See :func:`legacy_owner_id_claim`.

    Args:
        record: The stored record before the write.
        user_context: The authenticated user context.
        kind: Record kind for the log line.
        path: Record path for the log line.
        legacy_field: The record's username field.

    Returns:
        ``{"owner_id": value}`` when the binding applies, else an empty dict.
    """
    owner_id = legacy_owner_id_claim(
        record, user_context, kind=kind, path=path, legacy_field=legacy_field
    )
    return {OWNER_ID_FIELD: owner_id} if owner_id else {}


def bind_legacy_owner_id(
    record: dict[str, Any],
    user_context: Mapping[str, Any] | None,
    *,
    kind: str,
    path: str,
    legacy_field: str = REGISTERED_BY_FIELD,
) -> bool:
    """Set ``owner_id`` in place on a legacy dict record the caller owns.

    For write paths that persist the whole record dict: call after the
    ownership gate and before the write so the binding lands with it.

    Args:
        record: The stored record dict that is about to be written back.
        user_context: The authenticated user context.
        kind: Record kind for the log line.
        path: Record path for the log line.
        legacy_field: The record's username field.

    Returns:
        True when ``owner_id`` was set.
    """
    owner_id = legacy_owner_id_claim(
        record, user_context, kind=kind, path=path, legacy_field=legacy_field
    )
    if owner_id is None:
        return False
    record[OWNER_ID_FIELD] = owner_id
    return True
