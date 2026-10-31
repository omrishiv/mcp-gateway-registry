"""Intra-admin safety guards for user-management operations.

These helpers protect the administrator population from two self-inflicted
lockout classes that admin authorization alone does not prevent:

- **Self-deletion.** An admin accidentally (or under coercion) deleting their
  own account.
- **Last-admin removal.** Deleting or demoting the final administrator, which
  would leave the deployment with no one able to manage users, groups, or
  scopes.

The admin population is derived from the same rule the request path uses to set
``is_admin``: an IdP group reaches scopes through their ``group_mappings``, the
scopes' ui_permissions are merged, and :func:`registry.auth.dependencies._user_is_admin`
decides from the merged grants (via
:func:`registry.auth.privileged_constants.is_admin_conferring_action`). A group is
"admin-conferring" here exactly when a request bearing it is ``is_admin``. The
broader privileged-write predicate
(:func:`registry.services.scope_service._import_touches_privileged_scope`) is
deliberately NOT used here: it also matches read-only ``"all"`` grants and
privileged scope names, which would count non-admins (for example the
``federation-service`` seed) as administrators and let the last real admin go.

Fail-closed: if the admin population cannot be determined (IdP/DB error, empty
result), the caller must treat the operation as removing the last admin and
DENY. A guard that can be silently skipped is equivalent to no guard.
"""

from __future__ import annotations

import logging

from ..auth.privileged_constants import is_admin_conferring_action
from ..services import scope_service
from ..utils.iam_manager import get_iam_manager

logger = logging.getLogger(__name__)


class AdminSafetyError(Exception):
    """Raised when an admin-safety guard cannot be satisfied.

    Carries an HTTP-appropriate status code and a human-readable reason so the
    route layer can translate it into an HTTPException without re-deriving the
    failure mode.
    """

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _normalize(value: str | None) -> str:
    """Lower-case + strip a name for case-insensitive comparison.

    IdP usernames and group names are compared case-insensitively elsewhere in
    this module family (see the case-insensitive dedup in the user list/delete
    handlers), so we mirror that here to avoid a bypass where ``Admin`` and
    ``admin`` are treated as different principals.
    """
    return (value or "").strip().casefold()


def is_self_target(actor_username: str | None, target_username: str) -> bool:
    """Return True when the actor is operating on their own account.

    Comparison is case-insensitive and whitespace-insensitive. An empty or
    missing actor username never matches a target (fail closed: we cannot prove
    it is *not* self, but an unauthenticated actor should already have been
    rejected upstream, and refusing to match here avoids blocking legitimate
    deletes of a genuinely different user when the actor identity is unknown —
    the upstream admin gate remains the primary control).
    """
    actor = _normalize(actor_username)
    if not actor:
        return False
    return actor == _normalize(target_username)


def scope_confers_admin(ui_permissions: object) -> bool:
    """Return True if a scope's ui_permissions make its holders ``is_admin``.

    Mirrors the request path exactly: ``get_ui_permissions_for_user`` keeps a
    grant as ``"all"`` only when the stored value is a list containing
    ``"all"`` (a bare string is ignored), and ``_user_is_admin`` requires an
    admin-conferring action holding ``"all"``. Because the request path merges
    scopes by union, a principal is admin iff ANY one of its scopes satisfies
    this predicate.

    Args:
        ui_permissions: The scope's stored ``ui_permissions`` mapping.
    """
    if not isinstance(ui_permissions, dict):
        return False
    for action, resources in ui_permissions.items():
        if (
            isinstance(action, str)
            and is_admin_conferring_action(action)
            and isinstance(resources, list)
            and "all" in resources
        ):
            return True
    return False


def admin_group_names_from_catalogue(groups: dict) -> set[str]:
    """Return the case-folded IdP group names that confer admin in ``groups``.

    Args:
        groups: Scope catalogue in the :func:`scope_service.list_groups` shape
            (scope name to ``{"mappings": [...], "ui_scopes": {...}}``).

    Returns:
        Case-folded names of every group mapped by an admin-conferring scope.
        A scope's own name is not included: at request time a caller reaches a
        scope only through ``group_mappings``.
    """
    admin_names: set[str] = set()
    for scope_name, meta in groups.items():
        if not isinstance(scope_name, str) or not isinstance(meta, dict):
            continue
        if not scope_confers_admin(meta.get("ui_scopes")):
            continue
        for mapped in meta.get("mappings") or []:
            if isinstance(mapped, str) and _normalize(mapped):
                admin_names.add(_normalize(mapped))
    return admin_names


async def _list_scope_catalogue() -> dict:
    """Read the scope catalogue, failing closed on any error.

    Raises:
        AdminSafetyError: If the scope catalogue cannot be read.
    """
    try:
        groups = await scope_service.list_groups()
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("admin_safety: failed to list scope groups: %s", exc)
        raise AdminSafetyError(
            status_code=503,
            detail="Unable to verify administrator population; operation refused",
        ) from exc

    if not isinstance(groups, dict) or groups.get("error"):
        logger.error("admin_safety: scope group listing unavailable or errored: %r", groups)
        raise AdminSafetyError(
            status_code=503,
            detail="Unable to verify administrator population; operation refused",
        )
    return groups


async def resolve_admin_group_names() -> set[str]:
    """Return the set of IdP group names that confer admin, case-folded.

    A group confers admin when some scope maps it and that scope's
    ui_permissions satisfy :func:`scope_confers_admin`, which is the
    request-time ``is_admin`` rule.

    Raises:
        AdminSafetyError: If the scope catalogue cannot be read, or it yields
            no admin-conferring group. Fails closed so callers do not proceed on
            an incomplete admin picture.
    """
    groups = await _list_scope_catalogue()
    admin_names = admin_group_names_from_catalogue(groups)
    # Fail closed on an empty result. A scope catalogue that lists groups but
    # maps ZERO admin-conferring scopes to a group means the catalogue is
    # incomplete or unreadable, not that the deployment genuinely has no admin
    # groups. Proceeding would make every user look non-admin and silently
    # disable the last-admin guard, so we refuse rather than derive a lockout
    # decision from an unverifiable picture.
    if not admin_names:
        logger.error(
            "admin_safety: scope catalogue yielded ZERO admin-conferring groups "
            "(%d groups scanned); refusing to derive admin population",
            len(groups),
        )
        raise AdminSafetyError(
            status_code=503,
            detail="Unable to verify administrator population; operation refused",
        )

    logger.debug("admin_safety: resolved %d admin-conferring group names", len(admin_names))
    return admin_names


def groups_confer_admin(
    user_groups: list[str] | None,
    admin_group_names: set[str],
) -> bool:
    """Return True if any of the user's groups confers admin.

    Args:
        user_groups: The group names attached to the user (from the IdP listing).
        admin_group_names: Case-folded set from :func:`resolve_admin_group_names`.
    """
    for group in user_groups or []:
        if isinstance(group, str) and _normalize(group) in admin_group_names:
            return True
    return False


async def _m2m_admin_identities(admin_group_names: set[str]) -> list[frozenset[str]]:
    """Return one alias-set per admin M2M service account from ``idp_m2m_clients``.

    For non-Keycloak IdPs (Okta/Auth0/PingFederate) an M2M client's group
    membership lives ONLY in the MongoDB ``idp_m2m_clients`` collection, not in the
    IdP user listing. The user-management list handler merges this collection, so
    the admin count must too — otherwise an M2M-only admin is invisible and the
    last-admin guard both under-counts and (with the empty-set fail-closed) can
    wrongly refuse legitimate operations. Mirrors the merge in
    ``registry.api.management_routes.management_list_users``.

    Each admin is returned as a frozenset of ALL its identifiers (normalized
    ``name`` and ``client_id``). ``management_delete_user`` resolves an M2M client
    by ``{"$or": [{"client_id": ...}, {"name": ...}]}`` and the guard is called
    with the raw path param (either key), so the guard must recognise a delete by
    EITHER — but the two aliases are ONE admin, so they must count as one (a flat
    set of identifiers would double-count and re-open the last-admin fail-open).
    For Keycloak ``name == client_id`` so the set collapses to one element.

    Best-effort: a datastore error is logged and treated as "no M2M admins found"
    rather than raised, because the IdP listing is the primary source and the
    empty-population guard in :func:`list_admin_identities` still fails closed if
    the combined result is empty.

    Args:
        admin_group_names: Case-folded admin-conferring group set.

    Returns:
        One alias frozenset per M2M client whose groups confer admin.
    """
    from ..repositories.documentdb.client import get_documentdb_client

    m2m_admins: list[frozenset[str]] = []
    try:
        db = await get_documentdb_client()
        collection = db["idp_m2m_clients"]
        cursor = collection.find({})
        docs = await cursor.to_list(length=None)
    except Exception as exc:
        logger.warning(
            "admin_safety: could not read idp_m2m_clients for admin count "
            "(M2M admins not included): %s",
            exc,
        )
        return m2m_admins

    for doc in docs or []:
        if not isinstance(doc, dict):
            continue
        # The auth server ignores a record whose ``enabled`` is present and not
        # the boolean True (mongodb_groups_enrichment._is_record_enabled), so
        # such a client is not admin at request time and must not be counted.
        if "enabled" in doc and doc["enabled"] is not True:
            continue
        if not groups_confer_admin(doc.get("groups"), admin_group_names):
            continue
        aliases = {_normalize(key) for key in (doc.get("name"), doc.get("client_id")) if key}
        if aliases:
            m2m_admins.append(frozenset(aliases))

    logger.debug("admin_safety: %d M2M admin account(s) found", len(m2m_admins))
    return m2m_admins


async def _admin_identities_for(admin_group_names: set[str]) -> list[frozenset[str]]:
    """Return one alias-set per principal whose groups intersect ``admin_group_names``.

    Reads the IdP/DB user listing and the MongoDB ``idp_m2m_clients`` store. No
    empty-population check: callers decide what an empty result means.

    Raises:
        AdminSafetyError: If the IdP user listing cannot be read.
    """
    iam = get_iam_manager()
    try:
        users = await iam.list_users(max_results=1000, include_groups=True)
    except Exception as exc:
        logger.error("admin_safety: failed to list users for admin count: %s", exc)
        raise AdminSafetyError(
            status_code=503,
            detail="Unable to verify administrator population; operation refused",
        ) from exc

    admins: list[frozenset[str]] = []
    for user in users or []:
        if not isinstance(user, dict):
            continue
        username = user.get("username") or user.get("id")
        if not username:
            continue
        if groups_confer_admin(user.get("groups"), admin_group_names):
            admins.append(frozenset({_normalize(username)}))

    # Merge M2M admins (stored only in idp_m2m_clients for non-Keycloak IdPs) so
    # the count matches management_list_users and an M2M-only admin is not
    # invisible to the last-admin guard.
    admins.extend(await _m2m_admin_identities(admin_group_names))
    return admins


async def list_admin_identities() -> list[frozenset[str]]:
    """Return one alias-set per current administrator.

    Each element is the set of case-folded identifiers by which one admin can be
    addressed: a single username for an IdP user, or ``{name, client_id}`` for an
    M2M service account (which a delete may target by either). Returning one entry
    PER ADMIN, rather than a flat set of identifiers, is what lets the guards
    both (a) recognise the target by any of its aliases and (b) count distinct
    admins correctly (a flat identifier set would count a two-alias M2M admin
    twice and re-open the last-admin fail-open).

    Cross-references the IdP/DB user listing AND the MongoDB ``idp_m2m_clients``
    store against the admin-conferring group set, so the population matches what
    the user-management list handler shows (M2M-only admins included). Fails closed
    on any error enumerating the primary IdP listing, and on an empty population.

    Raises:
        AdminSafetyError: If users/groups cannot be enumerated, or the resolved
            population is empty (treated as unverifiable, not a genuine zero).
    """
    admin_group_names = await resolve_admin_group_names()
    admins = await _admin_identities_for(admin_group_names)

    # Fail closed on an empty admin population. We already know at least one
    # admin-conferring group exists (resolve_admin_group_names raises otherwise),
    # so finding NO admin means the listing didn't surface group membership (e.g.
    # an IdP adapter that returned groupless users, or a truncated/empty listing)
    # rather than a genuine zero-admin deployment. Deriving "target is not an
    # admin, nothing to guard" from that would silently bypass the guard, so
    # refuse instead.
    if not admins:
        logger.error(
            "admin_safety: no administrator accounts found despite %d "
            "admin-conferring group(s); refusing (user listing likely incomplete)",
            len(admin_group_names),
        )
        raise AdminSafetyError(
            status_code=503,
            detail="Unable to verify administrator population; operation refused",
        )

    logger.debug("admin_safety: %d administrator account(s) currently present", len(admins))
    return admins


def _would_empty_admins(
    admins: list[frozenset[str]],
    target: str,
) -> bool:
    """Return True if removing ``target`` leaves zero administrators.

    ``target`` is a normalized identifier. An admin is "the target" if that
    identifier is one of its aliases; the removal empties the population only if
    NO OTHER admin (a different alias-set) remains. Counting distinct admins —
    not identifiers — is what prevents a two-alias M2M admin from masking itself.
    """
    is_target_admin = any(target in aliases for aliases in admins)
    if not is_target_admin:
        return False
    remaining = [aliases for aliases in admins if target not in aliases]
    return not remaining


async def assert_not_last_admin(target_username: str) -> None:
    """Refuse an operation that would remove the last administrator.

    Call this immediately before deleting an admin account, or before a group
    update that would strip a user of every admin-conferring group. It is a
    no-op when the target is not currently an admin, or when at least one other
    admin remains.

    Args:
        target_username: The account being removed/demoted.

    Raises:
        AdminSafetyError: If the target is the only remaining administrator, or
            the admin population cannot be determined (fail closed).
    """
    admins = await list_admin_identities()
    target = _normalize(target_username)

    if _would_empty_admins(admins, target):
        raise AdminSafetyError(
            status_code=409,
            detail=(
                "Refusing to remove the last administrator. Grant admin to "
                "another account before removing or demoting this one."
            ),
        )


async def would_remove_last_admin_via_groups(
    target_username: str,
    desired_groups: list[str] | None,
) -> None:
    """Refuse a group update that demotes the last administrator.

    Determines whether ``desired_groups`` still confers admin on the target. If
    the target is currently the sole admin and the new group set would strip
    their admin status, the update is refused.

    Args:
        target_username: The account whose groups are being replaced.
        desired_groups: The complete new group set the update would apply.

    Raises:
        AdminSafetyError: If applying ``desired_groups`` would leave zero
            administrators, or the admin population cannot be determined.
    """
    admin_group_names = await resolve_admin_group_names()

    # If the new group set still confers admin, the target stays an admin and no
    # lockout is possible from this update.
    if groups_confer_admin(desired_groups, admin_group_names):
        return

    admins = await list_admin_identities()
    target = _normalize(target_username)

    if _would_empty_admins(admins, target):
        raise AdminSafetyError(
            status_code=409,
            detail=(
                "Refusing to demote the last administrator. Grant admin to "
                "another account before removing admin from this one."
            ),
        )


async def desired_groups_grant_admin(desired_groups: list[str] | None) -> bool:
    """Return True if the desired group set would confer admin on a user.

    Used to emit a distinct audit event when a group update elevates an account
    to admin-tier.
    """
    admin_group_names = await resolve_admin_group_names()
    return groups_confer_admin(desired_groups, admin_group_names)


async def assert_scope_change_keeps_an_admin(
    scope_name: str,
    *,
    group_mappings: list[str] | None = None,
    ui_permissions: dict | None = None,
    delete: bool = False,
    revoked_group: str | None = None,
) -> None:
    """Refuse a scope-group write or delete that would leave zero administrators.

    Applies the proposed change to the current scope catalogue, recomputes the
    admin-conferring groups, and counts the principals (IdP users and M2M
    clients) that would still be admin. Call it with the exact values the route
    is about to persist, after any normalization.

    Args:
        scope_name: The scope document being written or deleted.
        group_mappings: The new ``group_mappings``. ``None`` means the
            repository default (``[scope_name]``).
        ui_permissions: The new ``ui_permissions``. ``None`` is treated as no
            grants (the repository default confers nothing).
        delete: True when the scope document is being deleted.
        revoked_group: An IdP group the operation also deletes. Every
            principal is treated as losing it (fail closed).

    Raises:
        AdminSafetyError: 409 if no principal would remain admin; 503 if the
            scope catalogue or the principal listing cannot be read, or the
            current population is itself empty (unverifiable).
    """
    catalogue = await _list_scope_catalogue()
    current_names = admin_group_names_from_catalogue(catalogue)
    # The caller passed an is_admin gate, so the real catalogue maps at least one
    # admin-conferring group. An empty set means the read was incomplete; a
    # change judged against it could delete the real admin scope unchecked.
    if not current_names:
        logger.error(
            "admin_safety: scope catalogue yielded ZERO admin-conferring groups "
            "before change to '%s'; refusing",
            scope_name,
        )
        raise AdminSafetyError(
            status_code=503,
            detail="Unable to verify administrator population; operation refused",
        )

    proposed: dict = {
        name: meta
        for name, meta in catalogue.items()
        if not (isinstance(name, str) and name == scope_name)
    }
    if not delete:
        if group_mappings is None:
            mappings = [scope_name]
        elif isinstance(group_mappings, list):
            mappings = list(group_mappings)
        else:
            # Malformed input: assume it maps nobody (fail closed).
            mappings = []
        proposed[scope_name] = {
            "mappings": mappings,
            "ui_scopes": ui_permissions if isinstance(ui_permissions, dict) else {},
        }
    revoked = _normalize(revoked_group)
    if revoked:
        proposed = {
            name: {
                **meta,
                "mappings": [
                    mapped
                    for mapped in meta.get("mappings") or []
                    if not (isinstance(mapped, str) and _normalize(mapped) == revoked)
                ],
            }
            if isinstance(meta, dict)
            else meta
            for name, meta in proposed.items()
        }
    proposed_names = admin_group_names_from_catalogue(proposed)

    # No admin-conferring group is lost, so no principal loses admin.
    if current_names <= proposed_names:
        return

    refusal = AdminSafetyError(
        status_code=409,
        detail=(
            f"Refusing to change scope group '{scope_name}': it would leave no "
            "administrator. Grant admin to another account through a different "
            "group first."
        ),
    )
    if not proposed_names:
        raise refusal
    if await _admin_identities_for(proposed_names):
        return
    if not await _admin_identities_for(current_names):
        logger.error(
            "admin_safety: no administrator accounts found before scope change to "
            "'%s'; refusing (user listing likely incomplete)",
            scope_name,
        )
        raise AdminSafetyError(
            status_code=503,
            detail="Unable to verify administrator population; operation refused",
        )
    raise refusal


def caller_is_admin(
    user_context: dict | None,
    allowed_scopes: frozenset[str] = frozenset(),
) -> bool:
    """Return True if a route-level admin gate should admit ``user_context``.

    The canonical admin decision is the request-time ``is_admin`` flag derived
    by :func:`registry.auth.dependencies._derive_user_context`. Group or scope
    NAMES never stand in for it: a scope named ``mcp-registry-admin`` whose
    grants were narrowed no longer makes its holders admin. A gate may admit a
    documented extra credential through ``allowed_scopes`` (for example the
    federation static token's ``federation/peers``).

    Args:
        user_context: The authenticated request context, or None.
        allowed_scopes: Exact scope names this gate also accepts.
    """
    if not isinstance(user_context, dict):
        return False
    if user_context.get("is_admin") is True:
        return True
    if not allowed_scopes:
        return False
    scopes = user_context.get("scopes")
    if not isinstance(scopes, list):
        return False
    return any(isinstance(scope, str) and scope in allowed_scopes for scope in scopes)


def is_self_principal(
    user_context: dict | None,
    *target_identifiers: str | None,
) -> bool:
    """Return True when the caller is the principal named by any target identifier.

    Compares the caller's ``username`` and ``client_id`` (an M2M token's
    principal may be addressed by either) against every identifier of the
    target, case- and whitespace-insensitively. Empty values never match.

    Args:
        user_context: The authenticated request context.
        target_identifiers: Names by which the target principal is addressed.
    """
    if not isinstance(user_context, dict):
        return False
    actor = {
        _normalize(value)
        for value in (user_context.get("username"), user_context.get("client_id"))
        if isinstance(value, str) and _normalize(value)
    }
    targets = {
        _normalize(value)
        for value in target_identifiers
        if isinstance(value, str) and _normalize(value)
    }
    return bool(actor & targets)
