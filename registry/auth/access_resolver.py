"""Per-request scope resolution: servers + tools in a single scope-repo pass.

Used by `registry.auth.dependencies` to populate `user_context` with both
`accessible_servers` and `accessible_tools` without walking the scope
repository twice. The resolver is intentionally fail-closed: on any scope
repo error, callers observe an empty `UserAccess()` and every downstream
filter treats that as "no access".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


ToolAllowlist = dict[str, set[str]]


# Per-server TOOL wildcard values: `tools: ["*"]` / `tools: ["all"]` (and the
# bare-string forms) grant every tool on the rule's server, as the gateway's
# validate_server_tool_access does.
_WILDCARD_VALUES: frozenset[str] = frozenset(("all", "*"))

# Cross-server SERVER wildcard. Only `server: "*"` (slashes ignored, as the
# gateway's _server_names_match normalizes) names every server; the gateway
# never honours `server: "all"`, so the registry treats "all" as a plain server
# name that matches nothing (the WRITE-side guard
# registry.utils.url_guard._RESERVED_SERVER_PATH_NAMES keeps both "all" and "*"
# reserved so no registered server can carry either name).
CROSS_SERVER_WILDCARD: str = "*"


def _merge_tool_rule(
    tools: ToolAllowlist,
    key: str,
    tool_rules: object,
) -> None:
    """Union one rule's ``tools`` value into the allowlist for ``key``.

    A list or bare string naming a wildcard value records ``{"*"}`` (sticky);
    a bare string names one tool; list elements that are not strings are
    ignored; a missing or malformed value (None, number, dict) adds nothing,
    but still records an (empty) entry so the server is known and fail-closed.
    """
    existing = tools.setdefault(key, set())
    if existing == {"*"}:
        return
    if isinstance(tool_rules, str):
        names = {tool_rules}
    elif isinstance(tool_rules, list):
        names = {t for t in tool_rules if isinstance(t, str)}
    else:
        return
    if names & _WILDCARD_VALUES:
        tools[key] = {"*"}
        return
    existing.update(names)


@dataclass(frozen=True)
class UserAccess:
    """Resolved per-request access bag.

    Returned by `resolve_scope_access(user_scopes)`. Grows additively as
    future resource types (agents, skills) gain scope-driven filtering.

    Attributes:
        servers: List of server names the user can access. Contains the
            sentinel "*" when any scope grants cross-server access via
            `server: "*"`.
        tools: Mapping of server_name to the set of allowed tool names.
            `{"*"}` means wildcard on that server (no pruning). A missing
            entry or empty set means "no tools allowed" (fail-closed).
    """

    servers: list[str] = field(default_factory=list)
    tools: ToolAllowlist = field(default_factory=dict)


async def resolve_scope_access(
    user_scopes: list[str],
) -> UserAccess:
    """Resolve `accessible_servers` and `accessible_tools` in one loop.

    Wildcard semantics (mirrors auth_server/server.py
    validate_server_tool_access):
        - `server: "*"` at the rule level is a cross-server rule. It is
          recorded under the sentinel key "*" in both `servers` and `tools`,
          with that rule's OWN tool allowlist: the gateway still checks the
          rule's `tools` on every server, so `server: "*", tools: ["read"]`
          grants `read` everywhere, not every tool. `server: "all"` is NOT a
          wildcard (the gateway does not honour it); it is kept as a literal
          server name, which no registered server can carry.
        - `tools: ["all"]` / `tools: ["*"]` is a per-server wildcard and
          is recorded as `{"*"}`.
        - A missing `tools` key or a malformed value means "no tools
          allowed" on that server (fail-closed). A startup audit in
          `audit_legacy_scopes_on_startup` warns operators about the
          legacy shape so they can migrate before the tightening bites.

    Tool allowlists are unioned across scopes and rules, so the result does
    not depend on scope order; a wildcard is absorbing.

    Args:
        user_scopes: Flat list of user scope names.

    Returns:
        UserAccess. On scope-repo error, returns an empty UserAccess().
    """
    try:
        from ..repositories.factory import get_scope_repository

        scope_repo = get_scope_repository()
    except Exception as exc:
        logger.error("resolve_scope_access: scope repo unavailable: %s", exc, exc_info=True)
        return UserAccess()

    servers: set[str] = set()
    tools: ToolAllowlist = {}

    # Fetch every scope's rules in one round-trip rather than one per scope.
    # Iterate `user_scopes` (not the map) so a scope the repo returned but the
    # caller does not hold can never contribute.
    try:
        scope_rules = await scope_repo.get_server_scopes_bulk(user_scopes)
    except Exception as exc:
        logger.error("resolve_scope_access: get_server_scopes_bulk failed: %s", exc, exc_info=True)
        return UserAccess()

    for scope in user_scopes:
        scope_config = scope_rules.get(scope)
        if not scope_config:
            continue

        for rule in scope_config:
            if not isinstance(rule, dict):
                continue
            server_name = rule.get("server")
            if not isinstance(server_name, str) or not server_name:
                continue

            # Cross-server rule: server "*" (slashes ignored, as the gateway
            # normalizes). Recorded under the sentinel key "*" with the rule's
            # own tools; "all" is a literal name here, not a wildcard.
            if server_name.strip("/") == CROSS_SERVER_WILDCARD:
                server_name = CROSS_SERVER_WILDCARD

            servers.add(server_name)
            _merge_tool_rule(tools, server_name, rule.get("tools"))

    tool_restricted = sum(1 for v in tools.values() if v != {"*"})
    logger.info(
        "resolve_scope_access: scopes=%d servers=%d tool_restricted_servers=%d",
        len(user_scopes),
        len(servers),
        tool_restricted,
    )

    return UserAccess(servers=sorted(servers), tools=tools)


async def get_user_accessible_servers(
    user_scopes: list[str],
) -> list[str]:
    """Return the list of server names accessible to the given scopes.

    Thin wrapper around `resolve_scope_access` that preserves the
    historical signature used across the codebase (dependencies.py,
    user_can_access_server, tests, CLIs).
    """
    access = await resolve_scope_access(user_scopes)
    return access.servers


async def get_user_accessible_tools(
    user_scopes: list[str],
) -> dict[str, set[str]]:
    """Return the tool allowlist map for the given scopes.

    Parallel wrapper for symmetry with get_user_accessible_servers and
    for test ergonomics.
    """
    access = await resolve_scope_access(user_scopes)
    return access.tools


async def audit_legacy_scopes_on_startup() -> int:
    """One-time scan at boot for legacy scope documents.

    Emits a WARN per scope rule where:
        - `tools` key is absent (legacy shape), OR
        - `tools` is an empty list AND the scope declares a method
          set that includes tools/call (call will always fail, list
          will always be empty).

    Returns:
        The number of warnings emitted so tests / metrics can assert.
        On scope-repo error, returns 0 and logs an error.
    """
    try:
        from ..repositories.factory import get_scope_repository

        scope_repo = get_scope_repository()
    except Exception as exc:
        logger.error("audit_legacy_scopes_on_startup: scope repo unavailable: %s", exc)
        return 0

    try:
        scope_names = await scope_repo.list_scope_names()
    except Exception as exc:
        logger.error("audit_legacy_scopes_on_startup: list_scope_names failed: %s", exc)
        return 0

    warnings_emitted = 0
    for scope_name in scope_names:
        try:
            rules = await scope_repo.get_server_scopes(scope_name)
        except Exception as exc:
            logger.error(
                "audit_legacy_scopes_on_startup: get_server_scopes(%s) failed: %s",
                scope_name,
                exc,
            )
            continue

        for rule in rules or []:
            if not isinstance(rule, dict) or "server" not in rule:
                continue
            server_name = rule.get("server")
            tools = rule.get("tools")
            methods = rule.get("methods") or []

            if tools is None:
                logger.warning(
                    "legacy_scope_missing_tools scope=%s server=%s methods=%s "
                    "(post-upgrade this will deny all tools/list and tools/call; "
                    "migrate to tools: ['all'] if wildcard was intended)",
                    scope_name,
                    server_name,
                    methods,
                )
                warnings_emitted += 1
            elif (
                isinstance(tools, list)
                and not tools
                and ("tools/call" in methods or "all" in methods or "*" in methods)
            ):
                logger.warning(
                    "empty_tools_list_with_call_method scope=%s server=%s",
                    scope_name,
                    server_name,
                )
                warnings_emitted += 1

    if warnings_emitted:
        logger.warning(
            "Legacy scope audit: %d warnings. See log lines above for "
            "specific scope/server pairs. Update the mcp-scopes collection "
            "before upgrading.",
            warnings_emitted,
        )
    else:
        logger.info("Legacy scope audit: no issues found.")
    return warnings_emitted
