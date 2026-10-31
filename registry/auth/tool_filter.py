"""Per-user tool allowlist filtering for list/response endpoints.

This helper is called by the REST endpoints in `registry.api.server_routes`
and `registry.api.search_routes` (Issue #1026) to prune tool lists that
the caller is not allowed to see. It reads `accessible_tools` from the
already-built `user_context` dict, so there is no per-call DB access.

Fail-closed philosophy: a missing or empty allowlist for the requested
server yields an empty list. Wildcard and admin paths short-circuit to
the unfiltered input.
"""

from __future__ import annotations

import logging
from typing import Any

from ..core.config import settings

logger = logging.getLogger(__name__)


_WILDCARD_SENTINEL = {"*"}
# Key under which access_resolver records `server: "*"` rules. Only "*" is a
# cross-server wildcard (the gateway never honours `server: "all"`).
_CROSS_SERVER_KEY = "*"


def _is_admin(
    user_context: dict,
) -> bool:
    """Return True when the caller bypasses per-tool filtering entirely.

    Only admins skip pruning. A cross-server rule (`server: "*"`) does not:
    the gateway still checks that rule's own `tools`, so its allowlist is
    unioned into every server's lookup instead (see `_lookup_allowlist`).
    """
    return bool(user_context.get("is_admin"))


def _tool_identity(
    tool: dict[str, Any],
) -> str | None:
    """Return the canonical tool name for filtering.

    Different response shapes use different keys (Blocker 1 / Byte):
        - Registry `tool_list` entries use "name".
        - Semantic search `MatchingToolResult` / `ToolSearchResult` use
          "tool_name".
        - MCP `tools/list` JSON-RPC results use "name".

    Both keys are accepted. "name" wins if both are present.
    """
    if not isinstance(tool, dict):
        return None
    return tool.get("name") or tool.get("tool_name")


def _resolve_audit_log_level() -> int:
    """Resolve the launch-window log level from settings.

    The setting is `tool_filter_audit_log_level` (default "INFO"). Unknown
    values fall back to INFO to avoid dropping audit lines on typos.
    """
    level_name = (settings.tool_filter_audit_log_level or "INFO").upper()
    resolved = logging.getLevelName(level_name)
    if isinstance(resolved, int):
        return resolved
    return logging.INFO


def _emit_tool_filter_audit(
    *,
    user_context: dict,
    endpoint: str | None,
    server_name: str,
    kept: list[dict[str, Any]],
    pruned: list[dict[str, Any]],
) -> None:
    """Best-effort audit log of pruning events.

    Emits a `ToolFilterAuditEvent` via the audit sink whenever tools
    were pruned. Audit is strictly best-effort: any exception during
    emission is swallowed so the request path is never broken.
    """
    if not pruned:
        return
    try:
        from ..audit.events import ToolFilterAuditEvent
        from ..audit.sink import emit_audit_event

        pruned_names = sorted({_tool_identity(t) or "" for t in pruned if _tool_identity(t)})
        event = ToolFilterAuditEvent(
            username=user_context.get("username", ""),
            endpoint=endpoint or "unknown",  # type: ignore[arg-type]
            server_name=server_name,
            pruned_count=len(pruned),
            kept_count=len(kept),
            pruned_tool_names=pruned_names,
            user_scopes=list(user_context.get("scopes") or []),
        )
        emit_audit_event(event)
    except Exception:
        logger.exception("tool_filter audit emission failed")


def _lookup_allowlist(
    accessible_tools: dict[str, set[str]],
    *server_name_candidates: str | None,
) -> set[str] | None:
    """Look up a per-server allowlist, tolerating naming variants.

    Scope rules may store a server under its technical name
    ("airegistry-tools"), a path-style name with slashes
    ("/airegistry-tools/"), or a display name ("AI Registry tools").
    Callers pass as many candidate names as they have. Every stored key
    whose slash-stripped form equals a candidate's slash-stripped form
    contributes, as does the cross-server key "*", and the result is the
    UNION of their allowlists: the gateway allows a call when any matching
    rule allows it, so no single spelling may hide another's grant, and
    the result is independent of key order.

    Returns:
        The unioned allowlist (``{"*"}`` if any contributor is a
        wildcard), or None when no key matches.
    """
    if not accessible_tools:
        return None

    wanted = {name.strip("/") for name in server_name_candidates if name}
    wanted.discard("")
    wanted.add(_CROSS_SERVER_KEY)

    allow: set[str] | None = None
    for key, value in accessible_tools.items():
        if not isinstance(key, str) or key.strip("/") not in wanted:
            continue
        names = set(value or ())
        if "*" in names:
            return set(_WILDCARD_SENTINEL)
        allow = names if allow is None else allow | names
    return allow


def filter_tools_for_user(
    server_name: str,
    tools: list[dict[str, Any]] | None,
    user_context: dict,
    *,
    endpoint: str | None = None,
    server_path: str | None = None,
) -> list[dict[str, Any]]:
    """Return the subset of `tools` the user is allowed to see.

    Pruning rules:
        - Admin: return the input unchanged.
        - Per-server wildcard (`{"*"}`) on any matching key, including
          the cross-server key "*": return the input unchanged.
        - No entry for this server OR empty allowlist (`set()`): return
          [] (fail-closed).
        - Otherwise: keep tools whose name (or tool_name) is in the
          allowlist.

    Args:
        server_name: Human-readable or technical server name. Either the
            display name, the technical name, or a path form is accepted;
            the lookup tolerates leading/trailing slashes.
        tools: The tool list to filter. None is treated as [].
        user_context: Request user context dict. Must contain
            `accessible_tools` as populated by
            `registry.auth.dependencies.enhanced_auth` /
            `nginx_proxied_auth`.
        endpoint: Optional endpoint label used for audit events and
            metric/log labeling.
        server_path: Optional registered path (for example
            "/airegistry-tools/"). When provided, the lookup tries this
            key first, because scope rules usually store the technical
            name or path rather than the display name.

    Returns:
        The filtered list of tool dicts.
    """
    if tools is None:
        return []
    if _is_admin(user_context):
        return tools

    accessible_tools = user_context.get("accessible_tools") or {}
    allow = _lookup_allowlist(accessible_tools, server_path, server_name)

    # Missing entry or explicit empty set both mean fail-closed.
    if allow is None or allow == set():
        reason = "no_allowlist" if allow is None else "empty_allowlist"
        logger.log(
            _resolve_audit_log_level(),
            "tool_filter.prune_all user=%s server=%s endpoint=%s reason=%s",
            user_context.get("username"),
            server_name,
            endpoint,
            reason,
        )
        pruned: list[dict[str, Any]] = [t for t in tools if isinstance(t, dict)]
        _emit_tool_filter_audit(
            user_context=user_context,
            endpoint=endpoint,
            server_name=server_name,
            kept=[],
            pruned=pruned,
        )
        return []

    if allow == _WILDCARD_SENTINEL:
        return tools

    kept: list[dict[str, Any]] = []
    pruned = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_name = _tool_identity(tool)
        if tool_name and tool_name in allow:
            kept.append(tool)
        else:
            pruned.append(tool)

    if pruned:
        logger.log(
            _resolve_audit_log_level(),
            "tool_filter.prune user=%s server=%s endpoint=%s before=%d after=%d",
            user_context.get("username"),
            server_name,
            endpoint,
            len(tools),
            len(kept),
        )
        _emit_tool_filter_audit(
            user_context=user_context,
            endpoint=endpoint,
            server_name=server_name,
            kept=kept,
            pruned=pruned,
        )
    return kept


def tool_allowed_for_user(
    server_name: str,
    tool_name: str,
    user_context: dict,
    *,
    server_path: str | None = None,
) -> bool:
    """Return True when the given tool is visible to the current user.

    Thin wrapper around `filter_tools_for_user` with a single-item list.
    Used by the semantic-search top-level tool loop. When the caller
    knows the registered server path, pass it via `server_path` so the
    allowlist lookup can match either display name or technical path.
    """
    return bool(
        filter_tools_for_user(
            server_name,
            [{"name": tool_name}],
            user_context,
            endpoint="semantic_search",
            server_path=server_path,
        )
    )
