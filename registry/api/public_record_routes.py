"""Public, anonymous per-record endpoints for ARD catalog dereferencing.

The ARD catalog (``/.well-known/ai-catalog.json``) is crawled anonymously, so
each entry's ``url`` must be fetchable without auth. The existing per-record
endpoints (``/api/servers/{path}/server.json`` etc.) all require auth, so this
module adds parallel public endpoints under ``/api/public`` that:

1. Return ONLY public + enabled records.
2. Return 404 for anything not public+enabled (private/group/disabled/missing),
   so existence of non-public records is never disclosed.
3. Strip internal fields (backend URLs, auth schemes, group lists, owner) from
   the response body.

See issue #1294 (Blocker B1, SEC-1) and ``.scratchpad/issue-1294/lld.md``.
"""

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Path

from ..repositories.factory import (
    get_agent_repository,
    get_server_repository,
    get_skill_repository,
)
from ..services.ard_mapping import _sanitize_name, public_record_leaf
from ..services.canonical_export import redact_backend_urls, to_canonical
from ..services.visibility import redact_agent_backend_fields, should_redact_backend_urls
from ..utils.credential_encryption import strip_credentials_from_dict

logger = logging.getLogger(__name__)

router = APIRouter()

# Stored routing, DNS-pin, disable-state, and credential metadata is internal.
# ``is_proxied`` and ``proxy_client_url`` are intentionally not in this set: they
# are safe client-facing discovery fields and do not reveal the backend target.
_PUBLIC_PROXY_INTERNAL_FIELDS = frozenset(
    {
        "proxy_target_url",
        "proxy_streaming",
        "proxy_resolved_ips",
        "proxy_target_host",
        "proxy_disabled_reason",
        "custom_headers",
        "custom_headers_encrypted",
        "custom_header_names",
        "custom_header_overridable_names",
        "custom_headers_updated_at",
    }
)

# Fields that must never appear in an anonymous agent record body.
_AGENT_SENSITIVE_FIELDS = _PUBLIC_PROXY_INTERNAL_FIELDS | frozenset(
    {
        "security",
        "security_schemes",
        "security_requirements",
        "allowed_groups",
        "registered_by",
        "auth_credential_encrypted",
        "sync_metadata",
        "ans_metadata",
        "_identity_url_normalized",
        "rating_details",
    }
)

# Fields that must never appear in an anonymous skill record body.
_SKILL_SENSITIVE_FIELDS = _PUBLIC_PROXY_INTERNAL_FIELDS | frozenset(
    {
        "auth_credential_encrypted",
        "auth_scheme",
        "auth_header_name",
        "credential_updated_at",
        "allowed_groups",
        "owner",
        "_identity_url_normalized",
        "rating_details",
    }
)

# Fields that must never appear in an anonymous server.json body. ``to_canonical``
# copies owner, group and auth metadata into the ``_meta`` internal block, so the
# strip runs on the canonical document at every depth.
_SERVER_SENSITIVE_FIELDS = _PUBLIC_PROXY_INTERNAL_FIELDS | frozenset(
    {
        "registered_by",
        "allowed_groups",
        "auth_scheme",
        "auth_header_name",
        "auth_provider",
        "auth_credential_encrypted",
        "owner",
        "security_schemes",
        "sync_metadata",
        "ans_metadata",
        "_identity_url_normalized",
        "rating_details",
    }
)


def _strip_fields(
    value: Any,
    sensitive: frozenset[str],
) -> Any:
    """Return a recursive copy with sensitive keys removed at every depth."""
    if isinstance(value, dict):
        return {
            key: _strip_fields(item, sensitive)
            for key, item in value.items()
            if key not in sensitive
        }
    if isinstance(value, list):
        return [_strip_fields(item, sensitive) for item in value]
    if isinstance(value, tuple):
        return tuple(_strip_fields(item, sensitive) for item in value)
    return value


def _find_by_leaf(
    kind: str,
    leaf: str,
    paths: list[str],
) -> str | None:
    """Return the stored path a public URL ``leaf`` names, or None.

    The catalog builds each URL from the record's full path, so the exact match
    wins. A single-segment leaf that matches no path exactly still resolves by
    its sanitized last segment (the pre-full-path URL shape) only when exactly
    one public record has that segment; an ambiguous leaf resolves to nothing.
    """
    target = leaf.strip("/")
    for path in paths:
        if public_record_leaf(kind, path) == target:
            return path
    if "/" in target:
        return None
    legacy = [path for path in paths if _sanitize_name(path) == target]
    return legacy[0] if len(legacy) == 1 else None


@router.get("/public/servers/{leaf:path}/server.json")
async def get_public_server(
    leaf: str = Path(..., description="Server path from the catalog entry URL"),
) -> dict[str, Any]:
    """Public canonical server.json for a public + enabled MCP server.

    Matches the full server path the catalog URL carries. Only public + enabled
    servers are considered; anything else returns 404.
    """
    repo = get_server_repository()
    records = await repo.find_with_filter({"is_enabled": True, "visibility": "public"}, limit=None)
    path = _find_by_leaf("servers", leaf, list(records))
    if path is None:
        raise HTTPException(status_code=404, detail="Server not found")
    safe_record = strip_credentials_from_dict({**records[path], "path": path})
    canonical, _ = to_canonical(safe_record)
    # Anonymous callers never receive backend URLs, owner/group/auth metadata or
    # per-user rating PII, including copies nested inside preserved upstream metadata.
    redacted = redact_backend_urls(canonical)
    return _strip_fields(redacted, _SERVER_SENSITIVE_FIELDS)


@router.get("/public/agents/{leaf:path}")
async def get_public_agent(
    leaf: str = Path(..., description="Agent path from the catalog entry URL"),
) -> dict[str, Any]:
    """Public agent card for a public + enabled A2A agent."""
    repo = get_agent_repository()
    records = await repo.find_with_filter({"is_enabled": True, "visibility": "public"}, limit=None)
    path = _find_by_leaf("agents", leaf, list(records))
    if path is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    record = records[path]
    # Anonymous callers never receive the reverse-proxy backend: strip
    # proxy_pass_url and project a proxied agent's supported_interfaces
    # onto the gateway (per-entry urls are the backend the gateway hides).
    # Shared with the authenticated detail/search reads so the three
    # surfaces treat the agent backend identically. Gated on the same
    # mode decision: in registry-only mode there is no gateway to route
    # through, so the stored direct card is served as-is (matching
    # authenticated reads, which also skip backend redaction there).
    if should_redact_backend_urls(None):
        redact_agent_backend_fields(record)
    return _strip_fields(record, _AGENT_SENSITIVE_FIELDS)


@router.get("/public/skills/{leaf:path}")
async def get_public_skill(
    leaf: str = Path(..., description="Skill path from the catalog entry URL"),
) -> dict[str, Any]:
    """Public skill card for a public + enabled local skill."""
    repo = get_skill_repository()
    skills = await repo.list_filtered(
        include_disabled=False,
        visibility="public",
        registry_name="local",
    )
    by_path = {skill.path: skill for skill in skills}
    path = _find_by_leaf("skills", leaf, list(by_path))
    if path is None:
        raise HTTPException(status_code=404, detail="Skill not found")
    body = by_path[path].model_dump(mode="json")
    return _strip_fields(body, _SKILL_SENSITIVE_FIELDS)
