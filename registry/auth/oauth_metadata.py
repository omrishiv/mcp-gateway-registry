"""Helpers for building the gateway's OAuth discovery documents.

Used by the registry's `.well-known/oauth-protected-resource` and
`.well-known/oauth-authorization-server` routes (RFC 9728 and RFC 8414).

The functions here are intentionally small and pure: route handlers compose
them with provider-supplied IdP metadata to assemble a final response.
"""

import logging
from typing import Any

from ..common.scopes_loader import reload_scopes_config
from ..core.config import settings

logger = logging.getLogger(__name__)


WELLKNOWN_PRM_PATH: str = "/.well-known/oauth-protected-resource"
WELLKNOWN_AS_METADATA_PATH: str = "/.well-known/oauth-authorization-server"


def build_canonical_resource_url(registry_url: str) -> str:
    """Return the canonical MCP resource URL for the gateway.

    The result is used as both the `resource` field in the PRM document and
    the `resource_metadata` URL embedded in `WWW-Authenticate` 401 headers.
    They MUST match byte-for-byte (acceptance criterion for issue #989).

    Args:
        registry_url: Configured public URL of this gateway, from
            settings.registry_url. May or may not have a trailing slash.

    Returns:
        URL with no trailing slash.

    Raises:
        ValueError: If registry_url is empty or has no scheme.
    """
    if not registry_url:
        raise ValueError("registry_url is empty; cannot build canonical resource URL")

    if "://" not in registry_url:
        raise ValueError(
            f"registry_url '{registry_url}' has no scheme (expected http:// or https://)"
        )

    return registry_url.rstrip("/")


def enforce_https(
    resource_url: str,
    https_required: bool,
) -> None:
    """Raise if `resource_url` is http and HTTPS is required for this deployment.

    The MCP authorization spec requires HTTPS for all OAuth endpoints in
    non-local environments. We fail fast at startup rather than serve a
    PRM document advertising an http resource.

    Args:
        resource_url: The canonical resource URL.
        https_required: If True and `resource_url` is http, raise.

    Raises:
        ValueError: If https_required and the URL is not HTTPS.
    """
    if not https_required:
        return
    if resource_url.startswith("https://"):
        return
    raise ValueError(
        f"Canonical resource URL '{resource_url}' is not HTTPS; "
        "set MCP_HTTPS_REQUIRED=false for local development, or use an HTTPS registry_url"
    )


async def derive_supported_scopes() -> list[str]:
    """Build the `scopes_supported` array for the PRM document.

    When `mcp_advertised_scopes` is set, returns that explicit list (split on
    whitespace). Useful when the IdP performs RFC 7591 DCR and rejects scopes
    that don't exist in its realm.

    Otherwise pulls from the same scopes config used by the auth server's
    authorization decisions (DocumentDB-backed in production, YAML-backed in
    local dev). The result is the stable-sorted union of:

      * scope names defined in the registry (entries other than the
        `group_mappings` and `UI-Scopes` keys)
      * scope names referenced by group mappings

    Sorting is stable so the PRM document is byte-stable across requests
    (cache-friendly, per acceptance criterion).

    Returns:
        Stable-sorted, deduplicated list of scope name strings.
    """
    override = getattr(settings, "mcp_advertised_scopes", "") or ""
    if override.strip():
        # Preserve operator-specified order so it is byte-stable across requests.
        return [s for s in override.split() if s]

    config = await reload_scopes_config()

    scope_names: set[str] = set()
    for key in config.keys():
        if key in ("group_mappings", "UI-Scopes"):
            continue
        scope_names.add(key)

    group_mappings = config.get("group_mappings", {})
    if isinstance(group_mappings, dict):
        for mapped_scopes in group_mappings.values():
            if isinstance(mapped_scopes, list):
                scope_names.update(mapped_scopes)

    return sorted(scope_names)


def build_prm_resource_field(registry_url: str) -> str:
    """Return the value of the `resource` field in the PRM document (RFC 9728).

    By default this is the canonical gateway URL (RFC 8707-compliant). Some IdPs
    (notably Entra v2) require the `resource` parameter sent on /authorize to
    match the audience identifier used by the requested scope, e.g.
    `api://<entra-app-id>`, not the gateway's HTTPS URL. Operators can set
    `mcp_prm_resource_override` to advertise the IdP-specific resource ID.

    The `resource_metadata` URL embedded in WWW-Authenticate 401s remains
    derived from the gateway's HTTPS URL regardless, since it has to be
    fetchable by the discovery client.

    Args:
        registry_url: Configured public URL of this gateway.

    Returns:
        Either the override value or the canonical resource URL.
    """
    override = getattr(settings, "mcp_prm_resource_override", None)
    if override:
        return override.rstrip("/")
    return build_canonical_resource_url(registry_url)


def build_resource_documentation_url() -> str:
    """Return the URL of the operator-facing OAuth docs page.

    Used as the `resource_documentation` field in the PRM document. Defaults
    to a docs page on the registry itself; an explicit override via
    `mcp_resource_documentation_url` (settings) takes precedence when set.
    """
    override = getattr(settings, "mcp_resource_documentation_url", None)
    if override:
        return override
    return f"{build_canonical_resource_url(settings.registry_url)}/docs/oauth"


def build_www_authenticate_header(resource_metadata_url: str) -> str:
    """Build the WWW-Authenticate header value for 401 responses.

    Per RFC 9728 §5.1 and the MCP 2025-06-18 authorization spec, the
    `resource_metadata` parameter points discovery clients at the gateway's
    Protected Resource Metadata document.

    Args:
        resource_metadata_url: Absolute URL of the PRM endpoint. Must equal
            the `resource` field returned by the PRM document, byte-for-byte.

    Returns:
        A complete header value suitable for `WWW-Authenticate`.
    """
    return f'Bearer realm="mcp", resource_metadata="{resource_metadata_url}"'


def build_resource_metadata_url(resource_url: str) -> str:
    """Return the absolute URL of the gateway's PRM endpoint.

    Args:
        resource_url: The canonical resource URL (no trailing slash).

    Returns:
        `<resource_url>/.well-known/oauth-protected-resource`.
    """
    return f"{resource_url}{WELLKNOWN_PRM_PATH}"
