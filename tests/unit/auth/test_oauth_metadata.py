"""Tests for the OAuth discovery helpers in registry/auth/oauth_metadata.py.

These cover the pure helper functions used by the gateway's RFC 9728 PRM and
RFC 8414 AS-metadata routes (issue #989).
"""

from unittest.mock import patch

import pytest

from registry.auth.oauth_metadata import (
    WELLKNOWN_PRM_PATH,
    build_canonical_resource_url,
    build_resource_documentation_url,
    build_resource_metadata_url,
    build_www_authenticate_header,
    derive_supported_scopes,
    enforce_https,
)


pytestmark = [pytest.mark.unit, pytest.mark.auth]


class TestBuildCanonicalResourceUrl:
    """build_canonical_resource_url() normalizes the gateway's public URL."""

    def test_strips_trailing_slash(self):
        assert build_canonical_resource_url("https://gw.example.com/") == "https://gw.example.com"

    def test_no_change_when_no_trailing_slash(self):
        assert build_canonical_resource_url("https://gw.example.com") == "https://gw.example.com"

    def test_preserves_path_segments(self):
        assert (
            build_canonical_resource_url("https://gw.example.com/registry/")
            == "https://gw.example.com/registry"
        )

    def test_raises_on_empty(self):
        with pytest.raises(ValueError, match="empty"):
            build_canonical_resource_url("")

    def test_raises_on_missing_scheme(self):
        with pytest.raises(ValueError, match="no scheme"):
            build_canonical_resource_url("gw.example.com")


class TestEnforceHttps:
    """enforce_https() guards against http resource URLs in production."""

    def test_passes_with_https(self):
        enforce_https("https://gw.example.com", https_required=True)

    def test_passes_with_http_when_not_required(self):
        enforce_https("http://localhost:8000", https_required=False)

    def test_raises_with_http_when_required(self):
        with pytest.raises(ValueError, match="not HTTPS"):
            enforce_https("http://gw.example.com", https_required=True)


class TestBuildResourceMetadataUrl:
    """build_resource_metadata_url() must match the PRM `resource` byte-for-byte."""

    def test_appends_well_known_path(self):
        prm_url = build_resource_metadata_url("https://gw.example.com")
        assert prm_url == f"https://gw.example.com{WELLKNOWN_PRM_PATH}"

    def test_no_double_slash(self):
        prm_url = build_resource_metadata_url("https://gw.example.com")
        # Three "://" pairs, then exactly one slash before .well-known
        assert "//.well-known" not in prm_url


class TestBuildWWWAuthenticateHeader:
    """RFC 9728 §5.1 header format."""

    def test_includes_realm_and_resource_metadata(self):
        header = build_www_authenticate_header("https://gw.example.com/.well-known/oauth-protected-resource")
        assert header.startswith("Bearer ")
        assert 'realm="mcp"' in header
        assert (
            'resource_metadata="https://gw.example.com/.well-known/oauth-protected-resource"'
            in header
        )

    def test_byte_for_byte_match_with_prm_endpoint(self):
        """The header's resource_metadata MUST equal the PRM endpoint URL byte-for-byte."""
        resource = "https://gw.example.com"
        prm_url = build_resource_metadata_url(resource)
        header = build_www_authenticate_header(prm_url)

        assert prm_url in header


class TestDeriveSupportedScopes:
    """derive_supported_scopes() builds the PRM `scopes_supported` array."""

    @pytest.fixture(autouse=True)
    def _no_scope_override(self):
        """By default these tests cover the no-override path.

        The TestAdvertisedScopesOverride class below covers the override path.
        """
        with patch("registry.auth.oauth_metadata.settings") as mock_settings:
            mock_settings.mcp_advertised_scopes = ""
            yield

    @pytest.mark.asyncio
    async def test_unions_scope_names_and_group_mappings(self):
        config = {
            "group_mappings": {
                "keycloak-admins": ["mcp-admin", "registry-users"],
                "keycloak-readers": ["mcp-read"],
            },
            "UI-Scopes": {"mcp-admin": {"can_modify_servers": True}},
            "mcp-admin": [{"server": "x"}],
            "mcp-read": [{"server": "y"}],
            "registry-users": [{"server": "z"}],
        }

        with patch(
            "registry.auth.oauth_metadata.reload_scopes_config",
            return_value=config,
        ):
            scopes = await derive_supported_scopes()

        # mcp-admin, mcp-read, registry-users; UI-Scopes and group_mappings keys excluded
        assert scopes == ["mcp-admin", "mcp-read", "registry-users"]

    @pytest.mark.asyncio
    async def test_empty_config_returns_empty_list(self):
        with patch(
            "registry.auth.oauth_metadata.reload_scopes_config",
            return_value={"group_mappings": {}},
        ):
            scopes = await derive_supported_scopes()

        assert scopes == []

    @pytest.mark.asyncio
    async def test_dedupes_overlapping_sources(self):
        """Same scope name appearing in both top-level keys and group_mappings is deduped."""
        config = {
            "group_mappings": {
                "g1": ["mcp-read"],
                "g2": ["mcp-read", "mcp-admin"],
            },
            "mcp-read": [],
            "mcp-admin": [],
        }

        with patch(
            "registry.auth.oauth_metadata.reload_scopes_config",
            return_value=config,
        ):
            scopes = await derive_supported_scopes()

        assert scopes == ["mcp-admin", "mcp-read"]


class TestAdvertisedScopesOverride:
    """`mcp_advertised_scopes` setting overrides what derive_supported_scopes() returns.

    Operators set this when the IdP performs RFC 7591 DCR and would reject
    registration requests containing scope names it doesn't recognize."""

    @pytest.mark.asyncio
    async def test_override_replaces_dynamic_scopes(self):
        """When the override is set, scopes from the registry config are ignored."""
        config = {
            "group_mappings": {"g1": ["mcp-admin"]},
            "mcp-admin": [],
        }
        with (
            patch("registry.auth.oauth_metadata.settings") as mock_settings,
            patch(
                "registry.auth.oauth_metadata.reload_scopes_config",
                return_value=config,
            ),
        ):
            mock_settings.mcp_advertised_scopes = "openid profile email offline_access"

            scopes = await derive_supported_scopes()

        assert scopes == ["openid", "profile", "email", "offline_access"]

    @pytest.mark.asyncio
    async def test_override_preserves_caller_order(self):
        """Operators may want a specific order; the override doesn't sort."""
        with (
            patch("registry.auth.oauth_metadata.settings") as mock_settings,
            patch(
                "registry.auth.oauth_metadata.reload_scopes_config",
                return_value={"group_mappings": {}},
            ),
        ):
            mock_settings.mcp_advertised_scopes = "zeta alpha mu"

            scopes = await derive_supported_scopes()

        assert scopes == ["zeta", "alpha", "mu"]

    @pytest.mark.asyncio
    async def test_empty_override_falls_back_to_dynamic(self):
        """Empty string is not an override; the registry config is still used."""
        config = {
            "group_mappings": {},
            "mcp-admin": [],
        }
        with (
            patch("registry.auth.oauth_metadata.settings") as mock_settings,
            patch(
                "registry.auth.oauth_metadata.reload_scopes_config",
                return_value=config,
            ),
        ):
            mock_settings.mcp_advertised_scopes = ""

            scopes = await derive_supported_scopes()

        assert scopes == ["mcp-admin"]

    @pytest.mark.asyncio
    async def test_whitespace_only_override_falls_back_to_dynamic(self):
        """Whitespace-only override is treated as unset."""
        config = {
            "group_mappings": {},
            "mcp-admin": [],
        }
        with (
            patch("registry.auth.oauth_metadata.settings") as mock_settings,
            patch(
                "registry.auth.oauth_metadata.reload_scopes_config",
                return_value=config,
            ),
        ):
            mock_settings.mcp_advertised_scopes = "   "

            scopes = await derive_supported_scopes()

        assert scopes == ["mcp-admin"]


class TestBuildResourceDocumentationUrl:
    """build_resource_documentation_url() defaults to <registry>/docs/oauth or honors override."""

    def test_default_uses_registry_url(self):
        with patch("registry.auth.oauth_metadata.settings") as mock_settings:
            mock_settings.registry_url = "https://gw.example.com"
            mock_settings.mcp_resource_documentation_url = None

            url = build_resource_documentation_url()

        assert url == "https://gw.example.com/docs/oauth"

    def test_override_takes_precedence(self):
        with patch("registry.auth.oauth_metadata.settings") as mock_settings:
            mock_settings.registry_url = "https://gw.example.com"
            mock_settings.mcp_resource_documentation_url = "https://docs.example.com/mcp/oauth"

            url = build_resource_documentation_url()

        assert url == "https://docs.example.com/mcp/oauth"
