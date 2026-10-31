"""Unit tests for virtual server nginx configuration generation."""

import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from registry.schemas.virtual_server_models import (
    ToolMapping,
    ToolScopeOverride,
    VirtualServerConfig,
)


@pytest.fixture(autouse=True)
def _backends_healthy():
    """Report every backend as healthy unless a test says otherwise.

    The virtual backend gate requires a healthy status, and the health service
    has none in unit tests. Tests of the gate itself override this patch.
    """
    with patch(
        "registry.core.nginx_service._server_health_status",
        return_value="healthy",
    ) as health:
        yield health


def _make_vs_config(
    path="/virtual/dev-essentials",
    server_name="Dev Essentials",
    tool_mappings=None,
    tool_scope_overrides=None,
    is_enabled=True,
):
    """Helper to build VirtualServerConfig objects for tests."""
    if tool_mappings is None:
        tool_mappings = [
            ToolMapping(
                tool_name="search",
                backend_server_path="/github",
            ),
        ]
    if tool_scope_overrides is None:
        tool_scope_overrides = []
    return VirtualServerConfig(
        path=path,
        server_name=server_name,
        tool_mappings=tool_mappings,
        tool_scope_overrides=tool_scope_overrides,
        is_enabled=is_enabled,
    )


def _location_block(
    config: str,
    location_path: str,
) -> str:
    """Return the body of one exact-match location block from rendered config."""
    match = re.search(
        rf"location = {re.escape(location_path)} \{{(.*?)\n    \}}",
        config,
        re.S,
    )
    assert match, f"location {location_path} not rendered"
    return match.group(1)


async def _write_mappings_and_read(
    vs: VirtualServerConfig,
    tmpdir: str,
) -> dict:
    """Write the mapping for one virtual server into tmpdir and return its JSON."""
    from registry.core.nginx_service import NginxConfigService

    with patch("registry.core.nginx_service.VIRTUAL_MAPPINGS_DIR", Path(tmpdir)):
        await NginxConfigService()._write_virtual_server_mappings([vs])
    server_id = vs.path.replace("/virtual/", "", 1)
    return json.loads((Path(tmpdir) / f"{server_id}.json").read_text())


class TestGenerateVirtualServerBlocks:
    """Tests for _generate_virtual_server_blocks.

    Uses the conftest-provided mock_virtual_server_repository (autouse fixture).
    """

    @pytest.mark.asyncio
    async def test_no_enabled_virtual_servers(self, mock_virtual_server_repository):
        """Test empty string returned when no enabled virtual servers exist."""
        mock_virtual_server_repository.list_enabled.return_value = []

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_server_blocks()

        assert result == ""

    @pytest.mark.asyncio
    async def test_generates_location_block(self, mock_virtual_server_repository):
        """Test location block is generated for an enabled virtual server."""
        vs = _make_vs_config()
        mock_virtual_server_repository.list_enabled.return_value = [vs]

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_server_blocks()

        assert "/virtual/dev-essentials" in result

    @pytest.mark.asyncio
    async def test_block_includes_set_virtual_server_id(self, mock_virtual_server_repository):
        """Test that generated block includes set $virtual_server_id."""
        vs = _make_vs_config()
        mock_virtual_server_repository.list_enabled.return_value = [vs]

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_server_blocks()

        assert 'set $virtual_server_id "dev-essentials"' in result

    @pytest.mark.asyncio
    async def test_block_includes_auth_request(self, mock_virtual_server_repository):
        """Test that generated block includes auth_request directive."""
        vs = _make_vs_config()
        mock_virtual_server_repository.list_enabled.return_value = [vs]

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_server_blocks()

        assert "auth_request /validate" in result

    @pytest.mark.asyncio
    async def test_block_includes_lua_directives(self, mock_virtual_server_repository):
        """Test that generated block includes Lua directives."""
        vs = _make_vs_config()
        mock_virtual_server_repository.list_enabled.return_value = [vs]

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_server_blocks()

        assert "rewrite_by_lua_file" in result
        assert "content_by_lua_file" in result
        assert "virtual_router.lua" in result

    @pytest.mark.asyncio
    async def test_block_routes_401_through_auth_error(self, mock_virtual_server_repository):
        """Virtual-server blocks must route 401s through @auth_error so the
        RFC 9728 WWW-Authenticate header is emitted (issue #989)."""
        vs = _make_vs_config()
        mock_virtual_server_repository.list_enabled.return_value = [vs]

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_server_blocks()

        assert "error_page 401 = @auth_error" in result
        assert "error_page 403 = @forbidden_error" in result

    @pytest.mark.asyncio
    async def test_entra_block_points_401_at_the_per_virtual_prm(
        self, mock_virtual_server_repository
    ):
        """On Entra the 401 must advertise the virtual server's OWN PRM.

        The gateway-wide default is the bare origin, whose resource Entra cannot
        match to an App ID URI and whose OIDC-basics scopes it refuses, so a
        client following that default can never log in to a virtual path.
        """
        vs = _make_vs_config()
        mock_virtual_server_repository.list_enabled.return_value = [vs]

        # The gate reads settings from registry.api.wellknown_routes and the URL
        # from registry.core.nginx_service. The conftest rebinds the settings
        # singleton, so each module can hold a distinct object: patch both
        # references or the gate silently sees the unpatched provider.
        from registry.core.nginx_service import NginxConfigService

        with (
            patch("registry.api.wellknown_routes.settings.auth_provider", "entra"),
            patch("registry.core.nginx_service.settings.registry_url", "https://gw.example.com"),
        ):
            result = await NginxConfigService()._generate_virtual_server_blocks()

        assert (
            'set $mcp_resource_metadata "https://gw.example.com'
            '/.well-known/oauth-protected-resource/virtual/dev-essentials/mcp";' in result
        )

    @pytest.mark.asyncio
    async def test_lenient_idp_block_keeps_the_gateway_wide_prm(
        self, mock_virtual_server_repository, mock_server_repository
    ):
        """REGRESSION GUARD: on Keycloak/Cognito the bare-origin PRM works, so a
        plain-backed virtual server must NOT override $mcp_resource_metadata."""
        vs = _make_vs_config()
        mock_virtual_server_repository.list_enabled.return_value = [vs]
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://backend.example.com/mcp",
            "egress_auth_mode": "none",
        }

        from registry.core.nginx_service import NginxConfigService

        with (
            patch("registry.api.wellknown_routes.settings.auth_provider", "keycloak"),
            patch("registry.core.nginx_service.settings.registry_url", "https://gw.example.com"),
        ):
            result = await NginxConfigService()._generate_virtual_server_blocks()

        assert "/virtual/dev-essentials" in result
        assert "set $mcp_resource_metadata" not in result

    @pytest.mark.asyncio
    async def test_prm_gate_failure_still_renders_the_location(
        self, mock_virtual_server_repository
    ):
        """A backing-server lookup failure must cost only the PRM override.

        The gate reads backing entries, so letting its error escape would abort
        the generator and drop EVERY virtual location from the rendered config,
        taking the endpoints down to protect a discovery hint.
        """
        vs = _make_vs_config()
        mock_virtual_server_repository.list_enabled.return_value = [vs]

        from registry.core.nginx_service import NginxConfigService

        with (
            patch("registry.api.wellknown_routes.settings.auth_provider", "keycloak"),
            patch(
                "registry.api.wellknown_routes.server_service.get_server_info",
                side_effect=RuntimeError("documentdb unavailable"),
            ),
        ):
            result = await NginxConfigService()._generate_virtual_server_blocks()

        assert "location /virtual/dev-essentials/ {" in result
        assert "content_by_lua_file /etc/nginx/lua/virtual_router.lua" in result
        assert "set $mcp_resource_metadata" not in result

    @pytest.mark.asyncio
    async def test_location_normalised_to_trailing_slash(self, mock_virtual_server_repository):
        """Issue #1501: the virtual-server location must render with a trailing
        slash so nginx does a subtree prefix match (`/virtual/dev/`) instead of
        hijacking any URL that merely starts with the path (`/virtual/dev` would
        otherwise prefix-match `/virtual/devtools`)."""
        vs = _make_vs_config(path="/virtual/dev", server_name="Dev")
        mock_virtual_server_repository.list_enabled.return_value = [vs]

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_server_blocks()

        # The location directive is normalised to end with a slash ...
        assert "location /virtual/dev/ {" in result
        # ... and must NOT emit the bare-path form that prefix-matches
        # /virtual/devtools, /virtual/development, etc.
        assert "location /virtual/dev {" not in result

    @pytest.mark.asyncio
    async def test_multiple_virtual_servers(self, mock_virtual_server_repository):
        """Test that multiple virtual servers produce multiple location blocks."""
        vs1 = _make_vs_config(path="/virtual/dev", server_name="Dev")
        vs2 = _make_vs_config(path="/virtual/staging", server_name="Staging")
        mock_virtual_server_repository.list_enabled.return_value = [vs1, vs2]

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_server_blocks()

        assert "/virtual/dev" in result
        assert "/virtual/staging" in result


class TestGenerateVirtualBackendLocations:
    """Tests for _generate_virtual_backend_locations.

    Uses the conftest-provided mock_server_repository (autouse fixture).
    """

    @pytest.mark.asyncio
    async def test_no_backends(self, mock_server_repository):
        """Test empty string returned when virtual servers have no tool mappings."""
        vs = _make_vs_config(tool_mappings=[])

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])

        assert result == ""

    @pytest.mark.parametrize(
        ("proxy_pass_url", "backend_url"),
        [
            ("https://api.github.com", "https://api.github.com/mcp"),
            ("http://currenttime-server:8000/", "http://currenttime-server:8000/mcp"),
            ("http://93.184.216.34:8000/mcp", "http://93.184.216.34:8000/mcp"),
        ],
    )
    @pytest.mark.asyncio
    async def test_backend_location_proxies_only_to_the_auth_server_hop(
        self, mock_server_repository, proxy_pass_url, backend_url
    ):
        """nginx never resolves or dials a registrant host, whatever its form.

        The backend location proxies to the auth-server mcp-proxy hop for the
        registered path; the selected upstream reaches the hop only through the
        token the sibling /_vs_auth capture signs over $backend_url.
        """
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": proxy_pass_url,
        }

        from registry.core.nginx_service import NginxConfigService, settings

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])
        block = _location_block(result, "/_vs_backend_github")
        auth_block = _location_block(result, "/_vs_auth_github")

        hop = f"{settings.auth_server_url.rstrip('/')}/mcp-proxy/github/"
        assert re.findall(r"proxy_pass (\S+);", block) == [hop]
        assert "internal;" in block
        assert 'proxy_set_header X-Registered-Server-Path "/github";' in block
        assert 'proxy_set_header X-Registered-Route-Mode "virtual";' in block
        assert "proxy_set_header X-Internal-Token $http_x_internal_token;" in block
        assert "resolver " not in result
        assert f'set $backend_url "{backend_url}";' in auth_block
        assert "proxy_set_header X-Resolved-Upstream $backend_url;" in auth_block

    @pytest.mark.asyncio
    async def test_preserves_nested_mcp_transport_path(self, mock_server_repository):
        """A configured /mcp/... endpoint must not receive a second /mcp suffix."""
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://insights.example.com/mcp/http",
        }

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])

        assert 'set $backend_url "https://insights.example.com/mcp/http";' in result
        assert "/mcp/http/mcp" not in result

    @pytest.mark.parametrize(
        "endpoint",
        ["https://knowledge-mcp.global.api.aws/", "https://knowledge-mcp.global.api.aws"],
    )
    @pytest.mark.asyncio
    async def test_root_mcp_endpoint_replaces_internal_capture_uri(
        self, mock_server_repository, endpoint
    ):
        """The hop is bound to the root endpoint; the capture URI never reaches it."""
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://knowledge-mcp.global.api.aws",
            "mcp_endpoint": endpoint,
        }

        from registry.core.nginx_service import NginxConfigService

        blocks = await NginxConfigService()._generate_virtual_backend_locations([vs])
        assert 'set $backend_url "https://knowledge-mcp.global.api.aws";' in blocks
        assert "/_vs_backend_github;" not in blocks

    @pytest.mark.asyncio
    async def test_explicit_mcp_endpoint_keeps_proxy_host(self, mock_server_repository):
        """Explicit endpoint paths use the private proxy host for internal routing."""
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "http://insights-service:8000",
            "mcp_endpoint": "https://public.example.com/custom/mcp/http",
        }

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])

        assert 'set $backend_url "http://insights-service:8000/custom/mcp/http";' in result
        assert "public.example.com" not in result

    @pytest.mark.asyncio
    async def test_credentials_not_forwarded_to_untrusted_backend(self, mock_server_repository):
        """The caller's credential must not be relayed toward a registrant-controlled backend.

        This location relays to the auth-server hop for a backend supplied by
        whoever registered the server. Forwarding ``Authorization`` or the parent
        request's ``Cookie`` (inherited by the Lua subrequest) would hand the
        caller's registry-scoped token or session cookie to the hop's upstream
        request. Both must be cleared instead.
        """
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://api.github.com",
        }

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])

        assert 'proxy_set_header Authorization "";' in result
        assert "proxy_set_header Authorization $http_authorization;" not in result
        # The Lua subrequest inherits the parent request's Cookie header, so the
        # user's registry session cookie must also be cleared before reaching
        # the untrusted backend.
        assert 'proxy_set_header Cookie "";' in result

    @pytest.mark.asyncio
    async def test_identity_headers_forwarded_via_http_vars(self, mock_server_repository):
        """Caller identity is forwarded using $http_x_user/$http_x_username variables.

        The Lua virtual_router sets X-User and X-Username as request headers
        (ngx.req.set_header) before ngx.location.capture subrequests.  The
        _vs_backend location block then forwards them to the auth-server hop via
        proxy_set_header using the $http_x_user/$http_x_username variables
        (which read from incoming request headers, not auth_request_set vars).

        This two-part approach is required because auth_request_set variables
        ($auth_user) do not propagate into subrequest contexts.
        """
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://api.github.com",
        }

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])

        # Identity headers forwarded via $http_x_* (request header vars, set by Lua)
        assert "proxy_set_header X-User $http_x_user;" in result
        assert "proxy_set_header X-Username $http_x_username;" in result
        # Must NOT use $auth_user (doesn't propagate to subrequests)
        assert "proxy_set_header X-User $auth_user" not in result
        assert "proxy_set_header X-Username $auth_username" not in result

    @pytest.mark.asyncio
    async def test_pinned_mapping_uses_its_version_document_backend(self, mock_server_repository):
        """A pinned tool must not fall back to the active version's upstream."""
        mappings = [
            ToolMapping(tool_name="search", backend_server_path="/github"),
            ToolMapping(tool_name="issues", backend_server_path="/github", backend_version="v2"),
        ]
        vs = _make_vs_config(tool_mappings=mappings)
        mock_server_repository.get.side_effect = {
            "/github": {
                "is_enabled": True,
                "proxy_pass_url": "http://old-service:8000/mcp",
                "other_version_ids": ["/github:v2"],
            },
            "/github:v2": {
                "path": "/github:v2",
                "active_version_id": "/github",
                "version": "v2",
                "is_enabled": True,
                "proxy_pass_url": "http://new-service:8000/mcp",
                "tool_list": [
                    {
                        "name": "issues",
                        "description": "Version-specific issues",
                        "inputSchema": {"type": "object"},
                    }
                ],
            },
        }.get
        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        blocks = await service._generate_virtual_backend_locations([vs])
        assert blocks.count("    location = /_vs_backend") == 2
        assert 'set $backend_url "http://new-service:8000/mcp";' in blocks
        assert 'set $backend_url "http://old-service:8000/mcp";' in blocks
        assert "proxy_pass http://old-service" not in blocks
        assert "proxy_pass http://new-service" not in blocks

        with TemporaryDirectory() as tmpdir:
            with patch("registry.core.nginx_service.VIRTUAL_MAPPINGS_DIR", Path(tmpdir)):
                await service._write_virtual_server_mappings([vs])
            data = json.loads((Path(tmpdir) / "dev-essentials.json").read_text())
        active = data["tool_backend_map"]["search"]["backend_location"]
        pinned = data["tool_backend_map"]["issues"]["backend_location"]
        assert active != pinned
        assert f"location = {active} {{" in blocks
        assert f"location = {pinned} {{" in blocks
        # Each location signs its own version's upstream for the hop.
        auth_for = {loc: loc.replace("/_vs_backend", "/_vs_auth", 1) for loc in (active, pinned)}
        assert 'set $backend_url "http://old-service:8000/mcp";' in _location_block(
            blocks, auth_for[active]
        )
        assert 'set $backend_url "http://new-service:8000/mcp";' in _location_block(
            blocks, auth_for[pinned]
        )
        assert data["tool_backend_map"]["issues"]["backend_server_path"] == "/github:v2"
        assert data["tool_backend_map"]["issues"]["block_server_path"] == "/github"
        assert data["tools"][1]["backend_server_path"] == "/github:v2"
        assert data["tools"][1]["block_server_path"] == "/github"
        assert data["tools"][1]["original_name"] == "issues"
        assert data["tools"][1]["description"] == "Version-specific issues"
        assert data["tools"][1]["inputSchema"] == {"type": "object"}
        for key in ("backend_location", "backend_server_path", "original_name", "backend_version"):
            assert data["tools"][1][key] == data["tool_backend_map"]["issues"][key]
        assert f"location = {pinned.replace('/_vs_backend', '/_vs_auth', 1)} {{" in blocks

    @pytest.mark.asyncio
    async def test_versioned_path_without_explicit_pin_uses_selected_doc(
        self, mock_server_repository
    ):
        """A pre-versioned mapping must not become /github:v2:v2 or authorize under that path."""
        docs = {
            "/github": {
                "is_enabled": True,
                "proxy_pass_url": "https://active.example.com/mcp",
                "egress_auth_mode": "pat",
                "other_version_ids": ["/github:v2"],
            },
            "/github:v2": {
                "path": "/github:v2",
                "active_version_id": "/github",
                "version": "v2",
                "is_enabled": True,
                "proxy_pass_url": "https://pinned.example.com/mcp",
                "tool_list": [{"name": "issues", "description": "Pinned version"}],
            },
        }
        mock_server_repository.get.side_effect = docs.get
        vs = _make_vs_config(
            tool_mappings=[ToolMapping(tool_name="issues", backend_server_path="/github:v2")]
        )
        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        blocks = await service._generate_virtual_backend_locations([vs])
        assert "proxy_pass https://pinned.example.com/mcp;" not in blocks
        assert "location = /_vs_backend_github.3av2 {" in blocks
        assert 'set $resolved_version "/github:v2";' in blocks
        assert 'proxy_set_header X-Registered-Server-Path "/github";' in blocks
        assert "/mcp-proxy/github/;" in blocks

        with TemporaryDirectory() as tmpdir:
            with patch("registry.core.nginx_service.VIRTUAL_MAPPINGS_DIR", Path(tmpdir)):
                await service._write_virtual_server_mappings([vs])
            data = json.loads((Path(tmpdir) / "dev-essentials.json").read_text())
        assert data["tools"][0]["backend_server_path"] == "/github:v2"
        assert data["tools"][0]["block_server_path"] == "/github"
        assert data["tools"][0]["description"] == "Pinned version"
        assert data["tool_backend_map"]["issues"]["backend_location"] == (
            "/_vs_backend_github.3av2"
        )

    @pytest.mark.asyncio
    async def test_deduplicates_backends(self, mock_server_repository):
        """Test that duplicate backend paths are deduplicated."""
        mappings = [
            ToolMapping(tool_name="search", backend_server_path="/github"),
            ToolMapping(tool_name="issues", backend_server_path="/github"),
        ]
        vs = _make_vs_config(tool_mappings=mappings)
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://api.github.com",
        }

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])

        # Should only have one /_vs_backend block for /github
        assert result.count("/_vs_backend") == 1

    @pytest.mark.asyncio
    async def test_skips_missing_backends(self, mock_server_repository):
        """Test that missing backend servers are skipped."""
        vs = _make_vs_config()
        mock_server_repository.get.return_value = None

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])

        assert result == ""

    @pytest.mark.asyncio
    async def test_skips_backends_without_proxy_url(self, mock_server_repository):
        """Test that backends without proxy_pass_url are skipped."""
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "server_name": "GitHub",
        }

        from registry.core.nginx_service import NginxConfigService

        service = NginxConfigService()
        result = await service._generate_virtual_backend_locations([vs])

        assert result == ""

    @pytest.mark.asyncio
    async def test_egress_backend_uses_separate_backend_bound_auth_and_proxy(
        self, mock_server_repository
    ):
        """Distinct registered backends must authorize and vend separately."""
        vs = _make_vs_config(
            tool_mappings=[
                ToolMapping(tool_name="issues", backend_server_path="/jira"),
                ToolMapping(tool_name="pages", backend_server_path="/confluence"),
            ]
        )
        mock_server_repository.get.side_effect = lambda path: {
            "is_enabled": True,
            "proxy_pass_url": f"https://{path.strip('/')}.example.com/mcp",
            "egress_auth_mode": "pat",
            "egress_oauth": {"provider": "atlassian"},
        }

        from registry.core.nginx_service import NginxConfigService

        result = await NginxConfigService()._generate_virtual_backend_locations([vs])

        for path in ("jira", "confluence"):
            assert f"location = /_vs_auth_{path}" in result
            assert f"location = /_vs_backend_{path}" in result
            assert f"/mcp-proxy/{path}/" in result
            assert f"/{path}/mcp;" in result
            assert f"https://{path}.example.com/mcp" in result
        assert result.count("proxy_set_header X-Internal-Token $http_x_internal_token;") == 2

    @pytest.mark.asyncio
    async def test_backend_auth_uses_configured_nginx_marker(self, mock_server_repository):
        """The generated /validate hop must use the secret that enables token minting."""
        from registry.core.nginx_service import NginxConfigService, settings

        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://github.example.com/mcp",
            "egress_auth_mode": "pat",
        }
        with patch.object(settings, "auth_server_nginx_marker_secret", "example-marker-for-test"):
            result = await NginxConfigService()._generate_virtual_backend_locations(
                [_make_vs_config()]
            )

        assert 'X-Validate-Source-Secret "example-marker-for-test";' in result
        assert "proxy_set_header X-Virtual-Original-URL $scheme://$host$request_uri;" in result
        assert "proxy_set_header X-Original-URL $scheme://$host/github/mcp;" in result
        assert "{{NGINX_MARKER_SECRET}}" not in result

    @pytest.mark.asyncio
    async def test_pinned_version_uses_its_registered_endpoint(self, mock_server_repository):
        """A pinned virtual backend signs and routes the selected version's own endpoint."""
        from registry.core.nginx_service import NginxConfigService

        docs = {
            "/jira": {
                "is_enabled": True,
                "proxy_pass_url": "https://active.example.com/mcp",
                "version": "v2",
                "other_version_ids": ["/jira:v1"],
                "egress_auth_mode": "pat",
            },
            "/jira:v1": {
                "path": "/jira:v1",
                "is_enabled": True,
                "proxy_pass_url": "https://legacy.example.com/api",
                "mcp_endpoint": "https://legacy.example.com/api/custom/mcp",
                "version": "v1",
                "active_version_id": "/jira",
            },
        }
        mock_server_repository.get.side_effect = lambda path: docs.get(path)
        vs = _make_vs_config(
            tool_mappings=[
                ToolMapping(tool_name="search", backend_server_path="/jira"),
                ToolMapping(
                    tool_name="old_search", backend_server_path="/jira", backend_version="v1"
                ),
            ]
        )
        result = await NginxConfigService()._generate_virtual_backend_locations([vs])
        auth_block = result.split("location = /_vs_auth_jira {", 1)[1].split("\n    }", 1)[0]

        assert (
            'if ($http_x_mcp_server_version = "v1") {\n'
            '            set $backend_url "https://legacy.example.com/api/custom/mcp";\n'
            '            set $resolved_version "/jira:v1";'
        ) in auth_block
        # The active label and "latest" select the active version; anything else
        # is an unknown pin and signs the invalid sentinel (no credential minted).
        assert 'if ($http_x_mcp_server_version = "v2") { set $version_known "1"; }' in auth_block
        assert 'if ($version_known = "") { set $resolved_version "__invalid_version__"; }' in (
            auth_block
        )
        assert "proxy_set_header X-Resolved-Version $resolved_version;" in auth_block
        pinned_auth = result.split("location = /_vs_auth_jira.3av1 {", 1)[1].split("\n    }", 1)[0]
        assert 'set $backend_url "https://legacy.example.com/api/custom/mcp";' in pinned_auth
        assert 'set $resolved_version "/jira:v1";' in pinned_auth
        assert "$http_x_mcp_server_version" not in pinned_auth
        assert "proxy_set_header X-Resolved-Upstream $backend_url;" in pinned_auth
        assert 'proxy_set_header X-Registered-Server-Path "/jira";' in pinned_auth
        assert "location = /_vs_backend_jira.3av1 {" in result
        assert "proxy_pass " in result.split("location = /_vs_backend_jira.3av1 {", 1)[1]

    @pytest.mark.asyncio
    async def test_single_version_backend_accepts_its_active_label(self, mock_server_repository):
        """A mapping pinned to the label that is now the only (active) version still routes."""
        from registry.core.nginx_service import NginxConfigService

        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://jira.example.com/mcp",
            "version": "v3",
            "egress_auth_mode": "pat",
        }
        vs = _make_vs_config(
            tool_mappings=[
                ToolMapping(tool_name="search", backend_server_path="/jira", backend_version="v3")
            ]
        )
        result = await NginxConfigService()._generate_virtual_backend_locations([vs])
        pinned = result.split("location = /_vs_auth_jira.3av3 {", 1)[1].split("\n    }", 1)[0]
        assert 'set $backend_url "https://jira.example.com/mcp";' in pinned
        assert 'set $resolved_version "";' in pinned
        assert "$http_x_mcp_server_version" not in pinned

    @pytest.mark.asyncio
    async def test_plain_backend_authorization_never_refuses_a_pin(self, mock_server_repository):
        """A plain backend dispatches to its active endpoint whatever the pin, so its
        authorization binds the active version and a stale pin cannot break it."""
        from registry.core.nginx_service import NginxConfigService

        docs = {
            "/plain": {
                "is_enabled": True,
                "proxy_pass_url": "https://plain.example.com/mcp",
                "version": "v2",
                "other_version_ids": ["/plain:v1"],
            },
            "/plain:v1": {
                "path": "/plain:v1",
                "is_enabled": True,
                "proxy_pass_url": "https://old.example.com/mcp",
            },
        }
        mock_server_repository.get.side_effect = lambda path: docs.get(path)
        vs = _make_vs_config(
            tool_mappings=[ToolMapping(tool_name="t", backend_server_path="/plain")]
        )
        result = await NginxConfigService()._generate_virtual_backend_locations([vs])
        auth_block = result.split("location = /_vs_auth_plain {", 1)[1].split("\n    }", 1)[0]

        assert "__invalid_version__" not in auth_block
        assert "old.example.com" not in auth_block
        assert 'set $backend_url "https://plain.example.com/mcp";' in auth_block

    @pytest.mark.asyncio
    async def test_paths_differing_only_in_punctuation_get_distinct_locations(
        self, mock_server_repository
    ):
        """/a-b, /a.b and /a_b are distinct registrations and must never share a location."""
        from registry.core.nginx_service import NginxConfigService

        docs = {
            path: {"is_enabled": True, "proxy_pass_url": f"https://{host}.example.com/mcp"}
            for path, host in (("/a-b", "dash"), ("/a.b", "dot"), ("/a_b", "under"))
        }
        mock_server_repository.get.side_effect = lambda path: docs.get(path)
        vs = _make_vs_config(
            tool_mappings=[
                ToolMapping(tool_name=f"t{i}", backend_server_path=path)
                for i, path in enumerate(docs)
            ]
        )
        result = await NginxConfigService()._generate_virtual_backend_locations([vs])

        locations = re.findall(r"location = (/_vs_auth\S*) \{", result)
        assert sorted(locations) == ["/_vs_auth_a-b", "/_vs_auth_a.2eb", "/_vs_auth_a.5fb"]
        for location, host in (
            ("/_vs_auth_a-b", "dash"),
            ("/_vs_auth_a.2eb", "dot"),
            ("/_vs_auth_a.5fb", "under"),
        ):
            block = result.split(f"location = {location} {{", 1)[1].split("\n    }", 1)[0]
            assert f'set $backend_url "https://{host}.example.com/mcp";' in block

    @pytest.mark.asyncio
    async def test_builtin_backend_valid_endpoint_remains_routable(self, mock_server_repository):
        """The built-in private target may use its canonical /mcp endpoint."""
        from registry.core.nginx_service import NginxConfigService

        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "http://mcpgw-server:8003/",
            "mcp_endpoint": "http://mcpgw-server:8003/mcp",
        }
        vs = _make_vs_config(
            tool_mappings=[ToolMapping(tool_name="search", backend_server_path="/airegistry-tools")]
        )
        result = await NginxConfigService()._generate_virtual_backend_locations([vs])

        assert "location = /_vs_auth_airegistry-tools" in result
        assert "location = /_vs_backend_airegistry-tools" in result

    @pytest.mark.asyncio
    async def test_backend_auth_uses_bounded_validation_timeouts(self, mock_server_repository):
        """A stalled auth-server cannot hold each virtual subrequest for 60 seconds."""
        from registry.core.nginx_service import NginxConfigService

        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://github.example.com/mcp",
            "egress_auth_mode": "pat",
        }
        block = await NginxConfigService()._generate_virtual_backend_locations([_make_vs_config()])
        auth_block = block.split("location = /_vs_backend_github", 1)[0]

        for directive in (
            "proxy_connect_timeout 10s;",
            "proxy_read_timeout 10s;",
            "proxy_send_timeout 10s;",
        ):
            assert directive in auth_block

    @pytest.mark.parametrize(
        ("egress", "relayed_bearer"),
        [
            ({"egress_auth_mode": "none"}, set()),
            # obo_exchange exchanges the caller's bearer at the hop, which strips it.
            (
                {"egress_auth_mode": "pat", "egress_oauth": {"provider": "github"}},
                {"authorization", "x-authorization"},
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_backend_clears_every_reserved_header(
        self, mock_server_repository, egress, relayed_bearer
    ):
        """Every reserved header except framing, re-set identity and the hop token is cleared."""
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://backend.example.com/mcp",
            **egress,
        }
        from registry.core.nginx_service import NginxConfigService

        result = await NginxConfigService()._generate_virtual_backend_locations([_make_vs_config()])
        block = _location_block(result, "/_vs_backend_github")

        cleared = {name.lower() for name in re.findall(r'proxy_set_header (\S+) "";', block)}
        assert cleared | relayed_bearer == {
            "authorization",
            "x-authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-real-ip",
            "x-scopes",
            "x-auth-method",
            "x-groups",
            "x-client-id",
            "x-user-pool-id",
            "x-region",
            "x-original-url",
            "x-server-name",
            "x-tool-name",
            "x-entity-path",
            "x-original-method",
            "x-internal-token-generic",
            "x-internal-token-registry",
            "x-generic-proxy-kind",
            "x-generic-streaming",
            "x-generic-has-upstream-auth",
            "x-resolved-upstream",
            "x-resolved-generic-upstream",
            "x-upstream-url",
            "x-body",
            "x-body-uninspectable",
        }
        # Identity is re-set from the validated values, never cleared or passed through.
        assert "proxy_set_header X-User $http_x_user;" in block
        assert "proxy_set_header X-Username $http_x_username;" in block
        # X-Internal-Token carries the /_vs_auth-minted token; the hop verifies and strips it.
        assert "proxy_set_header X-Internal-Token $http_x_internal_token;" in block
        assert not cleared & relayed_bearer

    def test_stripped_headers_derive_from_reserved_set(self):
        """A header added to the reserved set is stripped without a second edit."""
        from registry.constants import RESERVED_CUSTOM_HEADER_NAMES
        from registry.core.nginx_service import (
            _VS_BACKEND_FRAMING_HEADERS,
            _VS_BACKEND_RESET_IDENTITY_HEADERS,
            _VS_BACKEND_STRIPPED_HEADERS,
        )

        assert _VS_BACKEND_FRAMING_HEADERS <= RESERVED_CUSTOM_HEADER_NAMES
        assert _VS_BACKEND_RESET_IDENTITY_HEADERS <= RESERVED_CUSTOM_HEADER_NAMES
        assert _VS_BACKEND_STRIPPED_HEADERS == (
            RESERVED_CUSTOM_HEADER_NAMES
            - _VS_BACKEND_FRAMING_HEADERS
            - _VS_BACKEND_RESET_IDENTITY_HEADERS
        )
        # Every ingress credential must stay on the stripped side of the carve-outs.
        for credential in ("authorization", "x-authorization", "proxy-authorization", "cookie"):
            assert credential in _VS_BACKEND_STRIPPED_HEADERS

    @pytest.mark.asyncio
    async def test_backend_auth_still_receives_the_caller_bearer(self, mock_server_repository):
        """The /_vs_auth capture validates the caller, so it keeps X-Authorization."""
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://backend.example.com/mcp",
        }
        from registry.core.nginx_service import NginxConfigService

        result = await NginxConfigService()._generate_virtual_backend_locations([_make_vs_config()])
        block = _location_block(result, "/_vs_auth_github")

        assert "proxy_set_header X-Authorization $http_x_authorization;" in block

    @pytest.mark.asyncio
    async def test_backend_auth_capture_fits_large_validate_response(self, mock_server_repository):
        """Issue #1939: the Lua router calls /_vs_auth_* with ngx.location.capture,
        and that location proxies straight to the auth server's /validate. It never
        passes through the template's shared `location = /validate` block, so it
        does not inherit that block's 64k header buffer and must set its own. It
        must also not request the group-bearing registry token."""
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://backend.example.com/mcp",
        }
        from registry.core.nginx_service import NginxConfigService

        result = await NginxConfigService()._generate_virtual_backend_locations([_make_vs_config()])
        block = _location_block(result, "/_vs_auth_github")

        for directive in (
            "proxy_buffer_size 64k;",
            "proxy_buffers 2 64k;",
            "proxy_busy_buffers_size 64k;",
            "error_page 500 502 504 = @auth_subrequest_failed;",
            'proxy_set_header X-Registry-Api-Auth "";',
        ):
            assert directive in block, directive

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "backend_doc",
        [
            {"is_enabled": False},
            {},
        ],
        ids=["disabled", "missing-enable-flag"],
    )
    async def test_disabled_backend_gets_no_location_or_mapping(
        self,
        mock_server_repository,
        backend_doc,
    ):
        """A disabled (or security-quarantined) backend is not reachable via a virtual server."""
        mock_server_repository.get.return_value = {
            "proxy_pass_url": "https://backend.example.com/mcp",
            "tool_list": [{"name": "search", "inputSchema": {"type": "object"}}],
            **backend_doc,
        }
        vs = _make_vs_config()
        from registry.core.nginx_service import NginxConfigService

        result = await NginxConfigService()._generate_virtual_backend_locations([vs])
        with TemporaryDirectory() as tmpdir:
            mapping = await _write_mappings_and_read(vs, tmpdir)

        assert "_vs_backend_github" not in result
        assert mapping["tools"] == []
        assert mapping["tool_backend_map"] == {}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "status",
        ["unknown", "checking", "unhealthy: timeout"],
    )
    async def test_unhealthy_backend_gets_no_location_or_mapping(
        self,
        mock_server_repository,
        _backends_healthy,
        status,
    ):
        """Parity with direct routes: only a healthy backend is rendered."""
        _backends_healthy.return_value = status
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://backend.example.com/mcp",
            "tool_list": [{"name": "search", "inputSchema": {"type": "object"}}],
        }
        vs = _make_vs_config()
        from registry.core.nginx_service import NginxConfigService

        result = await NginxConfigService()._generate_virtual_backend_locations([vs])
        with TemporaryDirectory() as tmpdir:
            mapping = await _write_mappings_and_read(vs, tmpdir)

        assert "_vs_backend_github" not in result
        assert mapping["tools"] == []

    @pytest.mark.asyncio
    async def test_auth_expired_backend_stays_routable(
        self,
        mock_server_repository,
        _backends_healthy,
    ):
        """An expired-auth backend is up, so the direct route keeps it and so do we."""
        _backends_healthy.return_value = "healthy-auth-expired"
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://backend.example.com/mcp",
        }
        from registry.core.nginx_service import NginxConfigService

        result = await NginxConfigService()._generate_virtual_backend_locations([_make_vs_config()])

        assert "location = /_vs_backend_github {" in result

    @pytest.mark.asyncio
    async def test_health_is_read_for_the_active_document_path(
        self,
        mock_server_repository,
        _backends_healthy,
    ):
        """Health is keyed by the server's own path, as the direct route keys it."""
        mock_server_repository.get.return_value = {
            "path": "/github",
            "is_enabled": True,
            "proxy_pass_url": "https://backend.example.com/mcp",
        }
        vs = _make_vs_config(
            tool_mappings=[ToolMapping(tool_name="search", backend_server_path="/github/")]
        )
        from registry.core.nginx_service import NginxConfigService

        await NginxConfigService()._generate_virtual_backend_locations([vs])

        _backends_healthy.assert_called_with("/github")


class TestWriteVirtualServerMappings:
    """Tests for _write_virtual_server_mappings.

    Uses the conftest-provided mock_server_repository (autouse fixture).
    """

    @pytest.mark.asyncio
    async def test_writes_mapping_file(self, mock_server_repository):
        """Test that mapping JSON file is written for each virtual server."""
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "server_name": "GitHub",
            "is_enabled": True,
            "proxy_pass_url": "https://github.example.com/mcp",
            "tool_list": [
                {
                    "name": "search",
                    "description": "Search repos",
                    "inputSchema": {"type": "object"},
                },
            ],
        }

        with TemporaryDirectory() as tmpdir:
            await _write_mappings_and_read(vs, tmpdir)
            written = sorted(p.name for p in Path(tmpdir).iterdir())

        # Only the final file remains: the atomic write leaves no temp file behind.
        assert written == ["dev-essentials.json"]

    @pytest.mark.asyncio
    async def test_mapping_contains_tools(self, mock_server_repository):
        """Test that mapping JSON contains tool data with alias."""
        vs = _make_vs_config(
            tool_mappings=[
                ToolMapping(
                    tool_name="search",
                    alias="gh-search",
                    backend_server_path="/github",
                ),
            ],
        )
        mock_server_repository.get.return_value = {
            "server_name": "GitHub",
            "is_enabled": True,
            "proxy_pass_url": "https://github.example.com/mcp",
            "tool_list": [
                {
                    "name": "search",
                    "description": "Search repos",
                    "inputSchema": {"type": "object"},
                },
            ],
        }

        with TemporaryDirectory() as tmpdir:
            written_data = await _write_mappings_and_read(vs, tmpdir)

        assert len(written_data["tools"]) == 1
        assert written_data["tools"][0]["name"] == "gh-search"
        assert written_data["tools"][0]["original_name"] == "search"

    @pytest.mark.asyncio
    async def test_mapping_marks_credentialed_backend_for_user_specific_discovery(
        self, mock_server_repository
    ):
        """Lua must not reuse another user's vaulted-backend tools list."""
        vs = _make_vs_config()
        mock_server_repository.get.return_value = {
            "is_enabled": True,
            "proxy_pass_url": "https://github.example.com/mcp",
            "egress_auth_mode": "oauth_user",
        }

        with TemporaryDirectory() as tmpdir:
            written_data = await _write_mappings_and_read(vs, tmpdir)

        assert written_data["tools"][0]["egress_auth_mode"] == "oauth_user"

    @pytest.mark.asyncio
    async def test_mapping_includes_scope_overrides(self, mock_server_repository):
        """Test that mapping JSON includes per-tool scope overrides."""
        vs = _make_vs_config(
            tool_mappings=[
                ToolMapping(tool_name="search", backend_server_path="/github"),
            ],
            tool_scope_overrides=[
                ToolScopeOverride(
                    tool_alias="search",
                    required_scopes=["github:read"],
                ),
            ],
        )
        mock_server_repository.get.return_value = {
            "server_name": "GitHub",
            "is_enabled": True,
            "proxy_pass_url": "https://github.example.com/mcp",
            "tool_list": [
                {
                    "name": "search",
                    "description": "Search repos",
                    "inputSchema": {"type": "object"},
                },
            ],
        }

        with TemporaryDirectory() as tmpdir:
            written_data = await _write_mappings_and_read(vs, tmpdir)

        assert written_data["tools"][0]["required_scopes"] == ["github:read"]

    @pytest.mark.asyncio
    async def test_mapping_includes_backend_map(self, mock_server_repository):
        """Test that mapping JSON includes tool_backend_map."""
        vs = _make_vs_config(
            tool_mappings=[
                ToolMapping(tool_name="search", backend_server_path="/github"),
            ],
        )
        mock_server_repository.get.return_value = {
            "server_name": "GitHub",
            "is_enabled": True,
            "proxy_pass_url": "https://github.example.com/mcp",
            "tool_list": [
                {
                    "name": "search",
                    "description": "Search repos",
                    "inputSchema": {"type": "object"},
                },
            ],
        }

        with TemporaryDirectory() as tmpdir:
            written_data = await _write_mappings_and_read(vs, tmpdir)

        assert "search" in written_data["tool_backend_map"]
        assert "/_vs_backend" in written_data["tool_backend_map"]["search"]["backend_location"]

    @pytest.mark.asyncio
    async def test_mapping_never_names_a_backend_without_internal_locations(
        self, mock_server_repository
    ):
        """A mapped backend that gets no internal location (deleted, unsafe URL, bad
        egress mode) must not appear in the mapping: the router would capture a
        location that does not exist and misreport it as a grant refusal."""
        from registry.core.nginx_service import NginxConfigService

        docs = {
            "/live": {"is_enabled": True, "proxy_pass_url": "https://live.example.com/mcp"},
            "/badmode": {
                "is_enabled": True,
                "proxy_pass_url": "https://bad.example.com/mcp",
                "egress_auth_mode": "unknown",
            },
        }
        mock_server_repository.get.side_effect = lambda path: docs.get(path)
        vs = _make_vs_config(
            tool_mappings=[
                ToolMapping(tool_name=name, backend_server_path=path)
                for name, path in (("a", "/live"), ("b", "/deleted"), ("c", "/badmode"))
            ]
        )
        with TemporaryDirectory() as tmpdir:
            written_data = await _write_mappings_and_read(vs, tmpdir)
        locations = await NginxConfigService()._generate_virtual_backend_locations([vs])

        mapped = {tool["backend_location"] for tool in written_data["tools"]}
        assert mapped == {"/_vs_backend_live"}
        for location in mapped:
            assert f"location = {location} {{" in locations


class TestEncodePathForLocation:
    """Tests for _encode_path_for_location."""

    def test_simple_path_keeps_its_name(self):
        from registry.core.nginx_service import NginxConfigService

        assert NginxConfigService._encode_path_for_location("/github") == "_github"

    def test_encoding_is_injective_over_valid_path_characters(self):
        """Every valid server-path character maps distinctly: no two paths collide."""
        from itertools import product

        from registry.core.nginx_service import NginxConfigService

        alphabet = ["a", "/", "-", ".", "_", "5", "f", "2", "e"]
        paths = ["/" + "".join(chars) for n in range(1, 5) for chars in product(alphabet, repeat=n)]
        encoded = {NginxConfigService._encode_path_for_location(p) for p in paths}
        assert len(encoded) == len(paths)

    def test_encoded_name_is_a_safe_location_suffix(self):
        from registry.core.nginx_service import NginxConfigService

        encoded = NginxConfigService._encode_path_for_location("/ai.smithery-test/x_y")
        assert re.fullmatch(r"[A-Za-z0-9_.\-]+", encoded)
