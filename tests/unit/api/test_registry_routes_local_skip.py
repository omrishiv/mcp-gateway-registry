"""Tests verifying the Anthropic-compatible registry API skips local servers.

The Anthropic API surface is remote-discovery (URL-based connect, HTTP
transport). Local (stdio) servers don't fit that model — emitting them would
produce malformed entries with empty proxy_pass_url and the wrong transport
type. The list endpoint filters them out; the per-server endpoints 404.
"""

from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.unit
@pytest.mark.asyncio
class TestAnthropicListServersSkipsLocal:
    """The list endpoint enumerates all servers and must drop local ones."""

    async def test_local_server_excluded_from_list(self):
        from registry.api.registry_routes import list_servers

        all_servers = {
            "/remote-srv": {
                "server_name": "remote",
                "path": "/remote-srv",
                "deployment": "remote",
                "proxy_pass_url": "http://upstream",
            },
            "/local-srv": {
                "server_name": "local",
                "path": "/local-srv",
                "deployment": "local",
                "local_runtime": {"type": "npx", "package": "@acme/mcp"},
            },
        }
        captured: list[dict] = []

        def fake_transform(filtered, cursor=None, limit=100):
            captured.extend(filtered)
            from registry.schemas.anthropic_schema import (
                PaginationMetadata,
                ServerList,
            )

            return ServerList(servers=[], metadata=PaginationMetadata(nextCursor=None))

        with (
            patch(
                "registry.api.registry_routes.server_service.get_all_servers",
                new_callable=AsyncMock,
                return_value=all_servers,
            ),
            patch(
                "registry.api.registry_routes.server_service.is_service_enabled",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "registry.api.registry_routes.health_service._get_service_health_data",
                return_value={"status": "healthy", "last_checked_iso": None},
            ),
            patch(
                "registry.api.registry_routes.transform_to_server_list",
                side_effect=fake_transform,
            ),
        ):
            await list_servers(
                cursor=None,
                limit=10,
                user_context={"username": "tester", "is_admin": True},
            )

        # The list passed to the transformer contains only the remote server.
        assert len(captured) == 1
        assert captured[0]["path"] == "/remote-srv"


@pytest.mark.unit
@pytest.mark.asyncio
class TestAnthropicVersionEndpointsSkipLocal:
    """list_server_versions and get_server_version both 404 on local servers
    rather than emit a malformed entry. Path normalization is unchanged from
    the remote case — only the deployment check differs."""

    async def test_list_server_versions_404s_for_local(self):
        from fastapi import HTTPException

        from registry.api.registry_routes import list_server_versions

        local_info = {
            "server_name": "local",
            "path": "/local-srv",
            "deployment": "local",
            "local_runtime": {"type": "npx", "package": "@acme/mcp"},
        }
        with patch(
            "registry.api.registry_routes.server_service.get_server_info",
            new_callable=AsyncMock,
            return_value=local_info,
        ):
            with pytest.raises(HTTPException) as exc:
                # Server name format: "<namespace>/<path>" — namespace from constants.
                from registry.constants import REGISTRY_CONSTANTS

                await list_server_versions(
                    serverName=f"{REGISTRY_CONSTANTS.ANTHROPIC_SERVER_NAMESPACE}/local-srv",
                    user_context={"username": "tester"},
                )
        assert exc.value.status_code == 404

    async def test_get_server_version_404s_for_local(self):
        from fastapi import HTTPException

        from registry.api.registry_routes import get_server_version

        local_info = {
            "server_name": "local",
            "path": "/local-srv",
            "deployment": "local",
            "local_runtime": {"type": "npx", "package": "@acme/mcp"},
        }
        with patch(
            "registry.api.registry_routes.server_service.get_server_info",
            new_callable=AsyncMock,
            return_value=local_info,
        ):
            with pytest.raises(HTTPException) as exc:
                from registry.constants import REGISTRY_CONSTANTS

                await get_server_version(
                    serverName=f"{REGISTRY_CONSTANTS.ANTHROPIC_SERVER_NAMESPACE}/local-srv",
                    version="1.0.0",
                    user_context={"username": "tester"},
                )
        assert exc.value.status_code == 404
