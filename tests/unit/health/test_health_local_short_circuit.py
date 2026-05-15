"""Tests for health-service short-circuit on deployment='local'."""

from unittest.mock import AsyncMock

import pytest

from registry.constants import HealthStatus
from registry.health.service import HealthMonitoringService


@pytest.mark.unit
@pytest.mark.asyncio
class TestLocalDeploymentShortCircuit:
    async def test_local_server_status_set_to_local(self):
        service = HealthMonitoringService()
        client = AsyncMock()
        server_info = {
            "deployment": "local",
            "local_runtime": {"type": "npx", "package": "@acme/mcp"},
        }

        changed = await service._check_single_service(client, "/local-srv", server_info)

        assert changed is True
        assert service.server_health_status["/local-srv"] == HealthStatus.LOCAL

    async def test_local_server_skips_http_probe(self):
        """Verify the http client is never called for local servers."""
        service = HealthMonitoringService()
        client = AsyncMock()
        server_info = {"deployment": "local", "local_runtime": {"type": "npx", "package": "x"}}

        await service._check_single_service(client, "/local-srv", server_info)

        client.get.assert_not_called()
        client.post.assert_not_called()

    async def test_remote_server_unchanged_path(self):
        """Sanity check: remote servers still go through the normal probe path."""
        service = HealthMonitoringService()
        # We don't actually probe — proxy_pass_url=None falls through to the
        # MISSING_PROXY_URL branch. The test just verifies we don't take the
        # local short-circuit.
        client = AsyncMock()
        server_info = {"deployment": "remote", "proxy_pass_url": None}

        await service._check_single_service(client, "/remote-srv", server_info)

        # Status should NOT be LOCAL — it took the normal (failing) path.
        assert service.server_health_status["/remote-srv"] != HealthStatus.LOCAL


@pytest.mark.unit
class TestGetServiceHealthDataFastLocal:
    """The fast (cache-based) health-data lookup is the read path used by
    list/dashboard endpoints. For local enabled servers, it must always report
    LOCAL — the cached status from a prior session ('unknown', 'checking',
    etc.) should not leak through, otherwise a freshly toggled-on local
    server briefly shows 'checking' even though it never gets probed."""

    def test_local_enabled_overrides_stale_cache(self):
        service = HealthMonitoringService()
        # Stale cache from a previous session.
        service.server_health_status["/local-srv"] = "checking"
        server_info = {
            "is_enabled": True,
            "deployment": "local",
            "local_runtime": {"type": "npx", "package": "@acme/mcp"},
        }

        result = service._get_service_health_data_fast("/local-srv", server_info)

        assert result["status"] == HealthStatus.LOCAL
        assert service.server_health_status["/local-srv"] == HealthStatus.LOCAL

    def test_local_disabled_takes_disabled_branch(self):
        """Disabled wins over local — the disabled branch fires first."""
        service = HealthMonitoringService()
        server_info = {
            "is_enabled": False,
            "deployment": "local",
            "local_runtime": {"type": "npx", "package": "@acme/mcp"},
        }

        result = service._get_service_health_data_fast("/local-srv", server_info)

        assert result["status"] == "disabled"


@pytest.mark.unit
@pytest.mark.asyncio
class TestPerformImmediateHealthCheckLocal:
    """toggling a local server ON triggers
    perform_immediate_health_check, which must short-circuit identically to
    the background-loop check. Otherwise the toggle response shows a misleading
    'missing proxy URL' error for valid local servers."""

    async def test_local_server_returns_local_status(self):
        from unittest.mock import AsyncMock, patch

        service = HealthMonitoringService()
        local_server = {
            "deployment": "local",
            "local_runtime": {"type": "npx", "package": "@acme/mcp"},
        }
        with patch(
            "registry.services.server_service.server_service.get_server_info",
            new_callable=AsyncMock,
            return_value=local_server,
        ):
            status, last_checked = await service.perform_immediate_health_check("/local-srv")

        assert status == HealthStatus.LOCAL
        # Don't stamp last_check_time — no actual check happened.
        assert last_checked is None
        assert "/local-srv" not in service.server_last_check_time
