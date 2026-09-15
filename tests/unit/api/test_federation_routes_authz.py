"""Authorization tests for federation_routes management endpoints.

The /api/federation/* mutating routes are JWT mirrors of admin-gated
operations that previously enforced no authorization. These tests verify the
_check_federation_management_scope gate added in fix/servers-api-authz:
admin OR federation/peers scope may manage federation config; everyone else
gets 403. Mirrors the sibling gate in peer_management_routes.py.
"""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from registry.api.federation_routes import _get_federation_repo
from registry.auth.dependencies import nginx_proxied_auth
from registry.main import app


def _non_admin_ctx():
    return {
        "username": "ctuser",
        "groups": ["currenttime-users"],
        "scopes": ["currenttime-users"],
        "is_admin": False,
    }


def _admin_ctx():
    return {
        "username": "admin",
        "groups": ["mcp-registry-admin"],
        "scopes": ["mcp-registry-admin"],
        "is_admin": True,
    }


def _federation_scope_ctx():
    return {
        "username": "peer-1",
        "groups": [],
        "scopes": ["federation/peers"],
        "is_admin": False,
    }


@pytest.fixture
def _mock_repo():
    """A repo whose methods are AsyncMocks so we can assert no-write on 403."""
    repo = AsyncMock()
    repo.delete_config = AsyncMock(return_value=True)
    repo.get_config = AsyncMock(return_value={"id": "default"})
    return repo


def _override(auth_ctx, repo):
    app.dependency_overrides[nginx_proxied_auth] = lambda: auth_ctx
    app.dependency_overrides[_get_federation_repo] = lambda: repo


def _clear():
    app.dependency_overrides.clear()


class TestFederationManagementAuthz:
    """All federation management routes require admin or federation/peers."""

    def test_delete_config_rejects_non_admin(self, _mock_repo):
        _override(_non_admin_ctx(), _mock_repo)
        try:
            client = TestClient(app)
            resp = client.delete("/api/federation/config/default")
        finally:
            _clear()

        assert resp.status_code == 403
        _mock_repo.delete_config.assert_not_called()

    def test_sync_rejects_non_admin(self, _mock_repo):
        _override(_non_admin_ctx(), _mock_repo)
        try:
            client = TestClient(app)
            resp = client.post("/api/federation/sync")
        finally:
            _clear()

        assert resp.status_code == 403

    def test_delete_config_allows_admin(self, _mock_repo):
        _override(_admin_ctx(), _mock_repo)
        try:
            client = TestClient(app)
            resp = client.delete("/api/federation/config/default")
        finally:
            _clear()

        # Admin passes the gate; the route proceeds (not 403).
        assert resp.status_code != 403

    def test_delete_config_allows_federation_scope(self, _mock_repo):
        _override(_federation_scope_ctx(), _mock_repo)
        try:
            client = TestClient(app)
            resp = client.delete("/api/federation/config/default")
        finally:
            _clear()

        # federation/peers scope passes the gate (matches peer management).
        assert resp.status_code != 403


@pytest.mark.unit
class TestCatalogImportRespectsPeerOwnership:
    """An external-catalog sync must not write over a peer-synced record, and
    must not let the upstream catalog name a local owner.

    Both reach ``server_service.register_server`` / ``update_server`` directly,
    so without these two rules the catalog import is a way around the guards on
    every server-mutation route.
    """

    def _run_sync(self, existing_server, catalog_server):
        from unittest.mock import MagicMock, patch

        config = MagicMock()
        config.anthropic.enabled = True
        config.anthropic.endpoint = "https://registry.example.com"
        config.anthropic.servers = ["srv"]
        config.asor.enabled = False
        config.aws_registry.enabled = False

        repo = AsyncMock()
        repo.get_config = AsyncMock(return_value=config)

        server_service = MagicMock()
        server_service.get_server_info = AsyncMock(return_value=existing_server)
        server_service.register_server = AsyncMock(
            return_value={"success": True, "is_new_version": False}
        )
        server_service.update_server = AsyncMock(return_value=True)
        server_service.toggle_service = AsyncMock(return_value=True)

        client_cls = MagicMock()
        client_cls.return_value.fetch_all_servers.return_value = [catalog_server]

        _override(_admin_ctx(), repo)
        try:
            with (
                patch("registry.api.federation_routes._validate_federation_endpoints"),
                patch("registry.services.server_service.server_service", server_service),
                patch(
                    "registry.services.federation.anthropic_client.AnthropicFederationClient",
                    client_cls,
                ),
            ):
                resp = TestClient(app).post("/api/federation/sync?source=anthropic")
        finally:
            _clear()
        return resp, server_service

    def test_skips_a_path_already_synced_from_a_peer(self):
        resp, server_service = self._run_sync(
            existing_server={
                "path": "/srv",
                "server_name": "Peer Server",
                "sync_metadata": {"is_federated": True, "source_peer_id": "peer-x"},
            },
            catalog_server={
                "path": "/srv",
                "server_name": "Catalog Server",
                "proxy_pass_url": "http://catalog-upstream:9000",
            },
        )

        assert resp.status_code == 200
        server_service.register_server.assert_not_awaited()
        server_service.update_server.assert_not_awaited()

    def test_clears_an_upstream_supplied_owner(self):
        resp, server_service = self._run_sync(
            existing_server=None,
            catalog_server={
                "path": "/srv",
                "server_name": "Catalog Server",
                "proxy_pass_url": "http://catalog-upstream:9000",
                # A foreign identity realm must not name a local owner.
                "registered_by": "admin",
            },
        )

        assert resp.status_code == 200
        persisted = server_service.register_server.await_args.args[0]
        assert persisted["registered_by"] == ""
