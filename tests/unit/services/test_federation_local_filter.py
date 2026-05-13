"""Tests for the federation sync_local_servers opt-in flag."""

import pytest

from registry.schemas.peer_federation_schema import PeerRegistryConfig
from registry.services.peer_federation_service import PeerFederationService


@pytest.mark.unit
class TestSyncLocalServersFilter:
    """Verify _filter_servers_by_config respects the sync_local_servers flag."""

    @pytest.fixture
    def service(self):
        return PeerFederationService()

    @pytest.fixture
    def remote_server(self):
        return {
            "path": "/weather",
            "server_name": "weather",
            "deployment": "remote",
            "proxy_pass_url": "http://upstream",
        }

    @pytest.fixture
    def local_server(self):
        return {
            "path": "/local-weather",
            "server_name": "local-weather",
            "deployment": "local",
            "local_runtime": {"type": "npx", "package": "@acme/weather-mcp"},
        }

    def _make_peer_config(self, **overrides):
        defaults = {
            "peer_id": "peer1",
            "name": "Peer One",
            "endpoint": "https://peer.example.com",
            "sync_mode": "all",
            "sync_local_servers": False,
        }
        defaults.update(overrides)
        return PeerRegistryConfig(**defaults)

    def test_local_excluded_by_default(self, service, remote_server, local_server):
        """sync_local_servers=False (default) drops local servers."""
        peer = self._make_peer_config()
        result = service._filter_servers_by_config([remote_server, local_server], peer)
        assert result == [remote_server]

    def test_local_included_when_opted_in(self, service, remote_server, local_server):
        peer = self._make_peer_config(sync_local_servers=True)
        result = service._filter_servers_by_config([remote_server, local_server], peer)
        assert local_server in result
        assert remote_server in result

    def test_local_excluded_with_whitelist(self, service, remote_server, local_server):
        """Local-server filter applies BEFORE whitelist; whitelist alone won't include them."""
        peer = self._make_peer_config(
            sync_mode="whitelist",
            whitelist_servers=["/weather", "/local-weather"],
            sync_local_servers=False,
        )
        result = service._filter_servers_by_config([remote_server, local_server], peer)
        # Local server filtered out at the deployment-type stage even though
        # it's in the whitelist.
        assert result == [remote_server]

    def test_local_included_with_whitelist_and_opt_in(self, service, remote_server, local_server):
        peer = self._make_peer_config(
            sync_mode="whitelist",
            whitelist_servers=["/local-weather"],
            sync_local_servers=True,
        )
        result = service._filter_servers_by_config([remote_server, local_server], peer)
        assert result == [local_server]

    def test_only_local_servers_returns_empty_when_opted_out(self, service, local_server):
        peer = self._make_peer_config()
        result = service._filter_servers_by_config([local_server], peer)
        assert result == []


@pytest.mark.unit
class TestPeerRegistryConfigSyncLocalServersField:
    def test_default_false(self):
        peer = PeerRegistryConfig(
            peer_id="p1",
            name="Peer",
            endpoint="https://example.com",
        )
        assert peer.sync_local_servers is False

    def test_explicit_true(self):
        peer = PeerRegistryConfig(
            peer_id="p1",
            name="Peer",
            endpoint="https://example.com",
            sync_local_servers=True,
        )
        assert peer.sync_local_servers is True
