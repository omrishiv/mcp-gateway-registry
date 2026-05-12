"""Unit tests for registry/utils/mongodb_connection.py."""

from unittest.mock import MagicMock, patch

import pytest

from registry.utils.mongodb_connection import (
    build_client_options,
    build_connection_string,
    build_tls_kwargs,
)


def _mock_settings(**overrides):
    defaults = {
        "mongodb_connection_string": None,
        "documentdb_use_iam": False,
        "documentdb_host": "mongo.example.com",
        "documentdb_port": 27017,
        "documentdb_database": "mcp_registry",
        "documentdb_username": None,
        "documentdb_password": None,
        "documentdb_use_tls": False,
        "documentdb_tls_ca_file": "",
        "documentdb_direct_connection": False,
        "storage_backend": "mongodb-ce",
    }
    defaults.update(overrides)
    s = MagicMock()
    for key, value in defaults.items():
        setattr(s, key, value)
    return s


class TestConnectionStringOverride:
    """When mongodb_connection_string is set, it short-circuits all other logic."""

    def test_override_returned_verbatim(self):
        uri = "mongodb+srv://user:pass@cluster.mongodb.net/mcp_registry?retryWrites=true"
        settings = _mock_settings(mongodb_connection_string=uri)
        with patch("registry.core.config.settings", settings):
            assert build_connection_string() == uri

    def test_override_ignores_iam(self):
        """Override wins over IAM auth path — no boto3 import attempted."""
        uri = "mongodb+srv://user:pass@cluster.mongodb.net/mcp_registry"
        settings = _mock_settings(mongodb_connection_string=uri, documentdb_use_iam=True)
        with patch("registry.core.config.settings", settings):
            assert build_connection_string() == uri

    def test_override_ignores_username_password(self):
        uri = "mongodb://override:creds@host/db"
        settings = _mock_settings(
            mongodb_connection_string=uri,
            documentdb_username="other",
            documentdb_password="other",
        )
        with patch("registry.core.config.settings", settings):
            assert build_connection_string() == uri

    def test_client_options_empty_when_override_set(self):
        """Override owns retryWrites, directConnection, etc. — no defaults injected."""
        settings = _mock_settings(
            mongodb_connection_string="mongodb+srv://x/y",
            documentdb_direct_connection=True,  # would normally set directConnection
        )
        with patch("registry.core.config.settings", settings):
            assert build_client_options() == {}

    def test_tls_kwargs_empty_when_override_set(self):
        """Override URI owns TLS (mongodb+srv:// implies TLS automatically)."""
        settings = _mock_settings(
            mongodb_connection_string="mongodb+srv://x/y",
            documentdb_use_tls=True,
            documentdb_tls_ca_file="/tmp/ca.pem",
        )
        with patch("registry.core.config.settings", settings):
            assert build_tls_kwargs() == {}


class TestDiscreteVarPathUnchanged:
    """Without the override, legacy behavior is preserved."""

    def test_username_password_builds_uri(self):
        settings = _mock_settings(
            documentdb_username="user",
            documentdb_password="pass",
            documentdb_host="myhost",
            documentdb_port=27018,
            documentdb_database="mydb",
            storage_backend="mongodb-ce",
        )
        with patch("registry.core.config.settings", settings):
            uri = build_connection_string()
        assert uri == (
            "mongodb://user:pass@myhost:27018/mydb"
            "?authMechanism=SCRAM-SHA-256&authSource=admin"
        )

    def test_documentdb_backend_uses_scram_sha_1(self):
        settings = _mock_settings(
            documentdb_username="user",
            documentdb_password="pass",
            storage_backend="documentdb",
        )
        with patch("registry.core.config.settings", settings):
            assert "SCRAM-SHA-1" in build_connection_string()

    def test_no_auth_local_dev(self):
        settings = _mock_settings(documentdb_host="localhost", documentdb_port=27017)
        with patch("registry.core.config.settings", settings):
            assert build_connection_string() == "mongodb://localhost:27017/mcp_registry"

    def test_client_options_forces_retry_writes_false(self):
        """DocumentDB requires retryWrites=false; preserved when no override."""
        settings = _mock_settings()
        with patch("registry.core.config.settings", settings):
            opts = build_client_options()
        assert opts == {"retryWrites": False}

    def test_client_options_direct_connection(self):
        settings = _mock_settings(documentdb_direct_connection=True)
        with patch("registry.core.config.settings", settings):
            opts = build_client_options()
        assert opts == {"retryWrites": False, "directConnection": True}

    def test_tls_kwargs_when_enabled(self):
        settings = _mock_settings(
            documentdb_use_tls=True,
            documentdb_tls_ca_file="/certs/ca.pem",
        )
        with patch("registry.core.config.settings", settings):
            assert build_tls_kwargs() == {"tls": True, "tlsCAFile": "/certs/ca.pem"}


@pytest.mark.parametrize(
    "value",
    ["", None],
)
def test_empty_override_falls_through_to_discrete_vars(value):
    """Empty string and None both mean 'override not set'."""
    settings = _mock_settings(mongodb_connection_string=value)
    with patch("registry.core.config.settings", settings):
        uri = build_connection_string()
    # Falls through to no-auth path
    assert uri == "mongodb://mongo.example.com:27017/mcp_registry"
