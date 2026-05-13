"""Tests for local-server schema additions.

Covers:
- LocalRuntime field validation (image_digest format, platforms/digest docker-only,
  required_env disjoint from env)
- ServerInfo.deployment + local_runtime invariants
- The shared _validate_deployment_invariants helper
"""

import pytest
from pydantic import ValidationError

from registry.core.schemas import LocalRuntime, ServerInfo


@pytest.mark.unit
class TestLocalRuntime:
    """Validation rules for the LocalRuntime model itself."""

    def test_minimal_npx(self):
        rt = LocalRuntime(type="npx", package="@acme/mcp")
        assert rt.type == "npx"
        assert rt.package == "@acme/mcp"
        assert rt.args == []
        assert rt.env == {}

    def test_required_env_overlap_with_env_rejected(self):
        """required_env keys MUST NOT also appear in env."""
        with pytest.raises(ValidationError, match="required_env keys must not also appear"):
            LocalRuntime(
                type="npx",
                package="@acme/mcp",
                env={"API_KEY": "${API_KEY}"},
                required_env=["API_KEY"],
            )

    def test_image_digest_must_be_sha256(self):
        with pytest.raises(ValidationError, match="image_digest must start with 'sha256:'"):
            LocalRuntime(
                type="docker",
                package="acme/mcp:1.0",
                image_digest="md5:abc",
            )

    def test_image_digest_only_valid_for_docker(self):
        with pytest.raises(ValidationError, match="image_digest is only valid for docker"):
            LocalRuntime(
                type="npx",
                package="@acme/mcp",
                image_digest="sha256:abc",
            )

    def test_platforms_only_valid_for_docker(self):
        with pytest.raises(ValidationError, match="platforms is only valid for docker"):
            LocalRuntime(
                type="npx",
                package="@acme/mcp",
                platforms=["linux/amd64"],
            )

    def test_docker_with_digest_and_platforms(self):
        rt = LocalRuntime(
            type="docker",
            package="acme/mcp:1.0",
            image_digest="sha256:" + "a" * 64,
            platforms=["linux/amd64", "linux/arm64"],
        )
        assert rt.image_digest.startswith("sha256:")

    def test_command_runtime_no_version_pin(self):
        # command runtime doesn't require version pin (free-form path)
        rt = LocalRuntime(type="command", package="/usr/local/bin/my-mcp")
        assert rt.version is None


@pytest.mark.unit
class TestServerInfoDeployment:
    """Deployment invariants on ServerInfo."""

    def test_remote_default(self):
        s = ServerInfo(
            server_name="s",
            path="/s",
            proxy_pass_url="http://test",
        )
        assert s.deployment == "remote"
        assert s.local_runtime is None

    def test_remote_requires_proxy_pass_url(self):
        with pytest.raises(ValidationError, match="deployment='remote' requires proxy_pass_url"):
            ServerInfo(server_name="s", path="/s")

    def test_remote_forbids_local_runtime(self):
        with pytest.raises(ValidationError, match="deployment='remote' must not set local_runtime"):
            ServerInfo(
                server_name="s",
                path="/s",
                proxy_pass_url="http://test",
                local_runtime=LocalRuntime(type="npx", package="@acme/mcp"),
            )

    def test_local_requires_local_runtime(self):
        with pytest.raises(ValidationError, match="deployment='local' requires local_runtime"):
            ServerInfo(server_name="s", path="/s", deployment="local")

    def test_local_forbids_proxy_pass_url(self):
        with pytest.raises(ValidationError, match="must not set proxy_pass_url"):
            ServerInfo(
                server_name="s",
                path="/s",
                deployment="local",
                local_runtime=LocalRuntime(type="npx", package="@acme/mcp"),
                proxy_pass_url="http://test",
            )

    def test_local_forbids_mcp_endpoint(self):
        with pytest.raises(ValidationError, match="must not set mcp_endpoint"):
            ServerInfo(
                server_name="s",
                path="/s",
                deployment="local",
                local_runtime=LocalRuntime(type="npx", package="@acme/mcp"),
                mcp_endpoint="http://test/mcp",
            )

    def test_local_forces_stdio_transport(self):
        s = ServerInfo(
            server_name="s",
            path="/s",
            deployment="local",
            local_runtime=LocalRuntime(type="npx", package="@acme/mcp"),
            transport="streamable-http",
        )
        assert s.transport == "stdio"
        assert s.supported_transports == ["stdio"]

    def test_local_requires_auth_scheme_none(self):
        with pytest.raises(ValidationError, match="must use auth_scheme='none'"):
            ServerInfo(
                server_name="s",
                path="/s",
                deployment="local",
                local_runtime=LocalRuntime(type="npx", package="@acme/mcp"),
                auth_scheme="bearer",
            )

    def test_local_no_multi_version(self):
        from registry.core.schemas import ServerVersion

        with pytest.raises(ValidationError, match="does not support multi-version"):
            ServerInfo(
                server_name="s",
                path="/s",
                deployment="local",
                local_runtime=LocalRuntime(type="npx", package="@acme/mcp"),
                versions=[ServerVersion(version="v1", proxy_pass_url="http://test")],
            )

    def test_local_happy_path(self):
        s = ServerInfo(
            server_name="weather",
            path="/weather",
            deployment="local",
            local_runtime=LocalRuntime(
                type="docker",
                package="acme/weather-mcp:1.0",
                image_digest="sha256:" + "f" * 64,
                env={"LOG_LEVEL": "info"},
                required_env=["API_KEY"],
            ),
        )
        assert s.deployment == "local"
        assert s.transport == "stdio"
        assert s.local_runtime.type == "docker"
        assert s.proxy_pass_url is None

    def test_registered_by_audit_field(self):
        s = ServerInfo(
            server_name="s",
            path="/s",
            proxy_pass_url="http://test",
            registered_by="alice",
        )
        assert s.registered_by == "alice"

    def test_registered_by_default_none(self):
        s = ServerInfo(server_name="s", path="/s", proxy_pass_url="http://test")
        assert s.registered_by is None
