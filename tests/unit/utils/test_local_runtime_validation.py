"""Tests for the env-leak guard and unpinned-version warning."""

import pytest

from registry.utils.local_runtime_validation import (
    _shannon_entropy,
    _value_looks_like_secret,
    add_unpinned_warning_tag,
    find_leaked_secrets,
)


@pytest.mark.unit
class TestSecretDetection:
    def test_placeholder_allowed(self):
        assert _value_looks_like_secret("${API_KEY}") is False
        assert _value_looks_like_secret("${FOO_BAR}") is False

    def test_embedded_placeholder_allowed(self):
        # Template strings with ${VAR} embedded anywhere are treated as templates,
        # not literal secrets.
        assert _value_looks_like_secret("https://${HOST}/api") is False
        assert _value_looks_like_secret("${USER}@${HOST}:${PORT}") is False
        assert _value_looks_like_secret("prefix-${TOKEN}-suffix") is False

    def test_empty_value_allowed(self):
        assert _value_looks_like_secret("") is False

    def test_normal_config_value_allowed(self):
        assert _value_looks_like_secret("info") is False
        assert _value_looks_like_secret("http://localhost:3000") is False
        assert _value_looks_like_secret("debug") is False

    def test_openai_key_flagged(self):
        assert _value_looks_like_secret("sk-proj-abc123") is True

    def test_github_token_flagged(self):
        assert _value_looks_like_secret("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") is True

    def test_aws_key_flagged(self):
        assert _value_looks_like_secret("AKIAIOSFODNN7EXAMPLE") is True

    def test_long_high_entropy_flagged(self):
        # 40 chars of mixed alphanumeric — base64-ish entropy
        secret = "aB3xY9kL7mN2pQ8rS5tU1vW6xY4zA7bC0dE3fG6h"
        assert _value_looks_like_secret(secret) is True

    def test_long_low_entropy_allowed(self):
        # Long but repetitive — shouldn't be flagged
        assert _value_looks_like_secret("a" * 50) is False

    def test_short_random_allowed(self):
        # Short strings even with high entropy aren't flagged (too many false positives)
        assert _value_looks_like_secret("aB3xY") is False


@pytest.mark.unit
class TestFindLeakedSecrets:
    def test_clean_env_no_leaks(self):
        result = find_leaked_secrets(
            env={"LOG_LEVEL": "info", "PORT": "3000"},
            args=["--verbose", "--config=/tmp/config"],
        )
        assert result == {"env_keys": [], "arg_indices": []}

    def test_placeholders_not_flagged(self):
        result = find_leaked_secrets(
            env={"API_KEY": "${API_KEY}", "TOKEN": "${MY_TOKEN}"},
            args=[],
        )
        assert result == {"env_keys": [], "arg_indices": []}

    def test_env_secret_flagged(self):
        result = find_leaked_secrets(
            env={"OPENAI_KEY": "sk-proj-realsecretvalue"},
            args=[],
        )
        assert result["env_keys"] == ["OPENAI_KEY"]

    def test_arg_secret_flagged(self):
        result = find_leaked_secrets(
            env={},
            args=["--api-key", "sk-proj-realsecretvalue"],
        )
        assert result["arg_indices"] == ["1"]

    def test_multiple_leaks_reported(self):
        result = find_leaked_secrets(
            env={"A": "ghp_abcdefghijklmnopqrstuvwxyz0123", "B": "${SAFE}"},
            args=["--token", "AKIAIOSFODNN7EXAMPLE"],
        )
        assert result["env_keys"] == ["A"]
        assert result["arg_indices"] == ["1"]


@pytest.mark.unit
class TestUnpinnedWarningTag:
    def test_docker_with_digest_no_tag(self):
        rt = {"type": "docker", "package": "acme/mcp:1.0", "image_digest": "sha256:abc"}
        assert add_unpinned_warning_tag(rt, []) == []

    def test_docker_without_digest_tagged(self):
        rt = {"type": "docker", "package": "acme/mcp:latest"}
        assert add_unpinned_warning_tag(rt, []) == ["unpinned-version"]

    def test_npx_with_version_no_tag(self):
        rt = {"type": "npx", "package": "@acme/mcp", "version": "1.0.0"}
        assert add_unpinned_warning_tag(rt, ["existing"]) == ["existing"]

    def test_npx_without_version_tagged(self):
        rt = {"type": "npx", "package": "@acme/mcp"}
        assert add_unpinned_warning_tag(rt, []) == ["unpinned-version"]

    def test_uvx_without_version_tagged(self):
        rt = {"type": "uvx", "package": "acme-mcp"}
        assert add_unpinned_warning_tag(rt, ["foo"]) == ["foo", "unpinned-version"]

    def test_command_runtime_no_pinning_check(self):
        # command runtime is just a path; no version concept
        rt = {"type": "command", "package": "/usr/local/bin/my-mcp"}
        assert add_unpinned_warning_tag(rt, []) == []

    def test_idempotent(self):
        rt = {"type": "npx", "package": "@acme/mcp"}
        tags = add_unpinned_warning_tag(rt, [])
        tags = add_unpinned_warning_tag(rt, tags)
        assert tags == ["unpinned-version"]


@pytest.mark.unit
class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_uniform_string_zero_entropy(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_random_string_high_entropy(self):
        # Mixed characters
        assert _shannon_entropy("aB3xY9kL7mN2") > 3.0
