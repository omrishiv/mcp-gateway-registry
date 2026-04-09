"""Unit tests for GitHubAuthProvider."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt


class TestDomainMatching:
    """Tests for _is_allowed_host and host allowlist logic."""

    def test_github_com_is_allowed(self):
        """Public github.com is allowed by default."""
        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        assert provider._is_allowed_host("https://github.com/owner/repo") is True

    def test_raw_githubusercontent_is_allowed(self):
        """raw.githubusercontent.com is allowed by default."""
        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        assert provider._is_allowed_host(
            "https://raw.githubusercontent.com/owner/repo/main/SKILL.md"
        ) is True

    def test_non_github_host_is_not_allowed(self):
        """Non-GitHub hosts are rejected."""
        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        assert provider._is_allowed_host("https://gitlab.com/owner/repo") is False

    def test_case_insensitive_matching(self):
        """Host matching is case-insensitive."""
        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        assert provider._is_allowed_host("https://GitHub.COM/owner/repo") is True

    @patch("registry.services.github_auth.settings")
    def test_extra_hosts_from_config(self, mock_settings):
        """Extra hosts from config are included in allowlist."""
        mock_settings.github_pat = ""
        mock_settings.github_app_id = ""
        mock_settings.github_app_installation_id = ""
        mock_settings.github_app_private_key = ""
        mock_settings.github_extra_hosts = "github.mycompany.com,raw.github.mycompany.com"

        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        assert provider._is_allowed_host("https://github.mycompany.com/org/repo") is True
        assert provider._is_allowed_host(
            "https://raw.github.mycompany.com/org/repo/main/f"
        ) is True

    @patch("registry.services.github_auth.settings")
    def test_empty_extra_hosts(self, mock_settings):
        """Empty extra hosts config doesn't break anything."""
        mock_settings.github_pat = ""
        mock_settings.github_app_id = ""
        mock_settings.github_app_installation_id = ""
        mock_settings.github_app_private_key = ""
        mock_settings.github_extra_hosts = ""

        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        assert provider._is_allowed_host("https://github.com/owner/repo") is True
        assert provider._is_allowed_host("https://example.com/foo") is False


class TestPATAuth:
    """Tests for Personal Access Token authentication."""

    @patch("registry.services.github_auth.settings")
    async def test_pat_returns_bearer_header(self, mock_settings):
        """PAT produces Authorization: Bearer header."""
        mock_settings.github_pat = "ghp_test_token_123"
        mock_settings.github_app_id = ""
        mock_settings.github_app_installation_id = ""
        mock_settings.github_app_private_key = ""
        mock_settings.github_extra_hosts = ""

        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        headers = await provider.get_auth_headers("https://github.com/owner/repo")
        assert headers == {"Authorization": "Bearer ghp_test_token_123"}

    @patch("registry.services.github_auth.settings")
    async def test_no_credentials_returns_empty(self, mock_settings):
        """No credentials configured returns empty headers."""
        mock_settings.github_pat = ""
        mock_settings.github_app_id = ""
        mock_settings.github_app_installation_id = ""
        mock_settings.github_app_private_key = ""
        mock_settings.github_extra_hosts = ""

        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        headers = await provider.get_auth_headers("https://github.com/owner/repo")
        assert headers == {}

    @patch("registry.services.github_auth.settings")
    async def test_non_github_host_returns_empty_even_with_pat(self, mock_settings):
        """PAT is not sent to non-GitHub hosts."""
        mock_settings.github_pat = "ghp_test_token_123"
        mock_settings.github_app_id = ""
        mock_settings.github_app_installation_id = ""
        mock_settings.github_app_private_key = ""
        mock_settings.github_extra_hosts = ""

        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        headers = await provider.get_auth_headers("https://gitlab.com/owner/repo")
        assert headers == {}

    @patch("registry.services.github_auth.settings")
    async def test_pat_works_with_raw_githubusercontent(self, mock_settings):
        """PAT is sent to raw.githubusercontent.com."""
        mock_settings.github_pat = "ghp_test_token_123"
        mock_settings.github_app_id = ""
        mock_settings.github_app_installation_id = ""
        mock_settings.github_app_private_key = ""
        mock_settings.github_extra_hosts = ""

        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        headers = await provider.get_auth_headers(
            "https://raw.githubusercontent.com/owner/repo/main/SKILL.md"
        )
        assert headers == {"Authorization": "Bearer ghp_test_token_123"}


class TestJWTCreation:
    """Tests for GitHub App JWT creation."""

    @patch("registry.services.github_auth.settings")
    def test_jwt_has_correct_claims(self, mock_settings):
        """JWT contains iat, exp, iss claims."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        mock_settings.github_pat = ""
        mock_settings.github_app_id = "12345"
        mock_settings.github_app_installation_id = "67890"
        mock_settings.github_app_private_key = pem
        mock_settings.github_extra_hosts = ""

        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        token = provider._create_jwt()

        # Decode without verification to check claims
        claims = jwt.decode(token, options={"verify_signature": False})
        assert claims["iss"] == "12345"
        assert "iat" in claims
        assert "exp" in claims
        # exp should be ~10 minutes after iat
        assert claims["exp"] - claims["iat"] <= 660  # 10 min + 60s skew

    @patch("registry.services.github_auth.settings")
    def test_jwt_uses_rs256(self, mock_settings):
        """JWT is signed with RS256 algorithm."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        mock_settings.github_pat = ""
        mock_settings.github_app_id = "12345"
        mock_settings.github_app_installation_id = "67890"
        mock_settings.github_app_private_key = pem
        mock_settings.github_extra_hosts = ""

        from registry.services.github_auth import GitHubAuthProvider

        provider = GitHubAuthProvider()
        token = provider._create_jwt()

        header = jwt.get_unverified_header(token)
        assert header["alg"] == "RS256"
