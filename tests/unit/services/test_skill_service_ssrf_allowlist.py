"""
Unit tests for SKILL.md SSRF allowlist derivation.

These tests verify that the SSRF allowlist used by skill_service._is_safe_url
honours settings.github_extra_hosts so GitHub Enterprise (GHES) hosts -- which
typically resolve to private IPs -- can be reached for SKILL.md fetching once
the operator has explicitly trusted them via configuration.

Issue #938: Support SKILLS from Github Enterprise.
"""

import logging
from unittest.mock import patch

import pytest

logger = logging.getLogger(__name__)


# =============================================================================
# Helpers
# =============================================================================


def _clear_trusted_domains_cache() -> None:
    """Reset the lru_cache so each test sees the patched settings value."""
    from registry.services.skill_service import _trusted_domains

    _trusted_domains.cache_clear()


# =============================================================================
# Default allowlist (no GHES configured)
# =============================================================================


class TestDefaultTrustedDomains:
    """Built-in allowlist behaviour when github_extra_hosts is empty."""

    @patch("registry.services.skill_service.settings")
    def test_default_hosts_are_trusted(
        self,
        mock_settings,
    ) -> None:
        """github.com, gitlab.com, raw.githubusercontent.com, bitbucket.org always trusted."""
        mock_settings.github_extra_hosts = ""
        _clear_trusted_domains_cache()

        from registry.services.skill_service import (
            _DEFAULT_TRUSTED_DOMAINS,
            _trusted_domains,
        )

        # With no extras configured the merged set must equal the defaults.
        # Using equality (rather than per-host membership) catches accidental
        # additions or omissions and keeps the assertion off CodeQL's
        # py/incomplete-url-substring-sanitization radar.
        assert _trusted_domains() == _DEFAULT_TRUSTED_DOMAINS

    @patch("registry.services.skill_service.settings")
    def test_unconfigured_ghes_host_not_trusted(
        self,
        mock_settings,
    ) -> None:
        """A GHES hostname not in github_extra_hosts is not in the allowlist."""
        mock_settings.github_extra_hosts = ""
        _clear_trusted_domains_cache()

        from registry.services.skill_service import (
            _DEFAULT_TRUSTED_DOMAINS,
            _trusted_domains,
        )

        assert _trusted_domains() == _DEFAULT_TRUSTED_DOMAINS


# =============================================================================
# GHES hosts via github_extra_hosts
# =============================================================================


class TestGHESHostMerge:
    """Configured GHES hosts are merged into the allowlist."""

    @patch("registry.services.skill_service.settings")
    def test_single_ghes_host_added(
        self,
        mock_settings,
    ) -> None:
        """One configured GHES host extends the default trusted set by exactly that host."""
        mock_settings.github_extra_hosts = "github.mycompany.com"
        _clear_trusted_domains_cache()

        from registry.services.skill_service import (
            _DEFAULT_TRUSTED_DOMAINS,
            _trusted_domains,
        )

        assert _trusted_domains() == _DEFAULT_TRUSTED_DOMAINS | {"github.mycompany.com"}

    @patch("registry.services.skill_service.settings")
    def test_multiple_ghes_hosts_added(
        self,
        mock_settings,
    ) -> None:
        """Comma-separated GHES hosts all extend the default set."""
        mock_settings.github_extra_hosts = (
            "github.mycompany.com,raw.github.mycompany.com"
        )
        _clear_trusted_domains_cache()

        from registry.services.skill_service import (
            _DEFAULT_TRUSTED_DOMAINS,
            _trusted_domains,
        )

        expected = _DEFAULT_TRUSTED_DOMAINS | {
            "github.mycompany.com",
            "raw.github.mycompany.com",
        }
        assert _trusted_domains() == expected

    @patch("registry.services.skill_service.settings")
    def test_whitespace_and_case_normalised(
        self,
        mock_settings,
    ) -> None:
        """Whitespace is stripped and hostnames are lowercased."""
        mock_settings.github_extra_hosts = "  GitHub.MyCompany.com  ,  RAW.github.mycompany.com  "
        _clear_trusted_domains_cache()

        from registry.services.skill_service import (
            _DEFAULT_TRUSTED_DOMAINS,
            _trusted_domains,
        )

        expected = _DEFAULT_TRUSTED_DOMAINS | {
            "github.mycompany.com",
            "raw.github.mycompany.com",
        }
        assert _trusted_domains() == expected

    @patch("registry.services.skill_service.settings")
    def test_defaults_preserved_when_extras_present(
        self,
        mock_settings,
    ) -> None:
        """Adding GHES hosts does not drop the built-in defaults."""
        mock_settings.github_extra_hosts = "github.mycompany.com"
        _clear_trusted_domains_cache()

        from registry.services.skill_service import (
            _DEFAULT_TRUSTED_DOMAINS,
            _trusted_domains,
        )

        # Subset assertion: every default must still be in the merged set.
        assert _DEFAULT_TRUSTED_DOMAINS <= _trusted_domains()


# =============================================================================
# _is_safe_url integration with the merged allowlist
# =============================================================================


class TestSafeUrlForGHES:
    """End-to-end: GHES URLs bypass the private-IP check once configured."""

    @patch("registry.services.skill_service.settings")
    def test_ghes_url_blocked_when_not_configured(
        self,
        mock_settings,
    ) -> None:
        """Without github_extra_hosts, GHES on a private IP fails SSRF."""
        mock_settings.github_extra_hosts = ""
        _clear_trusted_domains_cache()

        # Simulate DNS resolving the GHES host to an internal IP (10.0.0.5).
        with patch("registry.services.skill_service.socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (None, None, None, None, ("10.0.0.5", 443)),
            ]

            from registry.services.skill_service import _is_safe_url

            url = "https://github.mycompany.com/org/repo/blob/main/SKILL.md"
            assert _is_safe_url(url) is False

    @patch("registry.services.skill_service.settings")
    def test_ghes_url_allowed_when_configured(
        self,
        mock_settings,
    ) -> None:
        """With github_extra_hosts set, GHES on a private IP passes SSRF."""
        mock_settings.github_extra_hosts = "github.mycompany.com"
        _clear_trusted_domains_cache()

        # DNS resolution should be skipped entirely for trusted hosts -- we
        # patch getaddrinfo to ensure the test fails loudly if it gets called.
        with patch("registry.services.skill_service.socket.getaddrinfo") as mock_resolve:
            mock_resolve.side_effect = AssertionError(
                "getaddrinfo should not be called for trusted hosts"
            )

            from registry.services.skill_service import _is_safe_url

            url = "https://github.mycompany.com/org/repo/blob/main/SKILL.md"
            assert _is_safe_url(url) is True

    @patch("registry.services.skill_service.settings")
    def test_raw_ghes_url_allowed_when_configured(
        self,
        mock_settings,
    ) -> None:
        """raw.* GHES host trusted when listed in github_extra_hosts."""
        mock_settings.github_extra_hosts = "raw.github.mycompany.com"
        _clear_trusted_domains_cache()

        from registry.services.skill_service import _is_safe_url

        url = "https://raw.github.mycompany.com/org/repo/refs/heads/main/SKILL.md"
        assert _is_safe_url(url) is True

    @patch("registry.services.skill_service.settings")
    def test_unconfigured_internal_host_still_blocked(
        self,
        mock_settings,
    ) -> None:
        """A non-GitHub internal host on a private IP is still blocked.

        Confirms the allowlist is narrow: only configured GHES hosts skip the
        IP check, not arbitrary internal hostnames.
        """
        mock_settings.github_extra_hosts = "github.mycompany.com"
        _clear_trusted_domains_cache()

        with patch("registry.services.skill_service.socket.getaddrinfo") as mock_resolve:
            mock_resolve.return_value = [
                (None, None, None, None, ("10.0.0.5", 443)),
            ]

            from registry.services.skill_service import _is_safe_url

            assert _is_safe_url("https://internal.example.com/foo") is False


# =============================================================================
# Cache invalidation
# =============================================================================


class TestCacheBehavior:
    """The lru_cache on _trusted_domains is one-shot per process by design."""

    @pytest.fixture(autouse=True)
    def _reset_cache(self):
        _clear_trusted_domains_cache()
        yield
        _clear_trusted_domains_cache()

    @patch("registry.services.skill_service.settings")
    def test_cache_returns_same_frozenset(
        self,
        mock_settings,
    ) -> None:
        """Repeated calls return the cached frozenset without re-reading settings."""
        mock_settings.github_extra_hosts = "github.mycompany.com"

        from registry.services.skill_service import _trusted_domains

        first = _trusted_domains()
        second = _trusted_domains()

        assert first is second
