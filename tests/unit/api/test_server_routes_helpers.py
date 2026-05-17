"""Unit tests for the small private helpers in registry/api/server_routes.py.

These helpers were extracted to deduplicate logic across the register/edit/list
endpoints. Endpoint-level tests in test_server_routes.py exercise them via
HTTP, but direct unit coverage makes regressions cheap to catch and pins down
the contract for each helper independently.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from registry.api.server_routes import (
    _build_versions_list,
    _normalize_health_status,
    _validate_visibility_and_groups,
)
from registry.constants import HealthStatus


@pytest.mark.unit
class TestNormalizeHealthStatus:
    """The status cascade is preserved verbatim from the previous inline blocks
    for backward compatibility with error strings baked into status values."""

    def test_local_passes_through_verbatim(self):
        assert _normalize_health_status(HealthStatus.LOCAL) == HealthStatus.LOCAL

    def test_local_string_value(self):
        assert _normalize_health_status("local") == HealthStatus.LOCAL

    def test_healthy(self):
        assert _normalize_health_status("healthy") == "healthy"

    def test_unhealthy_substring_match(self):
        assert _normalize_health_status("unhealthy: 503") == "unhealthy"

    def test_error_substring_treated_as_unhealthy(self):
        assert _normalize_health_status("error: connection refused") == "unhealthy"

    def test_disabled(self):
        assert _normalize_health_status("disabled") == "disabled"

    def test_checking_collapsed_to_unknown(self):
        assert _normalize_health_status("checking") == "unknown"

    def test_non_string_passes_through(self):
        # Some callers pass HealthStatus enum members or other non-string types;
        # the helper should not stringify or coerce them.
        sentinel = object()
        assert _normalize_health_status(sentinel) is sentinel

    def test_unknown_string_passes_through(self):
        # If none of the substrings match, the original string is returned
        # so the caller's error context is preserved.
        assert _normalize_health_status("startup") == "startup"


@pytest.mark.unit
class TestValidateVisibilityAndGroups:
    """Visibility validation is shared between /register and /edit. Direct
    coverage avoids re-running the full HTTP test for each branch."""

    def test_public_no_groups(self):
        vis, groups = _validate_visibility_and_groups("public", None)
        assert vis == "public"
        assert groups == []

    def test_public_ignores_groups_input(self):
        # Submitting allowed_groups for public visibility is a no-op (kept for
        # backward compat with form layers that always send the field).
        vis, groups = _validate_visibility_and_groups("public", "team-a, team-b")
        assert vis == "public"
        assert groups == ["team-a", "team-b"]

    def test_private_alias_normalized_to_internal_form(self):
        # 'internal' is accepted as an alias for 'private' (legacy compat).
        vis, _ = _validate_visibility_and_groups("internal", None)
        assert vis == "private"

    def test_invalid_visibility_raises_400(self):
        with pytest.raises(HTTPException) as exc:
            _validate_visibility_and_groups("garbage", None)
        assert exc.value.status_code == 400
        assert "Invalid visibility" in exc.value.detail

    def test_group_restricted_requires_groups(self):
        with pytest.raises(HTTPException) as exc:
            _validate_visibility_and_groups("group-restricted", None)
        assert exc.value.status_code == 400
        assert "at least one allowed_group" in exc.value.detail

    def test_group_restricted_with_groups(self):
        vis, groups = _validate_visibility_and_groups("group-restricted", "a, b ,c")
        assert vis == "group-restricted"
        assert groups == ["a", "b", "c"]

    def test_empty_string_groups_filtered(self):
        # Comma-separated parsing strips whitespace and drops empty entries
        # rather than emitting empty group names.
        vis, groups = _validate_visibility_and_groups("group-restricted", "a, , b")
        assert groups == ["a", "b"]


@pytest.mark.unit
@pytest.mark.asyncio
class TestBuildVersionsList:
    """Multi-version routing list synthesis. Local servers short-circuit to
    an empty list since the ServerInfo validator forbids `versions` for them.
    Remote single-version servers return a one-entry list; multi-version
    fans out across other_version_ids via server_service.get_server_info."""

    async def test_local_short_circuits_to_empty(self):
        # Local servers can't have multi-version routing — early return with
        # no calls into server_service.get_server_info.
        with patch(
            "registry.api.server_routes.server_service.get_server_info",
            new_callable=AsyncMock,
        ) as mock_get:
            result = await _build_versions_list(
                {"deployment": "local", "other_version_ids": ["v1", "v2"]},
                "v1.0.0",
                "stable",
            )
        assert result == []
        mock_get.assert_not_called()

    async def test_single_remote_version(self):
        result = await _build_versions_list(
            {"deployment": "remote", "proxy_pass_url": "http://upstream"},
            "v1.0.0",
            "stable",
        )
        assert result == [
            {
                "version": "v1.0.0",
                "proxy_pass_url": "http://upstream",
                "status": "stable",
                "is_default": True,
            }
        ]

    async def test_multi_version_fanout(self):
        # other_version_ids → server_service.get_server_info per id; each
        # resolved entry contributes a non-default versions[] row.
        async def fake_get(version_id):
            return {
                "v2-id": {
                    "version": "v2.0.0",
                    "proxy_pass_url": "http://upstream-v2",
                    "status": "beta",
                },
                "v3-id": {
                    "version": "v3.0.0",
                    "proxy_pass_url": "http://upstream-v3",
                    "status": "deprecated",
                },
            }.get(version_id)

        with patch(
            "registry.api.server_routes.server_service.get_server_info",
            side_effect=fake_get,
        ):
            result = await _build_versions_list(
                {
                    "deployment": "remote",
                    "proxy_pass_url": "http://upstream",
                    "other_version_ids": ["v2-id", "v3-id"],
                },
                "v1.0.0",
                "stable",
            )
        assert len(result) == 3
        assert result[0]["is_default"] is True
        assert result[1]["version"] == "v2.0.0"
        assert result[1]["is_default"] is False
        assert result[2]["status"] == "deprecated"

    async def test_multi_version_skips_missing_ids(self):
        # If get_server_info returns None for a referenced id, the gap is
        # silently skipped rather than emitting a placeholder entry.
        async def fake_get(version_id):
            return (
                None
                if version_id == "missing"
                else {
                    "version": "v2.0.0",
                    "proxy_pass_url": "http://upstream-v2",
                    "status": "stable",
                }
            )

        with patch(
            "registry.api.server_routes.server_service.get_server_info",
            side_effect=fake_get,
        ):
            result = await _build_versions_list(
                {
                    "deployment": "remote",
                    "proxy_pass_url": "http://upstream",
                    "other_version_ids": ["missing", "real"],
                },
                "v1.0.0",
                "stable",
            )
        # Default entry + one resolved fanout, missing entry skipped.
        assert len(result) == 2
        assert result[1]["version"] == "v2.0.0"
