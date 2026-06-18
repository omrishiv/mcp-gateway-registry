"""Tests for federation skill deregistration (issue #1145)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from registry.api.federation_routes import _deregister_skills_from_registry


def _make_skill(
    path: str,
    *,
    metadata=None,
    tags=None,
):
    skill = MagicMock()
    skill.path = path
    skill.metadata = metadata
    skill.tags = tags or []
    return skill


@pytest.mark.unit
class TestDeregisterSkillsFromRegistry:
    """Tests for _deregister_skills_from_registry."""

    @pytest.mark.asyncio
    async def test_uses_skill_service_delete_for_matching_metadata(self):
        skill = _make_skill(
            "/skills/agentcore-foo",
            metadata={"agentcore_registry_id": "reg-123"},
            tags=["agentcore"],
        )
        mock_skill_repo = AsyncMock()
        mock_skill_repo.list_all.return_value = [skill]
        mock_skill_service = AsyncMock()
        mock_skill_service.delete_skill.return_value = True

        with (
            patch(
                "registry.repositories.factory.get_skill_repository",
                return_value=mock_skill_repo,
            ),
            patch(
                "registry.services.skill_service.get_skill_service",
                return_value=mock_skill_service,
            ),
        ):
            deregistered = await _deregister_skills_from_registry("reg-123")

        mock_skill_service.delete_skill.assert_awaited_once_with("/skills/agentcore-foo")
        assert deregistered == ["/skills/agentcore-foo"]

    @pytest.mark.asyncio
    async def test_matches_legacy_tag_and_path_pattern(self):
        skill = _make_skill(
            "/skills/agentcore-legacy",
            metadata={},
            tags=["agentcore"],
        )
        mock_skill_repo = AsyncMock()
        mock_skill_repo.list_all.return_value = [skill]
        mock_skill_service = AsyncMock()
        mock_skill_service.delete_skill.return_value = True

        with (
            patch(
                "registry.repositories.factory.get_skill_repository",
                return_value=mock_skill_repo,
            ),
            patch(
                "registry.services.skill_service.get_skill_service",
                return_value=mock_skill_service,
            ),
        ):
            deregistered = await _deregister_skills_from_registry("other-reg")

        mock_skill_service.delete_skill.assert_awaited_once_with("/skills/agentcore-legacy")
        assert deregistered == ["/skills/agentcore-legacy"]

    @pytest.mark.asyncio
    async def test_skips_paths_when_delete_returns_false(self):
        skill = _make_skill(
            "/skills/agentcore-missing",
            metadata={"agentcore_registry_id": "reg-123"},
        )
        mock_skill_repo = AsyncMock()
        mock_skill_repo.list_all.return_value = [skill]
        mock_skill_service = AsyncMock()
        mock_skill_service.delete_skill.return_value = False

        with (
            patch(
                "registry.repositories.factory.get_skill_repository",
                return_value=mock_skill_repo,
            ),
            patch(
                "registry.services.skill_service.get_skill_service",
                return_value=mock_skill_service,
            ),
        ):
            deregistered = await _deregister_skills_from_registry("reg-123")

        assert deregistered == []
