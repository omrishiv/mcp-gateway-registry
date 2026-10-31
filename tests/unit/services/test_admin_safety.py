"""Unit tests for registry/services/admin_safety.py.

Covers the intra-admin safety helpers: self-target detection, admin-group
resolution, admin-user counting, and the last-admin / demotion guards. Each
guard must fail closed (deny) when the admin population cannot be determined.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from registry.services import admin_safety
from registry.services.admin_safety import AdminSafetyError


class TestIsSelfTarget:
    """Tests for the self-deletion detection helper."""

    def test_matches_same_username(self):
        assert admin_safety.is_self_target("admin", "admin") is True

    def test_matches_case_insensitively(self):
        assert admin_safety.is_self_target("Admin", "admin") is True
        assert admin_safety.is_self_target("  admin ", "ADMIN") is True

    def test_different_user_is_not_self(self):
        assert admin_safety.is_self_target("admin", "someone-else") is False

    def test_empty_actor_never_matches(self):
        assert admin_safety.is_self_target("", "admin") is False
        assert admin_safety.is_self_target(None, "admin") is False


class TestGroupsConferAdmin:
    """Tests for the group->admin predicate."""

    def test_matches_admin_group(self):
        admins = {"mcp-registry-admin"}
        assert admin_safety.groups_confer_admin(["mcp-registry-admin"], admins) is True

    def test_case_insensitive(self):
        admins = {"mcp-registry-admin"}
        assert admin_safety.groups_confer_admin(["MCP-Registry-Admin"], admins) is True

    def test_no_match(self):
        admins = {"mcp-registry-admin"}
        assert admin_safety.groups_confer_admin(["some-group"], admins) is False

    def test_empty_groups(self):
        assert admin_safety.groups_confer_admin(None, {"mcp-registry-admin"}) is False
        assert admin_safety.groups_confer_admin([], {"mcp-registry-admin"}) is False


@pytest.mark.asyncio
class TestResolveAdminGroupNames:
    """Tests for admin-conferring group resolution from scope docs."""

    async def test_identifies_admin_via_ui_permissions(self):
        groups = {
            "custom-admins": {
                "ui_scopes": {"register_service": ["all"]},
                "mappings": ["idp-admin-group"],
            },
        }
        with patch(
            "registry.services.admin_safety.scope_service.list_groups",
            new=AsyncMock(return_value=groups),
        ):
            result = await admin_safety.resolve_admin_group_names()
        # The mapped IdP group confers admin; the scope's own name is not a
        # group a caller holds, so it is not counted.
        assert result == {"idp-admin-group"}

    async def test_fails_closed_on_error_result(self):
        with patch(
            "registry.services.admin_safety.scope_service.list_groups",
            new=AsyncMock(return_value={"error": "boom", "groups": {}}),
        ):
            with pytest.raises(AdminSafetyError) as exc:
                await admin_safety.resolve_admin_group_names()
        assert exc.value.status_code == 503

    async def test_fails_closed_on_exception(self):
        with patch(
            "registry.services.admin_safety.scope_service.list_groups",
            new=AsyncMock(side_effect=RuntimeError("db down")),
        ):
            with pytest.raises(AdminSafetyError):
                await admin_safety.resolve_admin_group_names()

    async def test_fails_closed_on_empty_admin_group_set(self):
        # Catalogue lists groups but NONE match the privileged-scope predicate
        # (predicate/catalogue drift). Must refuse rather than return an empty set
        # that would silently disable the last-admin guard.
        groups = {
            "readers": {"ui_scopes": {"list_service": ["some-server"]}, "mappings": []},
            "viewers": {"ui_scopes": {"list_service": ["another-server"]}, "mappings": []},
        }
        with patch(
            "registry.services.admin_safety.scope_service.list_groups",
            new=AsyncMock(return_value=groups),
        ):
            with pytest.raises(AdminSafetyError) as exc:
                await admin_safety.resolve_admin_group_names()
        assert exc.value.status_code == 503


def _iam_mock(users):
    mock = MagicMock()
    mock.list_users = AsyncMock(return_value=users)
    return mock


def _mongo_m2m_mock(docs):
    """Patch target: get_documentdb_client returning a db whose idp_m2m_clients
    collection yields ``docs`` from ``find({}).to_list()``."""
    cursor = MagicMock()
    cursor.to_list = AsyncMock(return_value=docs)
    collection = MagicMock()
    collection.find = MagicMock(return_value=cursor)
    db = MagicMock()
    db.__getitem__ = MagicMock(return_value=collection)
    return AsyncMock(return_value=db)


@pytest.mark.asyncio
class TestListAdminIdentities:
    """Tests for enumerating admin accounts (one alias-set per admin)."""

    async def test_counts_only_admin_users(self):
        users = [
            {"username": "admin1", "groups": ["mcp-registry-admin"]},
            {"username": "admin2", "groups": ["mcp-registry-admin"]},
            {"username": "regular", "groups": ["readers"]},
        ]
        with (
            patch(
                "registry.services.admin_safety.resolve_admin_group_names",
                new=AsyncMock(return_value={"mcp-registry-admin"}),
            ),
            patch(
                "registry.services.admin_safety.get_iam_manager",
                return_value=_iam_mock(users),
            ),
            patch(
                "registry.repositories.documentdb.client.get_documentdb_client",
                new=_mongo_m2m_mock([]),
            ),
        ):
            admins = await admin_safety.list_admin_identities()
        assert set(admins) == {frozenset({"admin1"}), frozenset({"admin2"})}

    async def test_counts_m2m_only_admin_from_mongo(self):
        # The IdP listing has NO admin (M2M group membership lives only in
        # idp_m2m_clients for non-Keycloak IdPs). The M2M admin must be counted so
        # the population is not falsely empty and the guard does not 503-brick.
        users = [{"username": "regular", "groups": ["readers"]}]
        m2m_docs = [
            {"client_id": "svc-admin", "name": "svc-admin", "groups": ["mcp-registry-admin"]},
            {"client_id": "svc-reader", "name": "svc-reader", "groups": ["readers"]},
        ]
        with (
            patch(
                "registry.services.admin_safety.resolve_admin_group_names",
                new=AsyncMock(return_value={"mcp-registry-admin"}),
            ),
            patch(
                "registry.services.admin_safety.get_iam_manager",
                return_value=_iam_mock(users),
            ),
            patch(
                "registry.repositories.documentdb.client.get_documentdb_client",
                new=_mongo_m2m_mock(m2m_docs),
            ),
        ):
            admins = await admin_safety.list_admin_identities()
        assert admins == [frozenset({"svc-admin"})]

    async def test_m2m_admin_aliases_are_ONE_admin_not_two(self):
        # Okta/Auth0 case: client_id (opaque IdP id) != name (friendly label), and
        # the M2M account is NOT in the IdP listing. Both aliases identify ONE
        # admin, so the entry is a single frozenset carrying both keys. This is
        # what lets the guard (a) recognise a delete by EITHER key AND (b) count it
        # as one admin — a flat two-element identifier set would double-count and
        # re-open the last-admin fail-open.
        users = [{"username": "regular", "groups": ["readers"]}]
        m2m_docs = [
            {
                "client_id": "0oa1b2c3d4e5",
                "name": "break-glass-admin",
                "groups": ["mcp-registry-admin"],
            },
        ]
        with (
            patch(
                "registry.services.admin_safety.resolve_admin_group_names",
                new=AsyncMock(return_value={"mcp-registry-admin"}),
            ),
            patch(
                "registry.services.admin_safety.get_iam_manager",
                return_value=_iam_mock(users),
            ),
            patch(
                "registry.repositories.documentdb.client.get_documentdb_client",
                new=_mongo_m2m_mock(m2m_docs),
            ),
        ):
            admins = await admin_safety.list_admin_identities()
        # ONE admin, addressable by either identifier.
        assert admins == [frozenset({"0oa1b2c3d4e5", "break-glass-admin"})]

    async def test_m2m_store_error_does_not_raise_when_idp_admin_present(self):
        # A datastore error reading idp_m2m_clients is best-effort: it must not
        # raise as long as the IdP listing already surfaced an admin.
        users = [{"username": "admin1", "groups": ["mcp-registry-admin"]}]
        broken = AsyncMock(side_effect=Exception("mongo down"))
        with (
            patch(
                "registry.services.admin_safety.resolve_admin_group_names",
                new=AsyncMock(return_value={"mcp-registry-admin"}),
            ),
            patch(
                "registry.services.admin_safety.get_iam_manager",
                return_value=_iam_mock(users),
            ),
            patch(
                "registry.repositories.documentdb.client.get_documentdb_client",
                new=broken,
            ),
        ):
            admins = await admin_safety.list_admin_identities()
        assert admins == [frozenset({"admin1"})]

    async def test_fails_closed_when_users_unavailable(self):
        mock = MagicMock()
        mock.list_users = AsyncMock(side_effect=Exception("keycloak down"))
        with (
            patch(
                "registry.services.admin_safety.resolve_admin_group_names",
                new=AsyncMock(return_value={"mcp-registry-admin"}),
            ),
            patch(
                "registry.services.admin_safety.get_iam_manager",
                return_value=mock,
            ),
        ):
            with pytest.raises(AdminSafetyError) as exc:
                await admin_safety.list_admin_identities()
        assert exc.value.status_code == 503

    async def test_fails_closed_when_no_admins_found(self):
        # Admin-conferring groups exist, but neither the user listing NOR the M2M
        # store surfaces an admin (e.g. an IdP adapter that returned groupless
        # users, or a truncated listing). Deriving "no admins, nothing to guard"
        # would bypass the last-admin guard, so this must fail closed.
        users = [
            {"username": "regular1", "groups": ["readers"]},
            {"username": "regular2", "groups": []},
        ]
        with (
            patch(
                "registry.services.admin_safety.resolve_admin_group_names",
                new=AsyncMock(return_value={"mcp-registry-admin"}),
            ),
            patch(
                "registry.services.admin_safety.get_iam_manager",
                return_value=_iam_mock(users),
            ),
            patch(
                "registry.repositories.documentdb.client.get_documentdb_client",
                new=_mongo_m2m_mock([]),
            ),
        ):
            with pytest.raises(AdminSafetyError) as exc:
                await admin_safety.list_admin_identities()
        assert exc.value.status_code == 503


@pytest.mark.asyncio
class TestAssertNotLastAdmin:
    """Tests for the last-admin deletion guard."""

    async def test_allows_when_other_admins_remain(self):
        with patch(
            "registry.services.admin_safety.list_admin_identities",
            new=AsyncMock(return_value=[frozenset({"admin1"}), frozenset({"admin2"})]),
        ):
            # Should not raise.
            await admin_safety.assert_not_last_admin("admin1")

    async def test_rejects_last_admin(self):
        with patch(
            "registry.services.admin_safety.list_admin_identities",
            new=AsyncMock(return_value=[frozenset({"admin1"})]),
        ):
            with pytest.raises(AdminSafetyError) as exc:
                await admin_safety.assert_not_last_admin("admin1")
        assert exc.value.status_code == 409

    async def test_noop_when_target_not_admin(self):
        with patch(
            "registry.services.admin_safety.list_admin_identities",
            new=AsyncMock(return_value=[frozenset({"admin1"})]),
        ):
            # Deleting a non-admin cannot empty the admin population.
            await admin_safety.assert_not_last_admin("regular-user")

    async def test_fails_closed_when_population_unknown(self):
        with patch(
            "registry.services.admin_safety.list_admin_identities",
            new=AsyncMock(side_effect=AdminSafetyError(503, "unknown")),
        ):
            with pytest.raises(AdminSafetyError):
                await admin_safety.assert_not_last_admin("admin1")

    async def test_rejects_last_admin_deleted_by_either_m2m_key(self):
        # The sole admin is ONE M2M client whose alias-set carries both client_id
        # and name. Deleting by EITHER identifier must be refused. This is the case
        # a flat identifier set got wrong: two aliases must count as one admin so
        # removing either empties the population.
        sole_admin = [frozenset({"0oa1b2c3d4e5", "break-glass-admin"})]
        for target in ("0oa1b2c3d4e5", "break-glass-admin"):
            with patch(
                "registry.services.admin_safety.list_admin_identities",
                new=AsyncMock(return_value=list(sole_admin)),
            ):
                with pytest.raises(AdminSafetyError) as exc:
                    await admin_safety.assert_not_last_admin(target)
            assert exc.value.status_code == 409

    async def test_allows_when_another_distinct_admin_remains_alongside_m2m(self):
        # Two DISTINCT admins: a two-alias M2M client and a regular user. Deleting
        # the M2M admin (by either alias) is allowed because the regular admin
        # remains. Guards against over-counting the aliases as "the only admin".
        admins = [
            frozenset({"0oa1b2c3d4e5", "break-glass-admin"}),
            frozenset({"human-admin"}),
        ]
        for target in ("0oa1b2c3d4e5", "break-glass-admin"):
            with patch(
                "registry.services.admin_safety.list_admin_identities",
                new=AsyncMock(return_value=list(admins)),
            ):
                # Must NOT raise — another distinct admin remains.
                await admin_safety.assert_not_last_admin(target)


@pytest.mark.asyncio
class TestWouldRemoveLastAdminViaGroups:
    """Tests for the last-admin demotion guard."""

    async def test_allows_when_new_groups_still_admin(self):
        with patch(
            "registry.services.admin_safety.resolve_admin_group_names",
            new=AsyncMock(return_value={"mcp-registry-admin"}),
        ):
            # Keeping the admin group means no demotion; must not raise.
            await admin_safety.would_remove_last_admin_via_groups("admin1", ["mcp-registry-admin"])

    async def test_rejects_demoting_last_admin(self):
        with (
            patch(
                "registry.services.admin_safety.resolve_admin_group_names",
                new=AsyncMock(return_value={"mcp-registry-admin"}),
            ),
            patch(
                "registry.services.admin_safety.list_admin_identities",
                new=AsyncMock(return_value=[frozenset({"admin1"})]),
            ),
        ):
            with pytest.raises(AdminSafetyError) as exc:
                await admin_safety.would_remove_last_admin_via_groups("admin1", ["readers"])
        assert exc.value.status_code == 409

    async def test_allows_demoting_when_other_admins_remain(self):
        with (
            patch(
                "registry.services.admin_safety.resolve_admin_group_names",
                new=AsyncMock(return_value={"mcp-registry-admin"}),
            ),
            patch(
                "registry.services.admin_safety.list_admin_identities",
                new=AsyncMock(return_value=[frozenset({"admin1"}), frozenset({"admin2"})]),
            ),
        ):
            await admin_safety.would_remove_last_admin_via_groups("admin1", ["readers"])


@pytest.mark.asyncio
class TestDesiredGroupsGrantAdmin:
    """Tests for the admin-grant detection used by the audit hook."""

    async def test_true_when_granting_admin_group(self):
        with patch(
            "registry.services.admin_safety.resolve_admin_group_names",
            new=AsyncMock(return_value={"mcp-registry-admin"}),
        ):
            assert await admin_safety.desired_groups_grant_admin(["mcp-registry-admin"])

    async def test_false_for_non_admin_groups(self):
        with patch(
            "registry.services.admin_safety.resolve_admin_group_names",
            new=AsyncMock(return_value={"mcp-registry-admin"}),
        ):
            assert not await admin_safety.desired_groups_grant_admin(["readers"])
