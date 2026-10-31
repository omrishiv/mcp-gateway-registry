"""Admin population property for the last-admin guard.

``resolve_admin_group_names`` decides which group names the last-admin and
self-demotion guards count as administrators. It must name exactly the groups
that make a caller ``is_admin`` at request time, where a group reaches scopes
through their ``group_mappings`` and admin comes from ``_user_is_admin`` over
the merged ui_permissions. A group the guard counts as admin that the request
path does not lets a deployment delete or demote its last real administrator.
"""

import asyncio
import json
from collections.abc import Iterable
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.auth import dependencies
from registry.auth.asset_permissions import _SCOPE_NAMES
from registry.services import admin_safety

_SEED_DIR = Path(__file__).resolve().parents[3] / "scripts"
_ADMIN_SEED_FILES = (
    "mcp-registry-admin.json",
    "registry-admins.json",
    "mcp-servers-unrestricted-read.json",
    "mcp-servers-unrestricted-execute.json",
)
_FEDERATION_SEED_FILE = "federation-service.json"

# Generated group names stay lower-case (the guard casefolds, the request path
# does not) and never use a reserved privileged name, so the only thing that
# varies between a group's guard verdict and its request-time verdict is the
# ui_permissions of the scopes that map it.
_GROUP_POOL = ("admins", "readers", "ops", "federation-service", "auditors")
# Scope names are disjoint from group names: a scope's own name is not a group a
# user can hold unless some scope maps it.
_SCOPE_NAME_POOL = ("scope-a", "scope-b", "scope-c", "scope-d", "scope-e")
_ACTIONS = tuple(
    sorted(
        set(_SCOPE_NAMES.values())
        | {
            "list_service",
            "get_agent",
            "change_lifecycle_status",
            "create_virtual_server",
            "create_dataset_entity",
            "delete_dataset_entity",
        }
    )
)
_GRANT_VALUES = (["all"], ["x"], [], "all")

# Always present so the guard's zero-admin fail-closed branch never fires.
_ADMIN_GROUP = "admins"
_ADMIN_SCOPE_NAME = "scope-admin"
_ADMIN_SCOPE_DOC = {
    "group_mappings": [_ADMIN_GROUP],
    "ui_permissions": {"register_service": ["all"]},
}
_FEDERATION_ONLY_CATALOGUE = {
    "federation-service": {
        "group_mappings": ["federation-service"],
        "ui_permissions": {
            "list_agents": ["all"],
            "get_agent": ["all"],
            "list_service": ["all"],
            "health_check_service": ["all"],
        },
    },
}


class _CatalogueScopeRepo:
    """Scope repository fake over an in-memory catalogue of scope documents.

    Implements the three reads the guard and the request-time admin derivation
    use, with the same return shapes as the DocumentDB repository.
    """

    def __init__(
        self,
        docs: dict[str, dict],
    ) -> None:
        self._docs = docs

    async def list_groups(self) -> dict[str, dict]:
        return {
            name: {
                "server_count": len(doc.get("server_access", [])),
                "ui_scopes": doc.get("ui_permissions", {}),
                "mappings": doc.get("group_mappings", []),
                "is_idp_managed": True,
                "description": doc.get("description"),
            }
            for name, doc in self._docs.items()
        }

    async def get_all_group_mappings(self) -> dict[str, list[str]]:
        return {name: doc.get("group_mappings", []) for name, doc in self._docs.items()}

    async def get_ui_scopes_bulk(
        self,
        group_names: list[str],
    ) -> dict[str, dict]:
        result = {}
        for name in sorted({g for g in group_names if g}):
            ui_permissions = self._docs.get(name, {}).get("ui_permissions", {})
            if ui_permissions:
                result[name] = ui_permissions
        return result


def _load_seed(
    filename: str,
) -> tuple[str, dict]:
    """Load one shipped seed scope document.

    Args:
        filename: File name under ``scripts/``.

    Returns:
        Tuple of (scope name, scope document).
    """
    doc = json.loads((_SEED_DIR / filename).read_text())
    return doc["_id"], doc


def _seed_catalogue(
    filenames: Iterable[str],
) -> dict[str, dict]:
    """Build a scope catalogue from shipped seed files.

    Args:
        filenames: Seed file names under ``scripts/``.

    Returns:
        Mapping of scope name to scope document.
    """
    return dict(_load_seed(name) for name in filenames)


async def _request_time_admin_groups(
    groups: Iterable[str],
) -> set[str]:
    """Return the casefolded groups that make a caller ``is_admin`` at request time.

    Runs each group alone through the request path: group to scopes via
    ``map_cognito_groups_to_scopes``, scopes to merged ui_permissions via
    ``get_ui_permissions_for_user``, then ``_user_is_admin``. Must run with the
    scope repository already patched.

    Args:
        groups: Group names to classify.

    Returns:
        Casefolded names of the groups that confer admin.
    """
    admin_groups: set[str] = set()
    for group in groups:
        scopes = await dependencies.map_cognito_groups_to_scopes([group])
        ui_permissions = await dependencies.get_ui_permissions_for_user(scopes)
        if dependencies._user_is_admin(ui_permissions):
            admin_groups.add(group.strip().casefold())
    return admin_groups


async def _guard_and_request_time_admins(
    docs: dict[str, dict],
) -> tuple[set[str], set[str]]:
    """Return the guard's and the request path's admin groups for one catalogue.

    The comparison is over the groups some scope maps, the only names a caller's
    IdP groups can turn into scopes.

    Args:
        docs: Mapping of scope name to scope document.

    Returns:
        Tuple of (guard admin groups, request-time admin groups), both casefolded.
    """
    repo = _CatalogueScopeRepo(docs)
    mapped_groups = {group for doc in docs.values() for group in doc.get("group_mappings", [])}
    with (
        patch("registry.services.scope_service.get_scope_repository", return_value=repo),
        patch("registry.repositories.factory.get_scope_repository", return_value=repo),
    ):
        guard_admins = await admin_safety.resolve_admin_group_names()
        request_time_admins = await _request_time_admin_groups(mapped_groups)
    universe = {group.strip().casefold() for group in mapped_groups}
    return guard_admins & universe, request_time_admins


def _assert_populations_agree(
    docs: dict[str, dict],
) -> None:
    """Assert the guard and the request path agree on the admin groups.

    Args:
        docs: Mapping of scope name to scope document.
    """
    guard_admins, request_time_admins = asyncio.run(_guard_and_request_time_admins(docs))
    assert guard_admins == request_time_admins, (
        f"guard counts as admin but request path does not: "
        f"{sorted(guard_admins - request_time_admins)}; "
        f"request path admin but guard does not: "
        f"{sorted(request_time_admins - guard_admins)}"
    )


_scope_docs = st.fixed_dictionaries(
    {
        "group_mappings": st.lists(st.sampled_from(_GROUP_POOL), max_size=3, unique=True),
        "ui_permissions": st.dictionaries(
            st.sampled_from(_ACTIONS), st.sampled_from(_GRANT_VALUES), max_size=4
        ),
    }
)
_catalogues = st.dictionaries(st.sampled_from(_SCOPE_NAME_POOL), _scope_docs, max_size=5)


@pytest.mark.unit
@pytest.mark.parametrize(
    "seed_files",
    [
        pytest.param(_ADMIN_SEED_FILES, id="admin-seeds-only"),
        pytest.param(
            (*_ADMIN_SEED_FILES, _FEDERATION_SEED_FILE),
            id="all-shipped-seeds",
        ),
    ],
)
def test_seed_catalogue_admin_population_matches_request_time(seed_files):
    """Property: over the shipped seed scopes, guard admin groups equal request-time ones."""
    _assert_populations_agree(_seed_catalogue(seed_files))


@pytest.mark.unit
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(catalogue=_catalogues)
@example(catalogue=_FEDERATION_ONLY_CATALOGUE)
def test_admin_population_matches_request_time(catalogue):
    """Property: for every catalogue, a mapped group is a guard admin iff it is admin at request time.

    Each catalogue also holds one genuinely admin scope mapping ``admins`` so the
    guard's zero-admin fail-closed branch is not what is being exercised.
    """
    docs = {name: dict(doc) for name, doc in catalogue.items()}
    docs[_ADMIN_SCOPE_NAME] = _ADMIN_SCOPE_DOC
    _assert_populations_agree(docs)
