"""Integration tests for the custom entity types feature (real MongoDB).

Exercises the full lifecycle through the service + DocumentDB repositories:
define a type, create records, list with in-query visibility filtering,
update (merge-then-validate), delete a record, and cascade-delete the type.
Search indexing is patched out (no embeddings server in CI); the persistence
and visibility paths are what these tests cover.

Requires a running MongoDB (the integration profile). Each test uses a unique
type name and cleans up the type (cascading its records) on teardown.
"""

import logging
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from registry.repositories.factory import (
    get_custom_entity_service,
    reset_repositories,
)
from registry.schemas.custom_entity_models import (
    CustomEntityCreate,
    CustomEntityUpdate,
    CustomFieldDescriptor,
    CustomFieldType,
    CustomTypeDescriptor,
)
from registry.services.custom_entity_errors import (
    CustomEntityNotFoundError,
    CustomTypeHasRecordsError,
    UnknownCustomTypeError,
)

logger = logging.getLogger(__name__)

ADMIN = {"username": "admin", "is_admin": True, "groups": []}
ALICE = {"username": "alice", "owner_id": "idp|alice", "is_admin": False, "groups": ["g1"]}
BOB = {"username": "bob", "owner_id": "idp|bob", "is_admin": False, "groups": ["g2"]}


def _descriptor(name: str) -> CustomTypeDescriptor:
    return CustomTypeDescriptor(
        name=name,
        display_name="Workflow",
        fields=[
            CustomFieldDescriptor(name="title", datatype=CustomFieldType.STRING, semantic=True),
            CustomFieldDescriptor(name="note", datatype=CustomFieldType.STRING),
        ],
        created_by="admin",
    )


@pytest.fixture
def no_index():
    """Patch out search indexing so tests need no embeddings backend."""
    from registry.repositories.documentdb.search_repository import (
        DocumentDBSearchRepository,
    )

    with (
        patch.object(DocumentDBSearchRepository, "index_custom_entity", new=AsyncMock()),
        patch.object(
            DocumentDBSearchRepository,
            "delete_custom_entity_index",
            new=AsyncMock(),
        ),
        patch.object(
            DocumentDBSearchRepository,
            "delete_custom_entity_index_by_type",
            new=AsyncMock(return_value=0),
        ),
    ):
        yield


@pytest.fixture
async def service(mock_settings, no_index):
    """Service backed by real DocumentDB repos against the test database."""
    reset_repositories()
    svc = get_custom_entity_service()
    type_name = f"wf_{uuid.uuid4().hex[:8]}"
    yield svc, type_name
    # Teardown: cascade-delete the type and its records.
    try:
        await svc.delete_type(type_name, force=True)
    except Exception:
        logger.exception("Teardown failed for custom type %s", type_name)
    reset_repositories()


@pytest.mark.integration
@pytest.mark.asyncio
class TestCustomEntityLifecycle:
    async def test_define_create_get_roundtrip(self, service):
        svc, type_name = service
        await svc.create_type(_descriptor(type_name))

        created = await svc.create_record(
            type_name,
            CustomEntityCreate(
                name="My Flow",
                visibility="public",
                attributes={"title": "build", "note": "n"},
            ),
            owner="alice",
        )
        assert created.path.startswith(f"/{type_name}/")
        assert created.owner == "alice"

        fetched = await svc.get_record(created.path, ALICE)
        assert fetched.name == "My Flow"
        assert fetched.attributes["title"] == "build"

    async def test_unknown_type_create_raises(self, service):
        svc, _ = service
        with pytest.raises(UnknownCustomTypeError):
            await svc.create_record(
                f"missing_{uuid.uuid4().hex[:6]}",
                CustomEntityCreate(name="x"),
                owner="alice",
            )

    async def test_list_visibility_filtering_and_count(self, service):
        svc, type_name = service
        await svc.create_type(_descriptor(type_name))
        await svc.create_record(
            type_name,
            CustomEntityCreate(name="pub", visibility="public", attributes={"title": "a"}),
            owner="alice",
        )
        await svc.create_record(
            type_name,
            CustomEntityCreate(name="priv", visibility="private", attributes={"title": "b"}),
            owner="alice",
        )

        # Bob sees only the public record; count matches the slice.
        items, total = await svc.list_records(type_name, 0, 100, BOB)
        assert total == 1
        assert {r.name for r in items} == {"pub"}

        # Admin sees both.
        _, admin_total = await svc.list_records(type_name, 0, 100, ADMIN)
        assert admin_total == 2

    async def test_update_merges_attributes_and_authz(self, service):
        svc, type_name = service
        await svc.create_type(_descriptor(type_name))
        rec = await svc.create_record(
            type_name,
            CustomEntityCreate(
                name="r", visibility="public", attributes={"title": "a", "note": "keep"}
            ),
            owner="alice",
        )

        # Non-owner cannot update (403 via HTTPException).
        from fastapi import HTTPException

        with pytest.raises(HTTPException):
            await svc.update_record(type_name, rec.path, CustomEntityUpdate(name="hacked"), BOB)

        # Owner update merges: title overwritten, note explicitly removed.
        updated = await svc.update_record(
            type_name,
            rec.path,
            CustomEntityUpdate(name="r2", attributes={"title": "z", "note": None}),
            ALICE,
        )
        assert updated.name == "r2"
        assert updated.attributes["title"] == "z"
        assert "note" not in updated.attributes

    async def test_delete_record_then_missing(self, service):
        svc, type_name = service
        await svc.create_type(_descriptor(type_name))
        rec = await svc.create_record(
            type_name,
            CustomEntityCreate(name="r", visibility="public", attributes={"title": "a"}),
            owner="alice",
        )
        await svc.delete_record(type_name, rec.path, ALICE)
        with pytest.raises(CustomEntityNotFoundError):
            await svc.get_record(rec.path, ALICE)

    async def test_delete_type_requires_force_when_records_exist(self, service):
        svc, type_name = service
        await svc.create_type(_descriptor(type_name))
        await svc.create_record(
            type_name,
            CustomEntityCreate(name="r", visibility="public", attributes={"title": "a"}),
            owner="alice",
        )
        with pytest.raises(CustomTypeHasRecordsError):
            await svc.delete_type(type_name, force=False)

        count = await svc.delete_type(type_name, force=True)
        assert count == 1
        assert await svc.get_type(type_name) is None


@pytest.mark.integration
@pytest.mark.asyncio
class TestListRecordsRestrictPaths:
    """Per-record discovery restriction against real MongoDB.

    Exercises list_records(restrict_paths=...), i.e. the $and of the record-path
    $in clause with the visibility filter, which unit tests (mocked repo) cannot
    verify actually behaves against the database.
    """

    async def _seed_three_public(self, svc, type_name):
        """Create three PUBLIC records; return their paths (a, b, c)."""
        await svc.create_type(_descriptor(type_name))
        paths = []
        for label in ("a", "b", "c"):
            rec = await svc.create_record(
                type_name,
                CustomEntityCreate(name=label, visibility="public", attributes={"title": label}),
                owner="alice",
            )
            paths.append(rec.path)
        return paths

    async def test_restrict_none_returns_whole_type(self, service):
        svc, type_name = service
        await self._seed_three_public(svc, type_name)
        # None = whole-type access; only the visibility filter applies (all public).
        items, total = await svc.list_records(type_name, 0, 100, BOB, restrict_paths=None)
        assert total == 3
        assert {r.name for r in items} == {"a", "b", "c"}

    async def test_restrict_to_one_path_returns_only_that_record(self, service):
        svc, type_name = service
        pa, _pb, _pc = await self._seed_three_public(svc, type_name)
        # Granting ONE record path must surface only that record — NOT the sibling
        # public records. This is the invariant, verified against real Mongo.
        items, total = await svc.list_records(type_name, 0, 100, BOB, restrict_paths=[pa])
        assert total == 1
        assert {r.name for r in items} == {"a"}

    async def test_restrict_to_subset_returns_that_subset(self, service):
        svc, type_name = service
        pa, pb, _pc = await self._seed_three_public(svc, type_name)
        items, total = await svc.list_records(type_name, 0, 100, BOB, restrict_paths=[pa, pb])
        assert total == 2
        assert {r.name for r in items} == {"a", "b"}

    async def test_empty_restrict_returns_nothing(self, service):
        svc, type_name = service
        await self._seed_three_public(svc, type_name)
        # Fail-closed: an empty path grant ($in: []) matches no records.
        items, total = await svc.list_records(type_name, 0, 100, BOB, restrict_paths=[])
        assert total == 0
        assert items == []

    async def test_restrict_intersects_visibility_not_union(self, service):
        """The path clause AND the visibility filter — a granted path the caller
        cannot see by visibility is still excluded (neither layer alone suffices).
        """
        svc, type_name = service
        await svc.create_type(_descriptor(type_name))
        pub = await svc.create_record(
            type_name,
            CustomEntityCreate(name="pub", visibility="public", attributes={"title": "p"}),
            owner="alice",
        )
        priv = await svc.create_record(
            type_name,
            CustomEntityCreate(name="priv", visibility="private", attributes={"title": "q"}),
            owner="alice",  # owned by alice, NOT bob
        )
        # Bob is granted BOTH paths, but priv is alice's private record: the
        # visibility filter must still exclude it (grant does not override
        # visibility). Only pub survives the $and.
        items, total = await svc.list_records(
            type_name, 0, 100, BOB, restrict_paths=[pub.path, priv.path]
        )
        assert total == 1
        assert {r.name for r in items} == {"pub"}

        # Alice (the owner) granted the same two paths sees both — her private
        # record passes visibility, confirming the exclusion above was visibility
        # (owner mismatch), not the path clause.
        items_a, total_a = await svc.list_records(
            type_name, 0, 100, ALICE, restrict_paths=[pub.path, priv.path]
        )
        assert total_a == 2
        assert {r.name for r in items_a} == {"pub", "priv"}
