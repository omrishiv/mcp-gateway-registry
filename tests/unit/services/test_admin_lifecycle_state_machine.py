"""Last-admin and self-delete properties across the whole admin lifecycle.

Every route that creates, deletes or re-groups a principal (human user or M2M
client), and every route that creates, edits or deletes a scope group, runs
against one in-memory deployment: a fake IdP user store, a fake DocumentDB
holding the real ``DocumentDBScopeRepository`` documents and the M2M client
collections, and actor contexts built by the real request-time derivation
(``map_cognito_groups_to_scopes``, ``get_ui_permissions_for_user``,
``_user_is_admin``). The security property is that no sequence of operations
leaves the deployment with zero administrators under that request-time
decision, that no principal ever deletes itself, and that no operation by a
non-admin caller succeeds.
"""

import asyncio
import copy
import os
import re
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from unittest.mock import (
    AsyncMock,
    patch,
)

import pytest
from fastapi import HTTPException
from hypothesis import (
    settings,
)
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)

from registry.api import (
    auth0_m2m_routes,
    m2m_management_routes,
    management_routes,
    okta_m2m_routes,
    server_routes,
)
from registry.auth import dependencies
from registry.repositories.documentdb.scope_repository import DocumentDBScopeRepository
from registry.schemas.idp_m2m_client import (
    IdPM2MClientPatch,
    IdPM2MClientUpdate,
)
from registry.schemas.management import (
    GroupCreateRequest,
    GroupUpdateRequest,
    HumanUserRequest,
    ScopeConfig,
    UpdateUserGroupsRequest,
)
from registry.schemas.okta_m2m_client import OktaM2MClientUpdate

pytestmark = [pytest.mark.unit]

STATEFUL_SETTINGS = settings(
    max_examples=50,
    stateful_step_count=15,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    deadline=None,
)

# The seed admin group and scope share this name, as in scripts/mcp-registry-admin.json.
ADMIN_GROUP: str = "mcp-registry-admin"
OPS_GROUP: str = "ops"
READERS_GROUP: str = "readers"
GROUP_POOL: tuple[str, ...] = (ADMIN_GROUP, OPS_GROUP, READERS_GROUP)

ROOT: str = "root"
ALICE: str = "alice"
NEW_USERNAMES: tuple[str, ...] = ("bob", "carol")
SVC_MANUAL: str = "svc-manual"
SVC_OKTA: str = "svc-okta"
SVC_AUTH0: str = "svc-auth0"

MANUAL_PROVIDER: str = "manual"
OKTA_PROVIDER: str = "okta"
AUTH0_PROVIDER: str = "auth0"
_PROVIDER_COLLECTIONS: dict[str, str] = {
    OKTA_PROVIDER: "okta_m2m_clients",
    AUTH0_PROVIDER: "auth0_m2m_clients",
}
_M2M_COLLECTION: str = "idp_m2m_clients"
_SCOPES_COLLECTION: str = "mcp_scopes"

# ui_permissions choices. Only ADMIN confers admin at request time. READ_ALL is
# the federation-service shape: an "all" grant on read actions only.
ADMIN_UI: dict[str, list[str]] = {"register_service": ["all"], "list_service": ["all"]}
READ_ALL_UI: dict[str, list[str]] = {"list_service": ["all"], "list_agents": ["all"]}
NARROW_UI: dict[str, list[str]] = {"list_service": ["alpha"]}
UI_CHOICES: dict[str, dict[str, list[str]]] = {
    "admin": ADMIN_UI,
    "read-all": READ_ALL_UI,
    "narrow": NARROW_UI,
    "empty": {},
}

# The Okta and Auth0 sync factories return None unless these are set; the
# constructors make no network calls.
_IDP_SYNC_ENV: dict[str, str] = {
    "OKTA_DOMAIN": "okta.invalid",
    "OKTA_API_TOKEN": "unit-test-token",
    "AUTH0_DOMAIN": "auth0.invalid",
    "AUTH0_M2M_CLIENT_ID": "unit-test-client",
    "AUTH0_M2M_CLIENT_SECRET": "unit-test-secret",
}

_DELETE_OPS: frozenset[str] = frozenset({"delete_user", "m2m_delete"})

ZERO_ADMIN_REASON: str = (
    "Known defect: scope group edits and deletes, M2M client group patches and "
    "deletes, and the mis-counted last-admin guard can each remove admin from "
    "every principal."
)
GROUP_EDIT_REASON: str = (
    "Known defect: scope group create, update, delete and import run no "
    "last-admin check, so editing the admin scope demotes every administrator."
)
WRONG_POPULATION_REASON: str = (
    "Known defect: the last-admin guard counts any scope with an 'all' grant as "
    "admin, so it lets the last real administrator demote themselves."
)
M2M_UNGUARDED_REASON: str = (
    "Known defect: M2M client group patches and deletes run no last-admin or self-delete check."
)
NAME_GATE_REASON: str = (
    "Known defect: the Okta and Auth0 M2M routes admit callers whose groups "
    "include the name mcp-registry-admin even when the request-time decision "
    "says they are not admin."
)


def _matches_value(
    value: Any,
    condition: Any,
) -> bool:
    """Match one stored field against one query value with Mongo semantics.

    Args:
        value: Stored field value.
        condition: Query value: a literal or a compiled regex.

    Returns:
        True when the field matches.
    """
    if isinstance(condition, re.Pattern):
        return isinstance(value, str) and condition.search(value) is not None
    if isinstance(value, list) and not isinstance(condition, list):
        return condition in value
    return value == condition


def _matches(
    doc: dict[str, Any],
    query: dict[str, Any],
) -> bool:
    """Return whether ``doc`` matches the subset of Mongo queries the code uses.

    Unknown operators raise, so a gap in the fake fails loudly instead of
    matching silently.

    Args:
        doc: Stored document.
        query: Mongo filter.

    Returns:
        True when every clause matches.
    """
    for key, condition in query.items():
        if key == "$or":
            if not any(_matches(doc, clause) for clause in condition):
                return False
            continue
        if isinstance(condition, dict):
            for operator, argument in condition.items():
                if operator == "$in":
                    ok = any(_matches_value(doc.get(key), item) for item in argument)
                elif operator == "$exists":
                    ok = (key in doc) == bool(argument)
                else:
                    raise NotImplementedError(f"fake collection: operator {operator}")
                if not ok:
                    return False
        elif not _matches_value(doc.get(key), condition):
            return False
    return True


class _FakeCursor:
    """Async cursor over a snapshot of matching documents."""

    def __init__(
        self,
        docs: list[dict[str, Any]],
    ) -> None:
        self._docs = docs

    def skip(
        self,
        count: int,
    ) -> "_FakeCursor":
        return _FakeCursor(self._docs[count:])

    def limit(
        self,
        count: int,
    ) -> "_FakeCursor":
        return _FakeCursor(self._docs[:count] if count else self._docs)

    async def to_list(
        self,
        length: int | None = None,
    ) -> list[dict[str, Any]]:
        return list(self._docs if length is None else self._docs[:length])

    def __aiter__(self):
        return self._iterate()

    async def _iterate(self):
        for doc in self._docs:
            yield doc


class _FakeCollection:
    """In-memory Motor collection; documents are deep-copied in and out."""

    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []

    def _find_all(
        self,
        query: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return [doc for doc in self.docs if _matches(doc, query)]

    def find(
        self,
        query: dict[str, Any] | None = None,
    ) -> _FakeCursor:
        return _FakeCursor([copy.deepcopy(doc) for doc in self._find_all(query or {})])

    async def find_one(
        self,
        query: dict[str, Any],
    ) -> dict[str, Any] | None:
        found = self._find_all(query)
        return copy.deepcopy(found[0]) if found else None

    async def count_documents(
        self,
        query: dict[str, Any],
    ) -> int:
        return len(self._find_all(query))

    async def insert_one(
        self,
        doc: dict[str, Any],
    ) -> SimpleNamespace:
        self.docs.append(copy.deepcopy(doc))
        return SimpleNamespace(inserted_id=doc.get("_id"))

    async def update_one(
        self,
        query: dict[str, Any],
        update: dict[str, Any],
    ) -> SimpleNamespace:
        if set(update) != {"$set"}:
            raise NotImplementedError(f"fake collection: update {sorted(update)}")
        found = self._find_all(query)
        if found:
            found[0].update(copy.deepcopy(update["$set"]))
        return SimpleNamespace(matched_count=len(found[:1]), modified_count=len(found[:1]))

    async def replace_one(
        self,
        query: dict[str, Any],
        doc: dict[str, Any],
        upsert: bool = False,
    ) -> SimpleNamespace:
        found = self._find_all(query)
        if found:
            index = self.docs.index(found[0])
            self.docs[index] = copy.deepcopy(doc)
            return SimpleNamespace(matched_count=1, modified_count=1, upserted_id=None)
        if upsert:
            self.docs.append(copy.deepcopy(doc))
            return SimpleNamespace(matched_count=0, modified_count=0, upserted_id=doc.get("_id"))
        return SimpleNamespace(matched_count=0, modified_count=0, upserted_id=None)

    async def delete_one(
        self,
        query: dict[str, Any],
    ) -> SimpleNamespace:
        found = self._find_all(query)
        if found:
            self.docs.remove(found[0])
        return SimpleNamespace(deleted_count=len(found[:1]))

    async def create_index(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        return "fake-index"


class _FakeDatabase:
    """Database handle returning one ``_FakeCollection`` per name."""

    def __init__(self) -> None:
        self.collections: dict[str, _FakeCollection] = {}

    def __getitem__(
        self,
        name: str,
    ) -> _FakeCollection:
        return self.collections.setdefault(name, _FakeCollection())


class _FakeIAM:
    """IdP admin fake holding human users only, as Okta and Auth0 deployments do.

    M2M clients live only in the ``idp_m2m_clients`` collection, which the
    admin-safety guard merges into its count.
    """

    def __init__(
        self,
        humans: dict[str, list[str]],
    ) -> None:
        self.users: dict[str, list[str]] = {name: list(groups) for name, groups in humans.items()}

    async def list_users(
        self,
        search: str | None = None,
        max_results: int = 500,
        include_groups: bool = True,
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": name,
                "username": name,
                "email": f"{name}@example.com",
                "enabled": True,
                "groups": list(groups),
            }
            for name, groups in sorted(self.users.items())
        ]

    async def create_human_user(
        self,
        username: str,
        email: str,
        first_name: str,
        last_name: str,
        groups: list[str],
        password: str | None = None,
    ) -> dict[str, Any]:
        if username in self.users:
            raise ValueError(f"User '{username}' already exists")
        self.users[username] = list(groups)
        return {"id": username, "username": username, "email": email, "groups": list(groups)}

    async def delete_user(
        self,
        username: str,
    ) -> bool:
        if username not in self.users:
            raise ValueError(f"User '{username}' not found")
        del self.users[username]
        return True

    async def update_user_groups(
        self,
        username: str,
        groups: list[str],
    ) -> dict[str, Any]:
        if username not in self.users:
            raise ValueError(f"User '{username}' not found")
        current = self.users[username]
        self.users[username] = list(groups)
        return {
            "username": username,
            "groups": list(groups),
            "added": sorted(set(groups) - set(current)),
            "removed": sorted(set(current) - set(groups)),
        }

    async def create_group(
        self,
        group_name: str,
        description: str = "",
    ) -> dict[str, Any]:
        return {"id": group_name, "name": group_name, "path": f"/{group_name}"}

    async def update_group(
        self,
        group_name: str,
        description: str = "",
    ) -> dict[str, Any]:
        return {"id": group_name, "name": group_name}

    async def delete_group(
        self,
        group_name: str,
    ) -> bool:
        return True

    async def group_exists(
        self,
        group_name: str,
    ) -> bool:
        return False


class _JsonRequest:
    """Minimal Starlette request stand-in: audit state plus an optional JSON body."""

    def __init__(
        self,
        body: dict[str, Any] | None = None,
    ) -> None:
        self.state = SimpleNamespace()
        self._body = body or {}

    async def json(self) -> dict[str, Any]:
        return copy.deepcopy(self._body)


@dataclass(frozen=True)
class _Outcome:
    """Result of one route call: who acted, whether it succeeded, and the status."""

    op: str
    actor: str
    actor_is_admin: bool
    target: str
    succeeded: bool
    status: int


def _scope_doc(
    name: str,
    group_mappings: list[str],
    ui_permissions: dict[str, list[str]],
    is_idp_managed: bool,
) -> dict[str, Any]:
    """Build a stored scope document in the DocumentDB repository's shape.

    Args:
        name: Scope name (the document ``_id``).
        group_mappings: IdP groups the scope maps.
        ui_permissions: UI permission grants.
        is_idp_managed: Whether edits also call the IdP.

    Returns:
        The scope document.
    """
    return {
        "_id": name,
        "scope_type": "group",
        "description": "",
        "server_access": [],
        "group_mappings": list(group_mappings),
        "ui_permissions": copy.deepcopy(ui_permissions),
        "agent_access": [],
        "is_idp_managed": is_idp_managed,
    }


def _m2m_doc(
    client_id: str,
    provider: str,
    groups: list[str],
) -> dict[str, Any]:
    """Build an ``idp_m2m_clients`` record.

    Args:
        client_id: Client id, also used as the display name.
        provider: ``manual``, ``okta`` or ``auth0``.
        groups: Groups the client holds.

    Returns:
        The M2M client document.
    """
    return {
        "client_id": client_id,
        "name": client_id,
        "description": None,
        "groups": list(groups),
        "enabled": True,
        "provider": provider,
        "idp_app_id": None,
    }


# Default deployment: one human admin, one M2M admin, and readers elsewhere.
DEFAULT_SCOPES: dict[str, tuple[list[str], dict[str, list[str]], bool]] = {
    ADMIN_GROUP: ([ADMIN_GROUP], ADMIN_UI, True),
    READERS_GROUP: ([READERS_GROUP], NARROW_UI, False),
}
DEFAULT_HUMANS: dict[str, list[str]] = {ROOT: [ADMIN_GROUP], ALICE: [READERS_GROUP]}
DEFAULT_M2M: dict[str, tuple[str, list[str]]] = {
    SVC_MANUAL: (MANUAL_PROVIDER, [ADMIN_GROUP]),
    SVC_OKTA: (OKTA_PROVIDER, [READERS_GROUP]),
    SVC_AUTH0: (AUTH0_PROVIDER, [READERS_GROUP]),
}


class _Deployment:
    """One in-memory deployment wired to the real route handlers.

    Args:
        scopes: Scope name to ``(group_mappings, ui_permissions, is_idp_managed)``.
        humans: Human username to groups, held by the fake IdP.
        m2m: M2M client id to ``(provider, groups)``.
    """

    def __init__(
        self,
        scopes: dict[str, tuple[list[str], dict[str, list[str]], bool]],
        humans: dict[str, list[str]],
        m2m: dict[str, tuple[str, list[str]]],
    ) -> None:
        self.db = _FakeDatabase()
        self.iam = _FakeIAM(humans)
        for name, (mappings, ui_permissions, idp_managed) in scopes.items():
            self.db[_SCOPES_COLLECTION].docs.append(
                _scope_doc(name, mappings, ui_permissions, idp_managed)
            )
        for client_id, (provider, groups) in m2m.items():
            self.db[_M2M_COLLECTION].docs.append(_m2m_doc(client_id, provider, groups))
            if provider in _PROVIDER_COLLECTIONS:
                self.db[_PROVIDER_COLLECTIONS[provider]].docs.append(
                    _m2m_doc(client_id, provider, groups)
                )
        self.repo = DocumentDBScopeRepository()
        self.repo._collection = self.db[_SCOPES_COLLECTION]
        self.repo._indexes_created = True

    @contextmanager
    def wired(self) -> Iterator["_Deployment"]:
        """Patch every store and IdP lookup the routes and guards use.

        Yields:
            This deployment, while the patches are active.
        """

        async def _get_db() -> _FakeDatabase:
            return self.db

        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, _IDP_SYNC_ENV))
            for target in (
                "registry.services.scope_service.get_scope_repository",
                "registry.repositories.factory.get_scope_repository",
            ):
                stack.enter_context(patch(target, return_value=self.repo))
            for target in (
                "registry.services.admin_safety.get_iam_manager",
                "registry.api.management_routes.get_iam_manager",
                "registry.utils.iam_manager.get_iam_manager",
            ):
                stack.enter_context(patch(target, return_value=self.iam))
            for target in (
                "registry.repositories.documentdb.client.get_documentdb_client",
                "registry.api.management_routes.get_documentdb_client",
                "registry.api.m2m_management_routes.get_documentdb_client",
                "registry.api.okta_m2m_routes.get_documentdb_client",
                "registry.api.auth0_m2m_routes.get_documentdb_client",
            ):
                stack.enter_context(patch(target, _get_db))
            stack.enter_context(
                patch(
                    "registry.services.scope_service._trigger_auth_server_reload",
                    AsyncMock(return_value=True),
                )
            )
            yield self

    def principals(self) -> dict[str, list[str]]:
        """Return every principal (human or M2M) and its current groups.

        Returns:
            Mapping of principal name to groups.
        """
        result = {name: list(groups) for name, groups in self.iam.users.items()}
        for doc in self.db[_M2M_COLLECTION].docs:
            result.setdefault(doc["name"], list(doc.get("groups") or []))
        return result

    def m2m_clients(
        self,
        provider: str,
    ) -> list[str]:
        """Return the client ids of current M2M records for one provider.

        Args:
            provider: ``manual``, ``okta`` or ``auth0``.

        Returns:
            Sorted client ids.
        """
        return sorted(
            doc["client_id"]
            for doc in self.db[_M2M_COLLECTION].docs
            if doc.get("provider") == provider
        )

    def scope_names(self) -> list[str]:
        """Return the current scope document names.

        Returns:
            Sorted scope names.
        """
        return sorted(doc["_id"] for doc in self.db[_SCOPES_COLLECTION].docs)

    async def context_for(
        self,
        name: str,
    ) -> dict[str, Any]:
        """Build the request-time user_context for one principal.

        Args:
            name: Principal name.

        Returns:
            The context ``nginx_proxied_auth`` would produce from its groups.
        """
        return await dependencies._resolve_context_from_groups(
            username=name,
            groups=self.principals().get(name, []),
            auth_method="oauth2",
            provider="keycloak",
        )

    async def request_time_admins(self) -> set[str]:
        """Return the principals that are admin under the request-time decision.

        Returns:
            Names of admin principals.
        """
        admins: set[str] = set()
        for name in self.principals():
            if (await self.context_for(name))["is_admin"]:
                admins.add(name)
        return admins

    async def perform(
        self,
        op: str,
        actor: str,
        target: str,
        **params: Any,
    ) -> _Outcome:
        """Call one route handler as ``actor`` and record the outcome.

        Args:
            op: Operation name; one of the ``_op_*`` handlers.
            actor: Acting principal.
            target: Principal, client or scope the operation acts on.
            **params: Operation parameters.

        Returns:
            The outcome; an ``HTTPException`` counts as a refusal.
        """
        context = await self.context_for(actor)
        handler = getattr(self, f"_op_{op}")
        try:
            await handler(context, target, **params)
        except HTTPException as exc:
            return _Outcome(op, actor, context["is_admin"], target, False, exc.status_code)
        return _Outcome(op, actor, context["is_admin"], target, True, 200)

    async def _op_create_user(
        self,
        context: dict[str, Any],
        target: str,
        groups: list[str],
    ) -> None:
        payload = HumanUserRequest(
            username=target,
            email=f"{target}@example.com",
            first_name="First",
            last_name="Last",
            groups=groups,
        )
        await management_routes.management_create_human_user(
            payload, _JsonRequest(), user_context=context
        )

    async def _op_delete_user(
        self,
        context: dict[str, Any],
        target: str,
    ) -> None:
        await management_routes.management_delete_user(target, _JsonRequest(), user_context=context)

    async def _op_patch_user_groups(
        self,
        context: dict[str, Any],
        target: str,
        groups: list[str],
    ) -> None:
        await management_routes.management_update_user_groups(
            target, UpdateUserGroupsRequest(groups=groups), _JsonRequest(), user_context=context
        )

    async def _op_create_group(
        self,
        context: dict[str, Any],
        target: str,
        ui_permissions: dict[str, list[str]],
    ) -> None:
        payload = GroupCreateRequest(
            name=target,
            scope_config=ScopeConfig(ui_permissions=copy.deepcopy(ui_permissions)),
        )
        await management_routes.management_create_group(
            payload, _JsonRequest(), user_context=context
        )

    async def _op_update_group(
        self,
        context: dict[str, Any],
        target: str,
        ui_permissions: dict[str, list[str]] | None,
        group_mappings: list[str] | None,
    ) -> None:
        payload = GroupUpdateRequest(
            scope_config=ScopeConfig(
                ui_permissions=copy.deepcopy(ui_permissions),
                group_mappings=group_mappings,
            ),
        )
        await management_routes.management_update_group(
            target, payload, _JsonRequest(), user_context=context
        )

    async def _op_delete_group(
        self,
        context: dict[str, Any],
        target: str,
    ) -> None:
        await management_routes.management_delete_group(
            target, _JsonRequest(), user_context=context
        )

    async def _op_servers_delete_group(
        self,
        context: dict[str, Any],
        target: str,
        force: bool,
    ) -> None:
        await server_routes.delete_group_api(
            _JsonRequest(),
            group_name=target,
            delete_from_keycloak=True,
            force=force,
            user_context=context,
        )

    async def _op_servers_import_group(
        self,
        context: dict[str, Any],
        target: str,
        ui_permissions: dict[str, list[str]],
        group_mappings: list[str] | None,
    ) -> None:
        body: dict[str, Any] = {
            "scope_name": target,
            "ui_permissions": copy.deepcopy(ui_permissions),
            "create_in_idp": False,
        }
        if group_mappings is not None:
            body["group_mappings"] = group_mappings
        await server_routes.import_group_definition(_JsonRequest(body), user_context=context)

    async def _op_m2m_patch_groups(
        self,
        context: dict[str, Any],
        target: str,
        groups: list[str],
    ) -> None:
        await m2m_management_routes.patch_m2m_client(
            target, IdPM2MClientPatch(groups=groups), _JsonRequest(), user_context=context
        )

    async def _op_m2m_delete(
        self,
        context: dict[str, Any],
        target: str,
    ) -> None:
        await m2m_management_routes.delete_m2m_client(target, _JsonRequest(), user_context=context)

    async def _op_okta_patch_groups(
        self,
        context: dict[str, Any],
        target: str,
        groups: list[str],
    ) -> None:
        await okta_m2m_routes.update_client_groups(
            target, OktaM2MClientUpdate(groups=groups), user_context=context
        )

    async def _op_auth0_patch_groups(
        self,
        context: dict[str, Any],
        target: str,
        groups: list[str],
    ) -> None:
        await auth0_m2m_routes.update_client_groups(
            target, IdPM2MClientUpdate(groups=groups), user_context=context
        )


def _default_deployment() -> _Deployment:
    """Build the default deployment the state machines start from.

    Returns:
        A fresh deployment.
    """
    return _Deployment(
        scopes=copy.deepcopy(DEFAULT_SCOPES),
        humans=copy.deepcopy(DEFAULT_HUMANS),
        m2m=copy.deepcopy(DEFAULT_M2M),
    )


def _self_delete_violations(
    outcomes: list[_Outcome],
) -> list[_Outcome]:
    """Return successful deletes whose actor is the deleted principal.

    Args:
        outcomes: Recorded outcomes.

    Returns:
        The violating outcomes.
    """
    return [
        outcome
        for outcome in outcomes
        if outcome.succeeded
        and outcome.op in _DELETE_OPS
        and outcome.actor.strip().casefold() == outcome.target.strip().casefold()
    ]


def _non_admin_violations(
    outcomes: list[_Outcome],
) -> list[_Outcome]:
    """Return successful mutations made by a non-admin actor.

    Args:
        outcomes: Recorded outcomes.

    Returns:
        The violating outcomes.
    """
    return [outcome for outcome in outcomes if outcome.succeeded and not outcome.actor_is_admin]


_group_sets = st.lists(st.sampled_from(GROUP_POOL), max_size=2, unique=True)
_nonempty_group_sets = st.lists(st.sampled_from(GROUP_POOL), min_size=1, max_size=2, unique=True)
_ui_choices = st.sampled_from(sorted(UI_CHOICES)).map(lambda key: UI_CHOICES[key])
_scope_targets = st.sampled_from(GROUP_POOL)


def _has_principals(machine: "_AdminLifecycleMachine") -> bool:
    """Return whether any principal remains to act."""
    return bool(machine.deployment.principals())


class _AdminLifecycleMachine(RuleBasedStateMachine):
    """Every user, M2M and scope-group mutation route, driven by a chosen actor.

    Subclasses add the invariant they check, so each property fails on its own.
    """

    def __init__(self) -> None:
        super().__init__()
        self.deployment = _default_deployment()
        self._wiring = self.deployment.wired()
        self._wiring.__enter__()
        self.outcomes: list[_Outcome] = []

    def teardown(self) -> None:
        self._wiring.__exit__(None, None, None)

    def _actor(
        self,
        data: st.DataObject,
    ) -> str:
        return data.draw(st.sampled_from(sorted(self.deployment.principals())), label="actor")

    def _run(
        self,
        op: str,
        actor: str,
        target: str,
        **params: Any,
    ) -> None:
        self.outcomes.append(asyncio.run(self.deployment.perform(op, actor, target, **params)))

    @precondition(_has_principals)
    @rule(data=st.data(), username=st.sampled_from(NEW_USERNAMES), groups=_nonempty_group_sets)
    def create_user(
        self,
        data: st.DataObject,
        username: str,
        groups: list[str],
    ) -> None:
        self._run("create_user", self._actor(data), username, groups=groups)

    @precondition(_has_principals)
    @rule(data=st.data())
    def delete_user(
        self,
        data: st.DataObject,
    ) -> None:
        actor = self._actor(data)
        target = data.draw(st.sampled_from(sorted(self.deployment.principals())), label="target")
        self._run("delete_user", actor, target)

    @precondition(_has_principals)
    @rule(data=st.data(), groups=_group_sets)
    def patch_user_groups(
        self,
        data: st.DataObject,
        groups: list[str],
    ) -> None:
        actor = self._actor(data)
        target = data.draw(st.sampled_from(sorted(self.deployment.principals())), label="target")
        self._run("patch_user_groups", actor, target, groups=groups)

    @precondition(_has_principals)
    @rule(data=st.data(), scope=_scope_targets, ui_permissions=_ui_choices)
    def create_group(
        self,
        data: st.DataObject,
        scope: str,
        ui_permissions: dict[str, list[str]],
    ) -> None:
        self._run("create_group", self._actor(data), scope, ui_permissions=ui_permissions)

    @precondition(_has_principals)
    @rule(
        data=st.data(),
        scope=_scope_targets,
        ui_permissions=st.none() | _ui_choices,
        group_mappings=st.none() | _group_sets,
    )
    def update_group(
        self,
        data: st.DataObject,
        scope: str,
        ui_permissions: dict[str, list[str]] | None,
        group_mappings: list[str] | None,
    ) -> None:
        self._run(
            "update_group",
            self._actor(data),
            scope,
            ui_permissions=ui_permissions,
            group_mappings=group_mappings,
        )

    @precondition(_has_principals)
    @rule(data=st.data(), scope=_scope_targets)
    def delete_group(
        self,
        data: st.DataObject,
        scope: str,
    ) -> None:
        self._run("delete_group", self._actor(data), scope)

    @precondition(_has_principals)
    @rule(data=st.data(), scope=_scope_targets, force=st.booleans())
    def servers_delete_group(
        self,
        data: st.DataObject,
        scope: str,
        force: bool,
    ) -> None:
        self._run("servers_delete_group", self._actor(data), scope, force=force)

    @precondition(_has_principals)
    @rule(
        data=st.data(),
        scope=_scope_targets,
        ui_permissions=_ui_choices,
        group_mappings=st.none() | _group_sets,
    )
    def servers_import_group(
        self,
        data: st.DataObject,
        scope: str,
        ui_permissions: dict[str, list[str]],
        group_mappings: list[str] | None,
    ) -> None:
        self._run(
            "servers_import_group",
            self._actor(data),
            scope,
            ui_permissions=ui_permissions,
            group_mappings=group_mappings,
        )

    def _m2m_target(
        self,
        data: st.DataObject,
        provider: str,
    ) -> str | None:
        clients = self.deployment.m2m_clients(provider)
        if not clients:
            return None
        return data.draw(st.sampled_from(clients), label="client")

    @precondition(_has_principals)
    @rule(data=st.data(), groups=_group_sets)
    def m2m_patch_groups(
        self,
        data: st.DataObject,
        groups: list[str],
    ) -> None:
        actor = self._actor(data)
        target = self._m2m_target(data, MANUAL_PROVIDER)
        if target is not None:
            self._run("m2m_patch_groups", actor, target, groups=groups)

    @precondition(_has_principals)
    @rule(data=st.data())
    def m2m_delete(
        self,
        data: st.DataObject,
    ) -> None:
        actor = self._actor(data)
        target = self._m2m_target(data, MANUAL_PROVIDER)
        if target is not None:
            self._run("m2m_delete", actor, target)

    @precondition(_has_principals)
    @rule(data=st.data(), groups=_nonempty_group_sets)
    def okta_patch_groups(
        self,
        data: st.DataObject,
        groups: list[str],
    ) -> None:
        actor = self._actor(data)
        target = self._m2m_target(data, OKTA_PROVIDER)
        if target is not None:
            self._run("okta_patch_groups", actor, target, groups=groups)

    @precondition(_has_principals)
    @rule(data=st.data(), groups=_nonempty_group_sets)
    def auth0_patch_groups(
        self,
        data: st.DataObject,
        groups: list[str],
    ) -> None:
        actor = self._actor(data)
        target = self._m2m_target(data, AUTH0_PROVIDER)
        if target is not None:
            self._run("auth0_patch_groups", actor, target, groups=groups)


class _AdminSurvivesMachine(_AdminLifecycleMachine):
    """Checks that some principal stays admin under the request-time decision."""

    @invariant()
    def some_principal_is_admin(self) -> None:
        admins = asyncio.run(self.deployment.request_time_admins())
        assert admins, (
            f"zero administrators after {self.outcomes[-1] if self.outcomes else 'start'}; "
            f"principals={self.deployment.principals()}; "
            f"scopes={self.deployment.scope_names()}"
        )


class _NoSelfDeleteMachine(_AdminLifecycleMachine):
    """Checks that no successful delete removed the acting principal."""

    @invariant()
    def no_self_delete(self) -> None:
        violations = _self_delete_violations(self.outcomes)
        assert not violations, f"principal deleted itself: {violations}"


class _OnlyAdminsMutateMachine(_AdminLifecycleMachine):
    """Checks that every successful mutation came from a request-time admin."""

    @invariant()
    def only_admins_mutate(self) -> None:
        violations = _non_admin_violations(self.outcomes)
        assert not violations, f"non-admin mutation succeeded: {violations}"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=ZERO_ADMIN_REASON)
def test_admin_lifecycle_never_reaches_zero_admins() -> None:
    """Property: after every operation some principal is admin at request time."""
    run_state_machine_as_test(_AdminSurvivesMachine, settings=STATEFUL_SETTINGS)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=M2M_UNGUARDED_REASON)
def test_admin_lifecycle_never_self_deletes() -> None:
    """Property: no successful user or M2M delete has the actor as its target."""
    run_state_machine_as_test(_NoSelfDeleteMachine, settings=STATEFUL_SETTINGS)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=NAME_GATE_REASON)
def test_admin_lifecycle_only_admins_mutate() -> None:
    """Property: no mutation by a principal that is not admin at request time succeeds."""
    run_state_machine_as_test(_OnlyAdminsMutateMachine, settings=STATEFUL_SETTINGS)


# Starting deployments for the pinned single-step cases.
_SOLE_HUMAN_ADMIN = {
    "scopes": {
        ADMIN_GROUP: ([ADMIN_GROUP], ADMIN_UI, True),
        READERS_GROUP: ([READERS_GROUP], NARROW_UI, False),
    },
    "humans": {ROOT: [ADMIN_GROUP], ALICE: [READERS_GROUP]},
    "m2m": {},
}
_SOLE_HUMAN_ADMIN_READ_ALL = {
    "scopes": {
        ADMIN_GROUP: ([ADMIN_GROUP], ADMIN_UI, True),
        READERS_GROUP: ([READERS_GROUP], READ_ALL_UI, False),
    },
    "humans": {ROOT: [ADMIN_GROUP], ALICE: [OPS_GROUP]},
    "m2m": {},
}


def _sole_m2m_admin(
    client_id: str,
    provider: str,
) -> dict[str, Any]:
    """Build a starting deployment whose only administrator is one M2M client.

    Args:
        client_id: The admin client.
        provider: Its provider: ``manual``, ``okta`` or ``auth0``.

    Returns:
        Keyword arguments for ``_Deployment``.
    """
    return {
        "scopes": {
            ADMIN_GROUP: ([ADMIN_GROUP], ADMIN_UI, True),
            READERS_GROUP: ([READERS_GROUP], NARROW_UI, False),
        },
        "humans": {ALICE: [READERS_GROUP]},
        "m2m": {client_id: (provider, [ADMIN_GROUP])},
    }


_HUMAN_AND_M2M_ADMIN = {
    "scopes": {ADMIN_GROUP: ([ADMIN_GROUP], ADMIN_UI, True)},
    "humans": {ROOT: [ADMIN_GROUP]},
    "m2m": {SVC_MANUAL: (MANUAL_PROVIDER, [ADMIN_GROUP])},
}
# The scope named mcp-registry-admin no longer confers admin; root is admin via ops.
_DISARMED_ADMIN_SCOPE = {
    "scopes": {
        ADMIN_GROUP: ([ADMIN_GROUP], NARROW_UI, True),
        OPS_GROUP: ([OPS_GROUP], ADMIN_UI, False),
    },
    "humans": {ROOT: [OPS_GROUP], ALICE: [ADMIN_GROUP]},
    "m2m": {
        SVC_OKTA: (OKTA_PROVIDER, [READERS_GROUP]),
        SVC_AUTH0: (AUTH0_PROVIDER, [READERS_GROUP]),
    },
}

_GROUP_EDIT_XFAIL = pytest.mark.xfail(strict=True, raises=AssertionError, reason=GROUP_EDIT_REASON)
_M2M_XFAIL = pytest.mark.xfail(strict=True, raises=AssertionError, reason=M2M_UNGUARDED_REASON)
_NAME_GATE_XFAIL = pytest.mark.xfail(strict=True, raises=AssertionError, reason=NAME_GATE_REASON)

_SINGLE_STEP_CASES = [
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ROOT,
        "patch_user_groups",
        ROOT,
        {"groups": [READERS_GROUP]},
        id="patch-user-groups-self-demote",
    ),
    pytest.param(_SOLE_HUMAN_ADMIN, ROOT, "delete_user", ROOT, {}, id="delete-user-self"),
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ROOT,
        "servers_delete_group",
        ADMIN_GROUP,
        {"force": False},
        id="servers-delete-admin-group-unforced",
    ),
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ALICE,
        "delete_group",
        ADMIN_GROUP,
        {},
        id="non-admin-delete-group",
    ),
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ROOT,
        "update_group",
        ADMIN_GROUP,
        {"ui_permissions": NARROW_UI, "group_mappings": None},
        id="update-admin-group-ui",
        marks=_GROUP_EDIT_XFAIL,
    ),
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ROOT,
        "update_group",
        ADMIN_GROUP,
        {"ui_permissions": None, "group_mappings": [OPS_GROUP]},
        id="update-admin-group-mappings",
        marks=_GROUP_EDIT_XFAIL,
    ),
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ROOT,
        "create_group",
        ADMIN_GROUP,
        {"ui_permissions": NARROW_UI},
        id="create-group-overwrites-admin-scope",
        marks=_GROUP_EDIT_XFAIL,
    ),
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ROOT,
        "delete_group",
        ADMIN_GROUP,
        {},
        id="delete-admin-group",
        marks=_GROUP_EDIT_XFAIL,
    ),
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ROOT,
        "servers_delete_group",
        ADMIN_GROUP,
        {"force": True},
        id="servers-delete-admin-group-forced",
        marks=_GROUP_EDIT_XFAIL,
    ),
    pytest.param(
        _SOLE_HUMAN_ADMIN,
        ROOT,
        "servers_import_group",
        ADMIN_GROUP,
        {"ui_permissions": NARROW_UI, "group_mappings": None},
        id="servers-import-overwrites-admin-scope",
        marks=_GROUP_EDIT_XFAIL,
    ),
    pytest.param(
        _SOLE_HUMAN_ADMIN_READ_ALL,
        ROOT,
        "patch_user_groups",
        ROOT,
        {"groups": [READERS_GROUP]},
        id="patch-user-groups-into-read-all-group",
        marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=WRONG_POPULATION_REASON),
    ),
    pytest.param(
        _sole_m2m_admin(SVC_MANUAL, MANUAL_PROVIDER),
        SVC_MANUAL,
        "patch_user_groups",
        SVC_MANUAL,
        {"groups": [READERS_GROUP]},
        id="management-patch-m2m-self-demote",
    ),
    pytest.param(
        _sole_m2m_admin(SVC_MANUAL, MANUAL_PROVIDER),
        SVC_MANUAL,
        "m2m_patch_groups",
        SVC_MANUAL,
        {"groups": [READERS_GROUP]},
        id="m2m-patch-self-demote",
        marks=_M2M_XFAIL,
    ),
    pytest.param(
        _sole_m2m_admin(SVC_MANUAL, MANUAL_PROVIDER),
        SVC_MANUAL,
        "m2m_delete",
        SVC_MANUAL,
        {},
        id="m2m-delete-self-last-admin",
        marks=_M2M_XFAIL,
    ),
    pytest.param(
        _sole_m2m_admin(SVC_OKTA, OKTA_PROVIDER),
        SVC_OKTA,
        "okta_patch_groups",
        SVC_OKTA,
        {"groups": [READERS_GROUP]},
        id="okta-patch-self-demote",
        marks=_M2M_XFAIL,
    ),
    pytest.param(
        _sole_m2m_admin(SVC_AUTH0, AUTH0_PROVIDER),
        SVC_AUTH0,
        "auth0_patch_groups",
        SVC_AUTH0,
        {"groups": [READERS_GROUP]},
        id="auth0-patch-self-demote",
        marks=_M2M_XFAIL,
    ),
    pytest.param(
        _HUMAN_AND_M2M_ADMIN,
        SVC_MANUAL,
        "m2m_delete",
        SVC_MANUAL,
        {},
        id="m2m-delete-self-other-admin-remains",
        marks=_M2M_XFAIL,
    ),
    pytest.param(
        _HUMAN_AND_M2M_ADMIN,
        SVC_MANUAL,
        "delete_user",
        SVC_MANUAL,
        {},
        id="management-delete-m2m-self",
    ),
    pytest.param(
        _DISARMED_ADMIN_SCOPE,
        ALICE,
        "okta_patch_groups",
        SVC_OKTA,
        {"groups": [OPS_GROUP]},
        id="okta-patch-by-non-admin-name-holder",
        marks=_NAME_GATE_XFAIL,
    ),
    pytest.param(
        _DISARMED_ADMIN_SCOPE,
        ALICE,
        "auth0_patch_groups",
        SVC_AUTH0,
        {"groups": [OPS_GROUP]},
        id="auth0-patch-by-non-admin-name-holder",
        marks=_NAME_GATE_XFAIL,
    ),
]


async def _single_step(
    deployment: _Deployment,
    actor: str,
    op: str,
    target: str,
    params: dict[str, Any],
) -> tuple[set[str], _Outcome, set[str]]:
    """Run one operation and return the admins before and after it.

    Args:
        deployment: The deployment to act on.
        actor: Acting principal.
        op: Operation name.
        target: Operation target.
        params: Operation parameters.

    Returns:
        Tuple of (admins before, outcome, admins after).
    """
    before = await deployment.request_time_admins()
    outcome = await deployment.perform(op, actor, target, **params)
    after = await deployment.request_time_admins()
    return before, outcome, after


@pytest.mark.parametrize(("start", "actor", "op", "target", "params"), _SINGLE_STEP_CASES)
def test_single_operation_keeps_admin_invariants(start, actor, op, target, params) -> None:
    """Property: one operation from a deployment with an admin keeps all three invariants.

    Starting from a deployment where some principal is admin at request time,
    one call to a lifecycle route leaves some principal admin, never deletes
    the acting principal, and never succeeds for a non-admin actor.
    """
    deployment = _Deployment(**copy.deepcopy(start))
    with deployment.wired():
        before, outcome, after = asyncio.run(
            _single_step(deployment, actor, op, target, copy.deepcopy(params))
        )
    assert before, "harness: the starting deployment must have an administrator"
    violations: list[str] = []
    if not after:
        violations.append(f"zero administrators remain (before: {sorted(before)})")
    if _self_delete_violations([outcome]):
        violations.append("the actor deleted itself")
    if _non_admin_violations([outcome]):
        violations.append("a non-admin actor's mutation succeeded")
    assert not violations, f"{outcome}: {'; '.join(violations)}"
