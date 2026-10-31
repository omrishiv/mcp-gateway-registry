"""Ownership predicates deny every caller whose username is falsy.

Servers, agents, skills, custom entities and agent batch jobs decide ownership
by comparing a record's owner field (``registered_by``, ``owner`` or
``submitted_by``) with ``user_context["username"]``. A caller only owns a
record when its username is a non-empty string equal to a non-empty owner. A
context whose username is absent, ``None`` or ``""`` must never own anything,
and in particular must not own a record whose owner field is also absent or
falsy, where a bare ``==`` turns ``None == None`` or ``"" == ""`` into a grant.
These tests drive every ownership predicate (pure helpers directly, inline
route gates through their handler with the stores patched) and observe the
ownership decision itself.
"""

from __future__ import annotations

import asyncio
from collections.abc import (
    Callable,
    Iterator,
)
from contextlib import contextmanager
from types import SimpleNamespace
from typing import (
    Any,
    NamedTuple,
)
from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
)

import pytest
from fastapi import (
    HTTPException,
    Request,
    Response,
)
from hypothesis import (
    given,
    settings,
)
from hypothesis import strategies as st

from registry.api import (
    agent_routes,
    ans_routes,
    custom_entity_visibility,
    egress_oauth_facade_routes,
    server_routes,
    skill_routes,
)
from registry.auth import resource_binding
from registry.schemas.agent_models import (
    AgentCard,
    BatchItemOp,
)
from registry.schemas.custom_entity_models import CustomEntityRecord
from registry.schemas.skill_models import (
    SkillCard,
    SkillInfo,
    VisibilityEnum,
)
from registry.services import (
    agent_batch_item_processor,
    ans_service,
    visibility,
)
from registry.services.agent_service import agent_service
from registry.services.duplicate_check_service import (
    ENTITY_TYPE_AGENT,
    ENTITY_TYPE_SERVER,
    ENTITY_TYPE_SKILL,
    DuplicateCheckService,
)
from registry.services.server_service import server_service
from registry.services.skill_service import SkillService

pytestmark = [pytest.mark.unit, pytest.mark.auth]


class _Missing:
    """Marker for a key that is absent from the context or the record."""

    def __repr__(self) -> str:
        return "missing"


_MISSING = _Missing()

# Falsy usernames, plus whitespace-only as a borderline value. A whitespace
# username is only asserted against owners it differs from, which is an
# identity bypass under any reading.
_FALSY_USERNAMES: tuple[Any, ...] = (_MISSING, None, "", " ")
_OWNERS: tuple[Any, ...] = (_MISSING, None, "", "alice")

_OWNER: str = "alice"
_OTHER_USER: str = "bob"

_SERVER_PATH: str = "/srv"
_SERVER_NAME: str = "srv"
_AGENT_PATH: str = "/agent"
_AGENT_NAME: str = "agent"
_SKILL_PATH: str = "/skills/demo"
_SKILL_NAME: str = "demo"

_SERVER_PERMISSIONS: dict[str, list[str]] = {
    "modify_service": ["all"],
    "delete_service": ["all"],
    "register_service": ["all"],
}
_AGENT_PERMISSIONS: dict[str, list[str]] = {
    "list_agents": ["all"],
    "modify_agent": ["all"],
    "delete_agent": ["all"],
    "toggle_agent": ["all"],
}
_SKILL_PERMISSIONS: dict[str, list[str]] = {
    "list_skills": ["all"],
    "modify_skill": ["all"],
}

_IDENTITIES = st.one_of(st.none(), st.just(""), st.text())


class _PastGate(Exception):
    """Raised by a probe placed immediately after an ownership gate."""


class _Tripwire:
    """Request body whose first attribute read means the gate was passed."""

    def __init__(
        self,
        probe: MagicMock,
    ) -> None:
        """Store the probe that fires on attribute access.

        Args:
            probe: Mock that raises ``_PastGate`` when called.
        """
        self._probe = probe

    def __getattr__(
        self,
        name: str,
    ) -> Any:
        """Fire the probe for any attribute the handler reads.

        Args:
            name: Attribute name the handler asked for.

        Returns:
            Never returns; the probe raises.
        """
        return self._probe(name)


class _ProbeContext(dict):
    """User context that fires a probe when one chosen key is read."""

    def __init__(
        self,
        base: dict,
        probe_key: str,
        probe: MagicMock,
    ) -> None:
        """Wrap a context dict.

        Args:
            base: The context fields.
            probe_key: Key whose ``get`` means the gate was passed.
            probe: Mock that raises ``_PastGate`` when called.
        """
        super().__init__(base)
        self._probe_key = probe_key
        self._probe = probe

    def get(
        self,
        key: Any,
        default: Any = None,
    ) -> Any:
        """Return a field, firing the probe for the chosen key.

        Args:
            key: Field name.
            default: Value returned when the field is absent.

        Returns:
            The field value or ``default``.
        """
        if key == self._probe_key:
            self._probe(key)
        return super().get(key, default)


class _Predicate(NamedTuple):
    """One ownership predicate and the driver that observes its decision."""

    name: str
    location: str
    drive: Callable[[Any, Any], bool]
    pure: bool
    usernames: tuple[Any, ...] = _FALSY_USERNAMES
    owners: tuple[Any, ...] = _OWNERS


def _label(
    value: Any,
) -> str:
    """Render a username or owner value for a test id.

    Args:
        value: The value, possibly ``_MISSING``.

    Returns:
        A short readable label.
    """
    if value is _MISSING:
        return "missing"
    if value is None:
        return "none"
    if value == "":
        return "empty"
    if value.strip() == "":
        return "space"
    return value


def _probe() -> MagicMock:
    """Build a synchronous probe that raises ``_PastGate``.

    Returns:
        The probe mock.
    """
    return MagicMock(side_effect=_PastGate)


def _async_probe() -> AsyncMock:
    """Build an awaitable probe that raises ``_PastGate``.

    Returns:
        The probe mock.
    """
    return AsyncMock(side_effect=_PastGate)


def _context(
    username: Any,
    **fields: Any,
) -> dict:
    """Build a non-admin user context with no groups.

    Args:
        username: The username, or ``_MISSING`` to omit the key.
        **fields: Extra context fields.

    Returns:
        The user context.
    """
    ctx: dict[str, Any] = {"is_admin": False, "groups": [], **fields}
    if username is not _MISSING:
        ctx["username"] = username
    return ctx


def _owner_kwargs(
    field: str,
    owner: Any,
) -> dict[str, Any]:
    """Return model kwargs that set an owner field, or omit it when missing.

    Args:
        field: The owner field name.
        owner: The owner value, or ``_MISSING``.

    Returns:
        Keyword arguments for the model constructor.
    """
    return {} if owner is _MISSING else {field: owner}


def _request() -> Request:
    """Build a minimal ASGI request for handlers that record audit state.

    Returns:
        A request with no headers.
    """
    return Request(
        {"type": "http", "method": "POST", "path": "/", "headers": [], "query_string": b""}
    )


def _reached(
    coro: Any,
    probe: MagicMock,
) -> bool:
    """Run a handler and report whether it got past its ownership gate.

    A denial surfaces as an ``HTTPException`` or a 403 response, and a
    ``KeyError`` on an absent ``username`` key is a fail-closed denial too.

    Args:
        coro: The handler coroutine.
        probe: The probe placed directly after the gate.

    Returns:
        True when the probe fired.
    """
    try:
        asyncio.run(coro)
    except (_PastGate, HTTPException, KeyError):
        pass
    return probe.called


def _mongo_matches(
    document: dict,
    query: dict,
) -> bool:
    """Evaluate a Mongo query against one document with MongoDB semantics.

    Covers the operators the visibility filter emits: ``$or``, ``$in`` over an
    array field, and scalar equality, where ``{field: None}`` matches a null
    value or an absent field.

    Args:
        document: The stored document.
        query: The query predicate.

    Returns:
        True when the document matches.
    """
    for key, condition in query.items():
        if key == "$or":
            if not any(_mongo_matches(document, clause) for clause in condition):
                return False
        elif isinstance(condition, dict) and "$in" in condition:
            value = document.get(key)
            values = value if isinstance(value, list) else [value]
            if not any(item in condition["$in"] for item in values):
                return False
        elif condition is None:
            if document.get(key) is not None:
                return False
        elif key not in document or document[key] != condition:
            return False
    return True


def _server_record(
    owner: Any,
) -> dict:
    """Build a remote, non-federated server document.

    Args:
        owner: ``registered_by`` value, or ``_MISSING`` to omit it.

    Returns:
        The server document.
    """
    record: dict[str, Any] = {
        "server_name": _SERVER_NAME,
        "path": _SERVER_PATH,
        "proxy_pass_url": "https://backend.example.com/mcp",
        "deployment": "remote",
        "auth_scheme": "none",
        "sync_metadata": {},
        "tool_list": [],
        "backend_oauth": {"client_id": "registry"},
        "oauth_discovery": {"oauth": {"client_id": "registry"}},
    }
    record.update(_owner_kwargs("registered_by", owner))
    return record


def _server_context(
    username: Any,
) -> dict:
    """Build a non-admin context holding every server mutation scope.

    Args:
        username: The username, or ``_MISSING``.

    Returns:
        The user context.
    """
    return _context(
        username,
        ui_permissions=_SERVER_PERMISSIONS,
        accessible_servers=["all"],
        auth_method="oauth2",
    )


def _agent_card(
    owner: Any,
) -> AgentCard:
    """Build a private, non-federated agent card.

    Args:
        owner: ``registered_by`` value, or ``_MISSING`` to omit it.

    Returns:
        The agent card.
    """
    return AgentCard(
        name=_AGENT_NAME,
        description="d",
        url="https://agent.example.com/",
        version="1.0.0",
        path=_AGENT_PATH,
        visibility="private",
        **_owner_kwargs("registered_by", owner),
    )


def _agent_context(
    username: Any,
    accessible_agents: list[str],
) -> dict:
    """Build a non-admin context holding every agent scope.

    Args:
        username: The username, or ``_MISSING``.
        accessible_agents: The caller's ``accessible_agents`` grant.

    Returns:
        The user context.
    """
    return _context(
        username,
        ui_permissions=_AGENT_PERMISSIONS,
        accessible_agents=accessible_agents,
    )


def _skill_card(
    owner: Any,
) -> SkillCard:
    """Build a private skill card.

    Args:
        owner: ``owner`` value, or ``_MISSING`` to omit it.

    Returns:
        The skill card.
    """
    return SkillCard(
        path=_SKILL_PATH,
        name=_SKILL_NAME,
        description="d",
        skill_md_url="https://skills.example.com/SKILL.md",
        visibility=VisibilityEnum.PRIVATE,
        **_owner_kwargs("owner", owner),
    )


def _skill_context(
    username: Any,
) -> dict:
    """Build a non-admin context holding the skill list and modify scopes.

    Args:
        username: The username, or ``_MISSING``.

    Returns:
        The user context.
    """
    return _context(username, ui_permissions=_SKILL_PERMISSIONS, accessible_skills=["all"])


def _custom_record(
    owner: Any,
) -> CustomEntityRecord:
    """Build a private custom entity record.

    Args:
        owner: ``owner`` value, or ``_MISSING`` to omit it.

    Returns:
        The record.
    """
    return CustomEntityRecord(
        entity_type="thing",
        name="r",
        visibility="private",
        **_owner_kwargs("owner", owner),
    )


def _plain_owner(
    owner: Any,
) -> Any:
    """Map ``_MISSING`` to the value callers pass for an absent owner field.

    Args:
        owner: The owner value, or ``_MISSING``.

    Returns:
        ``None`` for a missing owner, else the owner unchanged.
    """
    return None if owner is _MISSING else owner


@contextmanager
def _server_lookup(
    owner: Any,
) -> Iterator[None]:
    """Patch the server store to return one server document.

    Args:
        owner: ``registered_by`` of the stored server.

    Yields:
        None.
    """
    lookup = AsyncMock(side_effect=lambda *args, **kwargs: _server_record(owner))
    with patch.object(server_service, "get_server_info", lookup):
        yield


@contextmanager
def _agent_lookup(
    owner: Any,
) -> Iterator[None]:
    """Patch the agent store to return one private agent card.

    Args:
        owner: ``registered_by`` of the stored agent.

    Yields:
        None.
    """
    lookup = AsyncMock(side_effect=lambda *args, **kwargs: _agent_card(owner))
    with patch.object(agent_service, "get_agent_info", lookup):
        yield


# Pure helpers.


def _drive_redact_oauth_config(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the backend OAuth blocks survive redaction."""
    server = visibility.redact_oauth_config_for_non_owner(
        _server_record(owner), _server_context(username)
    )
    return "backend_oauth" in server


def _drive_agent_from_doc(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a private agent document is visible to the caller."""
    document = {"path": _AGENT_PATH, "visibility": "private", "allowed_groups": []}
    document.update(_owner_kwargs("registered_by", owner))
    return visibility.user_can_access_agent_from_doc(
        document, _agent_context(username, accessible_agents=["all"])
    )


def _drive_user_can_access_skill(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a private skill is visible to the caller."""
    return asyncio.run(
        visibility.user_can_access_skill(
            skill_path=_SKILL_PATH,
            visibility="private",
            owner=_plain_owner(owner),
            allowed_groups=[],
            user_context=_skill_context(username),
        )
    )


def _drive_user_can_access_custom_entity(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a private custom entity is visible to the caller."""
    return asyncio.run(
        visibility.user_can_access_custom_entity(
            visibility="private",
            owner=_plain_owner(owner),
            allowed_groups=[],
            user_context=_context(username),
        )
    )


def _drive_custom_user_can_view(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a private custom record is readable by the caller."""
    return custom_entity_visibility._user_can_view(_custom_record(owner), _context(username))


def _drive_custom_require_owner(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the custom record mutation guard admits the caller."""
    try:
        custom_entity_visibility._require_owner_or_admin(_custom_record(owner), _context(username))
    except HTTPException:
        return False
    return True


def _drive_custom_visibility_filter(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the list filter matches a stored private record."""
    document: dict[str, Any] = {"visibility": "private", "allowed_groups": []}
    document.update(_owner_kwargs("owner", owner))
    query = custom_entity_visibility._build_visibility_filter(_context(username))
    return _mongo_matches(document, query)


def _drive_skill_route_can_access(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the skill read gate admits the caller."""
    return skill_routes._user_can_access_skill(_skill_card(owner), _skill_context(username))


def _drive_skill_route_can_modify(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the skill mutation gate admits the caller."""
    return skill_routes._user_can_modify_skill(_skill_card(owner), _skill_context(username))


def _drive_caller_owns_skill(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a duplicate skill match is attributed to the caller."""
    document = _owner_kwargs("owner", owner)
    return DuplicateCheckService._caller_owns_match(ENTITY_TYPE_SKILL, document, _context(username))


def _drive_caller_owns_agent_nested(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a duplicate agent search hit is attributed to the caller."""
    document = {"agent_card": _owner_kwargs("registered_by", owner)}
    return DuplicateCheckService._caller_owns_match(ENTITY_TYPE_AGENT, document, _context(username))


def _drive_caller_owns_server(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a duplicate server match is attributed to the caller."""
    document = _owner_kwargs("registered_by", owner)
    return DuplicateCheckService._caller_owns_match(
        ENTITY_TYPE_SERVER, document, _context(username)
    )


def _drive_filter_agents_by_access(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the agent list keeps a private agent for the caller."""
    try:
        kept = agent_routes._filter_agents_by_access(
            [_agent_card(owner)], _agent_context(username, accessible_agents=["all"])
        )
    except KeyError:
        return False
    return bool(kept)


# Helpers that look a record up.


def _drive_user_can_access_agent(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the path-based agent visibility check admits the caller."""
    ctx = _agent_context(username, accessible_agents=[_AGENT_PATH])
    with _agent_lookup(owner):
        return asyncio.run(visibility.user_can_access_agent(_AGENT_PATH, ctx))


def _drive_bind_agent(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a token may be bound to a private agent."""
    ctx = _agent_context(username, accessible_agents=[_AGENT_NAME])
    with _agent_lookup(owner):
        return asyncio.run(
            resource_binding.validate_user_can_bind_resource("agent", _AGENT_PATH, ctx)
        )


def _drive_bind_skill(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a token may be bound to a private skill."""
    service = SimpleNamespace(get_skill=AsyncMock(return_value=_skill_card(owner)))
    with patch("registry.services.skill_service.get_skill_service", return_value=service):
        return asyncio.run(
            resource_binding.validate_user_can_bind_resource(
                "skill", _SKILL_PATH, _skill_context(username)
            )
        )


def _drive_list_skills_for_user(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the skill list shows a private skill to the caller."""
    skill = SkillInfo(
        id="demo",
        path=_SKILL_PATH,
        name=_SKILL_NAME,
        description="d",
        skill_md_url="https://skills.example.com/SKILL.md",
        visibility=VisibilityEnum.PRIVATE,
        **_owner_kwargs("owner", owner),
    )
    svc = SkillService()
    with patch.object(svc, "list_skills", AsyncMock(return_value=[skill])):
        return bool(asyncio.run(svc.list_skills_for_user(_skill_context(username))))


def _drive_ans_route_server(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the ANS route guard admits the caller to a server."""
    repo = SimpleNamespace(get=AsyncMock(return_value=_server_record(owner)))
    with patch("registry.repositories.factory.get_server_repository", return_value=repo):
        try:
            asyncio.run(ans_routes._require_server_owner_or_admin(_SERVER_PATH, _context(username)))
        except HTTPException:
            return False
    return True


def _drive_ans_route_agent(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when the ANS route guard admits the caller to an agent."""
    repo = SimpleNamespace(get=AsyncMock(return_value=_agent_card(owner)))
    with patch("registry.repositories.factory.get_agent_repository", return_value=repo):
        try:
            asyncio.run(ans_routes._require_agent_owner_or_admin(_AGENT_PATH, _context(username)))
        except HTTPException:
            return False
    return True


def _ans_username_kwargs(
    username: Any,
) -> dict[str, Any]:
    """Return the ``username`` kwarg for an ANS service call.

    Args:
        username: The username, or ``_MISSING`` to rely on the default.

    Returns:
        Keyword arguments for the call.
    """
    return {} if username is _MISSING else {"username": username}


def _drive_ans_service(
    call: Callable[..., Any],
    repo_factory: str,
    record: Any,
    username: Any,
    probe_target: str,
) -> bool:
    """Run one ANS service operation and report whether it passed ownership.

    Args:
        call: Zero-extra-arg coroutine factory taking ``**username_kwargs``.
        repo_factory: Name of the repository factory in ``ans_service``.
        record: The stored record the repository returns.
        username: The caller username, or ``_MISSING``.
        probe_target: ``"verify"`` to probe the ANS lookup, ``"update"`` to
            probe the repository write.

    Returns:
        True when the probe fired.
    """
    probe = _async_probe()
    repo = SimpleNamespace(get=AsyncMock(return_value=record), update_field=AsyncMock())
    if probe_target == "update":
        repo.update_field = probe
    with (
        patch.object(ans_service, repo_factory, return_value=repo),
        patch.object(
            ans_service, "verify_ans_agent", probe if probe_target == "verify" else AsyncMock()
        ),
    ):
        return _reached(call(**_ans_username_kwargs(username)), probe)


def _drive_ans_link_agent(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when ANS link-to-agent passes the ownership check."""
    return _drive_ans_service(
        lambda **kw: ans_service.link_ans_to_agent(_AGENT_PATH, "ans-1", is_admin=False, **kw),
        "get_agent_repository",
        _agent_card(owner),
        username,
        "verify",
    )


def _drive_ans_link_server(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when ANS link-to-server passes the ownership check."""
    return _drive_ans_service(
        lambda **kw: ans_service.link_ans_to_server(_SERVER_PATH, "ans-1", is_admin=False, **kw),
        "get_server_repository",
        _server_record(owner),
        username,
        "verify",
    )


def _drive_ans_unlink_agent(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when ANS unlink-from-agent passes the ownership check."""
    return _drive_ans_service(
        lambda **kw: ans_service.unlink_ans_from_agent(_AGENT_PATH, is_admin=False, **kw),
        "get_agent_repository",
        _agent_card(owner),
        username,
        "update",
    )


def _drive_ans_unlink_server(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when ANS unlink-from-server passes the ownership check."""
    return _drive_ans_service(
        lambda **kw: ans_service.unlink_ans_from_server(_SERVER_PATH, is_admin=False, **kw),
        "get_server_repository",
        _server_record(owner),
        username,
        "update",
    )


def _drive_batch_authorize(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when a batch delete item is authorized for the submitter."""
    item = SimpleNamespace(op=BatchItemOp.delete, path=_AGENT_PATH)
    with _agent_lookup(owner):
        allowed, _ = asyncio.run(
            agent_batch_item_processor._authorize(
                item,
                submitted_by=username,
                is_admin=False,
                ui_permissions=_AGENT_PERMISSIONS,
            )
        )
    return allowed


# Inline gates in agent route handlers.


def _drive_agent_toggle(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when POST /agents/{path}/toggle passes its owner check."""
    probe = _async_probe()
    ctx = _agent_context(username, accessible_agents=[])
    with _agent_lookup(owner), patch.object(agent_service, "toggle_agent", probe):
        return _reached(
            agent_routes.toggle_agent(
                request=_request(), path=_AGENT_PATH, enabled=False, user_context=ctx
            ),
            probe,
        )


def _drive_agent_batch_job(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when GET /agents/batch/{job_id} passes its submitter check."""
    probe = _probe()
    job = SimpleNamespace(submitted_by=owner, model_dump=probe)
    with patch.object(agent_routes.agent_batch_service, "get", AsyncMock(return_value=job)):
        return _reached(
            agent_routes.get_agent_batch_job(job_id="job-1", user_context=_context(username)),
            probe,
        )


def _drive_agent_pull_card(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when POST /agents/{path}/pull-card passes its owner check."""
    probe = _async_probe()
    ctx = _agent_context(username, accessible_agents=[])
    with _agent_lookup(owner), patch.object(agent_routes, "_fetch_remote_agent_card", probe):
        return _reached(
            agent_routes.pull_agent_card(
                request=_request(), path=_AGENT_PATH, user_context=ctx, dry_run=True
            ),
            probe,
        )


def _drive_agent_update(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when PUT /agents/{path} passes its owner check."""
    probe = _probe()
    body = _Tripwire(probe)
    # The audit description reads the name before the gate; every other field
    # is read after it.
    body.name = _AGENT_NAME
    ctx = _agent_context(username, accessible_agents=[])
    with _agent_lookup(owner):
        return _reached(
            agent_routes.update_agent(
                http_request=_request(),
                path=_AGENT_PATH,
                request=body,
                user_context=ctx,
            ),
            probe,
        )


def _drive_agent_patch(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when PATCH /agents/{path} passes its owner check."""
    probe = _probe()
    ctx = _agent_context(username, accessible_agents=[])
    with _agent_lookup(owner), patch.object(agent_routes, "_parse_if_match", probe):
        return _reached(
            agent_routes.patch_agent(
                http_request=_request(),
                path=_AGENT_PATH,
                patch_body=None,
                response=Response(),
                user_context=ctx,
                if_match=None,
            ),
            probe,
        )


def _drive_agent_delete(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when DELETE /agents/{path} passes its owner check."""
    probe = _async_probe()
    ctx = _agent_context(username, accessible_agents=[])
    with _agent_lookup(owner), patch.object(agent_service, "remove_agent", probe):
        return _reached(
            agent_routes.delete_agent(request=_request(), path=_AGENT_PATH, user_context=ctx),
            probe,
        )


# Inline gates in server route handlers.


def _allowed_gate() -> AsyncMock:
    """Build a registration admission gate that always allows.

    Returns:
        The patched ``check_registration_gate``.
    """
    return AsyncMock(return_value=SimpleNamespace(allowed=True, error_message=""))


def _drive_server_edit_scheme(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when POST /edit/{path} lets the caller change the auth scheme."""
    probe = _probe()
    with (
        _server_lookup(owner),
        patch.object(server_service, "user_can_access_server_path", AsyncMock(return_value=True)),
        patch.object(server_routes, "check_registration_gate", _allowed_gate()),
        patch.object(server_routes, "_parse_and_validate_custom_headers", probe),
    ):
        return _reached(
            server_routes.edit_server_submit(
                request=_request(),
                service_path=_SERVER_NAME,
                name=_SERVER_NAME,
                user_context=_server_context(username),
                proxy_pass_url="https://backend.example.com/mcp",
                auth_scheme="bearer",
            ),
            probe,
        )


def _drive_server_register_overwrite(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when POST /servers/register may overwrite the stored server."""
    probe = _async_probe()
    with (
        _server_lookup(owner),
        patch.object(server_routes, "check_registration_gate", _allowed_gate()),
        patch.object(server_service, "update_server", probe),
        patch.object(server_service, "register_server", AsyncMock(return_value={"success": False})),
    ):
        return _reached(
            server_routes.register_service_api(
                request=_request(),
                name=_SERVER_NAME,
                description="d",
                path=_SERVER_PATH,
                user_context=_server_context(username),
                proxy_pass_url="https://backend.example.com/mcp",
                overwrite=True,
            ),
            probe,
        )


def _drive_server_auth_credential(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when PATCH /servers/{path}/auth-credential passes its owner check."""
    probe = _probe()
    with _server_lookup(owner):
        return _reached(
            server_routes.update_server_auth_credential(
                request=_request(),
                server_path=_SERVER_PATH,
                body=_Tripwire(probe),
                user_context=_server_context(username),
            ),
            probe,
        )


def _drive_server_get_oauth_config(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when GET /servers/{path}/oauth-config passes its owner check."""
    probe = _probe()
    with _server_lookup(owner), patch.object(server_routes, "_backend_oauth_view", probe):
        return _reached(
            server_routes.get_server_oauth_config(
                request=_request(), server_path=_SERVER_PATH, user_context=_server_context(username)
            ),
            probe,
        )


def _drive_server_put_oauth_config(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when PUT /servers/{path}/oauth-config passes its owner check."""
    probe = _probe()
    with _server_lookup(owner):
        return _reached(
            server_routes.put_server_oauth_config(
                request=_request(),
                server_path=_SERVER_PATH,
                body=_Tripwire(probe),
                user_context=_server_context(username),
            ),
            probe,
        )


def _drive_server_get_oauth_discovery(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when GET /servers/{path}/oauth-discovery passes its owner check."""
    probe = _probe()
    with _server_lookup(owner), patch.object(server_routes, "_oauth_discovery_view", probe):
        return _reached(
            server_routes.get_server_oauth_discovery(
                request=_request(), server_path=_SERVER_PATH, user_context=_server_context(username)
            ),
            probe,
        )


def _drive_server_put_oauth_discovery(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when PUT /servers/{path}/oauth-discovery passes its owner check."""
    probe = _probe()
    with (
        _server_lookup(owner),
        patch.object(server_routes.settings, "egress_auth_enabled", True),
        patch("registry.egress_auth.service.canonical_auth_method", probe),
    ):
        return _reached(
            server_routes.put_server_oauth_discovery(
                request=_request(),
                server_path=_SERVER_PATH,
                body=_Tripwire(probe),
                user_context=_server_context(username),
            ),
            probe,
        )


def _drive_server_delete_oauth_discovery(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when DELETE /servers/{path}/oauth-discovery passes its owner check."""
    probe = _async_probe()
    with _server_lookup(owner), patch.object(server_service, "update_server", probe):
        return _reached(
            server_routes.delete_server_oauth_discovery(
                request=_request(), server_path=_SERVER_PATH, user_context=_server_context(username)
            ),
            probe,
        )


def _drive_server_remove(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when POST /servers/remove passes its owner check."""
    probe = _async_probe()
    with _server_lookup(owner), patch.object(server_service, "remove_server", probe):
        return _reached(
            server_routes.remove_service_api(
                request=_request(), path=_SERVER_PATH, user_context=_server_context(username)
            ),
            probe,
        )


def _drive_server_remove_version(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when DELETE /servers/{path}/versions/{v} passes its owner check."""
    probe = _async_probe()
    with _server_lookup(owner), patch.object(server_service, "remove_server_version", probe):
        return _reached(
            server_routes.remove_server_version(
                service_path=_SERVER_NAME, version="v2", user_context=_server_context(username)
            ),
            probe,
        )


def _drive_server_set_default_version(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when PUT /servers/{path}/versions/default passes its owner check."""
    probe = _async_probe()
    with _server_lookup(owner), patch.object(server_service, "set_default_version", probe):
        return _reached(
            server_routes.set_default_version(
                service_path=_SERVER_NAME,
                version_data=SimpleNamespace(version="v2"),
                user_context=_server_context(username),
            ),
            probe,
        )


def _drive_server_put(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when PUT /servers/{path} passes its owner check."""
    probe = _probe()
    with _server_lookup(owner), patch.object(server_routes, "parse_if_match", probe):
        return _reached(
            server_routes.update_server_endpoint(
                http_request=_request(),
                path=_SERVER_PATH,
                body=None,
                response=Response(),
                user_context=_server_context(username),
                if_match=None,
            ),
            probe,
        )


def _drive_server_patch(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when PATCH /servers/{path} passes its owner check."""
    probe = _probe()
    with _server_lookup(owner), patch.object(server_routes, "parse_if_match", probe):
        return _reached(
            server_routes.patch_server_endpoint(
                http_request=_request(),
                path=_SERVER_PATH,
                patch_body=None,
                response=Response(),
                user_context=_server_context(username),
                if_match=None,
            ),
            probe,
        )


def _drive_egress_discovery_connect(
    username: Any,
    owner: Any,
) -> bool:
    """Return True when GET /oauth2/egress/connect?purpose=discovery passes its owner check."""
    probe = _probe()
    ctx = _ProbeContext(_server_context(username), "egress_user", probe)
    facade = egress_oauth_facade_routes
    with (
        _server_lookup(owner),
        patch.object(facade, "_feature_on", return_value=True),
        patch.object(facade, "_optional_session", AsyncMock(return_value=ctx)),
    ):
        return _reached(
            facade.egress_connect(request=_request(), server=_SERVER_PATH, purpose="discovery"),
            probe,
        )


_PREDICATES: tuple[_Predicate, ...] = (
    _Predicate(
        "redact_oauth_config_for_non_owner",
        "registry/services/visibility.py:136",
        _drive_redact_oauth_config,
        pure=True,
    ),
    _Predicate(
        "user_can_access_agent_from_doc",
        "registry/services/visibility.py:462",
        _drive_agent_from_doc,
        pure=True,
    ),
    _Predicate(
        "user_can_access_skill",
        "registry/services/visibility.py:487",
        _drive_user_can_access_skill,
        pure=True,
    ),
    _Predicate(
        "user_can_access_custom_entity",
        "registry/services/visibility.py:514",
        _drive_user_can_access_custom_entity,
        pure=True,
    ),
    _Predicate(
        "custom_entity._user_can_view",
        "registry/api/custom_entity_visibility.py:59",
        _drive_custom_user_can_view,
        pure=True,
    ),
    _Predicate(
        "custom_entity._require_owner_or_admin",
        "registry/api/custom_entity_visibility.py:77",
        _drive_custom_require_owner,
        pure=True,
    ),
    _Predicate(
        "custom_entity._build_visibility_filter",
        "registry/api/custom_entity_visibility.py:37",
        _drive_custom_visibility_filter,
        pure=True,
    ),
    _Predicate(
        "skill_routes._user_can_access_skill",
        "registry/api/skill_routes.py:1661",
        _drive_skill_route_can_access,
        pure=True,
    ),
    _Predicate(
        "skill_routes._user_can_modify_skill",
        "registry/api/skill_routes.py:1707",
        _drive_skill_route_can_modify,
        pure=True,
    ),
    _Predicate(
        "duplicate_check._caller_owns_match[skill]",
        "registry/services/duplicate_check_service.py:307",
        _drive_caller_owns_skill,
        pure=True,
    ),
    _Predicate(
        "duplicate_check._caller_owns_match[agent]",
        "registry/services/duplicate_check_service.py:313",
        _drive_caller_owns_agent_nested,
        pure=True,
    ),
    _Predicate(
        "duplicate_check._caller_owns_match[server]",
        "registry/services/duplicate_check_service.py:315",
        _drive_caller_owns_server,
        pure=True,
    ),
    _Predicate(
        "agent_routes._filter_agents_by_access",
        "registry/api/agent_routes.py:1068",
        _drive_filter_agents_by_access,
        pure=True,
    ),
    _Predicate(
        "user_can_access_agent",
        "registry/services/visibility.py:417",
        _drive_user_can_access_agent,
        pure=False,
    ),
    _Predicate(
        "validate_user_can_bind_resource[agent]",
        "registry/auth/resource_binding.py:553",
        _drive_bind_agent,
        pure=False,
    ),
    _Predicate(
        "validate_user_can_bind_resource[skill]",
        "registry/auth/resource_binding.py:589",
        _drive_bind_skill,
        pure=False,
    ),
    _Predicate(
        "SkillService.list_skills_for_user",
        "registry/services/skill_service.py:1644",
        _drive_list_skills_for_user,
        pure=False,
    ),
    _Predicate(
        "ans_routes._require_server_owner_or_admin",
        "registry/api/ans_routes.py:174",
        _drive_ans_route_server,
        pure=False,
    ),
    _Predicate(
        "ans_routes._require_agent_owner_or_admin",
        "registry/api/ans_routes.py:218",
        _drive_ans_route_agent,
        pure=False,
    ),
    _Predicate(
        "ans_service.link_ans_to_agent",
        "registry/services/ans_service.py:132",
        _drive_ans_link_agent,
        pure=False,
    ),
    _Predicate(
        "ans_service.link_ans_to_server",
        "registry/services/ans_service.py:188",
        _drive_ans_link_server,
        pure=False,
    ),
    _Predicate(
        "ans_service.unlink_ans_from_agent",
        "registry/services/ans_service.py:238",
        _drive_ans_unlink_agent,
        pure=False,
    ),
    _Predicate(
        "ans_service.unlink_ans_from_server",
        "registry/services/ans_service.py:269",
        _drive_ans_unlink_server,
        pure=False,
    ),
    # ``submitted_by`` is a required ``str`` on the batch job, so only string
    # submitters are in its domain.
    _Predicate(
        "agent_batch_item_processor._authorize",
        "registry/services/agent_batch_item_processor.py:101",
        _drive_batch_authorize,
        pure=False,
        usernames=("", " "),
    ),
    _Predicate(
        "agent_routes.toggle_agent",
        "registry/api/agent_routes.py:1870",
        _drive_agent_toggle,
        pure=False,
    ),
    _Predicate(
        "agent_routes.get_agent_batch_job",
        "registry/api/agent_routes.py:2149",
        _drive_agent_batch_job,
        pure=False,
        owners=("", "alice"),
    ),
    _Predicate(
        "agent_routes.pull_agent_card",
        "registry/api/agent_routes.py:2217",
        _drive_agent_pull_card,
        pure=False,
    ),
    _Predicate(
        "agent_routes.update_agent",
        "registry/api/agent_routes.py:2515",
        _drive_agent_update,
        pure=False,
    ),
    _Predicate(
        "agent_routes.patch_agent",
        "registry/api/agent_routes.py:2723",
        _drive_agent_patch,
        pure=False,
    ),
    _Predicate(
        "agent_routes.delete_agent",
        "registry/api/agent_routes.py:2917",
        _drive_agent_delete,
        pure=False,
    ),
    _Predicate(
        "server_routes.edit_server_submit",
        "registry/api/server_routes.py:3023",
        _drive_server_edit_scheme,
        pure=False,
    ),
    _Predicate(
        "server_routes.register_service_api",
        "registry/api/server_routes.py:4771",
        _drive_server_register_overwrite,
        pure=False,
    ),
    _Predicate(
        "server_routes.update_server_auth_credential",
        "registry/api/server_routes.py:4947",
        _drive_server_auth_credential,
        pure=False,
    ),
    _Predicate(
        "server_routes.get_server_oauth_config",
        "registry/api/server_routes.py:5106",
        _drive_server_get_oauth_config,
        pure=False,
    ),
    _Predicate(
        "server_routes.put_server_oauth_config",
        "registry/api/server_routes.py:5155",
        _drive_server_put_oauth_config,
        pure=False,
    ),
    _Predicate(
        "server_routes.get_server_oauth_discovery",
        "registry/api/server_routes.py:5316",
        _drive_server_get_oauth_discovery,
        pure=False,
    ),
    _Predicate(
        "server_routes.put_server_oauth_discovery",
        "registry/api/server_routes.py:5383",
        _drive_server_put_oauth_discovery,
        pure=False,
    ),
    _Predicate(
        "server_routes.delete_server_oauth_discovery",
        "registry/api/server_routes.py:5567",
        _drive_server_delete_oauth_discovery,
        pure=False,
    ),
    _Predicate(
        "server_routes.remove_service_api",
        "registry/api/server_routes.py:5833",
        _drive_server_remove,
        pure=False,
    ),
    _Predicate(
        "server_routes.remove_server_version",
        "registry/api/server_routes.py:6971",
        _drive_server_remove_version,
        pure=False,
    ),
    _Predicate(
        "server_routes.set_default_version",
        "registry/api/server_routes.py:7036",
        _drive_server_set_default_version,
        pure=False,
    ),
    _Predicate(
        "server_routes.update_server_endpoint",
        "registry/api/server_routes.py:7271",
        _drive_server_put,
        pure=False,
    ),
    _Predicate(
        "server_routes.patch_server_endpoint",
        "registry/api/server_routes.py:7455",
        _drive_server_patch,
        pure=False,
    ),
    _Predicate(
        "egress_oauth_facade_routes.egress_connect",
        "registry/api/egress_oauth_facade_routes.py:221",
        _drive_egress_discovery_connect,
        pure=False,
    ),
)
_BY_NAME: dict[str, _Predicate] = {predicate.name: predicate for predicate in _PREDICATES}

# (username label, owner label) pairs for which a predicate grants ownership
# to a falsy username today, grouped by the shape of the comparison.
#
# ``owner == user_context.get("username")``: an absent key reads as None, so
# None owns a None or absent owner, and "" owns "".
_GET_EQUALITY_GRANTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("missing", "missing"),
        ("missing", "none"),
        ("none", "missing"),
        ("none", "none"),
        ("empty", "empty"),
    }
)
# ``owner != user_context["username"]``: an absent key raises KeyError (denied),
# but an explicit None or "" still matches an equally falsy owner.
_SUBSCRIPT_EQUALITY_GRANTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("none", "missing"),
        ("none", "none"),
        ("empty", "empty"),
    }
)
# An absent username defaults to "" while a None username stays None, so ""
# owns "" and None owns a None or absent owner.
_EMPTY_DEFAULT_GRANTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("missing", "empty"),
        ("none", "missing"),
        ("none", "none"),
        ("empty", "empty"),
    }
)
# The owner is coerced with ``str(owner or "")``, so "" owns every falsy owner.
_COERCED_OWNER_GRANTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("empty", "missing"),
        ("empty", "none"),
        ("empty", "empty"),
    }
)
_EMPTY_STRING_GRANTS: frozenset[tuple[str, str]] = frozenset({("empty", "empty")})

_KNOWN_FALSY_GRANTS: dict[str, frozenset[tuple[str, str]]] = {
    "user_can_access_agent_from_doc": _COERCED_OWNER_GRANTS,
    "user_can_access_skill": _GET_EQUALITY_GRANTS,
    "user_can_access_custom_entity": _GET_EQUALITY_GRANTS,
    "custom_entity._user_can_view": _GET_EQUALITY_GRANTS,
    "custom_entity._build_visibility_filter": _EMPTY_DEFAULT_GRANTS,
    "skill_routes._user_can_access_skill": _GET_EQUALITY_GRANTS,
    "skill_routes._user_can_modify_skill": _GET_EQUALITY_GRANTS,
    "agent_routes._filter_agents_by_access": _SUBSCRIPT_EQUALITY_GRANTS,
    "user_can_access_agent": _GET_EQUALITY_GRANTS,
    "validate_user_can_bind_resource[agent]": _GET_EQUALITY_GRANTS,
    "validate_user_can_bind_resource[skill]": _GET_EQUALITY_GRANTS,
    "SkillService.list_skills_for_user": _EMPTY_DEFAULT_GRANTS,
    "agent_batch_item_processor._authorize": _EMPTY_STRING_GRANTS,
    "agent_routes.toggle_agent": _GET_EQUALITY_GRANTS,
    "agent_routes.get_agent_batch_job": _EMPTY_STRING_GRANTS,
    "agent_routes.pull_agent_card": _SUBSCRIPT_EQUALITY_GRANTS,
    "agent_routes.update_agent": _SUBSCRIPT_EQUALITY_GRANTS,
    "agent_routes.patch_agent": _SUBSCRIPT_EQUALITY_GRANTS,
    "agent_routes.delete_agent": _SUBSCRIPT_EQUALITY_GRANTS,
    "server_routes.edit_server_submit": _GET_EQUALITY_GRANTS,
    "server_routes.register_service_api": _GET_EQUALITY_GRANTS,
    "server_routes.update_server_auth_credential": _GET_EQUALITY_GRANTS,
    "server_routes.get_server_oauth_config": _GET_EQUALITY_GRANTS,
    "server_routes.put_server_oauth_config": _GET_EQUALITY_GRANTS,
    "server_routes.get_server_oauth_discovery": _GET_EQUALITY_GRANTS,
    "server_routes.put_server_oauth_discovery": _GET_EQUALITY_GRANTS,
    "server_routes.delete_server_oauth_discovery": _GET_EQUALITY_GRANTS,
    "server_routes.remove_service_api": _GET_EQUALITY_GRANTS,
    "server_routes.remove_server_version": _GET_EQUALITY_GRANTS,
    "server_routes.set_default_version": _GET_EQUALITY_GRANTS,
    "server_routes.update_server_endpoint": _SUBSCRIPT_EQUALITY_GRANTS,
    "server_routes.patch_server_endpoint": _SUBSCRIPT_EQUALITY_GRANTS,
    "egress_oauth_facade_routes.egress_connect": _GET_EQUALITY_GRANTS,
}


def _known_defect_reason(
    predicate: _Predicate,
) -> str:
    """Build the xfail reason for a predicate that grants a falsy username.

    Args:
        predicate: The failing predicate.

    Returns:
        The reason string.
    """
    return (
        f"Known defect: {predicate.name} ({predicate.location}) decides ownership by "
        f"plain equality, so a falsy username owns a record whose owner field is also falsy."
    )


def _falsy_cases() -> list[Any]:
    """Enumerate predicate x falsy username x owner, marking known grants.

    Returns:
        The pytest params.
    """
    cases = []
    for predicate in _PREDICATES:
        known = _KNOWN_FALSY_GRANTS.get(predicate.name, frozenset())
        for username in predicate.usernames:
            for owner in predicate.owners:
                pair = (_label(username), _label(owner))
                marks = (
                    [
                        pytest.mark.xfail(
                            strict=True,
                            raises=AssertionError,
                            reason=_known_defect_reason(predicate),
                        )
                    ]
                    if pair in known
                    else []
                )
                cases.append(
                    pytest.param(
                        predicate.name,
                        username,
                        owner,
                        id=f"{predicate.name}-user={pair[0]}-owner={pair[1]}",
                        marks=marks,
                    )
                )
    return cases


def _pure_cases() -> list[Any]:
    """Enumerate the pure helpers, marking those with a known falsy grant.

    Returns:
        The pytest params.
    """
    cases = []
    for predicate in _PREDICATES:
        if not predicate.pure:
            continue
        marks = (
            [
                pytest.mark.xfail(
                    strict=True,
                    raises=AssertionError,
                    reason=_known_defect_reason(predicate),
                )
            ]
            if _KNOWN_FALSY_GRANTS.get(predicate.name)
            else []
        )
        cases.append(pytest.param(predicate.name, id=predicate.name, marks=marks))
    return cases


@pytest.mark.parametrize("name", [predicate.name for predicate in _PREDICATES])
def test_real_owner_owns_and_other_user_does_not(name):
    """Property: the named owner passes each predicate and a different user does not.

    This anchors every driver: it proves the probe sits behind a reachable
    ownership decision, so a denial in the falsy matrix is the predicate's.
    """
    predicate = _BY_NAME[name]
    assert predicate.drive(_OWNER, _OWNER), f"{predicate.location}: owner was denied"
    assert not predicate.drive(_OTHER_USER, _OWNER), f"{predicate.location}: non-owner admitted"


@pytest.mark.parametrize(("name", "username", "owner"), _falsy_cases())
def test_falsy_username_never_owns(name, username, owner):
    """Property: a falsy username owns no record, whatever its owner field holds."""
    predicate = _BY_NAME[name]
    granted = predicate.drive(username, owner)
    assert not granted, (
        f"{predicate.location}: username={username!r} granted ownership of a record "
        f"with owner={owner!r}"
    )


@pytest.mark.parametrize("name", _pure_cases())
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(username=_IDENTITIES, owner=_IDENTITIES)
def test_pure_owner_predicate_implies_equal_nonempty_identity(name, username, owner):
    """Property: a pure helper grants ownership only to a non-empty username equal to the owner."""
    predicate = _BY_NAME[name]
    if predicate.drive(username, owner):
        assert bool(username) and username == owner, (
            f"{predicate.location}: username={username!r} owns a record with owner={owner!r}"
        )
