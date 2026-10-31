"""Property tests: a user token never carries more than its scopes and current groups.

A user mints a self-signed token through ``/internal/tokens`` with
``requested_scopes`` narrower than the scopes their groups grant. That token is
then presented to ``/validate`` for both the MCP hop and the registry ``/api/``
hop. These tests pin that whatever the registry derives from the token
(``scopes``, ``ui_permissions`` and ``is_admin``) is bounded by the requested
scopes, that the MCP-hop scopes are bounded the same way, and that a token
minted while the user was an administrator stops conferring ``is_admin`` once
the user is no longer one.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import (
    AsyncMock,
    patch,
)

import pytest
from hypothesis import (
    HealthCheck,
    example,
    given,
    settings,
)
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    precondition,
    rule,
    run_state_machine_as_test,
)

pytestmark = [pytest.mark.unit, pytest.mark.auth]


ADMIN_GROUP: str = "mcp-registry-admin"
SERVER_READER_GROUP: str = "server-readers"
AGENT_READER_GROUP: str = "agent-readers"

ADMIN_SCOPE: str = "registry-admin"
SERVERS_READ_SCOPE: str = "servers-read"
AGENTS_READ_SCOPE: str = "agents-read"

# Fake group -> scope mapping shared by the auth server and the registry.
GROUP_TO_SCOPES: dict[str, list[str]] = {
    ADMIN_GROUP: [ADMIN_SCOPE],
    SERVER_READER_GROUP: [SERVERS_READ_SCOPE],
    AGENT_READER_GROUP: [AGENTS_READ_SCOPE],
}

# Fake UI-Scopes per scope. Only ADMIN_SCOPE holds a mutating "all" grant, so it
# is the single admin-conferring scope in the universe.
UI_SCOPES: dict[str, dict[str, list[str]]] = {
    ADMIN_SCOPE: {
        "list_service": ["all"],
        "register_service": ["all"],
    },
    SERVERS_READ_SCOPE: {"list_service": ["alpha-server"]},
    AGENTS_READ_SCOPE: {"list_agents": ["beta-agent"]},
}

USERNAME: str = "alice"
SESSION_ID: str = "sess-narrowing"
API_URL: str = "https://example.com/api/servers"

HYPOTHESIS_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
STATEFUL_SETTINGS = settings(
    max_examples=50,
    stateful_step_count=15,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    deadline=None,
)

DEMOTION_REASON: str = (
    "Known defect: a self-signed token carries the groups the user held at mint "
    "time, and the registry derives is_admin from those frozen groups."
)

# The user holds an admin group and one read group, and asks for the read scope only.
_ADMIN_USER_READ_ONLY_REQUEST = (
    [ADMIN_GROUP, SERVER_READER_GROUP],
    [SERVERS_READ_SCOPE],
)


def _scopes_for_groups(
    groups: list[str],
) -> list[str]:
    """Map groups to scopes through the fake mapping, deduped in order.

    Args:
        groups: Group names.

    Returns:
        The scopes those groups grant.
    """
    scopes: list[str] = []
    for group in groups:
        for scope in GROUP_TO_SCOPES.get(group, []):
            if scope not in scopes:
                scopes.append(scope)
    return scopes


def _ui_permissions_for_scopes(
    scopes: list[str],
) -> dict[str, set[str]]:
    """Union the fake UI-Scopes of ``scopes``.

    Args:
        scopes: Scope names.

    Returns:
        Mapping of UI action to the set of resources the scopes grant.
    """
    merged: dict[str, set[str]] = {}
    for scope in scopes:
        for action, resources in UI_SCOPES.get(scope, {}).items():
            merged.setdefault(action, set()).update(resources)
    return merged


class _FakeScopeRepository:
    """In-memory scope repository serving the fake mapping to both services."""

    async def get_group_mappings_bulk(
        self,
        groups: list[str],
    ) -> list[str]:
        """Return the scopes granted by ``groups``."""
        return _scopes_for_groups(groups)

    async def get_all_group_mappings(self) -> dict[str, list[str]]:
        """Return the scope -> groups mapping."""
        inverted: dict[str, list[str]] = {}
        for group, scopes in GROUP_TO_SCOPES.items():
            for scope in scopes:
                inverted.setdefault(scope, []).append(group)
        return inverted

    async def get_ui_scopes_bulk(
        self,
        scopes: list[str],
    ) -> dict[str, dict[str, list[str]]]:
        """Return the UI-Scopes config of each known scope."""
        return {scope: UI_SCOPES[scope] for scope in scopes if scope in UI_SCOPES}

    async def get_server_scopes_bulk(
        self,
        scopes: list[str],
    ) -> dict[str, list[dict]]:
        """Return no server access rules; this file pins UI-level permissions."""
        return {}


@st.composite
def _narrowed_requests(
    draw: st.DrawFn,
) -> tuple[list[str], list[str]]:
    """Draw a user's groups and a non-empty proper subset of the scopes they grant.

    Args:
        draw: Hypothesis draw function.

    Returns:
        Tuple ``(user_groups, requested_scopes)``.
    """
    groups = draw(
        st.lists(
            st.sampled_from(sorted(GROUP_TO_SCOPES)),
            min_size=2,
            unique=True,
        )
    )
    user_scopes = _scopes_for_groups(groups)
    requested = draw(
        st.lists(
            st.sampled_from(user_scopes),
            min_size=1,
            max_size=len(user_scopes) - 1,
            unique=True,
        )
    )
    return groups, requested


def _internal_auth_headers() -> dict[str, str]:
    """Build the Authorization header ``/internal/tokens`` requires.

    Returns:
        Header dict carrying a valid internal JWT.
    """
    from registry.auth.internal import generate_internal_token

    token = generate_internal_token(subject="test-suite", purpose="unit-test")
    return {"Authorization": f"Bearer {token}"}


@contextmanager
def _fake_scope_backends(
    user_groups: list[str],
) -> Iterator[None]:
    """Route session lookups and scope-repository reads to in-memory fakes.

    Args:
        user_groups: Groups the user's login session holds.

    Yields:
        None, while the patches are active.
    """
    session = {
        "username": USERNAME,
        "groups": list(user_groups),
        "provider": "keycloak",
        "auth_method": "oauth2",
        "subject": "oidc-sub-alice",
    }
    repo = _FakeScopeRepository()
    with (
        patch("session_store.resolve_session", AsyncMock(return_value=session)),
        patch("auth_server.server.get_scope_repository", return_value=repo),
        patch("registry.repositories.factory.get_scope_repository", return_value=repo),
    ):
        yield


def _mint_narrowed_token(
    client,
    server_module,
    user_groups: list[str],
    requested_scopes: list[str],
) -> str:
    """Mint a session-backed self-signed token narrowed to ``requested_scopes``.

    Args:
        client: TestClient bound to the auth server app.
        server_module: The ``auth_server.server`` module.
        user_groups: Groups the user holds.
        requested_scopes: Scopes the token is requested for.

    Returns:
        The minted access token.
    """
    server_module.user_token_generation_counts.clear()
    body = {
        "user_context": {
            "username": USERNAME,
            "email": "alice@example.com",
            "groups": list(user_groups),
            "scopes": _scopes_for_groups(user_groups),
            "auth_method": "oauth2",
            "provider": "keycloak",
            "session_id": SESSION_ID,
        },
        "requested_scopes": list(requested_scopes),
        "expires_in_hours": 1,
        "description": "narrowed",
    }
    minted = client.post("/internal/tokens", json=body, headers=_internal_auth_headers())
    assert minted.status_code == 200, minted.text
    return minted.json()["access_token"]


def _validate_for_registry_api(
    client,
    server_module,
    token: str,
    require_ok: bool = True,
):
    """Present ``token`` to ``/validate`` as nginx does for a registry ``/api/`` call.

    Args:
        client: TestClient bound to the auth server app.
        server_module: The ``auth_server.server`` module.
        token: The bearer token to validate.
        require_ok: Whether to assert a 200 response.

    Returns:
        The ``/validate`` response.
    """
    validated = client.get(
        "/validate",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Original-URL": API_URL,
            "X-Registry-Api-Auth": "1",
            "X-Validate-Source-Secret": server_module.settings.auth_server_nginx_marker_secret,
        },
    )
    if require_ok:
        assert validated.status_code == 200, validated.text
    return validated


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: a narrowed self-signed token carries the user's full groups, "
        "and the registry derives permissions including is_admin from those groups."
    ),
)
@HYPOTHESIS_SETTINGS
@given(case=_narrowed_requests())
@example(case=_ADMIN_USER_READ_ONLY_REQUEST)
def test_registry_permissions_bounded_by_requested_scopes(auth_env_vars, case):
    """Registry permissions derived from a narrowed token are bounded by its scopes.

    For every user whose groups grant scopes S and every non-empty proper subset
    R of S: the registry context built from the registry-ui token that
    ``/validate`` mints for the narrowed token has scopes within R, UI
    permissions within those R grants, and is admin only if R holds the
    admin-conferring scope.
    """
    from fastapi.testclient import TestClient

    import auth_server.server as server_module
    from registry.auth.dependencies import _context_from_internal_token

    user_groups, requested_scopes = case
    allowed_ui = _ui_permissions_for_scopes(requested_scopes)

    with _fake_scope_backends(user_groups):
        client = TestClient(server_module.app)
        token = _mint_narrowed_token(client, server_module, user_groups, requested_scopes)
        validated = _validate_for_registry_api(client, server_module, token)
        registry_token = validated.headers["X-Internal-Token-Registry"]
        request = SimpleNamespace(state=SimpleNamespace())
        context = asyncio.run(_context_from_internal_token(request, registry_token))

    violations: list[str] = []
    excess_scopes = sorted(set(context["scopes"]) - set(requested_scopes))
    if excess_scopes:
        violations.append(f"scopes beyond request: {excess_scopes}")
    excess_ui = {
        action: sorted(set(resources) - allowed_ui.get(action, set()))
        for action, resources in context["ui_permissions"].items()
        if set(resources) - allowed_ui.get(action, set())
    }
    if excess_ui:
        violations.append(f"ui_permissions beyond request: {excess_ui}")
    if context["is_admin"] and ADMIN_SCOPE not in requested_scopes:
        violations.append("is_admin=True without the admin scope")
    assert not violations, (
        f"registry context for a token requested with {requested_scopes} "
        f"(user groups {user_groups}): {'; '.join(violations)}"
    )


@HYPOTHESIS_SETTINGS
@given(case=_narrowed_requests())
@example(case=_ADMIN_USER_READ_ONLY_REQUEST)
def test_mcp_hop_scopes_bounded_by_requested_scopes(auth_env_vars, case):
    """The MCP-hop scopes of a narrowed token are bounded by its requested scopes.

    For every user whose groups grant scopes S and every non-empty proper subset
    R of S: the scopes ``/validate`` reports for the token (response body and
    ``X-Scopes``) are within R.
    """
    from fastapi.testclient import TestClient

    import auth_server.server as server_module

    user_groups, requested_scopes = case

    with _fake_scope_backends(user_groups):
        client = TestClient(server_module.app)
        token = _mint_narrowed_token(client, server_module, user_groups, requested_scopes)
        validated = _validate_for_registry_api(client, server_module, token)

    body_scopes = set(validated.json()["scopes"])
    header_scopes = set(validated.headers["X-Scopes"].split())
    assert body_scopes <= set(requested_scopes), (body_scopes, requested_scopes)
    assert header_scopes <= set(requested_scopes), (header_scopes, requested_scopes)


class _LiveIdentity:
    """The user's current IdP groups and the current group to scope mapping.

    Both are mutable so a test can demote or promote the user between minting
    a token and using it. The login session reports the current groups, as it
    does after the user signs in again.
    """

    def __init__(self) -> None:
        self.user_groups: list[str] = [ADMIN_GROUP, SERVER_READER_GROUP]
        self.group_to_scopes: dict[str, list[str]] = {
            group: list(scopes) for group, scopes in GROUP_TO_SCOPES.items()
        }

    def scopes_for(
        self,
        groups: list[str],
    ) -> list[str]:
        """Map groups to scopes through the current mapping, deduped in order.

        Args:
            groups: Group names.

        Returns:
            The scopes those groups grant now.
        """
        scopes: list[str] = []
        for group in groups:
            for scope in self.group_to_scopes.get(group, []):
                if scope not in scopes:
                    scopes.append(scope)
        return scopes

    def is_admin(self) -> bool:
        """Return whether the user is an administrator right now."""
        return ADMIN_SCOPE in self.scopes_for(self.user_groups)

    def apply(
        self,
        op: str,
    ) -> None:
        """Apply one IdP or scope-mapping change.

        Args:
            op: ``demote`` or ``promote`` (the user's admin group membership),
                ``unmap`` or ``remap`` (the admin group's scope mapping).
        """
        if op == "demote":
            self.user_groups = [g for g in self.user_groups if g != ADMIN_GROUP]
        elif op == "promote":
            if ADMIN_GROUP not in self.user_groups:
                self.user_groups = [ADMIN_GROUP, *self.user_groups]
        elif op == "unmap":
            self.group_to_scopes[ADMIN_GROUP] = []
        elif op == "remap":
            self.group_to_scopes[ADMIN_GROUP] = [ADMIN_SCOPE]
        else:
            raise ValueError(f"unknown identity change: {op}")


class _LiveScopeRepository(_FakeScopeRepository):
    """Scope repository fake that reads the current mapping of a ``_LiveIdentity``."""

    def __init__(
        self,
        identity: _LiveIdentity,
    ) -> None:
        self._identity = identity

    async def get_group_mappings_bulk(
        self,
        groups: list[str],
    ) -> list[str]:
        """Return the scopes granted by ``groups`` under the current mapping."""
        return self._identity.scopes_for(groups)

    async def get_all_group_mappings(self) -> dict[str, list[str]]:
        """Return the current scope -> groups mapping."""
        inverted: dict[str, list[str]] = {}
        for group, scopes in self._identity.group_to_scopes.items():
            for scope in scopes:
                inverted.setdefault(scope, []).append(group)
        return inverted


class _DemotionHarness:
    """Mints and uses tokens for one user whose admin status can change.

    Args:
        server_module: The ``auth_server.server`` module.
    """

    def __init__(
        self,
        server_module,
    ) -> None:
        from fastapi.testclient import TestClient

        self.server_module = server_module
        self.identity = _LiveIdentity()
        self.client = TestClient(server_module.app)

    @contextmanager
    def wired(self) -> Iterator[_DemotionHarness]:
        """Route session lookups and scope reads to the live identity.

        Yields:
            This harness, while the patches are active.
        """

        async def _resolve_session(*_args, **_kwargs) -> dict:
            return {
                "username": USERNAME,
                "groups": list(self.identity.user_groups),
                "provider": "keycloak",
                "auth_method": "oauth2",
                "subject": "oidc-sub-alice",
            }

        repo = _LiveScopeRepository(self.identity)
        with (
            patch("session_store.resolve_session", _resolve_session),
            patch("auth_server.server.get_scope_repository", return_value=repo),
            patch("registry.repositories.factory.get_scope_repository", return_value=repo),
        ):
            yield self

    def mint(self) -> str:
        """Mint a token for every scope the user's current groups grant.

        Returns:
            The minted access token.
        """
        groups = list(self.identity.user_groups)
        return _mint_narrowed_token(
            self.client,
            self.server_module,
            groups,
            self.identity.scopes_for(groups),
        )

    def registry_is_admin(
        self,
        token: str,
    ) -> bool:
        """Use ``token`` for a registry ``/api/`` call and report ``is_admin``.

        A token ``/validate`` rejects, a response without a registry token, or a
        registry token the registry rejects all count as not admin.

        Args:
            token: The bearer token to use.

        Returns:
            The registry context's ``is_admin``.
        """
        from fastapi import HTTPException

        from registry.auth.dependencies import _context_from_internal_token

        validated = _validate_for_registry_api(
            self.client, self.server_module, token, require_ok=False
        )
        registry_token = validated.headers.get("X-Internal-Token-Registry")
        if validated.status_code != 200 or not registry_token:
            return False
        request = SimpleNamespace(state=SimpleNamespace())
        try:
            context = asyncio.run(_context_from_internal_token(request, registry_token))
        except HTTPException:
            return False
        return bool(context["is_admin"])


def _demotion_violation(
    harness: _DemotionHarness,
    token: str,
    history: list[str],
) -> str | None:
    """Return a description when ``token`` confers admin on a non-admin user.

    Args:
        harness: The harness holding the live identity.
        token: The token being used.
        history: Operations applied so far, for the message.

    Returns:
        None when the property holds, otherwise the violation.
    """
    if harness.registry_is_admin(token) and not harness.identity.is_admin():
        return (
            f"is_admin=True for a user who is not an administrator "
            f"(groups={harness.identity.user_groups}, "
            f"admin mapping={harness.identity.group_to_scopes[ADMIN_GROUP]}) "
            f"after {history}"
        )
    return None


_DEMOTION_SEQUENCES = [
    pytest.param(
        ("mint", "demote", "use"),
        id="mint-demote-use",
        marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=DEMOTION_REASON),
    ),
    pytest.param(
        ("mint", "unmap", "demote", "remap", "use"),
        id="mint-unmap-demote-remap-use",
        marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=DEMOTION_REASON),
    ),
    pytest.param(("mint", "unmap", "use"), id="mint-unmap-use"),
    pytest.param(("mint", "demote", "promote", "use"), id="mint-demote-promote-use"),
    pytest.param(("demote", "mint", "promote", "use"), id="demote-mint-promote-use"),
]


@pytest.mark.parametrize("sequence", _DEMOTION_SEQUENCES)
def test_registry_admin_revoked_after_demotion(auth_env_vars, sequence):
    """A token stops conferring is_admin once its user is no longer an administrator.

    Each sequence mints tokens, changes the user's admin group membership or
    the admin group's scope mapping, then uses the latest token through
    ``/validate`` and the registry context. Whenever the user is not an
    administrator at use time, the registry context must have
    ``is_admin=False``.
    """
    import auth_server.server as server_module

    harness = _DemotionHarness(server_module)
    history: list[str] = []
    token: str | None = None
    with harness.wired():
        for op in sequence:
            history.append(op)
            if op == "mint":
                token = harness.mint()
                assert harness.registry_is_admin(token) == harness.identity.is_admin(), (
                    "harness: a freshly minted token must match the user's admin status"
                )
            elif op == "use":
                violation = _demotion_violation(harness, token, history)
                assert violation is None, violation
            else:
                harness.identity.apply(op)


def _holds_tokens(machine: _TokenDemotionMachine) -> bool:
    """Return whether the user holds any minted token."""
    return bool(machine.tokens)


class _TokenDemotionMachine(RuleBasedStateMachine):
    """Mint, demote, promote, unmap, remap and use, in any order.

    ``use`` presents every token the user holds, so a stale token is checked
    no matter how many tokens were minted after it.
    """

    def __init__(self) -> None:
        super().__init__()
        import auth_server.server as server_module

        self.harness = _DemotionHarness(server_module)
        self._wiring = ExitStack()
        self._wiring.enter_context(self.harness.wired())
        self.tokens: list[str] = []
        self.history: list[str] = []

    def teardown(self) -> None:
        self._wiring.close()

    @rule()
    def mint(self) -> None:
        self.history.append("mint")
        self.tokens.append(self.harness.mint())

    @rule(op=st.sampled_from(("demote", "promote", "unmap", "remap")))
    def change_identity(
        self,
        op: str,
    ) -> None:
        self.history.append(op)
        self.harness.identity.apply(op)

    @precondition(_holds_tokens)
    @rule()
    def use(self) -> None:
        self.history.append("use")
        for index, token in enumerate(self.tokens):
            violation = _demotion_violation(self.harness, token, self.history)
            assert violation is None, f"token #{index}: {violation}"


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=DEMOTION_REASON)
def test_registry_admin_tracks_demotion_state_machine(auth_env_vars):
    """For every operation sequence, a used token confers is_admin only on a current admin."""
    run_state_machine_as_test(_TokenDemotionMachine, settings=STATEFUL_SETTINGS)
