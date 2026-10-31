"""Property tests: a session-backed token mint never exceeds the session's groups.

``auth_server.server._reconcile_context_against_session`` decides which groups
and scopes a session-backed ``/internal/tokens`` mint stamps into the token.
The caller-supplied body may claim any groups, scopes and subject. Whatever it
claims, the minted groups must be a subset of the groups the resolved session
holds, the scopes must come only from those groups, the subject must be the
session's, a claimed admin group the session lacks must be refused with 403,
and a session id that does not resolve must be refused with 401.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import (
    AsyncMock,
    patch,
)

import pytest
from fastapi import HTTPException
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

pytestmark = [pytest.mark.unit, pytest.mark.auth]


# Groups that confer registry admin; a body may never claim one the session lacks.
ADMIN_GROUPS: frozenset[str] = frozenset({"mcp-registry-admin", "registry-admins"})

ORDINARY_GROUPS: tuple[str, ...] = (
    "developers",
    "server-readers",
    "mcp-servers-unrestricted",
    "MCP-Registry-Admin",
    " mcp-registry-admin",
)

GROUP_UNIVERSE: tuple[str, ...] = (*sorted(ADMIN_GROUPS), *ORDINARY_GROUPS)

# Fake group -> scope mapping used in place of the scope repository.
GROUP_TO_SCOPES: dict[str, list[str]] = {
    "mcp-registry-admin": ["registry-admin"],
    "registry-admins": ["registry-admin"],
    "developers": ["servers-read", "servers-write"],
    "server-readers": ["servers-read"],
    "mcp-servers-unrestricted": ["servers-execute"],
}

SCOPE_UNIVERSE: tuple[str, ...] = (
    "registry-admin",
    "servers-read",
    "servers-write",
    "servers-execute",
    "federation/peers",
)

SESSION_ID: str = "sess-reconcile"
SESSION_SUBJECT: str = "oidc-sub-session-user"

HYPOTHESIS_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)


def _scopes_for(
    groups: list[str],
) -> list[str]:
    """Map groups through the fake mapping, deduped in order.

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


async def _fake_map_groups_to_scopes(
    groups: list[str],
) -> list[str]:
    """Async stand-in for ``map_groups_to_scopes`` backed by the fake mapping.

    Args:
        groups: Group names.

    Returns:
        The scopes those groups grant.
    """
    return _scopes_for(groups)


def _reconcile(
    user_context: dict[str, Any],
    session: dict[str, Any] | None,
) -> tuple[list[str], list[str], str, bool]:
    """Run the reconciler against an in-memory session store.

    Args:
        user_context: The mint request body's ``user_context``.
        session: The record ``resolve_session`` returns, or None.

    Returns:
        The reconciler's ``(groups, scopes, subject, graph_resolved)`` tuple.
    """
    from auth_server.server import _reconcile_context_against_session

    with (
        patch("session_store.resolve_session", AsyncMock(return_value=session)),
        patch("auth_server.server.map_groups_to_scopes", _fake_map_groups_to_scopes),
    ):
        return asyncio.run(_reconcile_context_against_session(user_context))


@st.composite
def _mint_cases(
    draw: st.DrawFn,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Draw a session record and a session-backed mint body that claims anything.

    Args:
        draw: Hypothesis draw function.

    Returns:
        Tuple ``(user_context, session_record)``.
    """
    session_groups = draw(st.lists(st.sampled_from(GROUP_UNIVERSE), unique=True))
    body_groups = draw(st.lists(st.sampled_from(GROUP_UNIVERSE), max_size=6))
    body_scopes = draw(st.lists(st.sampled_from(SCOPE_UNIVERSE), max_size=5))
    provider = draw(st.sampled_from(("keycloak", "entra", "okta")))
    user_context = {
        "username": "session-user",
        "groups": body_groups,
        "scopes": body_scopes,
        "session_id": SESSION_ID,
        "egress_user": draw(st.sampled_from(("", "attacker-sub", SESSION_SUBJECT))),
        "subject": draw(st.sampled_from(("", "attacker-sub"))),
        "entra_graph_groups_resolved": draw(st.booleans()),
    }
    session = {
        "username": "session-user",
        "groups": session_groups,
        "provider": provider,
        "subject": SESSION_SUBJECT,
        "entra_graph_groups_resolved": draw(st.booleans()),
    }
    return user_context, session


@HYPOTHESIS_SETTINGS
@given(case=_mint_cases())
@example(
    case=(
        {
            "groups": ["developers", "mcp-servers-unrestricted"],
            "scopes": ["registry-admin"],
            "session_id": SESSION_ID,
            "egress_user": "attacker-sub",
        },
        {"username": "u", "groups": ["developers"], "subject": SESSION_SUBJECT},
    )
)
@example(
    case=(
        {"groups": [], "scopes": ["registry-admin"], "session_id": SESSION_ID},
        {"username": "u", "groups": ["server-readers"], "subject": SESSION_SUBJECT},
    )
)
def test_minted_context_bounded_by_session(case):
    """The reconciled groups, scopes and subject come only from the session.

    For any session S and any body B with a session id: unless the call is
    refused with 403, the returned groups are a subset of S's groups, the
    scopes are exactly those S's mapping grants for the returned groups (body
    scopes never leak through), the subject is S's subject, and the Entra Graph
    marker is set only when S is an Entra session that recorded it.
    """
    user_context, session = case
    try:
        groups, scopes, subject, graph_resolved = _reconcile(user_context, session)
    except HTTPException as exc:
        assert exc.status_code == 403, exc.status_code
        return

    session_groups = set(session["groups"])
    assert set(groups) <= session_groups, (groups, session["groups"])
    assert scopes == _scopes_for(groups), (scopes, groups)
    assert subject == session["subject"], subject
    expected_graph = (
        session.get("provider") == "entra" and session.get("entra_graph_groups_resolved") is True
    )
    assert graph_resolved is expected_graph


@HYPOTHESIS_SETTINGS
@given(case=_mint_cases())
@example(
    case=(
        {"groups": ["registry-admins"], "scopes": [], "session_id": SESSION_ID},
        {"username": "u", "groups": ["mcp-registry-admin"], "subject": SESSION_SUBJECT},
    )
)
def test_claimed_admin_group_outside_session_refused(case):
    """A claimed admin group the session does not hold is refused with 403.

    For any session S and body B: if B claims an admin group not in S's
    groups, the reconciler raises 403; if it claims none, it does not raise.
    """
    user_context, session = case
    forged = (set(user_context["groups"]) & ADMIN_GROUPS) - set(session["groups"])
    if forged:
        with pytest.raises(HTTPException) as exc:
            _reconcile(user_context, session)
        assert exc.value.status_code == 403
    else:
        _reconcile(user_context, session)


@pytest.mark.parametrize(
    "session",
    [None, {}],
    ids=["missing", "empty"],
)
@pytest.mark.parametrize(
    "body_groups",
    [[], ["developers"], sorted(ADMIN_GROUPS)],
    ids=["no-groups", "ordinary", "admin"],
)
def test_unresolvable_session_refused(session, body_groups):
    """A session id that does not resolve is refused with 401 for any body.

    For every body group claim, a ``session_id`` the store does not resolve
    makes the reconciler raise 401 rather than fall back to the body.
    """
    user_context = {
        "groups": body_groups,
        "scopes": ["registry-admin"],
        "session_id": SESSION_ID,
    }
    with pytest.raises(HTTPException) as exc:
        _reconcile(user_context, session)
    assert exc.value.status_code == 401
