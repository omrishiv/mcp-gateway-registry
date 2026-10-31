"""Every route-level admin gate agrees with the canonical admin decision.

The registry derives ``user_context["is_admin"]`` once, from the caller's
scopes' ui_permissions. A route gate that also admits a caller by group or
scope name keeps admitting a caller after an operator demotes that group's
scope, so the gates must pass exactly when ``is_admin`` holds, apart from an
explicit allowlist of extra scopes that a gate documents as its own
credential. The sweep is exhaustive: groups are every subset of six
admin-looking names, scopes every subset of four, and ``is_admin`` both
values, 2,048 contexts per gate.
"""

import asyncio
import itertools
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import (
    Any,
    NamedTuple,
)
from unittest.mock import patch

import pytest
from fastapi import HTTPException

os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-definitely-long-enough-32b")

# auth_server.server imports its siblings by flat name (the container layout),
# so its directory must be importable, as tests/auth_server/conftest.py arranges.
_AUTH_SERVER_DIR = str(Path(__file__).resolve().parents[3] / "auth_server")
if _AUTH_SERVER_DIR not in sys.path:
    sys.path.append(_AUTH_SERVER_DIR)

from auth_server.server import validate_a2a_agent_access  # noqa: E402
from registry.api import (  # noqa: E402
    ans_routes,
    auth0_m2m_routes,
    custom_type_routes,
    egress_auth_routes,
    embeddings_admin_routes,
    export_routes,
    federation_routes,
    iam_user_groups_routes,
    log_routes,
    m2m_management_routes,
    management_routes,
    okta_m2m_routes,
    peer_management_routes,
    proxied_entities_routes,
    rate_limit_routes,
    registry_management_routes,
    server_routes,
    skill_routes,
    virtual_server_routes,
)

pytestmark = pytest.mark.unit

_GROUP_NAMES = (
    "admin",
    "Admin",
    "mcp-registry-admin",
    "registry-admins",
    " mcp-registry-admin",
    "other",
)
_SCOPE_NAMES = (
    "mcp-registry-admin",
    "federation/peers",
    "ans-admin/manage",
    "mcp-servers-unrestricted/execute",
)
_REPORTED_MISMATCHES = 5

_GROUP_NAME_GATE_REASON = (
    "Known defect: this gate also admits a caller by group or scope name, so a "
    "caller whose admin scope was demoted still passes while is_admin is False."
)
_A2A_BYPASS_REASON = (
    "Known defect: the A2A admin bypass admits any caller holding an admin "
    "marker group or scope name without checking the derived admin decision."
)


class _Gate(NamedTuple):
    """One admin gate: a callable that raises HTTPException to deny."""

    check: Callable[[dict[str, Any]], Any]
    extra_scopes: frozenset[str]


# Extra scopes a gate admits besides is_admin, each documented at the gate:
# - federation/peers: the federation static token's scope. Documented as an
#   allowed credential at registry/api/federation_routes.py:42-43 and
#   registry/api/peer_management_routes.py:44-45, checked at :55 and :59.
# - ans-admin/manage: the dedicated ANS admin scope, described at
#   registry/api/ans_routes.py:112-116 (checked at :125) and in
#   docs/design/ans-integration.md:206.
_FEDERATION_SCOPE = frozenset({"federation/peers"})
_ANS_SCOPE = frozenset({"ans-admin/manage"})
_NONE = frozenset()

_GATES: dict[str, _Gate] = {
    "ans_routes._check_admin": _Gate(ans_routes._check_admin, _ANS_SCOPE),
    "auth0_m2m_routes._require_admin": _Gate(auth0_m2m_routes._require_admin, _NONE),
    "custom_type_routes._require_admin": _Gate(custom_type_routes._require_admin, _NONE),
    "egress_auth_routes._require_admin": _Gate(egress_auth_routes._require_admin, _NONE),
    "embeddings_admin_routes._require_admin": _Gate(embeddings_admin_routes._require_admin, _NONE),
    "export_routes._require_admin": _Gate(export_routes._require_admin, _NONE),
    "federation_routes._check_federation_management_scope": _Gate(
        federation_routes._check_federation_management_scope, _FEDERATION_SCOPE
    ),
    "iam_user_groups_routes._require_admin": _Gate(iam_user_groups_routes._require_admin, _NONE),
    "log_routes._require_admin": _Gate(log_routes._require_admin, _NONE),
    "m2m_management_routes._require_admin": _Gate(
        lambda ctx: m2m_management_routes._require_admin(ctx, operation="update"), _NONE
    ),
    "management_routes._require_admin": _Gate(management_routes._require_admin, _NONE),
    "okta_m2m_routes._require_admin": _Gate(okta_m2m_routes._require_admin, _NONE),
    "peer_management_routes._check_peer_management_scope": _Gate(
        peer_management_routes._check_peer_management_scope, _FEDERATION_SCOPE
    ),
    "proxied_entities_routes._require_admin": _Gate(proxied_entities_routes._require_admin, _NONE),
    "rate_limit_routes._require_admin": _Gate(rate_limit_routes._require_admin, _NONE),
    "registry_management_routes._require_admin": _Gate(
        registry_management_routes._require_admin, _NONE
    ),
    "server_routes._require_admin": _Gate(server_routes._require_admin, _NONE),
    "skill_routes._require_admin_for_global_credentials": _Gate(
        lambda ctx: skill_routes._require_admin_for_global_credentials(ctx, "global_credentials"),
        _NONE,
    ),
    "virtual_server_routes._require_admin": _Gate(virtual_server_routes._require_admin, _NONE),
}
_GROUP_NAME_GATES = frozenset(
    {
        "ans_routes._check_admin",
        "auth0_m2m_routes._require_admin",
        "custom_type_routes._require_admin",
        "federation_routes._check_federation_management_scope",
        "okta_m2m_routes._require_admin",
        "peer_management_routes._check_peer_management_scope",
        "virtual_server_routes._require_admin",
    }
)


def _subsets(names: tuple[str, ...]) -> list[tuple[str, ...]]:
    """Return every subset of ``names``, smallest first."""
    return [
        combo for size in range(len(names) + 1) for combo in itertools.combinations(names, size)
    ]


def _contexts() -> list[dict[str, Any]]:
    """Return all 2,048 (groups, scopes, is_admin) contexts, smallest first."""
    return [
        {"username": "caller", "groups": list(groups), "scopes": list(scopes), "is_admin": flag}
        for groups in _subsets(_GROUP_NAMES)
        for scopes in _subsets(_SCOPE_NAMES)
        for flag in (False, True)
    ]


def _passes(check: Callable[[dict[str, Any]], Any], ctx: dict[str, Any]) -> bool:
    """Return True when ``check`` admits ``ctx``; an HTTPException is a denial."""
    try:
        check(ctx)
    except HTTPException:
        return False
    return True


def _describe(cases: list[dict[str, Any]]) -> str:
    """Render the first few mismatching contexts for an assertion message."""
    shown = [
        f"groups={c['groups']} scopes={c['scopes']} is_admin={c['is_admin']}"
        for c in cases[:_REPORTED_MISMATCHES]
    ]
    return f"{len(cases)} of 2048 contexts disagree, e.g. " + "; ".join(shown)


@pytest.mark.parametrize(
    "gate_id",
    [
        pytest.param(
            gate_id,
            marks=[
                pytest.mark.xfail(
                    strict=True, raises=AssertionError, reason=_GROUP_NAME_GATE_REASON
                )
            ]
            if gate_id in _GROUP_NAME_GATES
            else [],
        )
        for gate_id in sorted(_GATES)
    ],
)
def test_admin_gate_matches_canonical_decision(gate_id: str) -> None:
    """Property: a gate admits a context iff is_admin holds or it carries an allowlisted extra scope."""
    gate = _GATES[gate_id]
    wrong = [
        ctx
        for ctx in _contexts()
        if _passes(gate.check, ctx)
        != (ctx["is_admin"] or bool(gate.extra_scopes & set(ctx["scopes"])))
    ]
    assert not wrong, f"{gate_id}: {_describe(wrong)}"


class _NoRulesScopeRepo:
    """Scope repository holding no scope documents."""

    async def get_server_scopes_bulk(self, scope_names: list[str]) -> dict:
        return {}

    async def get_server_scopes(self, scope_name: str) -> list:
        return []

    async def get_ui_scopes_bulk(self, group_names: list[str]) -> dict:
        return {}

    async def get_ui_scopes(self, scope_name: str) -> dict:
        return {}

    async def get_all_group_mappings(self) -> dict:
        return {}


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=_A2A_BYPASS_REASON)
def test_a2a_admin_bypass_admits_only_admins() -> None:
    """Property: with no scope rules stored, A2A invoke is allowed only for an is_admin caller.

    The gateway sees scopes and groups but not the registry's is_admin flag, so
    this direction (admitted implies admin) is the whole property: with an
    empty scope store no scope can grant invoke, and nothing derives admin.
    """

    async def _run() -> list[dict[str, Any]]:
        with patch("auth_server.server.get_scope_repository", return_value=_NoRulesScopeRepo()):
            return [
                ctx
                for ctx in _contexts()
                if not ctx["is_admin"]
                and await validate_a2a_agent_access("/travel", ctx["scopes"], ctx["groups"])
            ]

    wrong = asyncio.run(_run())
    assert not wrong, f"validate_a2a_agent_access: {_describe(wrong)}"
