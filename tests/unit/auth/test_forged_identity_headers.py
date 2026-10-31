"""Property tests: forged identity headers never authenticate a registry API call.

``registry.auth.dependencies.nginx_proxied_auth`` authenticates ``/api/``
requests from the signed ``X-Internal-Token-Registry`` that the auth server
mints, or else from the session cookie. Headers such as ``X-User``,
``X-Username``, ``X-Scopes``, ``X-Groups`` and ``X-Auth-Method`` are set by
nginx only after authentication and are forgeable by a client that reaches the
app directly. Whatever forged headers arrive, in either nginx deployment mode,
the request must be refused with 401 or authenticated as the session cookie's
own user with exactly the cookie's groups, never with an identity, group or
scope taken from a header.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

import jwt as pyjwt
import pytest
from fastapi import (
    Depends,
    FastAPI,
)
from fastapi.testclient import TestClient
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st
from itsdangerous import URLSafeTimedSerializer

from registry.auth.dependencies import nginx_proxied_auth
from registry.core.config import settings as registry_settings

pytestmark = [pytest.mark.unit, pytest.mark.auth]


SECRET: str = "forged-identity-headers-secret-key-for-unit-tests-only-0123456789abcdef"
COOKIE_SECRET: str = "forged-identity-headers-cookie-signing-key-for-unit-tests"

SESSION_ID: str = "sess-cookie-user"
SESSION_USER: str = "bob"
SESSION_GROUPS: list[str] = ["server-readers"]

ATTACKER_USER: str = "mallory"
ADMIN_GROUP: str = "mcp-registry-admin"
ADMIN_SCOPE: str = "registry-admin"
SERVERS_READ_SCOPE: str = "servers-read"

# Fake group -> scope mapping. ADMIN_SCOPE is the only admin-conferring scope.
GROUP_TO_SCOPES: dict[str, list[str]] = {
    ADMIN_GROUP: [ADMIN_SCOPE],
    "server-readers": [SERVERS_READ_SCOPE],
}

UI_SCOPES: dict[str, dict[str, list[str]]] = {
    ADMIN_SCOPE: {
        "list_service": ["all"],
        "register_service": ["all"],
    },
    SERVERS_READ_SCOPE: {"list_service": ["alpha-server"]},
}

# Headers nginx sets after authentication; all are client-forgeable.
IDENTITY_HEADERS: tuple[str, ...] = (
    "X-User",
    "X-Username",
    "X-Scopes",
    "X-Groups",
    "X-Auth-Method",
    "X-Client-Id",
    "X-Email",
)

FORGED_VALUES: tuple[str, ...] = (
    ATTACKER_USER,
    ADMIN_GROUP,
    ADMIN_SCOPE,
    f"{ADMIN_GROUP},{ADMIN_SCOPE}",
    "oauth2",
    "keycloak",
    "network-trusted",
    "",
)

COOKIE_STATES: tuple[str, ...] = (
    "none",
    "valid",
    "bad-signature",
    "unknown-session",
)

TOKEN_STATES: tuple[str, ...] = (
    "none",
    "wrong-key",
    "garbage",
)

PROBE_PATH: str = "/api/probe"

HYPOTHESIS_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)


class _FakeScopeRepository:
    """In-memory scope repository serving the fake mapping."""

    async def get_group_mappings_bulk(
        self,
        groups: list[str],
    ) -> list[str]:
        """Return the scopes granted by ``groups``."""
        scopes: list[str] = []
        for group in groups:
            for scope in GROUP_TO_SCOPES.get(group, []):
                if scope not in scopes:
                    scopes.append(scope)
        return scopes

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
        """Return no server access rules."""
        return {}


async def _fake_resolve_session(
    session_id: str,
) -> dict[str, Any] | None:
    """Resolve only the cookie user's session id.

    Args:
        session_id: The opaque session id from the signed cookie.

    Returns:
        The cookie user's session record, or None for any other id.
    """
    if session_id != SESSION_ID:
        return None
    return {
        "session_id": SESSION_ID,
        "username": SESSION_USER,
        "groups": list(SESSION_GROUPS),
        "auth_method": "oauth2",
        "provider": "keycloak",
    }


def _build_probe_app() -> FastAPI:
    """Build a minimal app whose route authenticates through ``nginx_proxied_auth``.

    Returns:
        FastAPI app exposing ``GET`` and ``POST`` on ``PROBE_PATH``.
    """
    app = FastAPI()

    async def _probe(
        user_context: dict[str, Any] = Depends(nginx_proxied_auth),
    ) -> dict[str, Any]:
        return {
            "username": user_context.get("username"),
            "groups": list(user_context.get("groups") or []),
            "scopes": list(user_context.get("scopes") or []),
            "is_admin": bool(user_context.get("is_admin")),
        }

    app.add_api_route(PROBE_PATH, _probe, methods=["GET", "POST"])
    return app


_CLIENT = TestClient(_build_probe_app())


@contextmanager
def _isolated_backends(
    api_auth_request_disabled: bool,
) -> Iterator[URLSafeTimedSerializer]:
    """Route session, cookie-signing and scope lookups to in-memory fakes.

    Args:
        api_auth_request_disabled: Value for ``NGINX_DISABLE_API_AUTH_REQUEST``.

    Yields:
        The serializer the registry uses to verify session cookies.
    """
    signer = URLSafeTimedSerializer(COOKIE_SECRET)
    env = {
        "SECRET_KEY": SECRET,
        "NGINX_DISABLE_API_AUTH_REQUEST": "true" if api_auth_request_disabled else "false",
    }
    with (
        patch.dict(os.environ, env),
        patch("registry.auth.dependencies.signer", signer),
        patch("registry.auth.dependencies._store_resolve_session", _fake_resolve_session),
        patch(
            "registry.repositories.factory.get_scope_repository",
            return_value=_FakeScopeRepository(),
        ),
    ):
        yield signer


def _cookie_header(
    signer: URLSafeTimedSerializer,
    state: str,
) -> dict[str, str]:
    """Build the Cookie header for a cookie state.

    Args:
        signer: The registry's session-cookie serializer.
        state: One of ``COOKIE_STATES``.

    Returns:
        A header dict, empty when there is no cookie.
    """
    name = registry_settings.session_cookie_name
    if state == "none":
        return {}
    if state == "valid":
        value = signer.dumps(SESSION_ID)
    elif state == "unknown-session":
        value = signer.dumps("sess-that-does-not-exist")
    else:
        value = URLSafeTimedSerializer("not-the-registry-key").dumps(SESSION_ID)
    return {"Cookie": f"{name}={value}"}


def _registry_token_header(
    state: str,
) -> dict[str, str]:
    """Build an ``X-Internal-Token-Registry`` header the registry must not accept.

    Args:
        state: One of ``TOKEN_STATES``.

    Returns:
        A header dict, empty when there is no token.
    """
    if state == "none":
        return {}
    if state == "garbage":
        return {"X-Internal-Token-Registry": "not.a.jwt"}
    now = int(time.time())
    forged = pyjwt.encode(
        {
            "iss": "mcp-auth-server",
            "aud": "mcp-registry-ui",
            "token_use": "mcp-registry-ui",
            "sub": ATTACKER_USER,
            "groups": [ADMIN_GROUP],
            "session_id": "",
            "iat": now,
            "exp": now + 60,
        },
        "attacker-chosen-signing-key-that-is-long-enough-0123456789",
        algorithm="HS256",
    )
    return {"X-Internal-Token-Registry": forged}


@st.composite
def _forged_requests(
    draw: st.DrawFn,
) -> dict[str, Any]:
    """Draw forged identity headers plus cookie, token and deployment state.

    Args:
        draw: Hypothesis draw function.

    Returns:
        Dict with ``headers``, ``cookie``, ``token``, ``disabled`` and ``method``.
    """
    names = draw(st.lists(st.sampled_from(IDENTITY_HEADERS), min_size=1, unique=True))
    headers = {
        name: draw(
            st.one_of(
                st.sampled_from(FORGED_VALUES),
                st.text(alphabet="abcdefghijklmnopqrstuvwxyz-,/ ", max_size=24),
            )
        )
        for name in names
    }
    if draw(st.booleans()):
        headers["Authorization"] = "Bearer forged-bearer-the-registry-never-validated"
    return {
        "headers": headers,
        "cookie": draw(st.sampled_from(COOKIE_STATES)),
        "token": draw(st.sampled_from(TOKEN_STATES)),
        "disabled": draw(st.booleans()),
        "method": draw(st.sampled_from(("GET", "POST"))),
    }


def _send(
    case: dict[str, Any],
):
    """Send one probe request for ``case``.

    Args:
        case: A drawn case from ``_forged_requests``.

    Returns:
        The HTTP response.
    """
    with _isolated_backends(case["disabled"]) as signer:
        headers = {
            **case["headers"],
            **_cookie_header(signer, case["cookie"]),
            **_registry_token_header(case["token"]),
        }
        return _CLIENT.request(case["method"], PROBE_PATH, headers=headers)


@HYPOTHESIS_SETTINGS
@given(case=_forged_requests())
@example(
    case={
        "headers": {"X-User": ATTACKER_USER, "X-Groups": ADMIN_GROUP, "X-Scopes": ADMIN_SCOPE},
        "cookie": "none",
        "token": "none",
        "disabled": True,
        "method": "POST",
    }
)
@example(
    case={
        "headers": {"X-Scopes": ADMIN_SCOPE, "X-Groups": ADMIN_GROUP},
        "cookie": "valid",
        "token": "none",
        "disabled": False,
        "method": "GET",
    }
)
def test_forged_identity_headers_never_authenticate(case):
    """Forged identity headers yield 401 or the cookie user's own context.

    For any set of forged identity headers, any cookie state, any invalid
    registry token and either nginx mode, the response is 401, or 200 with
    exactly the valid cookie's username, groups and scopes and no admin. A 200
    without a valid cookie is a failure.
    """
    response = _send(case)

    if response.status_code == 401:
        return
    assert response.status_code == 200, (response.status_code, response.text)
    context = response.json()
    assert case["cookie"] == "valid", f"authenticated without a valid cookie: {context}"
    assert case["token"] == "none", f"authenticated despite an invalid token: {context}"
    assert context == {
        "username": SESSION_USER,
        "groups": SESSION_GROUPS,
        "scopes": [SERVERS_READ_SCOPE],
        "is_admin": False,
    }, context


@pytest.mark.parametrize("disabled", [False, True], ids=["auth-request", "disable-mode"])
@pytest.mark.parametrize("token", TOKEN_STATES[1:])
def test_invalid_registry_token_refused_even_with_valid_cookie(disabled, token):
    """A present but invalid registry token is refused, never bypassed by the cookie.

    In both nginx modes, an ``X-Internal-Token-Registry`` that fails
    verification yields 401 even when a valid session cookie and forged
    identity headers accompany it.
    """
    case = {
        "headers": {"X-User": ATTACKER_USER, "X-Groups": ADMIN_GROUP},
        "cookie": "valid",
        "token": token,
        "disabled": disabled,
        "method": "GET",
    }
    assert _send(case).status_code == 401


@pytest.mark.parametrize("disabled", [False, True], ids=["auth-request", "disable-mode"])
def test_valid_cookie_alone_authenticates_cookie_user(disabled):
    """A valid session cookie with no headers authenticates as the cookie user.

    This anchors the forged-header property: the cookie path the property
    allows does work, so a 401 there is a refusal, not a broken harness.
    """
    case = {
        "headers": {},
        "cookie": "valid",
        "token": "none",
        "disabled": disabled,
        "method": "GET",
    }
    response = _send(case)
    assert response.status_code == 200, response.text
    assert response.json()["username"] == SESSION_USER
