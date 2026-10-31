"""Static route walk: every mutating registry route is authenticated and CSRF-guarded.

A route that accepts POST, PUT, PATCH or DELETE changes state, so it must carry
an authentication dependency somewhere in its FastAPI dependency tree, and,
because ``nginx_proxied_auth`` and ``enhanced_auth`` accept the browser session
cookie, it must also carry a CSRF verifier. These tests walk every route the
registry app publishes, plus the routers ``registry/main.py`` mounts only behind
a feature flag, recursively through sub-dependencies and router-level
dependencies, and pin both properties. The only exceptions are the explicit
allowlists below, each with a justification checked against the handler.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import (
    APIRouter,
    FastAPI,
)
from fastapi.dependencies.models import Dependant
from fastapi.routing import (
    APIRoute,
    iter_route_contexts,
)

from registry.api.custom_entity_routes import router as custom_entity_router
from registry.api.custom_type_routes import router as custom_type_router
from registry.api.egress_oauth_facade_routes import router as egress_oauth_facade_router
from registry.api.m2m_management_routes import router as m2m_management_router
from registry.auth.csrf import (
    verify_csrf_token,
    verify_csrf_token_flexible,
    verify_csrf_token_header_only,
)
from registry.auth.dependencies import (
    api_auth,
    enhanced_auth,
    get_current_user,
    get_user_session_data,
    nginx_proxied_auth,
    web_auth,
)
from registry.auth.internal import (
    validate_internal_auth,
    validate_internal_session_secret,
)
from registry.main import app

pytestmark = [pytest.mark.unit, pytest.mark.auth]


_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# Dependencies that establish a caller identity. Cookie-based ones first, then
# the header-only internal gates (Bearer internal JWT, X-Internal-Secret). Any
# wrapper that depends on one of these (for example a module's _require_admin
# that takes Depends(nginx_proxied_auth)) is found by the recursive walk.
_AUTH_DEPENDENCIES: frozenset[Callable[..., Any]] = frozenset(
    {
        nginx_proxied_auth,
        enhanced_auth,
        get_current_user,
        get_user_session_data,
        api_auth,
        web_auth,
        validate_internal_auth,
        validate_internal_session_secret,
    }
)

_CSRF_DEPENDENCIES: frozenset[Callable[..., Any]] = frozenset(
    {
        verify_csrf_token,
        verify_csrf_token_flexible,
        verify_csrf_token_header_only,
    }
)

# Routers registry/main.py mounts only when a feature flag is on, with the same
# prefix main.py uses. They are walked unconditionally so a disabled flag in the
# test environment does not hide their routes from these properties.
_FLAG_GATED_ROUTERS: tuple[tuple[APIRouter, str], ...] = (
    (custom_type_router, "/api"),
    (custom_entity_router, "/api"),
    (egress_oauth_facade_router, ""),
    (m2m_management_router, "/api"),
)

# The walk observed 143 mutating routes on 2026-10-31. A floor at half of that
# catches a walk that silently stops descending into included routers.
_MIN_MUTATING_ROUTES: int = 70

_AUTH_ALLOWLIST: dict[tuple[str, str], str] = {
    ("POST", "/api/auth/logout"): (
        "Logout must work without a valid session; it only destroys the session "
        "named by the caller's own cookie and is CSRF-protected."
    ),
}

_INTERNAL_JWT_REASON: str = (
    "Service-to-service route gated by validate_internal_auth, which accepts only "
    "a Bearer internal JWT in the Authorization header; a browser never attaches "
    "that header to a cross-site request."
)
_INTERNAL_SECRET_REASON: str = (
    "Called only by the nginx Lua router; gated by validate_internal_session_secret "
    "on the X-Internal-Secret header, which a cross-site request cannot set."
)
_DUPLICATE_CHECK_REASON: str = (
    "Advisory duplicate lookup that only reads the registry and persists nothing; "
    "a cross-site caller cannot read the response."
)
_SEMANTIC_SEARCH_REASON: str = (
    "Read-only semantic search whose only handler write is the fail-silent search "
    "usage counter; a cross-site caller cannot read the response."
)

_CSRF_ALLOWLIST: dict[tuple[str, str], str] = {
    ("POST", "/api/internal/generic-upstream-headers"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/egress-token"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/register"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/remove"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/toggle"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/healthcheck"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/add-to-groups"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/remove-from-groups"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/create-group"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/delete-group"): _INTERNAL_JWT_REASON,
    ("POST", "/api/internal/sessions/client"): _INTERNAL_SECRET_REASON,
    ("PUT", "/api/internal/sessions/backend/{session_key:path}"): _INTERNAL_SECRET_REASON,
    ("DELETE", "/api/internal/sessions/backend/{session_key:path}"): _INTERNAL_SECRET_REASON,
    ("POST", "/api/servers/check-duplicates"): _DUPLICATE_CHECK_REASON,
    ("POST", "/api/agents/check-duplicates"): _DUPLICATE_CHECK_REASON,
    ("POST", "/api/skills/check-duplicates"): _DUPLICATE_CHECK_REASON,
    ("POST", "/api/agents/discover"): (
        "Read-only skill match over the agents the caller can see; persists "
        "nothing, and a cross-site caller cannot read the response."
    ),
    ("POST", "/api/agents/discover/semantic"): _SEMANTIC_SEARCH_REASON,
    ("POST", "/api/search/semantic"): _SEMANTIC_SEARCH_REASON,
    ("POST", "/api/ard/search"): (
        "Read-only, access-scoped ARD search; persists nothing, and a cross-site "
        "caller cannot read the response."
    ),
    ("POST", "/api/skills/parse-skill-md"): (
        "Stateless registration preview that fetches and parses a SKILL.md and "
        "persists nothing; the shared GitHub token is only sent to allowlisted "
        "GitHub hosts, and a cross-site caller cannot read the response."
    ),
}


@dataclass(frozen=True)
class _MutatingRoute:
    """One (method, path) pair of a published APIRoute.

    Attributes:
        method: Upper-case HTTP method outside the safe set.
        path: The full published path template, including router prefixes.
        endpoint: Dotted name of the handler, for failure messages.
        calls: Every dependency callable reachable from the route's dependant.
    """

    method: str
    path: str
    endpoint: str
    calls: frozenset[Callable[..., Any]]


def _dependency_calls(
    dependant: Dependant,
) -> frozenset[Callable[..., Any]]:
    """Collect every dependency callable in a dependant tree.

    Args:
        dependant: The route's root dependant. Router-level dependencies are
            already folded into it by FastAPI when the router is included.

    Returns:
        The set of ``.call`` values of all transitive sub-dependencies.
    """
    calls: set[Callable[..., Any]] = set()
    stack = list(dependant.dependencies)
    while stack:
        sub = stack.pop()
        if sub.call is not None:
            calls.add(sub.call)
        stack.extend(sub.dependencies)
    return frozenset(calls)


def _flag_gated_app() -> FastAPI:
    """Mount the feature-flag-gated routers on a scratch app.

    Returns:
        A FastAPI app carrying only the routers main.py includes conditionally.
    """
    gated = FastAPI()
    for router, prefix in _FLAG_GATED_ROUTERS:
        gated.include_router(router, prefix=prefix)
    return gated


def _collect_mutating_routes() -> tuple[list[_MutatingRoute], list[str]]:
    """Enumerate every mutating (method, path) the registry can publish.

    Starlette serves the first matching route, so a (method, path) pair seen
    again (a flag-gated router already mounted in the app) keeps its first entry.

    Returns:
        The mutating APIRoutes in publication order, and an id for every
        mutating route that is not an APIRoute (and so has no dependency tree).
    """
    seen: set[tuple[str, str]] = set()
    routes: list[_MutatingRoute] = []
    opaque: list[str] = []
    for source in (app, _flag_gated_app()):
        for context in iter_route_contexts(source.routes):
            methods = context.methods or set()
            mutating = sorted(m.upper() for m in methods if m.upper() not in _SAFE_METHODS)
            if not mutating:
                continue
            if not isinstance(context.original_route, APIRoute):
                opaque.extend(f"{m} {context.path}" for m in mutating)
                continue
            calls = _dependency_calls(context.dependant)
            endpoint = f"{context.endpoint.__module__}.{context.endpoint.__qualname__}"
            for method in mutating:
                key = (method, context.path)
                if key in seen:
                    continue
                seen.add(key)
                routes.append(_MutatingRoute(method, context.path, endpoint, calls))
    return routes, opaque


_MUTATING_ROUTES, _OPAQUE_MUTATING_ROUTES = _collect_mutating_routes()
_ROUTE_PARAMS = [pytest.param(r, id=f"{r.method} {r.path}") for r in _MUTATING_ROUTES]


def _names(
    calls: frozenset[Callable[..., Any]],
) -> list[str]:
    """Render dependency callables for a failure message.

    Args:
        calls: Dependency callables of one route.

    Returns:
        Sorted qualified names.
    """
    return sorted(f"{c.__module__}.{getattr(c, '__qualname__', repr(c))}" for c in calls)


@pytest.mark.parametrize("route", _ROUTE_PARAMS)
def test_mutating_route_has_an_auth_dependency(route: _MutatingRoute):
    """Property: every mutating route authenticates its caller, or is allowlisted.

    Authentication means some dependency in the route's tree is one of the
    registry's identity dependencies, directly or through a wrapper.
    """
    if (route.method, route.path) in _AUTH_ALLOWLIST:
        return
    assert route.calls & _AUTH_DEPENDENCIES, (
        f"{route.method} {route.path} ({route.endpoint}) has no authentication "
        f"dependency in its tree; dependencies: {_names(route.calls)}"
    )


@pytest.mark.parametrize("route", _ROUTE_PARAMS)
def test_mutating_route_has_a_csrf_dependency(route: _MutatingRoute):
    """Property: every mutating route verifies a CSRF token, or is allowlisted.

    The allowlist holds routes that a browser cannot drive with its session
    cookie, and POSTs that only read.
    """
    if (route.method, route.path) in _CSRF_ALLOWLIST:
        return
    assert route.calls & _CSRF_DEPENDENCIES, (
        f"{route.method} {route.path} ({route.endpoint}) has no CSRF dependency "
        f"in its tree; dependencies: {_names(route.calls)}"
    )


@pytest.mark.parametrize(
    ("allowlist_name", "allowlist"),
    [
        pytest.param("_AUTH_ALLOWLIST", _AUTH_ALLOWLIST, id="auth"),
        pytest.param("_CSRF_ALLOWLIST", _CSRF_ALLOWLIST, id="csrf"),
    ],
)
def test_allowlist_entries_name_existing_mutating_routes(
    allowlist_name: str,
    allowlist: dict[tuple[str, str], str],
):
    """Property: every allowlist entry names a mutating route the walk found.

    A stale entry (route renamed, removed or made read-only) would otherwise
    linger and silently exempt whatever later reuses the path.
    """
    published = {(r.method, r.path) for r in _MUTATING_ROUTES}
    stale = sorted(set(allowlist) - published)
    assert not stale, f"{allowlist_name} entries match no mutating route: {stale}"


def test_route_walk_reaches_every_mutating_route():
    """Property: the walk sees the whole app, and every mutating route has a tree.

    A walk that stops at included routers would find almost nothing and pass the
    per-route properties vacuously. A mutating route that is not an APIRoute has
    no dependency tree, so neither property could hold for it.
    """
    assert len(_MUTATING_ROUTES) >= _MIN_MUTATING_ROUTES, (
        f"route walk found only {len(_MUTATING_ROUTES)} mutating routes, "
        f"expected at least {_MIN_MUTATING_ROUTES}"
    )
    assert not _OPAQUE_MUTATING_ROUTES, (
        f"mutating routes without a FastAPI dependency tree: {_OPAQUE_MUTATING_ROUTES}"
    )
