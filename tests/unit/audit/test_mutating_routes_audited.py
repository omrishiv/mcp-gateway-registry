"""Property tests for audit coverage of mutating registry routes.

Pins the accountability property of the registry API: every state-changing
request (POST, PUT, PATCH, DELETE) leaves an audit record naming the caller,
unless the route is on an explicit, justified allowlist. Audit is attached by
``AuditMiddleware`` around the whole application, so coverage reduces to two
facts: the middleware is installed whenever audit is enabled, and its path
filter never drops a mutating route, whatever value a caller puts in the path.
A behavioural case adds the durable-by-default invariant: a mutating request
whose audit record cannot be written must fail rather than succeed unaudited.
"""

import re
import string
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import (
    strategies as st,
)

from registry.audit.middleware import AuditMiddleware
from registry.auth.csrf import verify_csrf_token_flexible
from registry.auth.dependencies import nginx_proxied_auth
from registry.core.config import Settings
from registry.core.config import settings as registry_settings
from registry.main import app

MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
PATH_PARAM_RE = re.compile(r"\{([^}:]+)(?::[^}]+)?\}")
BENIGN_PARAM_VALUE: str = "sample-entity"
SAMPLE_ROUTE_PATH: str = "/api/registry-management/telemetry/heartbeat"
SAMPLE_ACTOR: str = "auditor@example.com"

# Mounted sub-applications are opaque to the route walk. Each one listed here
# serves read-only content; a new mount must be reviewed and added.
REVIEWED_MOUNTS: dict[str, str] = {
    "/static": "StaticFiles: serves the built frontend assets, GET and HEAD only.",
}

# Mutating routes deliberately left out of the audit trail, with the reason.
UNAUDITED_ROUTE_ALLOWLIST: dict[tuple[str, str], str] = {
    ("POST", "/api/internal/healthcheck"): (
        "Read-only health probe from mcpgw (returns health_service status, writes "
        "nothing); suppressed as monitoring traffic while audit_log_health_checks "
        "is False."
    ),
}

# Suffixes a caller can append to a path parameter. The static-asset ones are the
# extensions AuditMiddleware treats as static files.
PARAM_SUFFIXES: tuple[str, ...] = (
    "",
    ".js",
    ".css",
    ".png",
    ".ico",
    ".svg",
    ".woff2",
    ".json",
    "-health",
    "/health",
)


def _walk_routes(
    routes: list[Any],
) -> Iterator[Any]:
    """Yield every concrete route, descending into included routers.

    This FastAPI wraps ``include_router`` results in ``_IncludedRouter`` objects
    that expose their routes through ``effective_candidates()``.

    Args:
        routes: A router's ``routes`` list.

    Yields:
        Route objects that carry ``path`` (and ``methods`` for HTTP routes).
    """
    for route in routes:
        candidates = getattr(route, "effective_candidates", None)
        if callable(candidates):
            yield from _walk_routes(candidates())
        else:
            yield route


def _mutating_routes() -> list[tuple[str, str]]:
    """List every (method, path template) pair with a mutating method.

    Returns:
        Sorted, de-duplicated (method, path) pairs from the registry app.
    """
    pairs: set[tuple[str, str]] = set()
    for route in _walk_routes(app.routes):
        methods = getattr(route, "methods", None) or set()
        for method in set(methods) & MUTATING_METHODS:
            pairs.add((method, route.path))
    return sorted(pairs)


def _mounts() -> list[str]:
    """List the paths of mounted sub-applications (routes with no method set).

    Returns:
        Sorted mount paths.
    """
    return sorted(
        route.path
        for route in _walk_routes(app.routes)
        if getattr(route, "methods", None) is None and hasattr(route, "app")
    )


def _concrete_path(
    template: str,
    value: str,
) -> str:
    """Substitute ``value`` for every path parameter in a route template.

    Args:
        template: Route path such as ``/api/servers/{path:path}/rescan``.
        value: Value to place in each parameter.

    Returns:
        The request path a caller would send.
    """
    return PATH_PARAM_RE.sub(value, template)


def _installed_audit_middleware() -> AuditMiddleware:
    """Build an AuditMiddleware with the options the registry app installed it with.

    Returns:
        Middleware instance whose ``_should_log`` matches the running app.
    """
    for middleware in app.user_middleware:
        if middleware.cls is AuditMiddleware:
            return AuditMiddleware(app=MagicMock(), **middleware.kwargs)
    pytest.skip("audit_log_enabled is false in this environment; AuditMiddleware is not installed")


MUTATING_ROUTES: list[tuple[str, str]] = _mutating_routes()
AUDITED_ROUTES: list[tuple[str, str]] = [
    route for route in MUTATING_ROUTES if route not in UNAUDITED_ROUTE_ALLOWLIST
]
PARAMETRIC_ROUTES: list[tuple[str, str]] = [
    route for route in AUDITED_ROUTES if PATH_PARAM_RE.search(route[1])
]


@pytest.mark.unit
def test_audit_middleware_installed_by_default() -> None:
    """Property: audit is on by default and the middleware wraps the app when enabled."""
    assert Settings.model_fields["audit_log_enabled"].default is True
    assert Settings.model_fields["audit_log_require_durable"].default is True
    installed = any(m.cls is AuditMiddleware for m in app.user_middleware)
    assert installed is registry_settings.audit_log_enabled


@pytest.mark.unit
def test_route_walk_inventory_is_reviewed() -> None:
    """Property: every mount is reviewed and every allowlisted route still exists.

    Mounted sub-applications hide their routes from the walk, so each one must
    be listed as reviewed; a stale allowlist entry would silently exempt a
    future route that reuses the path.
    """
    unreviewed = sorted(set(_mounts()) - set(REVIEWED_MOUNTS))
    assert not unreviewed, f"unreviewed mounted sub-applications: {unreviewed}"
    stale = sorted(set(UNAUDITED_ROUTE_ALLOWLIST) - set(MUTATING_ROUTES))
    assert not stale, f"allowlisted routes that no longer exist: {stale}"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("method", "template"),
    AUDITED_ROUTES,
    ids=[f"{method} {path}" for method, path in AUDITED_ROUTES],
)
def test_mutating_route_is_audited(
    method: str,
    template: str,
) -> None:
    """Property: the installed audit filter logs every non-allowlisted mutating route."""
    middleware = _installed_audit_middleware()
    path = _concrete_path(template, BENIGN_PARAM_VALUE)
    assert middleware._should_log(path), f"{method} {path} is excluded from the audit trail"


@pytest.mark.unit
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(
    route=st.sampled_from(PARAMETRIC_ROUTES),
    base=st.text(alphabet=string.ascii_lowercase + string.digits + "-_", min_size=1, max_size=12),
    suffix=st.sampled_from(PARAM_SUFFIXES),
)
@example(route=("PUT", "/api/servers/{path:path}"), base="team", suffix=".js")
@example(route=("POST", "/api/toggle/{service_path:path}"), base="team", suffix=".css")
def test_caller_chosen_path_cannot_suppress_audit(
    route: tuple[str, str],
    base: str,
    suffix: str,
) -> None:
    """Property: no value a caller puts in a path parameter removes the audit record."""
    method, template = route
    middleware = _installed_audit_middleware()
    path = _concrete_path(template, base + suffix)
    assert middleware._should_log(path), f"{method} {path} is excluded from the audit trail"


def _authenticated_admin(
    request: Request,
) -> dict[str, Any]:
    """Stand in for ``nginx_proxied_auth``: return an admin and record it for audit.

    The real dependency stores the validated context on ``request.state`` for
    the audit middleware, so this override does the same.

    Args:
        request: The incoming request.

    Returns:
        The admin user context.
    """
    context = {
        "username": "auditor",
        "email": SAMPLE_ACTOR,
        "is_admin": True,
        "auth_method": "session",
        "groups": ["mcp-registry-admin"],
        "scopes": [],
    }
    request.state.user_context = context
    return context


@contextmanager
def _sample_mutation_client(
    insert: AsyncMock,
) -> Iterator[TestClient]:
    """Yield a client for the sample mutating route with a controlled audit sink.

    Args:
        insert: Replacement for the durable audit repository's ``insert``.

    Yields:
        TestClient bound to the registry app.
    """
    audit_logger = getattr(app.state, "audit_logger", None)
    if audit_logger is None:
        pytest.skip("audit_log_enabled is false in this environment; no audit logger")
    repository = MagicMock()
    repository.insert = insert
    with ExitStack() as stack:
        stack.enter_context(patch.object(audit_logger, "_audit_repository", repository))
        stack.enter_context(patch.object(audit_logger, "mongodb_enabled", True))
        stack.enter_context(
            patch(
                "registry.core.telemetry.send_forced_heartbeat",
                AsyncMock(return_value={"status": "sent"}),
            )
        )
        app.dependency_overrides[nginx_proxied_auth] = _authenticated_admin
        app.dependency_overrides[verify_csrf_token_flexible] = lambda: None
        stack.callback(app.dependency_overrides.pop, nginx_proxied_auth, None)
        stack.callback(app.dependency_overrides.pop, verify_csrf_token_flexible, None)
        yield TestClient(app, raise_server_exceptions=False)


@pytest.mark.unit
def test_sample_mutation_writes_attributed_audit_record() -> None:
    """Property: a successful mutating request writes one record naming its caller."""
    insert = AsyncMock(return_value=None)
    with _sample_mutation_client(insert) as client:
        response = client.post(SAMPLE_ROUTE_PATH)

    assert response.status_code == 200, response.text
    records = [
        call.args[0]
        for call in insert.await_args_list
        if call.args[0].request.path == SAMPLE_ROUTE_PATH
    ]
    assert len(records) == 1
    assert records[0].request.method == "POST"
    assert records[0].identity.username == SAMPLE_ACTOR


@pytest.mark.unit
def test_mutation_fails_when_audit_write_fails() -> None:
    """Property: a mutating request fails when its durable audit write fails."""
    insert = AsyncMock(side_effect=RuntimeError("audit store unavailable"))
    with _sample_mutation_client(insert) as client:
        response = client.post(SAMPLE_ROUTE_PATH)

    insert.assert_awaited()
    assert response.status_code >= 500, (
        f"mutation succeeded with status {response.status_code} although its audit "
        "record was not written"
    )
