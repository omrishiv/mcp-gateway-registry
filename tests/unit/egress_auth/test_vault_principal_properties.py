"""Property tests: every registry vault route keys on one principal.

The per-user egress vault is addressed by ``(auth_method, user_id)``. The vend
reads that pair from the claims of the internal token the auth-server mints:
the canonical ``auth_method`` (every per-user IdP method folds into ``oauth2``)
and the ``egress_user`` claim, with no fallback. A registry route that reads or
writes the vault from a request's user context must derive the same pair, or a
consent writes a bucket the vend never reads. The rule the routes share:

* ``auth_method`` canonicalizes; a non-per-user method (``network-trusted``,
  ``federation-static``, empty, unknown, not a string) owns no bucket;
* ``user_id`` is ``egress_user`` when that is a non-empty string, else
  ``username`` when that is a non-empty string, else there is no principal.

``_model_principal`` states that rule independently of the code under test.
The first property pins ``vault_principal`` to it. The others drive each real
route through TestClient with a recording fake behind it and check the
principal the route hands to the service or store, or, when the model has no
principal, that the route refuses with its usual response and never reaches
the vault. The last property pins the vend, which keys on the minted claims and
never falls back to the username.
"""

from copy import deepcopy
from datetime import UTC, datetime
from unittest.mock import (
    AsyncMock,
    MagicMock,
)
from urllib.parse import (
    parse_qs,
    urlparse,
)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from hypothesis import (
    HealthCheck,
    example,
    given,
    settings,
)
from hypothesis import strategies as st

import registry.api.egress_auth_routes as routes
import registry.api.egress_oauth_facade_routes as facade
import registry.api.server_routes as server_routes
from registry.egress_auth import (
    oauth_engine,
    state_codec,
)
from registry.egress_auth.schemas import (
    EgressConnection,
    OAuthState,
)
from registry.egress_auth.service import (
    EgressAuthService,
    vault_principal,
)
from registry.secrets.interfaces import SecretStoreBase
from registry.utils.credential_encryption import encrypt_credential

_CANONICAL_PER_USER_METHOD = "oauth2"
# Every method name the auth-server reports for a per-user caller: the canonical
# value plus the token-format and IdP names that fold into it.
_PER_USER_INPUT_METHODS = frozenset(
    {
        "oauth2",
        "session_cookie",
        "self_signed",
        "jwt",
        "boto3",
        "keycloak",
        "entra",
        "cognito",
        "okta",
        "auth0",
        "pingfederate",
    }
)
_NON_PER_USER_METHODS = ("network-trusted", "federation-static")
_RAW_IDP_METHODS = tuple(sorted(_PER_USER_INPUT_METHODS - {_CANONICAL_PER_USER_METHOD}))

_OAUTH_SERVER_PATH = "/github-mcp"
_PAT_SERVER_PATH = "/github-pat"
_DISCOVERY_SERVER_PATH = "/tableau"
_UPSTREAM = "https://api.githubcopilot.com/mcp"
_AUTHORIZE_URL = "https://github.com/login/oauth/authorize?x=1"
_SESSION_COOKIE = "live-session"
_REGISTRY_URL = "https://gw.example.com"

# A key left out of the user context entirely, as opposed to present with None.
_ABSENT = object()

_PURE_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)
# Route properties send a full ASGI request per example through TestClient, so
# they run 100 examples rather than 200 to keep the file fast under -n 8; the
# strategies are small enough that 100 still reaches every branch of the model.
# The harness fixtures are built once per test and reset per example, which is
# why the function-scoped-fixture health check is suppressed. No deadline: the
# first request of a test pays FastAPI's route compilation.
_ROUTE_SETTINGS = settings(
    max_examples=100,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

_auth_methods = st.one_of(
    st.sampled_from(sorted(_PER_USER_INPUT_METHODS)),
    st.sampled_from(_NON_PER_USER_METHODS),
    st.just(""),
    st.none(),
    st.just(_ABSENT),
    st.text(max_size=12),
    st.integers(),
    st.lists(st.text(max_size=3), max_size=2),
)
# A few fixed ids so egress_user and username often coincide, and so a drawn
# caller often is the drawn discovery designee.
_KNOWN_IDS = ("alice", "sub-1")
_identity_values = st.one_of(
    st.none(),
    st.just(""),
    st.just(_ABSENT),
    st.sampled_from(_KNOWN_IDS),
    st.text(min_size=1, max_size=12),
    st.integers(),
    st.booleans(),
    st.lists(st.text(max_size=3), max_size=2),
)
_user_ids = st.text(min_size=1, max_size=12)


@st.composite
def _caller_contexts(draw) -> dict:
    """Draw the identity part of a registry user context.

    Each of ``auth_method``, ``egress_user`` and ``username`` is either left out
    or set to a drawn value, which may be None, empty, a non-string or text.
    """
    ctx: dict = {}
    for key, values in (
        ("auth_method", _auth_methods),
        ("egress_user", _identity_values),
        ("username", _identity_values),
    ):
        value = draw(values)
        if value is not _ABSENT:
            ctx[key] = value
    return ctx


def _model_principal(
    ctx: dict,
) -> tuple[str, str] | None:
    """Reference model of the vault principal for a registry user context.

    ``egress_user`` wins; ``username`` is read only when ``egress_user`` is
    absent, None or empty. Whichever is read must be a non-empty string: a
    present value of another type refuses rather than falling through.

    Args:
        ctx: The identity fields of a user context.

    Returns:
        ``(auth_method, user_id)`` the vault is keyed on, or None when the caller
        owns no per-user bucket.
    """
    method = ctx.get("auth_method")
    if not isinstance(method, str) or method not in _PER_USER_INPUT_METHODS:
        return None
    for key in ("egress_user", "username"):
        value = ctx.get(key)
        if value is None or value == "":
            continue
        if not isinstance(value, str):
            return None
        return _CANONICAL_PER_USER_METHOD, value
    return None


def _caller_context(
    caller: dict,
    is_admin: bool,
) -> dict:
    """Wrap drawn identity fields in a full user context, as an admin or not.

    Both shapes carry the access the self-service routes check (every server,
    modify and list permission); only ``is_admin`` and the admin group differ.
    The vault principal a route derives must not depend on either.
    """
    return {
        **caller,
        "is_admin": is_admin,
        "groups": ["mcp-registry-admin"] if is_admin else ["mcp-registry-user"],
        "scopes": ["mcp-servers-unrestricted/execute"],
        "accessible_servers": ["*"],
        "ui_permissions": {"modify_service": ["all"], "list_service": ["all"]},
        "client_id": "web",
        "session_id": "sid-1",
    }


def _encrypted_oauth_config() -> dict:
    return {
        "provider": "github",
        "client_id": "Iv1.testclient",
        "client_secret_encrypted": encrypt_credential("ghs_testsecret"),
        "scopes": ["repo"],
    }


def _servers() -> dict[str, dict]:
    """Server records keyed by path: one ``oauth_user`` server, one ``pat`` server."""
    return {
        _OAUTH_SERVER_PATH: {
            "path": _OAUTH_SERVER_PATH,
            "server_name": "GitHub",
            "proxy_pass_url": _UPSTREAM,
            "egress_auth_mode": "oauth_user",
            "egress_oauth": _encrypted_oauth_config(),
        },
        _PAT_SERVER_PATH: {
            "path": _PAT_SERVER_PATH,
            "server_name": "GitHub PAT",
            "proxy_pass_url": _UPSTREAM,
            "egress_auth_mode": "pat",
            "egress_oauth": {"provider": "github", "scopes": []},
        },
    }


class _RecordingService:
    """EgressAuthService stand-in that records every call and its arguments."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def principals(
        self,
        name: str,
    ) -> list[tuple[str, str]]:
        """Return the ``(auth_method, user_id)`` of every recorded call to ``name``."""
        return [(kw["auth_method"], kw["user_id"]) for n, kw in self.calls if n == name]

    async def build_consent_url(self, **kwargs) -> str:
        self.calls.append(("build_consent_url", kwargs))
        return _AUTHORIZE_URL

    async def handle_callback(self, **kwargs) -> EgressConnection:
        self.calls.append(("handle_callback", kwargs))
        return EgressConnection(provider="github", server_path=_OAUTH_SERVER_PATH)

    async def discard_state(self, **kwargs) -> None:
        self.calls.append(("discard_state", kwargs))

    async def list_connections(self, **kwargs) -> list:
        self.calls.append(("list_connections", kwargs))
        return []

    async def disconnect(self, **kwargs) -> None:
        self.calls.append(("disconnect", kwargs))

    async def get_pat_status(self, **kwargs) -> None:
        self.calls.append(("get_pat_status", kwargs))

    async def delete_pat(self, **kwargs) -> None:
        self.calls.append(("delete_pat", kwargs))


class _RecordingStore(SecretStoreBase):
    """In-memory SecretStore that records the principal of every token write."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, str]] = []
        self._data: dict[tuple, object] = {}

    async def put_token(self, auth_method, user_id, provider, server_path, token, *, purpose):
        self.writes.append((auth_method, user_id))
        self._data[(purpose, auth_method, user_id, provider, server_path)] = token

    async def get_token(self, auth_method, user_id, provider, server_path, *, purpose):
        return self._data.get((purpose, auth_method, user_id, provider, server_path))

    async def delete_token(self, auth_method, user_id, provider, server_path, *, purpose):
        self._data.pop((purpose, auth_method, user_id, provider, server_path), None)

    async def list_for_user(self, auth_method, user_id):
        return []

    def reset(self) -> None:
        self.writes.clear()
        self._data.clear()


class _EgressHarness:
    """The real egress-auth router with a recording service and store behind it."""

    def __init__(
        self,
        client: TestClient,
        holder: dict,
        svc: _RecordingService,
        store: _RecordingStore,
    ) -> None:
        self.client = client
        self._holder = holder
        self.svc = svc
        self.store = store

    def act_as(
        self,
        ctx: dict,
    ) -> None:
        """Make every following request resolve to ``ctx`` and clear the records."""
        self._holder["ctx"] = ctx
        self.svc.calls.clear()
        self.store.reset()


async def _fake_post_token(
    cfg,
    data,
    headers,
) -> dict:
    """Provider token endpoint stub: every code exchange succeeds."""
    return {
        "access_token": "gho_upstream_token",
        "refresh_token": "rt",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "repo",
    }


def _mount_egress_routes(
    monkeypatch: pytest.MonkeyPatch,
    holder: dict,
    svc: object,
) -> TestClient:
    """Mount the egress-auth router with every request resolving to ``holder['ctx']``.

    The callback resolves the session itself by calling ``nginx_proxied_auth``
    directly, so the module attribute is replaced too, not only the dependency.
    """
    servers = _servers()

    async def _get_server_info(path, include_credentials=False):
        return deepcopy(servers.get(path))

    async def _session(request, session=None):
        return dict(holder["ctx"])

    original_auth_dependency = routes.nginx_proxied_auth
    monkeypatch.setattr(routes.settings, "egress_auth_enabled", True)
    monkeypatch.setattr(routes.server_service, "get_server_info", _get_server_info)
    monkeypatch.setattr(
        routes.server_service, "get_all_servers", AsyncMock(return_value=deepcopy(servers))
    )
    monkeypatch.setattr(routes, "get_egress_auth_service", lambda: svc)
    monkeypatch.setattr(routes, "nginx_proxied_auth", _session)
    monkeypatch.setattr(oauth_engine, "_post_token", _fake_post_token)

    app = FastAPI()
    app.include_router(routes.router, prefix="/api")
    app.dependency_overrides[original_auth_dependency] = lambda: dict(holder["ctx"])
    app.dependency_overrides[routes.verify_csrf_token_flexible] = lambda: None
    return TestClient(app, cookies={routes.settings.session_cookie_name: _SESSION_COOKIE})


@pytest.fixture(autouse=True)
def _reset_cipher():
    state_codec.reset_cipher_for_tests()
    yield
    state_codec.reset_cipher_for_tests()


@pytest.fixture
def egress_routes(monkeypatch) -> _EgressHarness:
    """Egress-auth router over a recording service and a recording secret store."""
    holder: dict = {"ctx": {}}
    svc = _RecordingService()
    store = _RecordingStore()
    monkeypatch.setattr(routes, "get_secret_store", lambda: store)
    client = _mount_egress_routes(monkeypatch, holder, svc)
    return _EgressHarness(client, holder, svc, store)


@pytest.fixture
def consent_routes(monkeypatch) -> _EgressHarness:
    """Egress-auth router over the real EgressAuthService and an in-memory store."""
    holder: dict = {"ctx": {}}
    store = _RecordingStore()
    svc = EgressAuthService(secret_store=store, callback_base_url="https://gw.example")
    client = _mount_egress_routes(monkeypatch, holder, svc)
    return _EgressHarness(client, holder, _RecordingService(), store)


def _consent_state() -> str:
    """Encode a valid consent state for the oauth_user server."""
    return state_codec.encode_state(
        OAuthState(
            user_id="state-user",
            auth_method=_CANONICAL_PER_USER_METHOD,
            provider="github",
            server_path=_OAUTH_SERVER_PATH,
            nonce="n1",
            issued_at=datetime.now(UTC).isoformat(),
        )
    )


def _state_from(
    authorize_url: str,
) -> str:
    return parse_qs(urlparse(authorize_url).query)["state"][0]


_KEYCLOAK_BEARER = {"auth_method": "keycloak", "egress_user": "sub-1", "username": "alice"}
_SESSION_COOKIE_METHOD = {"auth_method": "session_cookie", "egress_user": "sub-1"}
_USERNAME_ONLY = {"auth_method": "oauth2", "egress_user": "", "username": "alice"}
_STATIC_KEY = {"auth_method": "network-trusted", "egress_user": "ci-bot", "username": "ci-bot"}
_FEDERATION = {"auth_method": "federation-static", "username": "peer"}
_NO_IDENTITY = {"auth_method": "oauth2", "egress_user": "", "username": ""}
# A present identity of the wrong type refuses; it never falls through to the
# next field, which would key the vault on a different identity.
_NON_STR_IDENTITY = {"auth_method": "oauth2", "egress_user": 7, "username": "alice"}
_NON_STR_FALLBACK = {"auth_method": "oauth2", "egress_user": "", "username": ["alice"]}


def _pin_contexts(**extra):
    """Return a decorator applying the caller contexts every route property must pin.

    Args:
        **extra: Values for the test's other ``@given`` arguments in each example.
    """

    def _apply(test):
        for ctx in (
            _KEYCLOAK_BEARER,
            _SESSION_COOKIE_METHOD,
            _USERNAME_ONLY,
            _STATIC_KEY,
            _FEDERATION,
            _NO_IDENTITY,
            _NON_STR_IDENTITY,
            _NON_STR_FALLBACK,
        ):
            test = example(caller=ctx, **extra)(test)
        return test

    return _apply


@pytest.mark.unit
@_PURE_SETTINGS
@given(caller=_caller_contexts())
@_pin_contexts()
@example(caller={"auth_method": ["oauth2"], "egress_user": "sub-1"})
@example(caller={"egress_user": "sub-1", "username": "alice"})
def test_vault_principal_matches_the_reference_model(caller):
    """Property: ``vault_principal`` returns exactly the reference model's principal."""
    assert vault_principal(caller) == _model_principal(caller)


@pytest.mark.unit
@pytest.mark.parametrize(
    "caller",
    [
        pytest.param(_NON_STR_IDENTITY, id="egress-user-int"),
        pytest.param({**_NON_STR_IDENTITY, "egress_user": ["sub-1"]}, id="egress-user-list"),
        pytest.param({**_NON_STR_IDENTITY, "egress_user": False}, id="egress-user-bool"),
        pytest.param(_NON_STR_FALLBACK, id="fallback-username-list"),
        pytest.param({**_NON_STR_FALLBACK, "egress_user": None, "username": 7}, id="fallback-int"),
    ],
)
def test_wrong_type_identity_refuses_instead_of_falling_through(caller):
    """A present non-string ``egress_user`` (or fallback ``username``) yields no principal."""
    assert vault_principal(caller) is None


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_initiate_binds_the_consent_to_the_model_principal(egress_routes, caller, is_admin):
    """Property: initiate passes the model principal to the service, or refuses 403."""
    ctx = _caller_context(caller, is_admin)
    egress_routes.act_as(ctx)
    expected = _model_principal(ctx)

    r = egress_routes.client.post(
        "/api/egress-auth/initiate", json={"server_path": _OAUTH_SERVER_PATH}
    )

    if expected is None:
        assert r.status_code == 403, r.text
        assert egress_routes.svc.calls == []
    else:
        assert r.status_code == 200, r.text
        assert egress_routes.svc.principals("build_consent_url") == [expected]


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_callback_compares_the_model_principal_of_the_live_session(egress_routes, caller, is_admin):
    """Property: the callback's account-swap principal is the model principal.

    With no principal the callback answers with the sign-in page, burns the
    state, and never calls ``handle_callback``.
    """
    ctx = _caller_context(caller, is_admin)
    egress_routes.act_as(ctx)
    expected = _model_principal(ctx)

    state_blob = _consent_state()
    r = egress_routes.client.get(
        "/api/oauth2/egress/callback", params={"code": "c", "state": state_blob}
    )

    if expected is None:
        assert r.status_code == 401, r.text
        assert "not signed in" in r.text
        assert egress_routes.svc.calls == [("discard_state", {"state_blob": state_blob})]
    else:
        assert r.status_code == 200, r.text
        [(name, kwargs)] = egress_routes.svc.calls
        assert name == "handle_callback"
        assert (kwargs["current_auth_method"], kwargs["current_user_id"]) == expected


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_list_connections_reads_the_model_principal(egress_routes, caller, is_admin):
    """Property: the connection list reads the model principal, or returns [] unread."""
    ctx = _caller_context(caller, is_admin)
    egress_routes.act_as(ctx)
    expected = _model_principal(ctx)

    r = egress_routes.client.get("/api/egress-auth/connections")

    assert r.status_code == 200, r.text
    if expected is None:
        assert r.json() == []
        assert egress_routes.svc.calls == []
    else:
        assert egress_routes.svc.principals("list_connections") == [expected]


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_disconnect_deletes_only_the_model_principal(egress_routes, caller, is_admin):
    """Property: disconnect deletes the model principal's entry, or deletes nothing."""
    ctx = _caller_context(caller, is_admin)
    egress_routes.act_as(ctx)
    expected = _model_principal(ctx)

    r = egress_routes.client.request(
        "DELETE", f"/api/egress-auth/connections/github{_OAUTH_SERVER_PATH}"
    )

    assert r.status_code == 200, r.text
    assert r.json() == {"status": "revoked"}
    if expected is None:
        assert egress_routes.svc.calls == []
    else:
        assert egress_routes.svc.principals("disconnect") == [expected]


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_available_servers_are_offered_iff_the_caller_has_a_principal(
    egress_routes, caller, is_admin
):
    """Property: Connected Accounts offers servers exactly to callers the initiate accepts."""
    ctx = _caller_context(caller, is_admin)
    egress_routes.act_as(ctx)
    expected = _model_principal(ctx)

    r = egress_routes.client.get("/api/egress-auth/available-servers")

    assert r.status_code == 200, r.text
    offered = [s["server_path"] for s in r.json()]
    assert offered == ([] if expected is None else [_OAUTH_SERVER_PATH, _PAT_SERVER_PATH])


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_pat_self_submit_stores_under_the_model_principal(egress_routes, caller, is_admin):
    """Property: a self-submitted PAT is written at the model principal, or refused 403."""
    ctx = _caller_context(caller, is_admin)
    egress_routes.act_as(ctx)
    expected = _model_principal(ctx)

    r = egress_routes.client.put(
        f"/api/servers{_PAT_SERVER_PATH}/egress-pat",
        json={"secret": "ghp_secret", "ttl_value": 1, "ttl_unit": "days"},
    )

    if expected is None:
        assert r.status_code == 403, r.text
        assert egress_routes.store.writes == []
    else:
        assert r.status_code == 200, r.text
        assert egress_routes.store.writes == [expected]


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(
    caller=_caller_contexts(),
    method=st.sampled_from(["GET", "DELETE"]),
    is_admin=st.booleans(),
)
@_pin_contexts(method="GET", is_admin=True)
@_pin_contexts(method="GET", is_admin=False)
@_pin_contexts(method="DELETE", is_admin=True)
@_pin_contexts(method="DELETE", is_admin=False)
def test_pat_self_status_and_delete_use_the_model_principal(
    egress_routes, caller, method, is_admin
):
    """Property: PAT status and delete for self address the model principal, or refuse 403."""
    ctx = _caller_context(caller, is_admin)
    egress_routes.act_as(ctx)
    expected = _model_principal(ctx)
    service_call = {"GET": "get_pat_status", "DELETE": "delete_pat"}[method]

    r = egress_routes.client.request(method, f"/api/servers{_PAT_SERVER_PATH}/egress-pat")

    if expected is None:
        assert r.status_code == 403, r.text
        assert egress_routes.svc.calls == []
    else:
        assert r.status_code == 200, r.text
        assert egress_routes.svc.principals(service_call) == [expected]


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(
    target_method=st.one_of(
        st.sampled_from(sorted(_PER_USER_INPUT_METHODS)),
        st.sampled_from(_NON_PER_USER_METHODS),
        st.text(max_size=12),
    ),
    target_sub=_user_ids,
)
@example(target_method="jwt", target_sub="bob")
@example(target_method="keycloak", target_sub="bob")
@example(target_method="network-trusted", target_sub="bob")
@example(target_method="", target_sub="bob")
def test_pat_admin_on_behalf_canonicalizes_the_target_method(
    egress_routes, target_method, target_sub
):
    """Property: an admin's on-behalf PAT lands in the canonical bucket the target vends from.

    The target is named by the body, not by the caller's context, so the stored
    principal is the model principal of ``(target_method, target_sub)``. An
    omitted method is a 400; a non-per-user one a 403.
    """
    egress_routes.act_as(_caller_context({"auth_method": "oauth2", "username": "admin"}, True))
    expected = _model_principal({"auth_method": target_method, "egress_user": target_sub})

    r = egress_routes.client.put(
        f"/api/servers{_PAT_SERVER_PATH}/egress-pat",
        json={
            "secret": "ghp_secret",
            "ttl_value": 1,
            "ttl_unit": "days",
            "sub": target_sub,
            "auth_method": target_method,
        },
    )

    if not target_method:
        assert r.status_code == 400, r.text
        assert egress_routes.store.writes == []
    elif expected is None:
        assert r.status_code == 403, r.text
        assert egress_routes.store.writes == []
    else:
        assert r.status_code == 200, r.text
        assert egress_routes.store.writes == [expected]


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_initiate_then_callback_as_the_same_caller_vaults_at_the_model_principal(
    consent_routes, caller, is_admin
):
    """Property: one caller's consent round trip writes exactly the model principal's bucket.

    Runs the real EgressAuthService, so the account-swap guard compares the
    principal bound into the state at initiate with the one the callback
    derives. A caller without a principal is refused at initiate and nothing
    is written.
    """
    ctx = _caller_context(caller, is_admin)
    consent_routes.act_as(ctx)
    expected = _model_principal(ctx)

    initiate = consent_routes.client.post(
        "/api/egress-auth/initiate", json={"server_path": _OAUTH_SERVER_PATH}
    )
    if expected is None:
        assert initiate.status_code == 403, initiate.text
        assert consent_routes.store.writes == []
        return
    assert initiate.status_code == 200, initiate.text
    callback = consent_routes.client.get(
        "/api/oauth2/egress/callback",
        params={"code": "provider-code", "state": _state_from(initiate.json()["authorize_url"])},
    )

    assert callback.status_code == 200, callback.text
    assert consent_routes.store.writes == [expected]


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(
    initiate_method=st.sampled_from(sorted(_PER_USER_INPUT_METHODS)),
    callback_method=st.sampled_from(sorted(_PER_USER_INPUT_METHODS)),
    user_id=_user_ids,
    is_admin=st.booleans(),
)
@example(initiate_method="keycloak", callback_method="oauth2", user_id="sub-1", is_admin=False)
@example(initiate_method="oauth2", callback_method="session_cookie", user_id="sub-1", is_admin=True)
def test_consent_started_under_any_per_user_method_completes_in_the_browser(
    consent_routes, initiate_method, callback_method, user_id, is_admin
):
    """Property: the account-swap guard accepts the same human across per-user methods.

    A consent started by an IdP bearer (raw method, e.g. ``keycloak``) and
    completed in a browser session (``oauth2``) is one principal: the write
    lands in the canonical bucket the vend reads.
    """
    initiator = _caller_context({"auth_method": initiate_method, "egress_user": user_id}, is_admin)
    consent_routes.act_as(initiator)
    initiate = consent_routes.client.post(
        "/api/egress-auth/initiate", json={"server_path": _OAUTH_SERVER_PATH}
    )
    assert initiate.status_code == 200, initiate.text

    consent_routes.act_as(
        _caller_context({"auth_method": callback_method, "egress_user": user_id}, is_admin)
    )
    callback = consent_routes.client.get(
        "/api/oauth2/egress/callback",
        params={"code": "provider-code", "state": _state_from(initiate.json()["authorize_url"])},
    )

    assert callback.status_code == 200, callback.text
    assert consent_routes.store.writes == [(_CANONICAL_PER_USER_METHOD, user_id)]


class _DesignationHarness:
    """The real server router's PUT /oauth-discovery over a mocked server service."""

    def __init__(
        self,
        client: TestClient,
        holder: dict,
        server_service: MagicMock,
    ) -> None:
        self.client = client
        self._holder = holder
        self.server_service = server_service

    def act_as(
        self,
        ctx: dict,
    ) -> None:
        self._holder["ctx"] = ctx
        self.server_service.update_server.reset_mock()

    def written_designation(self) -> tuple[str, str]:
        record = self.server_service.update_server.await_args.args[1]["oauth_discovery"]
        return record["auth_method"], record["user_id"]


@pytest.fixture
def designation_route(monkeypatch) -> _DesignationHarness:
    """PUT /api/servers/tableau/oauth-discovery on a server with no designation yet.

    The discovery provider config is already stored (so a blank client_secret
    keeps it); only the designation is missing, so the caller is the one
    recorded. The route is owner-or-admin, so the server is registered by the
    caller's ``username`` and a non-admin caller passes as its owner.
    """
    holder: dict = {"ctx": {}}
    record = {
        "server_name": "tableau",
        "path": _DISCOVERY_SERVER_PATH,
        "registered_by": "owner-user",
        "deployment": "remote",
        "proxy_pass_url": "https://upstream.example.com/mcp",
        "oauth_discovery": {
            "enabled": True,
            "oauth": {
                "provider": "custom",
                "client_id": "disc-client",
                "client_secret_encrypted": "stored-ciphertext",
                "custom_authorize_url": "https://idp.example.com/authorize",
                "custom_token_url": "https://idp.example.com/token",
            },
        },
    }

    async def _get_server_info(path, include_credentials=False):
        return {**deepcopy(record), "registered_by": holder["ctx"].get("username")}

    service = MagicMock()
    service.get_server_info = AsyncMock(side_effect=_get_server_info)
    service.update_server = AsyncMock(return_value=True)
    monkeypatch.setattr(server_routes, "server_service", service)
    monkeypatch.setattr(server_routes.settings, "egress_auth_enabled", True)

    app = FastAPI()
    app.include_router(server_routes.router, prefix="/api")
    app.dependency_overrides[server_routes.nginx_proxied_auth] = lambda: dict(holder["ctx"])
    app.dependency_overrides[server_routes.verify_csrf_token_flexible] = lambda: None
    return _DesignationHarness(TestClient(app), holder, service)


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_discovery_designation_records_the_model_principal(designation_route, caller, is_admin):
    """Property: PUT /oauth-discovery designates the model principal, or refuses 403."""
    ctx = _caller_context(caller, is_admin)
    designation_route.act_as(ctx)
    expected = _model_principal(ctx)

    r = designation_route.client.put(
        f"/api/servers{_DISCOVERY_SERVER_PATH}/oauth-discovery",
        json={
            "provider": "custom",
            "client_id": "disc-client",
            "scopes": ["read"],
            "custom_authorize_url": "https://idp.example.com/authorize",
            "custom_token_url": "https://idp.example.com/token",
        },
    )

    if expected is None:
        assert r.status_code == 403, r.text
        designation_route.server_service.update_server.assert_not_awaited()
    else:
        assert r.status_code == 200, r.text
        assert designation_route.written_designation() == expected


class _FacadeHarness:
    """The real /oauth2/egress/connect route over a recording service."""

    def __init__(
        self,
        client: TestClient,
        holder: dict,
        svc: _RecordingService,
    ) -> None:
        self.client = client
        self._holder = holder
        self.svc = svc

    def act_as(
        self,
        ctx: dict,
        designation: tuple[str, str] | None = None,
    ) -> None:
        """Set the caller and the discovery designation stored on the server."""
        self._holder["ctx"] = ctx
        self._holder["designation"] = designation
        self.svc.calls.clear()


@pytest.fixture
def facade_route(monkeypatch) -> _FacadeHarness:
    """GET /oauth2/egress/connect with the session resolving to ``holder['ctx']``.

    Discovery consent is owner-or-admin, so the discovery server is registered
    by the caller's ``username`` and a non-admin caller passes as its owner.
    """
    holder: dict = {"ctx": {}, "designation": None}
    svc = _RecordingService()

    async def _get_server_info(path, include_credentials=False):
        if path == _OAUTH_SERVER_PATH:
            return _servers()[_OAUTH_SERVER_PATH]
        designation = holder["designation"] or ("", "")
        return {
            "path": _DISCOVERY_SERVER_PATH,
            "registered_by": holder["ctx"].get("username"),
            "oauth_discovery": {
                "enabled": True,
                "oauth": _encrypted_oauth_config(),
                "auth_method": designation[0],
                "user_id": designation[1],
                "designated_by": "owner-user",
            },
        }

    async def _session(request, session=None):
        return dict(holder["ctx"])

    monkeypatch.setattr(facade.settings, "egress_auth_enabled", True)
    monkeypatch.setattr(facade.settings, "registry_url", _REGISTRY_URL)
    monkeypatch.setattr(facade.server_service, "get_server_info", _get_server_info)
    monkeypatch.setattr(facade, "nginx_proxied_auth", _session)
    monkeypatch.setattr(facade, "get_egress_auth_service", lambda: svc)

    app = FastAPI()
    app.include_router(facade.router)
    return _FacadeHarness(TestClient(app, follow_redirects=False), holder, svc)


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(caller=_caller_contexts(), is_admin=st.booleans())
@_pin_contexts(is_admin=True)
@_pin_contexts(is_admin=False)
def test_connect_binds_the_consent_to_the_model_principal(facade_route, caller, is_admin):
    """Property: /oauth2/egress/connect starts consent for the model principal, or refuses 403."""
    ctx = _caller_context(caller, is_admin)
    facade_route.act_as(ctx)
    expected = _model_principal(ctx)

    r = facade_route.client.get("/oauth2/egress/connect", params={"server": _OAUTH_SERVER_PATH})

    if expected is None:
        assert r.status_code == 403, r.text
        assert facade_route.svc.calls == []
    else:
        assert r.status_code == 302, r.text
        assert facade_route.svc.principals("build_consent_url") == [expected]


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(
    caller=_caller_contexts(),
    designee=st.one_of(st.sampled_from(_KNOWN_IDS), _user_ids),
    is_admin=st.booleans(),
)
@_pin_contexts(designee="sub-1", is_admin=True)
@_pin_contexts(designee="sub-1", is_admin=False)
@example(caller=_USERNAME_ONLY, designee="alice", is_admin=False)
def test_discovery_connect_admits_exactly_the_designated_principal(
    facade_route, caller, designee, is_admin
):
    """Property: discovery consent proceeds iff the caller's model principal is the designee.

    The designation is stored canonical, as PUT /oauth-discovery writes it, so a
    designee who connects through an IdP bearer (raw ``keycloak``) is still the
    designee. Anyone else, admin or not, is refused before consent starts.
    """
    designation = (_CANONICAL_PER_USER_METHOD, designee)
    ctx = _caller_context(caller, is_admin)
    facade_route.act_as(ctx, designation)
    expected = _model_principal(ctx)

    r = facade_route.client.get(
        "/oauth2/egress/connect",
        params={"server": _DISCOVERY_SERVER_PATH, "purpose": "discovery"},
    )

    if expected == designation:
        assert r.status_code == 302, r.text
        assert facade_route.svc.principals("build_consent_url") == [designation]
    else:
        assert r.status_code == 403, r.text
        assert facade_route.svc.calls == []


class _VendRepo:
    def __init__(self, server: dict) -> None:
        self._server = server

    async def get(self, path):
        return self._server if path == _OAUTH_SERVER_PATH else None


class _VendService:
    """Records every vault read the vend makes."""

    def __init__(self) -> None:
        self.reads: list[dict] = []

    async def get_valid_token(self, **kwargs):
        self.reads.append(kwargs)
        return "at_vended"

    async def get_pat(self, **kwargs):
        self.reads.append(kwargs)
        return "ghp_vended"


@pytest.mark.unit
@_ROUTE_SETTINGS
@given(
    egress_user=st.sampled_from([_ABSENT, None, ""]),
    username=_user_ids,
    egress_mode=st.sampled_from(["oauth_user", "pat"]),
)
def test_vend_never_falls_back_to_the_username(monkeypatch, egress_user, username, egress_mode):
    """Property: a per-user token with no ``egress_user`` claim never reads the vault.

    The claims still carry the login name in ``sub`` and ``username``; the vend
    must answer consent_required rather than key on either.
    """
    claims = {
        "sub": username,
        "username": username,
        "server": _OAUTH_SERVER_PATH.strip("/"),
        "version_id": "",
        "virtual_backend": False,
        "auth_method": _CANONICAL_PER_USER_METHOD,
        "upstream_url": _UPSTREAM,
    }
    if egress_user is not _ABSENT:
        claims["egress_user"] = egress_user
    server = {
        "egress_auth_mode": egress_mode,
        "egress_oauth": {"provider": "github", "client_id": "Iv1.x"},
        "proxy_pass_url": _UPSTREAM,
        "versions": [],
    }
    svc = _VendService()
    repo = _VendRepo(server)
    with monkeypatch.context() as patch:
        patch.setattr(routes.settings, "egress_auth_enabled", True)
        patch.setattr(routes, "verify_mcp_proxy_token", lambda token: claims)
        patch.setattr(routes, "get_server_repository", lambda: repo)
        patch.setattr("registry.repositories.factory.get_server_repository", lambda: repo)
        patch.setattr(routes, "get_egress_auth_service", lambda: svc)
        app = FastAPI()
        app.include_router(routes.router)
        app.dependency_overrides[routes.validate_internal_auth] = lambda: "auth-server"
        r = TestClient(app).post(
            "/internal/egress-token",
            json={"server_path": _OAUTH_SERVER_PATH},
            headers={"X-Internal-Token": "proxy-token"},
        )

    assert r.status_code == 200, r.text
    assert r.json()["consent_required"] is True
    assert r.json()["access_token"] is None
    assert svc.reads == []
