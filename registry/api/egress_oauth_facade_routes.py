"""OAuth Authorization-Server facade routes (IDE-driven egress consent).

These routes make the gateway look like an OAuth authorization server for the
egress (third-party) consent, so an MCP client (Claude Code) can discover and
drive the GitHub/Google/... login the same way it drives the gateway's own
ingress login. The third-party token stays in the vault; the client receives a
gateway-minted bearer.

Endpoints (all on the registry, mounted WITHOUT the /api prefix so the
discovery URLs are clean and match the WWW-Authenticate challenge):

  GET  /.well-known/oauth-protected-resource/{server_path}  -> per-server PRM
  GET  /.well-known/oauth-authorization-server/oauth2/egress -> AS metadata
  POST /oauth2/egress/register                               -> RFC 7591 DCR
  GET  /oauth2/egress/authorize                              -> leg-1 start
  POST /oauth2/egress/token                                  -> code -> bearer

The provider leg (leg 2) reuses the existing ``/oauth2/egress/callback`` in
``egress_auth_routes.py``; this module only adds the client-facing AS surface.

SECURITY MODEL
--------------
- ``/authorize`` REQUIRES a live gateway session; the captured identity is the
  SESSION principal, never anything the client asserts. This is what binds the
  third-party consent to a real user and prevents an unauthenticated caller from
  minting a gateway bearer. When no session exists (first IDE use), it redirects
  the browser through the gateway's Keycloak login and returns to ``/authorize``
  -- the "unified facade" behavior that chains ingress identity then the egress
  provider, so the IDE sees ONE authorization server for the server.
- The leg-1 authorization code is single-use, short-TTL, and PKCE-bound.
- ``/token`` does NOT sign anything: it delegates to the auth-server
  ``/internal/tokens`` mint (the sole JWT-signing authority), passing the
  captured identity's existing scopes/groups (no privilege escalation).
- Pending-authorize + auth-code correlation state lives in the Mongo operational
  repo (no credentials), so the flow works across registry replicas.
"""

import logging
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pymongo.errors import DuplicateKeyError

from registry.auth.dependencies import nginx_proxied_auth
from registry.auth.internal import generate_internal_token
from registry.core.config import settings
from registry.egress_auth import as_facade
from registry.egress_auth.factory import get_egress_auth_service, get_facade_operational_repo
from registry.egress_auth.service import is_per_user_auth_method
from registry.services.server_service import server_service

logger = logging.getLogger(__name__)

router = APIRouter()

# TTL for a pending-authorize record -- only needs to outlive the provider
# round-trip (the user completing the GitHub consent in a browser).
_PENDING_TTL_SECONDS: int = 600


def _registry_base_url() -> str:
    return settings.registry_url.rstrip("/")


def _feature_on() -> bool:
    return bool(settings.egress_auth_enabled)


# --------------------------------------------------------------------------- #
# Discovery documents
# --------------------------------------------------------------------------- #


@router.get("/.well-known/oauth-protected-resource/{server_path:path}")
async def egress_protected_resource_metadata(server_path: str) -> JSONResponse:
    """Per-server RFC 9728 PRM. Advertises the gateway egress AS as the
    authorization server for this server's third-party resource."""
    if not _feature_on():
        return JSONResponse({"error": "not_found"}, status_code=404)
    server = await server_service.get_server_info(
        as_facade._normalize_server_path(server_path), include_credentials=False
    )
    scopes = as_facade.server_advertised_scopes(server) if server else []
    doc = as_facade.build_protected_resource_metadata(
        registry_url=_registry_base_url(),
        server_path=server_path,
        scopes_supported=scopes,
    )
    return JSONResponse(doc, headers={"Cache-Control": "public, max-age=3600"})


@router.get("/.well-known/oauth-authorization-server/oauth2/egress")
async def egress_authorization_server_metadata() -> JSONResponse:
    """RFC 8414 AS metadata for the egress facade (server-independent)."""
    if not _feature_on():
        return JSONResponse({"error": "not_found"}, status_code=404)
    doc = as_facade.build_authorization_server_metadata(_registry_base_url())
    return JSONResponse(doc, headers={"Cache-Control": "public, max-age=3600"})


# --------------------------------------------------------------------------- #
# Dynamic Client Registration (RFC 7591)
# --------------------------------------------------------------------------- #


@router.post("/oauth2/egress/register")
async def egress_register(request: Request) -> JSONResponse:
    """RFC 7591 DCR: issue a public client_id for a loopback-redirect IDE client."""
    if not _feature_on():
        return JSONResponse({"error": "not_found"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": "body must be JSON"},
            status_code=400,
        )
    try:
        info = as_facade.register_client(body if isinstance(body, dict) else {})
    except as_facade.RegistrationError as exc:
        return JSONResponse(
            {"error": "invalid_redirect_uri", "error_description": str(exc)},
            status_code=400,
        )
    return JSONResponse(info, status_code=201)


# --------------------------------------------------------------------------- #
# /authorize -- leg 1 start (requires a live gateway session)
# --------------------------------------------------------------------------- #


def _authorize_error_redirect(redirect_uri: str, client_state: str, error: str, desc: str):
    """Bounce an OAuth error back to the client per RFC 6749 §4.1.2.1."""
    params = {"error": error, "error_description": desc}
    if client_state:
        params["state"] = client_state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(params)}", status_code=302)


async def _optional_session(request: Request) -> dict | None:
    """Read the gateway session, returning None instead of raising when there is
    no valid session (so /authorize can bounce to login).

    ``nginx_proxied_auth`` declares ``session`` as a FastAPI ``Cookie(...)``
    parameter that is only populated by dependency injection. Since we call it
    directly (not as a route dependency), we must extract the session cookie off
    the request and pass it explicitly -- otherwise it always sees ``session=None``
    and reports "no session" even when the cookie is present (the login-loop bug)."""
    session = request.cookies.get(settings.session_cookie_name)
    try:
        return await nginx_proxied_auth(request, session=session)
    except Exception:
        return None


def _login_bootstrap_redirect(request: Request) -> RedirectResponse:
    """302 the browser through the gateway's Keycloak login, returning to this
    exact /authorize URL (with its OAuth params) once a session is established.

    Uses the auth-server's validated same-origin redirect_uri round-trip. The
    return URL is the request's own path+query on the gateway origin."""
    return_to = request.url.path
    if request.url.query:
        return_to = f"{return_to}?{request.url.query}"
    login = (
        f"{_registry_base_url()}/oauth2/login/keycloak?"
        + urlencode({"redirect_uri": return_to})
    )
    logger.info("egress facade /authorize: no session -> bounce to gateway login")
    return RedirectResponse(login, status_code=302)


@router.get("/oauth2/egress/authorize")
async def egress_authorize(
    request: Request,
    response_type: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    scope: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "",
    resource: str = "",
) -> object:
    """Start the consent (unified facade leg 1).

    If the browser has no gateway session, bounce through Keycloak login first
    (and return here). Once authenticated, capture the SESSION identity, then
    open the real provider (GitHub) OAuth leg; the browser is redirected to the
    provider authorize URL. Leg-1 (client) params + the captured identity are
    persisted (Mongo, cross-replica) under a correlation id threaded as the
    provider-leg ``session_id`` so the provider callback can resume and mint the
    client's code.
    """
    if not _feature_on():
        return JSONResponse({"error": "not_found"}, status_code=404)

    # Validate the client request shape early; redirect_uri must be loopback so
    # we never bounce an error/code to an attacker host.
    if not redirect_uri or not as_facade._is_loopback_redirect(redirect_uri):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "missing/invalid redirect_uri"},
            status_code=400,
        )
    if response_type != "code":
        return _authorize_error_redirect(
            redirect_uri, state, "unsupported_response_type", "only code is supported"
        )
    if code_challenge_method != "S256" or not code_challenge:
        return _authorize_error_redirect(
            redirect_uri, state, "invalid_request", "S256 PKCE required"
        )

    # The server to connect is identified by the resource (PRM) URL; map it back
    # to a server path. Fall back to a ?server query if a client passes it.
    server_path = _server_path_from_resource(resource) or request.query_params.get("server", "")
    if not server_path:
        return _authorize_error_redirect(
            redirect_uri, state, "invalid_request", "missing resource/server"
        )
    server_path = as_facade._normalize_server_path(server_path)

    server = await server_service.get_server_info(server_path, include_credentials=True)
    if not as_facade.is_server_egress_configured(server):
        return _authorize_error_redirect(
            redirect_uri, state, "invalid_request", "server has no per-user egress auth"
        )

    # Session bootstrap: no gateway session -> log in via Keycloak, return here.
    user_context = await _optional_session(request)
    if user_context is None:
        return _login_bootstrap_redirect(request)

    auth_method = user_context.get("auth_method") or ""
    if not is_per_user_auth_method(auth_method):
        return _authorize_error_redirect(
            redirect_uri, state, "access_denied", "this caller cannot connect a per-user account"
        )

    # Remember leg-1 params + the captured SESSION identity, keyed by a
    # correlation id threaded as the provider-leg session_id. Persisted in Mongo
    # so the provider callback (possibly on another replica) can resume.
    ctx = as_facade.ClientAuthzContext(
        client_id=client_id,
        redirect_uri=redirect_uri,
        client_state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        server_path=server_path,
        resource=resource,
    )
    identity = as_facade.CapturedIdentity(
        user_id=user_context.get("username") or "",
        auth_method=auth_method,
        groups=list(user_context.get("groups") or []),
        scopes=list(user_context.get("scopes") or []),
        provider=server["egress_oauth"].get("provider") or "",
        server_path=server_path,
    )
    correlation_id = as_facade.new_correlation_id()
    await get_facade_operational_repo().put_pending(
        correlation_id,
        as_facade.serialize_pending(ctx, identity),
        _PENDING_TTL_SECONDS,
    )

    # Open the provider OAuth leg via the existing service. The provider state
    # binds (user_id, auth_method) and carries our correlation id in session_id.
    provider_authorize_url = get_egress_auth_service().build_consent_url(
        auth_method=auth_method,
        user_id=user_context.get("username") or "",
        client_id_audit=user_context.get("client_id") or "",
        session_id=_FACADE_SESSION_PREFIX + correlation_id,
        server_path=server_path,
        egress_oauth=server["egress_oauth"],
    )
    logger.info(
        "egress facade /authorize: user=%s server=%s -> provider consent (corr=%s)",
        user_context.get("username"),
        server_path,
        correlation_id,
    )
    return RedirectResponse(provider_authorize_url, status_code=302)


# --------------------------------------------------------------------------- #
# /token -- leg 1 finish (delegates minting to auth-server)
# --------------------------------------------------------------------------- #


@router.post("/oauth2/egress/token")
async def egress_token(request: Request) -> JSONResponse:
    """Redeem the single-use code (PKCE) and return a gateway-minted bearer.

    No signing here: the captured identity is sent to the auth-server
    ``/internal/tokens`` mint, which is the sole JWT-signing authority. The
    minted token carries the user's existing scopes/groups (no escalation) and
    is accepted by ingress ``/validate`` (self-signed issuer), so the client can
    immediately retry the tool call with it.
    """
    if not _feature_on():
        return JSONResponse({"error": "not_found"}, status_code=404)
    form = await request.form()
    grant_type = form.get("grant_type", "")
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    code_verifier = form.get("code_verifier", "")
    client_id = form.get("client_id", "")

    if grant_type != "authorization_code":
        return JSONResponse(
            {"error": "unsupported_grant_type"}, status_code=400
        )

    # Atomically consume the code (single-use + TTL enforced by the repo). A
    # missing/expired/already-used code yields None -> invalid_grant.
    payload = await get_facade_operational_repo().consume_code(str(code))
    if payload is None:
        logger.info("egress facade /token: unknown/expired/used code")
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "invalid authorization code"},
            status_code=400,
        )
    try:
        record = as_facade.deserialize_auth_code_record(payload)
        identity = as_facade.verify_auth_code_record(
            record,
            code_verifier=str(code_verifier),
            redirect_uri=str(redirect_uri),
            # Public clients MAY omit client_id; enforce the binding only when
            # present (RFC 6749 §4.1.3 / §3.2.1). PKCE is the primary anchor.
            client_id=str(client_id) or None,
        )
    except as_facade.AuthCodeError as exc:
        logger.info("egress facade /token: code verification failed: %s", exc)
        return JSONResponse(
            {"error": "invalid_grant", "error_description": str(exc)}, status_code=400
        )

    try:
        access_token, expires_in = await _mint_user_token(identity)
    except Exception as exc:
        logger.error("egress facade /token: mint delegation failed: %s", exc)
        return JSONResponse(
            {"error": "server_error", "error_description": "could not mint token"},
            status_code=500,
        )

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": " ".join(identity.scopes),
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def _mint_user_token(identity: as_facade.CapturedIdentity) -> tuple[str, int]:
    """Ask the auth-server to mint a self-signed user JWT for the captured identity.

    Reuses the existing ``/internal/tokens`` contract (the same path the
    registry's user-token-generation route uses), so the auth-server remains the
    single signing authority. Returns (access_token, expires_in_seconds).
    """
    internal_token = generate_internal_token(
        subject="registry-egress-facade",
        purpose="egress-consent-token",
    )
    auth_request = {
        "user_context": {
            "username": identity.user_id,
            "auth_method": identity.auth_method,
            "groups": identity.groups,
            "scopes": identity.scopes,
            "provider": identity.provider,
        },
        "requested_scopes": identity.scopes,
        "expires_in_hours": 8,
        "description": f"egress consent token for {identity.server_path}",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{settings.auth_server_url}/internal/tokens",
            json=auth_request,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {internal_token}",
            },
            timeout=10.0,
        )
    if resp.status_code != 200:
        raise RuntimeError(f"auth-server mint returned {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    return data["access_token"], int(data.get("expires_in") or 8 * 3600)


# --------------------------------------------------------------------------- #
# Provider-callback resumption (called from egress_auth_routes callback)
# --------------------------------------------------------------------------- #

# A correlation prefix that marks a provider-leg session_id as belonging to the
# facade flow (vs the web Connected-Accounts flow, which uses the real
# session_id). The callback inspects the decoded state's session_id for this.
_FACADE_SESSION_PREFIX: str = "facade:"

# Auth-code TTL (the client redeems immediately after the browser redirect).
_AUTH_CODE_TTL_SECONDS: int = as_facade.AUTH_CODE_TTL_SECONDS


def is_facade_session(session_id: str | None) -> bool:
    """True if a provider-leg state's session_id marks the IDE facade flow."""
    return bool(session_id) and session_id.startswith(_FACADE_SESSION_PREFIX)


async def issue_facade_code_redirect(
    state_session_id: str,
    callback_user_id: str | None = None,
    callback_auth_method: str | None = None,
):
    """Resume the facade flow after the provider token is vaulted.

    Called by the provider callback when ``is_facade_session`` is true. Takes the
    remembered leg-1 context + captured identity (single-use, from the Mongo
    operational repo), mints the single-use client auth-code (also persisted in
    the repo), and returns a RedirectResponse to the client's loopback
    redirect_uri with code+state. Returns None (caller falls back to the HTML
    page) if the correlation is unknown/expired.

    ``callback_user_id``/``callback_auth_method`` are the live-session principal
    observed at the callback (when a session cookie is present). If provided they
    MUST match the identity captured at /authorize -- a defense-in-depth
    account-swap guard mirroring EgressAuthService.handle_callback. A mismatch
    refuses the resume (returns None).
    """
    correlation_id = state_session_id[len(_FACADE_SESSION_PREFIX) :]
    repo = get_facade_operational_repo()
    blob = await repo.take_pending(correlation_id)  # single-use
    if blob is None:
        return None
    ctx, identity = as_facade.deserialize_pending(blob)

    if callback_user_id is not None and callback_user_id != identity.user_id:
        logger.warning("egress facade resume refused: callback user != captured user")
        return None
    if callback_auth_method is not None and callback_auth_method != identity.auth_method:
        logger.warning("egress facade resume refused: callback auth_method != captured")
        return None

    record_blob = as_facade.serialize_auth_code_record(
        as_facade.build_auth_code_record(ctx, identity)
    )
    # Mint the single-use code, retrying on the astronomically-rare collision so a
    # token_urlsafe(32) clash can never 500 the callback (kiro cold-review nit).
    code = ""
    for _ in range(3):
        candidate = as_facade.new_auth_code()
        try:
            await repo.store_code(candidate, record_blob, _AUTH_CODE_TTL_SECONDS)
            code = candidate
            break
        except DuplicateKeyError:
            logger.warning("egress facade: auth-code collision; retrying with a fresh code")
    if not code:
        logger.error("egress facade: could not mint a unique auth-code after retries")
        return None
    params = {"code": code}
    if ctx.client_state:
        params["state"] = ctx.client_state
    sep = "&" if "?" in ctx.redirect_uri else "?"
    return RedirectResponse(f"{ctx.redirect_uri}{sep}{urlencode(params)}", status_code=302)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _server_path_from_resource(resource: str) -> str:
    """Recover the server path from the OAuth ``resource`` parameter.

    Per RFC 8707, the client echoes the PRM document's ``resource`` field as the
    ``resource`` request param. That value is the MCP server identifier
    ``<registry>/<server>`` (``as_facade.build_resource_identifier``), e.g.
    ``https://gw.example.com/github`` -> ``/github``.

    Defensively also accepts the PRM *document* URL form
    (``<registry>/.well-known/oauth-protected-resource/<server>``) in case a
    client sends that instead -- strip the well-known prefix first, then fall
    back to stripping the registry base. Returns "" when neither matches.
    """
    if not resource:
        return ""
    # Form 1: PRM document URL -- strip the well-known prefix.
    marker = as_facade.PRM_WELLKNOWN_PREFIX
    idx = resource.find(marker)
    if idx != -1:
        return resource[idx + len(marker) :] or ""
    # Form 2: canonical resource identifier -- strip the registry base origin.
    base = settings.registry_url.rstrip("/")
    if resource.startswith(base):
        return resource[len(base) :] or ""
    # Last resort: if it looks like a bare path, accept it.
    return resource if resource.startswith("/") else ""
