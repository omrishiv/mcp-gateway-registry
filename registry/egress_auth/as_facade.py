"""OAuth Authorization-Server facade for IDE-driven egress consent.

WHY THIS EXISTS
---------------
When an MCP tool call needs a per-user third-party token (e.g. GitHub) that the
vault does not yet hold, the gateway must get the user to consent. The existing
web flow (Connected Accounts page) works but is not discoverable from the IDE.
MCP clients (Claude Code) DO know how to react to an RFC 9728 ``401 +
WWW-Authenticate`` challenge: they fetch the Protected Resource Metadata, find
its authorization server, run RFC 8414 discovery + RFC 7591 dynamic client
registration, and open the browser at the AS ``/authorize`` endpoint.

So the gateway advertises *itself* as the authorization server for the egress
resource and brokers the real third-party OAuth behind its own endpoints. The
third-party token never leaves the gateway vault; the client only ever receives
a gateway-minted bearer (minted by the auth-server -- see the route layer).

This module is the PURE-LOGIC core (discovery documents, DCR registration, and
the single-use authorization-code store). It performs NO JWT signing and NO
HTTP I/O: the route layer (``registry/api/egress_oauth_facade_routes.py``)
composes these helpers with the session, the provider OAuth leg
(``EgressAuthService``), and the auth-server mint delegation.

THE TWO OAUTH LEGS (do not conflate)
------------------------------------
1. CLIENT  <-> FACADE  : we are the AS. The client brings its own PKCE pair,
   ``state``, and loopback ``redirect_uri`` (RFC 8252). We hand back a one-time
   ``code`` and later a gateway bearer at ``/token``.
2. FACADE  <-> PROVIDER: the real GitHub/Google/... OAuth, driven by the
   existing ``EgressAuthService`` + ``oauth_engine`` + AEAD state codec. Its
   redirect target is the existing ``/oauth2/egress/callback``.

The facade ``/authorize`` opens leg 2 while remembering leg 1's parameters; the
provider callback completes leg 2 (token -> vault) and then issues leg 1's
``code``. ``/token`` redeems that ``code`` for the captured identity and asks
the auth-server to mint the user bearer.
"""

import json
import logging
import secrets
from dataclasses import asdict, dataclass, field

from registry.egress_auth.providers import resolve_provider

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Path segment under the registry that hosts the facade's OAuth endpoints. The
# discovery docs and the route registration MUST agree on these.
FACADE_BASE_PATH: str = "/oauth2/egress"
AUTHORIZE_PATH: str = f"{FACADE_BASE_PATH}/authorize"
TOKEN_PATH: str = f"{FACADE_BASE_PATH}/token"
REGISTER_PATH: str = f"{FACADE_BASE_PATH}/register"

# Per-server Protected Resource Metadata lives under the standard well-known
# prefix, suffixed with the server path so each egress-protected server gets a
# distinct ``resource`` (and thus a distinct AS-discovery entry point). RFC 9728
# permits a path-suffixed PRM; Claude Code follows the ``resource_metadata`` URL
# verbatim, so the suffix is opaque to it.
PRM_WELLKNOWN_PREFIX: str = "/.well-known/oauth-protected-resource"

# A single AS-metadata document serves every egress server (the AS endpoints are
# server-independent; the server is selected via the ``resource`` param on the
# authorize request). Issuer-suffixed per RFC 8414 §3.1.
AS_METADATA_WELLKNOWN_PATH: str = "/.well-known/oauth-authorization-server/oauth2/egress"
FACADE_ISSUER_SUFFIX: str = "/oauth2/egress"

# Authorization codes are single-use and very short-lived: the client redeems
# immediately after the browser redirect. Keep the TTL tight to bound the replay
# window even before single-use consumption.
AUTH_CODE_TTL_SECONDS: int = 120

# We mint a PKCE-capable, public-client AS (the IDE is a public client). DCR is
# open (no client authentication) but loopback-only redirect URIs are enforced.
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


# --------------------------------------------------------------------------- #
# Discovery documents (RFC 9728 / RFC 8414)
# --------------------------------------------------------------------------- #


def _normalize_server_path(server_path: str) -> str:
    """Return the canonical leading-slash server path (e.g. ``/github``)."""
    return server_path if server_path.startswith("/") else "/" + server_path


def strip_registry_path_prefix(
    server_path: str,
    registry_url: str,
) -> str:
    """Strip the registry's ROOT_PATH prefix from a captured ``server_path``.

    The PRM route captures ``{server_path:path}`` from the request URL. A client
    doing ORIGIN-ROOT RFC 9728 discovery requests
    ``/.well-known/oauth-protected-resource/<root_path>/<server>`` (path mode,
    e.g. ``registry/github``), so the captured value carries the ROOT_PATH
    prefix. Building ``resource = {registry_url}{server_path}`` would then DOUBLE
    the prefix (``…/registry`` + ``/registry/github`` ->
    ``…/registry/registry/github``), which the MCP client rejects as a resource
    mismatch.

    The registry's ROOT_PATH equals the path component of ``registry_url``
    (``/registry`` in path mode, empty in subdomain mode). Strip exactly one
    leading copy of it so both discovery forms (origin-root and the
    ``/registry``-prefixed WWW-Authenticate pointer form) yield the SAME
    canonical ``<root_path>/<server>`` resource.
    """
    from urllib.parse import urlparse

    root_path = urlparse(registry_url).path.strip("/")
    if not root_path:
        return server_path
    candidate = server_path.strip("/")
    prefix = root_path + "/"
    if candidate == root_path:
        return ""
    if candidate.startswith(prefix):
        return candidate[len(prefix) :]
    return server_path


def is_facade_issuer_path(issuer_path: str) -> str | None:
    """True-ish if ``issuer_path`` is the trailing portion of THIS facade's
    RFC 8414 issuer URL, regardless of any ROOT_PATH prefix (routing mode).

    The PRM advertises the AS issuer as ``{registry_url}/oauth2/egress``. A
    client locating the AS metadata inserts the well-known segment after the
    origin and appends the issuer's path, which is:

      - subdomain mode: ``oauth2/egress``           (registry_url has no path)
      - path mode:      ``registry/oauth2/egress``  (ROOT_PATH=/registry)

    Both must resolve to the same single AS-metadata document. We accept any
    path that ENDS in the facade issuer suffix (``/oauth2/egress``), tolerating
    surrounding slashes, so the route works in either mode without hardcoding
    the deployment's prefix. Returns the matched suffix (truthy) or None.

    Matching the *suffix* (not an exact string) is safe: the suffix
    ``/oauth2/egress`` is specific to this facade, and a non-matching path falls
    through to 404 rather than leaking the document under an arbitrary URL.
    """
    normalized = "/" + issuer_path.strip("/")
    suffix = FACADE_ISSUER_SUFFIX  # "/oauth2/egress"
    if normalized == suffix or normalized.endswith(suffix):
        return normalized
    return None


def build_resource_metadata_url(
    registry_url: str,
    server_path: str,
) -> str:
    """The per-server PRM *document* URL -- where the PRM is served, and the
    value embedded in the ``WWW-Authenticate`` 401 ``resource_metadata`` param.

    This is DISTINCT from the PRM document's ``resource`` field (see
    ``build_resource_identifier``). RFC 9728 requires the
    ``resource_metadata`` URL to LOCATE the document, while the ``resource``
    field inside identifies the resource the client is accessing (the MCP server
    URL). The MCP client validates ``resource`` against the URL it is actually
    talking to and rejects a mismatch -- so they must NOT be the same value.
    """
    base = registry_url.rstrip("/")
    return f"{base}{PRM_WELLKNOWN_PREFIX}{_normalize_server_path(server_path)}"


def build_resource_identifier(
    registry_url: str,
    server_path: str,
) -> str:
    """The PRM document's ``resource`` field: the canonical MCP server URL the
    client connects to (e.g. ``https://gw.example.com/github``).

    RFC 9728 §3.3: this MUST equal the resource identifier the client is
    accessing. Claude Code compares it against the server URL (``.../github``)
    and refuses the flow on mismatch (the live failure that motivated splitting
    this out from the metadata-document URL).
    """
    base = registry_url.rstrip("/")
    return f"{base}{_normalize_server_path(server_path)}"


def build_protected_resource_metadata(
    registry_url: str,
    server_path: str,
    scopes_supported: list[str] | None = None,
) -> dict:
    """RFC 9728 Protected Resource Metadata for one egress-protected server.

    ``resource`` is the MCP server URL (what the client is accessing);
    ``authorization_servers`` points at the gateway's OWN egress AS (this
    facade), not the ingress IdP -- that is what makes the IDE drive the
    third-party consent through us.
    """
    base = registry_url.rstrip("/")
    return {
        "resource": build_resource_identifier(registry_url, server_path),
        "authorization_servers": [f"{base}{FACADE_ISSUER_SUFFIX}"],
        "bearer_methods_supported": ["header"],
        "scopes_supported": list(scopes_supported or []),
    }


def build_authorization_server_metadata(registry_url: str) -> dict:
    """RFC 8414 Authorization Server Metadata for the egress AS facade.

    Advertises the gateway's own authorize/token/registration endpoints and S256
    PKCE. ``token_endpoint_auth_methods_supported`` is ``none`` because the IDE
    is a public client (DCR issues a client_id with no secret).
    """
    base = registry_url.rstrip("/")
    issuer = f"{base}{FACADE_ISSUER_SUFFIX}"
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{base}{AUTHORIZE_PATH}",
        "token_endpoint": f"{base}{TOKEN_PATH}",
        "registration_endpoint": f"{base}{REGISTER_PATH}",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


# --------------------------------------------------------------------------- #
# Dynamic Client Registration (RFC 7591)
# --------------------------------------------------------------------------- #


def _is_loopback_redirect(uri: str) -> bool:
    """True if ``uri`` is an RFC 8252 loopback redirect (the only kind we allow).

    MCP IDE clients register ``http://127.0.0.1:<port>/...`` (or ``localhost``).
    We refuse anything else so a registered client cannot redirect a leaked code
    to an attacker-controlled host.
    """
    from urllib.parse import urlparse

    try:
        p = urlparse(uri)
    except ValueError:
        return False
    host = (p.hostname or "").lower()
    if host in _LOOPBACK_HOSTS:
        return True
    # Some clients use a custom private-use scheme (RFC 8252 §7.1), e.g.
    # ``com.example.app:/callback`` -- no host. Accept only when there is no
    # network host component at all.
    if p.scheme and p.scheme not in ("http", "https") and not p.netloc:
        return True
    return False


class RegistrationError(Exception):
    """Raised when a DCR request is malformed or has a non-loopback redirect."""


def register_client(request_body: dict) -> dict:
    """Process an RFC 7591 dynamic client registration request.

    The facade is a public-client AS; we issue a random ``client_id`` with no
    secret. We do NOT persist the registration: the issued ``client_id`` is
    opaque to us (we never authenticate the client at ``/token`` -- PKCE +
    single-use code binding are the security anchors), so a stored row would add
    state with no security value. We DO validate the redirect URIs are loopback.

    Returns the RFC 7591 client information response.
    """
    redirect_uris = request_body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise RegistrationError("redirect_uris is required and must be a non-empty list")
    for uri in redirect_uris:
        if not isinstance(uri, str) or not _is_loopback_redirect(uri):
            raise RegistrationError(f"redirect_uri not permitted (loopback only): {uri!r}")

    client_id = "egress-" + secrets.token_urlsafe(24)
    return {
        "client_id": client_id,
        "client_id_issued_at": 0,  # we do not stamp time (Date.now unavailable in some envs); 0 = N/A
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }


# --------------------------------------------------------------------------- #
# Pending-authorize context + single-use authorization code
# --------------------------------------------------------------------------- #


@dataclass
class ClientAuthzContext:
    """Leg-1 (client<->facade) parameters captured at ``/authorize``.

    Carried through the provider OAuth leg (inside the AEAD provider-state's
    ``session_id`` slot is NOT enough -- these are client-specific), so they are
    held in the facade auth-code store keyed by an opaque correlation id that we
    thread as the provider-leg ``session_id``.
    """

    client_id: str
    redirect_uri: str
    client_state: str
    code_challenge: str
    code_challenge_method: str
    server_path: str
    resource: str


@dataclass
class CapturedIdentity:
    """The gateway identity bound to a completed consent.

    Recovered at ``/token`` and handed to the auth-server mint so the gateway
    bearer the client receives carries the SAME ingress authority the user
    already had (it replaces their ingress bearer on retry -- no escalation).
    """

    user_id: str
    auth_method: str
    groups: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    provider: str = ""
    server_path: str = ""


@dataclass
class AuthCodeRecord:
    """A redeemable authorization code's bound data: identity + leg-1 PKCE binding.

    Persisted (serialized) in the operational repo keyed by the code value, so it
    survives across registry replicas. The TTL + single-use semantics are the
    repo's (atomic find-and-delete); the PKCE/redirect/client_id checks are the
    pure ``verify_auth_code_record`` below.
    """

    identity: CapturedIdentity
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str


class AuthCodeError(Exception):
    """Raised when an authorization code fails a redemption check (PKCE, etc.)."""


# -- (de)serialization for cross-replica storage ----------------------------- #


def serialize_client_ctx(ctx: ClientAuthzContext) -> dict:
    return asdict(ctx)


def deserialize_client_ctx(d: dict) -> ClientAuthzContext:
    return ClientAuthzContext(**d)


def serialize_identity(identity: CapturedIdentity) -> dict:
    return asdict(identity)


def deserialize_identity(d: dict) -> CapturedIdentity:
    return CapturedIdentity(**d)


def serialize_pending(ctx: ClientAuthzContext, identity: CapturedIdentity) -> str:
    """JSON for a pending-authorize record (leg-1 ctx + captured identity)."""
    return json.dumps({"ctx": serialize_client_ctx(ctx), "identity": serialize_identity(identity)})


def deserialize_pending(blob: str) -> tuple[ClientAuthzContext, CapturedIdentity]:
    obj = json.loads(blob)
    return deserialize_client_ctx(obj["ctx"]), deserialize_identity(obj["identity"])


def build_auth_code_record(ctx: ClientAuthzContext, identity: CapturedIdentity) -> AuthCodeRecord:
    """Build the auth-code record bound to leg-1's client/PKCE/redirect."""
    return AuthCodeRecord(
        identity=identity,
        client_id=ctx.client_id,
        redirect_uri=ctx.redirect_uri,
        code_challenge=ctx.code_challenge,
        code_challenge_method=ctx.code_challenge_method,
    )


def serialize_auth_code_record(record: AuthCodeRecord) -> str:
    return json.dumps(
        {
            "identity": serialize_identity(record.identity),
            "client_id": record.client_id,
            "redirect_uri": record.redirect_uri,
            "code_challenge": record.code_challenge,
            "code_challenge_method": record.code_challenge_method,
        }
    )


def deserialize_auth_code_record(blob: str) -> AuthCodeRecord:
    obj = json.loads(blob)
    return AuthCodeRecord(
        identity=deserialize_identity(obj["identity"]),
        client_id=obj["client_id"],
        redirect_uri=obj["redirect_uri"],
        code_challenge=obj["code_challenge"],
        code_challenge_method=obj["code_challenge_method"],
    )


def new_auth_code() -> str:
    """A fresh opaque authorization code value."""
    return secrets.token_urlsafe(32)


def new_correlation_id() -> str:
    """A fresh opaque correlation id (threaded as the provider-leg session_id)."""
    return secrets.token_urlsafe(18)


def verify_auth_code_record(
    record: AuthCodeRecord,
    code_verifier: str,
    redirect_uri: str,
    client_id: str | None = None,
) -> CapturedIdentity:
    """Validate a redeemed auth-code record (the repo already enforced TTL +
    single-use by atomically deleting it). Returns the captured identity.

    Enforces: redirect_uri match, PKCE S256
    (``base64url(sha256(verifier)) == code_challenge``), and -- when ``client_id``
    is supplied -- the RFC 6749 §4.1.3 code/client binding (defense-in-depth on
    top of PKCE). Raises ``AuthCodeError`` without leaking which check failed.
    """
    if redirect_uri != record.redirect_uri:
        raise AuthCodeError("redirect_uri mismatch")
    if client_id is not None and client_id != record.client_id:
        raise AuthCodeError("client_id mismatch")
    if not _verify_pkce(code_verifier, record.code_challenge, record.code_challenge_method):
        raise AuthCodeError("PKCE verification failed")
    return record.identity


def _verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    """RFC 7636 S256 verification (the only method we advertise)."""
    if not verifier or not challenge:
        return False
    if method != "S256":
        return False
    from registry.egress_auth.oauth_engine import pkce_challenge_s256

    return secrets.compare_digest(pkce_challenge_s256(verifier), challenge)


# --------------------------------------------------------------------------- #
# Server egress-config resolution helper
# --------------------------------------------------------------------------- #


def server_advertised_scopes(server: dict) -> list[str]:
    """The egress provider scopes to advertise in the PRM ``scopes_supported``.

    Best-effort: pulled from the server's egress_oauth config so the IDE sees
    what access the consent will request. Empty when not egress-configured.
    """
    eo = server.get("egress_oauth") or {}
    return list(eo.get("scopes") or [])


def is_server_egress_configured(server: dict | None) -> bool:
    """True iff the server has per-user OAuth egress wired (mode + provider config)."""
    if not server:
        return False
    if server.get("egress_auth_mode") != "oauth_user":
        return False
    eo = server.get("egress_oauth")
    if not eo:
        return False
    try:
        resolve_provider(eo)
    except ValueError:
        return False
    return True
