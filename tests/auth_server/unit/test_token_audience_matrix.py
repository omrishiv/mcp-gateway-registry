"""Exhaustive and property tests: every gateway token is accepted only by its own verifier.

The gateway mints five kinds of HS256 token from one ``SECRET_KEY``: the user's
self-signed access token (``/internal/tokens``), the registry-UI, mcp-proxy and
generic-proxy hop tokens (``auth_server/internal_request_token.py``) and the
internal service-to-service token (``registry/auth/internal.py``). Each verifier
(the auth server's and every provider's self-signed validator, both proxy-hop
verifiers on each side, the registry-UI verifier and the internal validator)
must accept exactly the tokens of its own kind, so no token can be replayed at a
hop it was not minted for. Within each accepted pairing, changing the audience,
issuer, ``token_use``, expiry, algorithm or signing key must make it reject.
"""

from __future__ import annotations

import asyncio
import importlib
import itertools
import os
import time
import warnings
from collections.abc import Iterator
from contextlib import (
    ExitStack,
    contextmanager,
)
from types import ModuleType
from unittest.mock import (
    AsyncMock,
    patch,
)

import jwt as pyjwt
import pytest
from fastapi import HTTPException
from hypothesis import (
    given,
    settings,
)
from hypothesis import strategies as st
from jwt.warnings import InsecureKeyLengthWarning
from starlette.requests import Request

pytestmark = [pytest.mark.unit, pytest.mark.auth]


SECRET: str = "token-audience-matrix-secret-key-for-unit-tests-only-not-production-0123456789"
OTHER_SECRET: str = "an-unrelated-secret-key-that-no-gateway-component-holds-0123456789abcdefghij"

USERNAME: str = "alice"
USER_GROUPS: list[str] = ["developers"]
USER_SCOPES: list[str] = ["servers-read"]
MCP_SERVER: str = "github"
GENERIC_ENTITY_TYPE: str = "skill"
GENERIC_ENTITY_PATH: str = "skills/demo"
UPSTREAM_URL: str = "http://upstream.internal:8080/mcp"

USER_AUDIENCE: str = "mcp-registry"

MINTERS: tuple[str, ...] = (
    "user",
    "registry-ui",
    "mcp-proxy",
    "generic-proxy",
    "internal",
)

PROVIDERS: tuple[str, ...] = (
    "auth0",
    "entra",
    "keycloak",
    "okta",
    "pingfederate",
)

_PROVIDER_CLASSES: dict[str, str] = {
    "auth0": "Auth0Provider",
    "entra": "EntraIdProvider",
    "keycloak": "KeycloakProvider",
    "okta": "OktaProvider",
    "pingfederate": "PingFederateProvider",
}

# The auth server imports its providers as the top-level ``providers`` package
# (``auth_server/`` is on ``sys.path``), so those are the module copies whose
# validators run in production.
_PROVIDER_PACKAGE: str = "providers"

VERIFIERS: tuple[str, ...] = (
    "auth_server.self_signed",
    *(f"provider.{name}" for name in PROVIDERS),
    "auth_server.mcp_proxy",
    "auth_server.generic_proxy",
    "registry.registry_ui",
    "registry.mcp_proxy",
    "registry.generic_proxy",
    "registry.internal",
)

# The only (minter, verifier) pairs that may accept.
DIAGONAL: dict[str, frozenset[str]] = {
    "user": frozenset({"auth_server.self_signed", *(f"provider.{p}" for p in PROVIDERS)}),
    "registry-ui": frozenset({"registry.registry_ui"}),
    "mcp-proxy": frozenset({"auth_server.mcp_proxy", "registry.mcp_proxy"}),
    "generic-proxy": frozenset({"auth_server.generic_proxy", "registry.generic_proxy"}),
    "internal": frozenset({"registry.internal"}),
}

ALL_AUDIENCES: tuple[str, ...] = (
    "mcp-registry",
    "mcp-registry-ui",
    "mcp-proxy",
    "generic-proxy",
    "mcp-internal",
)

ALL_TOKEN_USES: tuple[str, ...] = (
    "access",
    "mcp-registry-ui",
    "mcp-proxy",
    "generic-proxy",
    "refresh",
    "id",
)

# Values a provider's import-time JWT_AUDIENCE may be set to: the default, every
# other minter's audience, and an unrelated custom value.
JWT_AUDIENCE_OVERRIDES: tuple[str, ...] = (*ALL_AUDIENCES, "custom-gateway-audience")

# Past expiries beyond every verifier's clock-skew leeway (the largest is 30s).
_MIN_EXPIRED_SECONDS: int = 61

_DELETE = object()

HYPOTHESIS_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_DIAGONAL_CELLS: list[tuple[str, str]] = [
    (minter, verifier) for minter in MINTERS for verifier in sorted(DIAGONAL[minter])
]


def _provider_module(
    name: str,
) -> ModuleType:
    """Import the provider module the auth server runs.

    Args:
        name: Provider module name, e.g. ``keycloak``.

    Returns:
        The imported module.
    """
    return importlib.import_module(f"{_PROVIDER_PACKAGE}.{name}")


def _internal_signing_key() -> bytes:
    """Return the derived key internal service tokens are signed with.

    Returns:
        The HMAC key ``registry.auth.internal`` derives from ``SECRET``.
    """
    from registry.auth.internal import _derive_internal_signing_key

    return _derive_internal_signing_key(SECRET)


def _signing_key_kind(
    minter: str,
) -> str:
    """Name the key a minter signs with.

    Args:
        minter: Minter name.

    Returns:
        ``"derived"`` for the internal service token, else ``"raw"``.
    """
    return "derived" if minter == "internal" else "raw"


def _key_for_kind(
    kind: str,
) -> str | bytes:
    """Resolve a key kind to key material.

    Args:
        kind: One of ``raw``, ``derived`` or ``other``.

    Returns:
        The key bytes or string.
    """
    if kind == "raw":
        return SECRET
    if kind == "derived":
        return _internal_signing_key()
    return OTHER_SECRET


@contextmanager
def _shared_secret() -> Iterator[None]:
    """Give every minter and verifier the same ``SECRET_KEY``.

    The auth server and the provider modules read ``SECRET_KEY`` at import
    time, while the hop-token code reads the environment on each call, so both
    are pinned.

    Yields:
        None, while the patches are active.
    """
    import auth_server.server as server_module

    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"SECRET_KEY": SECRET}))
        stack.enter_context(patch.object(server_module, "SECRET_KEY", SECRET))
        for name in PROVIDERS:
            module = _provider_module(name)
            stack.enter_context(patch.object(module, "SECRET_KEY", SECRET))
        yield


def _mint_user_token() -> str:
    """Mint a self-signed user token through the ``/internal/tokens`` handler.

    Returns:
        The encoded access token.
    """
    import auth_server.server as server_module

    body = server_module.GenerateTokenRequest(
        user_context={
            "username": USERNAME,
            "email": "alice@example.com",
            "groups": list(USER_GROUPS),
            "scopes": list(USER_SCOPES),
            "auth_method": "oauth2",
            "provider": "keycloak",
        },
        requested_scopes=[],
        expires_in_hours=1,
        description="audience-matrix",
    )
    with (
        patch.object(server_module, "check_rate_limit", return_value=True),
        patch.object(server_module, "_emit_token_mint_audit", AsyncMock()),
    ):
        response = asyncio.run(server_module.generate_user_token(body=body, caller="test-suite"))
    return response.access_token


def _mint(
    minter: str,
) -> str:
    """Mint one token of the named kind with its production minter.

    Args:
        minter: Minter name from ``MINTERS``.

    Returns:
        The encoded token.
    """
    from auth_server.internal_request_token import (
        mint_generic_proxy_token,
        mint_mcp_proxy_token,
        mint_registry_ui_token,
    )
    from registry.auth.internal import generate_internal_token

    if minter == "user":
        return _mint_user_token()
    if minter == "registry-ui":
        return mint_registry_ui_token(
            subject=USERNAME,
            session_id="",
            groups=list(USER_GROUPS),
            auth_method="oauth2",
            client_id="registry-ui-client",
        )
    if minter == "mcp-proxy":
        return mint_mcp_proxy_token(
            subject=USERNAME,
            scopes=list(USER_SCOPES),
            server_name=MCP_SERVER,
            upstream_url=UPSTREAM_URL,
            auth_method="oauth2",
        )
    if minter == "generic-proxy":
        return mint_generic_proxy_token(
            subject=USERNAME,
            scopes=list(USER_SCOPES),
            entity_type=GENERIC_ENTITY_TYPE,
            registered_path=GENERIC_ENTITY_PATH,
            upstream_url=UPSTREAM_URL,
            http_method="GET",
        )
    if minter == "internal":
        return generate_internal_token(subject="registry-service", purpose="matrix")
    raise AssertionError(f"unknown minter {minter}")


def _hop_request(
    headers: dict[str, str],
    path_params: dict[str, str],
) -> Request:
    """Build the Starlette request a proxy-hop verifier dependency receives.

    Args:
        headers: Request headers.
        path_params: Route path parameters.

    Returns:
        A GET request carrying ``headers`` and ``path_params``.
    """
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "path_params": path_params,
        }
    )


def _verify(
    verifier: str,
    token: str,
) -> None:
    """Present ``token`` to the named production verifier.

    Args:
        verifier: Verifier name from ``VERIFIERS``.
        token: Encoded token.

    Raises:
        ValueError: The provider or auth-server validator rejected the token.
        HTTPException: A hop or registry verifier rejected the token.
    """
    import auth_server.internal_request_token as hop
    import auth_server.server as server_module
    from registry.auth import proxied_token
    from registry.auth.internal import _validate_authorization_header

    if verifier == "auth_server.self_signed":
        server_module.validator.validate_self_signed_token(token)
    elif verifier.startswith("provider."):
        name = verifier.split(".", 1)[1]
        module = _provider_module(name)
        cls = getattr(module, _PROVIDER_CLASSES[name])
        cls.__new__(cls)._validate_self_signed_token(token)
    elif verifier == "auth_server.mcp_proxy":
        request = _hop_request({"X-Internal-Token": token}, {"server_name": MCP_SERVER})
        asyncio.run(hop.verify_mcp_proxy_token(request))
    elif verifier == "auth_server.generic_proxy":
        request = _hop_request(
            {"X-Internal-Token-Generic": token},
            {"entity_type": GENERIC_ENTITY_TYPE, "entity_path": GENERIC_ENTITY_PATH},
        )
        asyncio.run(hop.verify_generic_proxy_token(request))
    elif verifier == "registry.registry_ui":
        proxied_token.verify_registry_ui_token(token)
    elif verifier == "registry.mcp_proxy":
        proxied_token.verify_mcp_proxy_token(token)
    elif verifier == "registry.generic_proxy":
        proxied_token.verify_generic_proxy_token(token)
    elif verifier == "registry.internal":
        _validate_authorization_header(f"Bearer {token}")
    else:
        raise AssertionError(f"unknown verifier {verifier}")


def _accepts(
    verifier: str,
    token: str,
) -> bool:
    """Return whether ``verifier`` accepts ``token``.

    A rejection must be the verifier's normal fail-closed signal: a
    ``ValueError`` from a self-signed validator or a 401 from a dependency.
    Any other exception propagates and fails the test.

    Args:
        verifier: Verifier name from ``VERIFIERS``.
        token: Encoded token.

    Returns:
        True if the verifier accepted the token.
    """
    try:
        _verify(verifier, token)
    except ValueError:
        return False
    except HTTPException as exc:
        assert exc.status_code == 401, (verifier, exc.status_code, exc.detail)
        return False
    return True


def _resign(
    claims: dict,
    key: str | bytes | None,
    algorithm: str,
) -> str:
    """Encode ``claims`` again, silencing PyJWT's short-key warning.

    Args:
        claims: Claim set.
        key: Signing key, or None for ``alg=none``.
        algorithm: JWS algorithm.

    Returns:
        The encoded token.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureKeyLengthWarning)
        return pyjwt.encode(claims, key, algorithm=algorithm)


def _claim_values(
    pool: tuple[str, ...],
) -> st.SearchStrategy:
    """Strategy for a replacement claim value, or a deletion.

    Args:
        pool: Realistic values to sample alongside arbitrary text.

    Returns:
        Strategy over strings, case variants of ``pool`` and ``_DELETE``.
    """
    return st.one_of(
        st.just(_DELETE),
        st.sampled_from(pool),
        st.sampled_from(pool).map(str.upper),
        st.sampled_from(pool).map(lambda value: value + " "),
        st.text(max_size=16),
    )


def _mutations() -> st.SearchStrategy[tuple[str, object]]:
    """Strategy over single-field mutations of a minted token.

    Returns:
        Strategy of ``(field, value)`` pairs: a replacement or deletion of
        ``aud``, ``iss`` or ``token_use``; an ``exp`` this many seconds in the
        past; a different ``alg``; or a different signing key kind.
    """
    audiences = st.one_of(
        _claim_values(ALL_AUDIENCES),
        st.lists(st.sampled_from(ALL_AUDIENCES), min_size=1, max_size=3),
    )
    return st.one_of(
        st.tuples(st.just("aud"), audiences),
        st.tuples(st.just("iss"), _claim_values(("mcp-auth-server", "mcp-registry", ""))),
        st.tuples(st.just("token_use"), _claim_values(ALL_TOKEN_USES)),
        st.tuples(st.just("exp"), st.integers(_MIN_EXPIRED_SECONDS, 10**7)),
        st.tuples(st.just("alg"), st.sampled_from(("none", "HS384", "HS512"))),
        st.tuples(st.just("key"), st.sampled_from(("raw", "derived", "other"))),
    )


def _is_noop(
    claims: dict,
    minter: str,
    field: str,
    value: object,
) -> bool:
    """Return whether a drawn mutation leaves the token semantically unchanged.

    Args:
        claims: The minted claim set.
        minter: Minter name.
        field: Mutated field.
        value: Mutation value.

    Returns:
        True if the mutation is a no-op for this token, so it proves nothing.
    """
    if field == "key":
        return value == _signing_key_kind(minter)
    if field in ("aud", "iss", "token_use"):
        original = claims.get(field)
        if value is _DELETE:
            return field not in claims
        if field == "aud" and isinstance(value, list):
            return original in value
        return value == original
    return False


def _apply_mutation(
    token: str,
    minter: str,
    field: str,
    value: object,
) -> str:
    """Return ``token`` with one field mutated and the result re-signed.

    The token is re-signed with the minter's own key unless the mutation is to
    the key, so each case isolates one claim check.

    Args:
        token: The minted token.
        minter: Minter name.
        field: Field to mutate.
        value: Mutation value.

    Returns:
        The mutated token.
    """
    claims = pyjwt.decode(token, options={"verify_signature": False})
    key = _key_for_kind(_signing_key_kind(minter))
    algorithm = "HS256"
    if field in ("aud", "iss", "token_use"):
        if value is _DELETE:
            claims.pop(field, None)
        else:
            claims[field] = value
    elif field == "exp":
        claims["exp"] = int(time.time()) - int(value)
    elif field == "alg":
        algorithm = str(value)
        key = None if algorithm == "none" else key
    elif field == "key":
        key = _key_for_kind(str(value))
    return _resign(claims, key, algorithm)


@pytest.mark.parametrize(
    ("minter", "verifier"),
    list(itertools.product(MINTERS, VERIFIERS)),
    ids=[f"{m}->{v}" for m, v in itertools.product(MINTERS, VERIFIERS)],
)
def test_token_accepted_only_by_its_own_verifier(minter, verifier):
    """A minted token is accepted exactly by the verifiers of its own kind.

    For every (minter, verifier) pair, the verifier accepts the freshly minted
    token if and only if the pair is on the diagonal in ``DIAGONAL``.
    """
    with _shared_secret():
        token = _mint(minter)
        accepted = _accepts(verifier, token)

    expected = verifier in DIAGONAL[minter]
    assert accepted is expected, (
        f"{verifier} {'accepted' if accepted else 'rejected'} a {minter} token; "
        f"expected {'accept' if expected else 'reject'}"
    )


@pytest.mark.parametrize(
    ("minter", "verifier"),
    _DIAGONAL_CELLS,
    ids=[f"{m}->{v}" for m, v in _DIAGONAL_CELLS],
)
@HYPOTHESIS_SETTINGS
@given(mutation=_mutations())
def test_mutated_claim_rejected_on_diagonal(minter, verifier, mutation):
    """Changing one security claim of an accepted token makes its verifier reject.

    For every diagonal (minter, verifier) pair: replacing or deleting ``aud``,
    ``iss`` or ``token_use``, moving ``exp`` beyond the leeway into the past,
    re-signing with another algorithm (including ``none``), or signing with a
    different key kind, yields a token the verifier rejects.
    """
    field, value = mutation
    with _shared_secret():
        token = _mint(minter)
        claims = pyjwt.decode(token, options={"verify_signature": False})
        if _is_noop(claims, minter, field, value):
            return
        mutated = _apply_mutation(token, minter, field, value)
        accepted = _accepts(verifier, mutated)

    shown = "<deleted>" if value is _DELETE else value
    assert not accepted, f"{verifier} accepted a {minter} token with {field}={shown!r}"


@pytest.mark.parametrize(
    ("provider", "override", "minter"),
    list(itertools.product(PROVIDERS, JWT_AUDIENCE_OVERRIDES, MINTERS)),
    ids=[
        f"{p}-aud={o}-{m}"
        for p, o, m in itertools.product(PROVIDERS, JWT_AUDIENCE_OVERRIDES, MINTERS)
    ],
)
def test_provider_jwt_audience_override_never_admits_other_token_kinds(provider, override, minter):
    """A provider's ``JWT_AUDIENCE`` setting never makes it accept a foreign token kind.

    Each provider module reads ``JWT_AUDIENCE`` from the environment at import
    time. Whatever it is set to, including another minter's audience, the
    provider's self-signed validator accepts a minted token only when it is a
    user token and the setting matches the audience the auth server mints user
    tokens for.
    """
    module = _provider_module(provider)
    with _shared_secret(), patch.object(module, "JWT_AUDIENCE", override):
        token = _mint(minter)
        accepted = _accepts(f"provider.{provider}", token)

    expected = minter == "user" and override == USER_AUDIENCE
    assert accepted is expected, (
        f"{provider} with JWT_AUDIENCE={override!r} "
        f"{'accepted' if accepted else 'rejected'} a {minter} token"
    )
