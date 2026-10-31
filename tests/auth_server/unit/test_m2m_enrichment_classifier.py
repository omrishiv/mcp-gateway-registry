"""Exhaustive tests: M2M group enrichment only ever runs for machine callers.

``/validate`` fills an empty group list from the ``idp_m2m_clients`` collection
when ``should_enrich_groups`` accepts the validation result (and the provider
does not classify the token as a delegated user). That collection grants groups
to machine clients, so it must never be consulted for a human. The rate
limiter's caller classifier, ``_resolve_rate_limit_caller``, is the auth
server's provider-aware machine-versus-human decision. The security property
pinned here is: for every validation result a supported provider can return,
the M2M enrichment gate accepting it implies the classifier calls it a machine.
"""

from __future__ import annotations

import asyncio
import functools
import itertools
import json
import os
import time
from typing import Any
from unittest.mock import (
    AsyncMock,
    patch,
)

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-definitely-long-enough-32b")

from mongodb_groups_enrichment import should_enrich_groups  # noqa: E402
from providers.auth0 import Auth0Provider  # noqa: E402
from providers.cognito import CognitoProvider  # noqa: E402
from providers.entra import EntraIdProvider  # noqa: E402
from providers.keycloak import KeycloakProvider  # noqa: E402
from providers.okta import OktaProvider  # noqa: E402
from providers.pingfederate import PingFederateProvider  # noqa: E402

import auth_server.server as server_module  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.auth]


KID: str = "m2m-classifier-kid"
WEB_CLIENT_ID: str = "gateway-web"
M2M_CLIENT_ID: str = "gateway-m2m"
SUBJECT: str = "subject-0001"
SERVICE_ACCOUNT_NAME: str = f"service-account-{M2M_CLIENT_ID}"
HUMAN_NAME: str = "alice"
NON_EMPTY_GROUPS: list[str] = ["mcp-servers-unrestricted"]
ENTRA_DELEGATED_SCOPE: str = "access_as_user"

PROVIDERS: tuple[str, ...] = (
    "keycloak",
    "okta",
    "auth0",
    "cognito",
    "pingfederate",
    "entra",
)

# Groups claim shapes: absent, present but empty, present and non-empty.
GROUP_SHAPES: tuple[str, ...] = ("absent", "empty", "non_empty")

# Environment variables that change how a provider is constructed. Cleared so a
# developer's shell cannot change the issuer or audience the tokens must carry.
_PROVIDER_ENV_VARS: tuple[str, ...] = (
    "OKTA_AUTH_SERVER_ID",
    "ENTRA_LOGIN_BASE_URL",
    "ENTRA_GRAPH_BASE_URL",
    "ENTRA_SCOPE_FORMAT",
    "ENTRA_APPLICATION_ID_URI",
    "ENTRA_GRAPH_RESOURCE_URL",
)

_GENERIC_DEFECT_REASON: str = (
    "Known defect: should_enrich_groups accepts any groupless token whose result "
    "carries a client_id, and every provider fills client_id from azp, cid or its "
    "own client id, so a groupless human token enters M2M enrichment."
)
_COGNITO_DEFECT_REASON: str = (
    "Known defect: a groupless Cognito user token or id token carries a client_id "
    "in its validation result, so should_enrich_groups accepts it although the "
    "classifier calls it a human."
)
_SESSION_DEFECT_REASON: str = (
    "Known defect: a session-cookie result has client_id '' (not None), so "
    "should_enrich_groups accepts a groupless browser session for M2M enrichment."
)

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_JWK: dict[str, Any] = {
    **json.loads(RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key())),
    "kid": KID,
    "alg": "RS256",
}
_JWKS: dict[str, Any] = {"keys": [_PUBLIC_JWK]}


@functools.cache
def _provider(
    name: str,
):
    """Build the named provider once, with a clean provider environment.

    Args:
        name: Provider method name, one of ``PROVIDERS``.

    Returns:
        A configured provider whose web client is ``WEB_CLIENT_ID`` and whose
        M2M client is ``M2M_CLIENT_ID``.
    """
    clean_env = {k: v for k, v in os.environ.items() if k not in _PROVIDER_ENV_VARS}
    with patch.dict(os.environ, clean_env, clear=True):
        if name == "keycloak":
            return KeycloakProvider(
                keycloak_url="http://keycloak:8080",
                realm="mcp-gateway",
                client_id=WEB_CLIENT_ID,
                client_secret="secret",
                m2m_client_id=M2M_CLIENT_ID,
            )
        if name == "okta":
            return OktaProvider(
                "dev-123456.okta.com",
                WEB_CLIENT_ID,
                "secret",
                m2m_client_id=M2M_CLIENT_ID,
            )
        if name == "auth0":
            return Auth0Provider(
                domain="tenant.auth0.com",
                client_id=WEB_CLIENT_ID,
                client_secret="secret",
                m2m_client_id=M2M_CLIENT_ID,
            )
        if name == "cognito":
            return CognitoProvider(
                user_pool_id="us-east-1_TESTPOOL",
                client_id=WEB_CLIENT_ID,
                client_secret="secret",
                region="us-east-1",
                m2m_client_ids=[M2M_CLIENT_ID],
            )
        if name == "pingfederate":
            return PingFederateProvider(
                base_url="https://pf.example.com",
                client_id=WEB_CLIENT_ID,
                client_secret="secret",
                m2m_client_id=M2M_CLIENT_ID,
            )
        if name == "entra":
            return EntraIdProvider(
                tenant_id="tenant-abc",
                client_id=WEB_CLIENT_ID,
                client_secret="secret",
            )
    raise ValueError(f"unknown provider {name}")


def _issuer(
    name: str,
) -> str:
    """Return the issuer a token from ``name`` must carry to verify.

    Args:
        name: Provider method name.

    Returns:
        The issuer the provider accepts.
    """
    provider = _provider(name)
    if name == "keycloak":
        return provider.realm_url
    if name == "entra":
        return provider.issuer_v2
    if name == "pingfederate":
        return "https://pf.example.com"
    return provider.issuer


def _groups_claim_name(
    name: str,
) -> str:
    """Return the claim the provider reads group memberships from.

    Args:
        name: Provider method name.

    Returns:
        The groups claim name.
    """
    if name == "cognito":
        return "cognito:groups"
    if name == "auth0":
        return _provider(name).groups_claim
    return "groups"


def _provider_claims(
    name: str,
    has_client_id_claim: bool,
    service_account: bool,
    has_username_claim: bool,
    group_shape: str,
    delegated_scope: bool,
) -> dict[str, Any]:
    """Build an access-token claim set shaped like ``name`` issues it.

    The enumerated axes are set literally. The remaining claims follow each
    IdP: Keycloak, Auth0 and Entra always carry ``azp``, Okta always carries
    ``cid``, and a Cognito token without a ``client_id`` claim is the id token
    (``token_use=id``, audience-bound), since a Cognito access token always
    carries ``client_id``.

    Args:
        name: Provider method name.
        has_client_id_claim: Whether a top-level ``client_id`` claim is present.
        service_account: Whether ``preferred_username`` is a ``service-account-``
            name (otherwise it is a human handle).
        has_username_claim: Whether a ``username`` claim is present.
        group_shape: One of ``GROUP_SHAPES``.
        delegated_scope: Entra only: whether a delegated ``scp`` claim is present.

    Returns:
        The claim set to sign.
    """
    now = int(time.time())
    oauth_client = M2M_CLIENT_ID if has_client_id_claim else WEB_CLIENT_ID
    claims: dict[str, Any] = {
        "iss": _issuer(name),
        "aud": WEB_CLIENT_ID,
        "sub": SUBJECT,
        "iat": now,
        "exp": now + 600,
        "preferred_username": SERVICE_ACCOUNT_NAME if service_account else HUMAN_NAME,
    }
    if has_client_id_claim:
        claims["client_id"] = M2M_CLIENT_ID
    if has_username_claim:
        claims["username"] = HUMAN_NAME
    if name in ("keycloak", "auth0", "entra"):
        claims["azp"] = oauth_client
    if name == "okta":
        claims["cid"] = oauth_client
    if name == "cognito":
        claims["token_use"] = "access" if has_client_id_claim else "id"
        if has_client_id_claim:
            claims.pop("aud")
    if name == "entra" and delegated_scope:
        claims["scp"] = ENTRA_DELEGATED_SCOPE
    if group_shape == "empty":
        claims[_groups_claim_name(name)] = []
    elif group_shape == "non_empty":
        claims[_groups_claim_name(name)] = list(NON_EMPTY_GROUPS)
    return claims


def _validate_provider_token(
    name: str,
    claims: dict[str, Any],
) -> dict[str, Any]:
    """Sign ``claims`` and run them through the provider's real ``validate_token``.

    Only the JWKS fetch (and PingFederate discovery) is replaced; signature,
    issuer, audience and expiry are verified for real.

    Args:
        name: Provider method name.
        claims: The claim set to sign.

    Returns:
        The provider's validation result.
    """
    provider = _provider(name)
    token = jwt.encode(claims, _PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})
    with patch.object(provider, "get_jwks", return_value=_JWKS):
        if name == "pingfederate":
            with patch.object(
                provider,
                "_get_openid_configuration",
                return_value={"issuer": _issuer(name)},
            ):
                return provider.validate_token(token)
        return provider.validate_token(token)


def _m2m_enrichment_accepts(
    validation_result: dict[str, Any],
    provider,
) -> bool:
    """Return whether ``/validate`` would consult the M2M group collection.

    Mirrors the gate at ``auth_server/server.py`` (``should_enrich =
    not delegated_provider_user and should_enrich_groups(validation_result)``),
    where ``delegated_provider_user`` is the verifying provider's
    ``is_delegated_user`` and is False when no provider verified the token
    (session cookie and self-signed paths).

    Args:
        validation_result: The validation result.
        provider: The provider that verified the token, or None.

    Returns:
        True if the M2M enrichment lookup runs for this result.
    """
    delegated = provider.is_delegated_user(validation_result) if provider is not None else False
    return not delegated and should_enrich_groups(validation_result)


def _classified_as_machine(
    validation_result: dict[str, Any],
) -> bool:
    """Return whether the rate limiter's classifier calls the caller a machine.

    Args:
        validation_result: The validation result.

    Returns:
        True if ``_resolve_rate_limit_caller`` takes the agent branch.
    """
    _username, client_id = server_module._resolve_rate_limit_caller(validation_result)
    return client_id is not None


def _provider_cell_is_known_defect(
    name: str,
    has_client_id_claim: bool,
    service_account: bool,
    has_username_claim: bool,
    group_shape: str,
    delegated_scope: bool,
) -> str | None:
    """Return the xfail reason for a provider cell that fails today, else None.

    Args:
        name: Provider method name.
        has_client_id_claim: Whether a top-level ``client_id`` claim is present.
        service_account: Whether ``preferred_username`` is a service account.
        has_username_claim: Whether a ``username`` claim is present.
        group_shape: One of ``GROUP_SHAPES``.
        delegated_scope: Entra only: whether ``scp`` is present.

    Returns:
        The reason string, or None for a cell expected to pass.
    """
    if group_shape == "non_empty":
        return None
    if name == "cognito":
        machine = has_client_id_claim and not has_username_claim
        return None if machine else _COGNITO_DEFECT_REASON
    machine = has_client_id_claim or service_account
    if machine:
        return None
    if name == "entra" and delegated_scope:
        return None
    return _GENERIC_DEFECT_REASON


def _provider_cells() -> list:
    """Enumerate every provider cell, marking the ones that fail today.

    Returns:
        ``pytest.param`` objects over the full grid.
    """
    cells = []
    for name, cid, sa, uname, shape in itertools.product(
        PROVIDERS,
        (True, False),
        (True, False),
        (True, False),
        GROUP_SHAPES,
    ):
        for scp in (True, False) if name == "entra" else (False,):
            reason = _provider_cell_is_known_defect(name, cid, sa, uname, shape, scp)
            marks = (
                [pytest.mark.xfail(strict=True, raises=AssertionError, reason=reason)]
                if reason
                else []
            )
            cell_id = "-".join(
                [
                    name,
                    "cid" if cid else "nocid",
                    "sa" if sa else "human",
                    "uname" if uname else "nouname",
                    f"groups_{shape}",
                ]
                + (["scp" if scp else "noscp"] if name == "entra" else [])
            )
            cells.append(pytest.param(name, cid, sa, uname, shape, scp, marks=marks, id=cell_id))
    return cells


def _self_signed_cells() -> list:
    """Enumerate self-signed token cells (the provider is irrelevant here).

    ``/validate`` checks for a self-signed token before any provider, so these
    results never depend on the configured provider.

    Returns:
        ``pytest.param`` objects over the self-signed grid.
    """
    return [
        pytest.param(
            cid,
            sa,
            uname,
            shape,
            id="-".join(
                [
                    "cid" if cid else "nocid",
                    "sa" if sa else "human",
                    "uname" if uname else "nouname",
                    f"groups_{shape}",
                ]
            ),
        )
        for cid, sa, uname, shape in itertools.product(
            (True, False), (True, False), (True, False), GROUP_SHAPES
        )
    ]


@pytest.mark.parametrize(
    ("name", "has_client_id_claim", "service_account", "has_username_claim", "group_shape", "scp"),
    _provider_cells(),
)
def test_provider_token_enrichment_implies_machine(
    name,
    has_client_id_claim,
    service_account,
    has_username_claim,
    group_shape,
    scp,
):
    """M2M enrichment of a provider-verified token implies a machine caller.

    For every provider and every combination of top-level ``client_id`` claim,
    ``service-account-`` ``preferred_username``, ``username`` claim and groups
    claim shape: if ``/validate`` would fill the token's groups from the M2M
    collection, the rate limiter's classifier calls the caller a machine.
    """
    claims = _provider_claims(
        name, has_client_id_claim, service_account, has_username_claim, group_shape, scp
    )
    result = _validate_provider_token(name, claims)
    assert result["valid"] is True, result

    if _m2m_enrichment_accepts(result, _provider(name)):
        assert _classified_as_machine(result), (
            f"{name} token enters M2M enrichment but is classified human",
            {k: result.get(k) for k in ("method", "client_id", "groups", "username")},
            claims,
        )


@pytest.mark.parametrize(
    ("has_client_id_claim", "service_account", "has_username_claim", "group_shape"),
    _self_signed_cells(),
)
def test_self_signed_token_enrichment_implies_machine(
    has_client_id_claim,
    service_account,
    has_username_claim,
    group_shape,
):
    """M2M enrichment of a self-signed token implies a machine caller.

    Self-signed tokens are minted for a logged-in user. For every shape of
    their claims, if ``/validate`` would fill their groups from the M2M
    collection, the classifier calls the caller a machine.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": server_module.JWT_ISSUER,
        "aud": server_module._USER_JWT_AUDIENCE,
        "sub": HUMAN_NAME,
        "preferred_username": SERVICE_ACCOUNT_NAME if service_account else HUMAN_NAME,
        "token_use": "access",
        "scope": "",
        "iat": now,
        "exp": now + 600,
    }
    if has_client_id_claim:
        claims["client_id"] = M2M_CLIENT_ID
    if has_username_claim:
        claims["username"] = HUMAN_NAME
    if group_shape == "empty":
        claims["groups"] = []
    elif group_shape == "non_empty":
        claims["groups"] = list(NON_EMPTY_GROUPS)
    token = jwt.encode(claims, server_module.SECRET_KEY, algorithm="HS256")
    result = server_module.validator.validate_self_signed_token(token)
    assert result["token_type"] == "user_generated", result

    if _m2m_enrichment_accepts(result, None):
        assert _classified_as_machine(result), (result, claims)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=_SESSION_DEFECT_REASON)
def test_session_cookie_never_enters_m2m_enrichment():
    """A browser session is a human, so it never enters M2M enrichment.

    For a groupless login session, the result of ``validate_session_cookie``
    passes the M2M enrichment gate only if the classifier calls it a machine.
    The session's provider does not reach either function, so one provider
    stands for all of them.
    """
    session = {
        "username": HUMAN_NAME,
        "groups": [],
        "provider": "keycloak",
        "auth_method": "oauth2",
        "subject": SUBJECT,
    }
    cookie = server_module.signer.dumps("session-m2m-classifier")
    with (
        patch("session_store.resolve_session", AsyncMock(return_value=session)),
        patch.object(server_module, "map_groups_to_scopes", AsyncMock(return_value=[])),
    ):
        result = asyncio.run(server_module.validate_session_cookie(cookie))
    assert result["method"] == "session_cookie", result

    if _m2m_enrichment_accepts(result, None):
        assert _classified_as_machine(result), (
            "groupless session enters M2M enrichment but is classified human",
            {k: result.get(k) for k in ("method", "client_id", "groups", "username")},
        )
