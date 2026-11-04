"""Property tests: the egress vault key is the IdP's immutable account id.

The per-user egress credential vault stores each user's upstream provider
tokens under one key, computed by ``_canonical_egress_user``. A user reaches
the vault on two paths. The browser consent path presents a session cookie
whose record the OAuth2 login callback wrote; the vend path presents a bearer
token, either the IdP's own access token or a token this gateway minted from
the session. The properties pinned here:

* every path derives the same key for one account (agreement);
* two accounts with distinct immutable ids get distinct keys even when every
  mutable or reusable claim is identical (injectivity), which covers a Cognito
  username reused after its account is deleted and an Okta login moved to a
  new user;
* an account keeps its key when only those claims change (stability);
* an OIDC login that yields no subject creates no session;
* an Okta client-credentials token keys on its client id, and ``uid`` counts
  only for Okta;
* a token minted from a session carries the session's key.

The immutable id is the token ``sub`` everywhere except Okta access tokens,
whose ``sub`` is the user's editable login and whose ``uid`` is the user id the
Okta id_token puts in ``sub``. Bearer tokens are signed with a local RSA key
and verified for real; on the login path the provider's id_token verification
returns the claims as verified, and the session store runs against an
in-memory collection.
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import string
import time
from contextlib import (
    ExitStack,
    contextmanager,
)
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
)

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st
from jwt.algorithms import RSAAlgorithm

os.environ.setdefault("SECRET_KEY", "Zq8v3Lp0Wm7Xr2Tn5Yb9Kc4Hd6Jf1Ga8Qe3Us0Vt")

import session_store  # noqa: E402
from providers.auth0 import Auth0Provider  # noqa: E402
from providers.cognito import CognitoProvider  # noqa: E402
from providers.entra import EntraIdProvider  # noqa: E402
from providers.keycloak import KeycloakProvider  # noqa: E402
from providers.okta import OktaProvider  # noqa: E402
from providers.pingfederate import PingFederateProvider  # noqa: E402

import auth_server.server as server_module  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.auth]


KID: str = "egress-vault-identity-kid"
WEB_CLIENT_ID: str = "gateway-web"
COGNITO_POOL_ID: str = "us-east-1_TESTPOOL"
COGNITO_REGION: str = "us-east-1"
PINGFEDERATE_ISSUER: str = "https://pf.example.com"
SESSION_COOKIE_NAME: str = "mcp_gateway_session"
OAUTH2_PROVIDERS_YML: Path = (
    Path(__file__).resolve().parents[3] / "auth_server" / "oauth2_providers.yml"
)

# Claims an account holder or IdP administrator can change, or that a later
# account can hold. ``cognito:username`` is the Cognito username, which Cognito
# frees for reuse when its account is deleted; ``login`` doubles as the Okta
# login that an Okta user access token carries in ``sub``.
MUTABLE_CLAIMS: tuple[str, ...] = (
    "preferred_username",
    "email",
    "nickname",
    "login",
    "upn",
    "cognito:username",
)

# Bearer paths: path id -> provider. ``cognito`` is ``CognitoProvider`` (what
# ``/validate`` uses when AUTH_PROVIDER=cognito); the ``cognito-validator-*``
# paths are the two branches of ``SimplifiedCognitoValidator.validate_token``.
BEARER_PATHS: dict[str, str] = {
    "keycloak": "keycloak",
    "entra": "entra",
    "okta": "okta",
    "auth0": "auth0",
    "pingfederate": "pingfederate",
    "cognito": "cognito",
    "cognito-validator-jwt": "cognito",
    "cognito-validator-boto3": "cognito",
}

# Login paths through ``/oauth2/callback/{provider}``: path id -> provider.
# Bare names use the verified id_token, or for Cognito the verified access
# token (``cognito-boto3`` is the GetUser fallback). ``-userinfo`` paths are the
# userInfo fallback taken when there is no id_token, or no Cognito pool is
# configured. GitHub and Google only have the userInfo path.
LOGIN_PATHS: dict[str, str] = {
    "keycloak": "keycloak",
    "entra": "entra",
    "okta": "okta",
    "auth0": "auth0",
    "pingfederate": "pingfederate",
    "cognito": "cognito",
    "cognito-boto3": "cognito",
    "keycloak-userinfo": "keycloak",
    "okta-userinfo": "okta",
    "auth0-userinfo": "auth0",
    "pingfederate-userinfo": "pingfederate",
    "cognito-userinfo": "cognito",
    "github": "github",
    "google": "google",
}

NON_OIDC_LOGIN_PATHS: frozenset[str] = frozenset({"github", "google"})

PROVIDERS_WITH_BOTH_PATHS: tuple[str, ...] = (
    "keycloak",
    "entra",
    "okta",
    "auth0",
    "pingfederate",
    "cognito",
)

_ENV_VARS_CLEARED: tuple[str, ...] = (
    "OKTA_AUTH_SERVER_ID",
    "ENTRA_LOGIN_BASE_URL",
    "ENTRA_GRAPH_BASE_URL",
    "ENTRA_SCOPE_FORMAT",
    "ENTRA_APPLICATION_ID_URI",
    "ENTRA_GRAPH_RESOURCE_URL",
    "ENTRA_GROUP_RECOVERY_ENABLED",
)

HYPOTHESIS_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_COLLIDING_PROFILE: dict[str, str] = {
    "preferred_username": "alice",
    "email": "alice@example.com",
    "nickname": "alice",
    "login": "alice@example.com",
    "upn": "alice@example.com",
    "cognito:username": "alice@example.com",
}

# The same account after a rename: every mutable claim has a new value.
_RENAMED_PROFILE: dict[str, str] = {
    "preferred_username": "alice.smith",
    "email": "alice.smith@example.com",
    "nickname": "alice.smith",
    "login": "alice.smith@example.com",
    "upn": "alice.smith@example.com",
    "cognito:username": "alice.smith@example.com",
}

# Cognito username ``alice@example.com`` deleted and recreated: a new ``sub``.
_COGNITO_USERNAME_REUSE = (
    "0f6c-uuid-old-account",
    "0f6c-uuid-new-account",
    _COLLIDING_PROFILE,
    _COLLIDING_PROFILE,
)
# Okta login ``alice@example.com`` moved from user id A to user id B.
_OKTA_LOGIN_REASSIGNED = (
    "00u-alice-a",
    "00u-alice-b",
    _COLLIDING_PROFILE,
    _COLLIDING_PROFILE,
)

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_JWKS: dict[str, Any] = {
    "keys": [
        {
            **json.loads(RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key())),
            "kid": KID,
            "alg": "RS256",
        }
    ]
}

_ACCOUNT_IDS = st.text(
    alphabet=string.ascii_lowercase + string.digits + "-", min_size=1, max_size=16
)
_CLAIM_VALUES = st.text(
    alphabet=string.ascii_lowercase + string.digits + "._@-", min_size=1, max_size=16
)
_PROFILES = st.fixed_dictionaries(dict.fromkeys(MUTABLE_CLAIMS, _CLAIM_VALUES))


class _FakeSessionCollection:
    """In-memory stand-in for the ``oauth_sessions`` collection."""

    def __init__(self) -> None:
        self.documents: list[dict[str, Any]] = []

    async def insert_one(
        self,
        document: dict[str, Any],
    ) -> None:
        """Store a copy of ``document``."""
        self.documents.append(dict(document))

    async def find_one(
        self,
        query: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Return the document whose ``session_id`` matches, or None."""
        for document in self.documents:
            if document["session_id"] == query["session_id"]:
                return document
        return None


@dataclass
class _Login:
    """What one ``/oauth2/callback`` request produced."""

    status_code: int
    cookie: str | None
    store: _FakeSessionCollection


def _clean_env() -> dict[str, str]:
    """Return the process environment without provider-shaping variables.

    Returns:
        A copy of ``os.environ`` with ``_ENV_VARS_CLEARED`` removed.
    """
    return {k: v for k, v in os.environ.items() if k not in _ENV_VARS_CLEARED}


@functools.cache
def _provider(
    name: str,
):
    """Build the named provider once, with a clean provider environment.

    Args:
        name: Provider name, one of ``PROVIDERS_WITH_BOTH_PATHS``.

    Returns:
        A provider configured with ``WEB_CLIENT_ID`` as its client.
    """
    with patch.dict(os.environ, _clean_env(), clear=True):
        if name == "keycloak":
            return KeycloakProvider(
                keycloak_url="http://keycloak:8080",
                realm="mcp-gateway",
                client_id=WEB_CLIENT_ID,
                client_secret="secret",
            )
        if name == "entra":
            return EntraIdProvider(
                tenant_id="tenant-abc", client_id=WEB_CLIENT_ID, client_secret="secret"
            )
        if name == "okta":
            return OktaProvider("dev-123456.okta.com", WEB_CLIENT_ID, "secret")
        if name == "auth0":
            return Auth0Provider(
                domain="tenant.auth0.com", client_id=WEB_CLIENT_ID, client_secret="secret"
            )
        if name == "cognito":
            return CognitoProvider(
                user_pool_id=COGNITO_POOL_ID,
                client_id=WEB_CLIENT_ID,
                client_secret="secret",
                region=COGNITO_REGION,
            )
        if name == "pingfederate":
            pingfederate = PingFederateProvider(
                base_url=PINGFEDERATE_ISSUER, client_id=WEB_CLIENT_ID, client_secret="secret"
            )
            # Stands in for the discovery document fetch.
            pingfederate._get_openid_configuration = lambda: {"issuer": PINGFEDERATE_ISSUER}
            return pingfederate
    raise ValueError(f"unknown provider {name}")


@functools.cache
def _yml_provider_config(
    name: str,
) -> dict[str, Any]:
    """Return the shipped ``oauth2_providers.yml`` entry for ``name``.

    The claim mapping (``username_claim``, ``subject_claim`` and so on) is the
    production configuration; only the endpoint URL is replaced.

    Args:
        name: Provider key in the YAML file.

    Returns:
        The provider config dict the callback reads.
    """
    shipped = yaml.safe_load(OAUTH2_PROVIDERS_YML.read_text())["providers"][name]
    return {
        **shipped,
        "client_id": WEB_CLIENT_ID,
        "user_info_url": "https://idp.example.com/userinfo",
    }


@functools.cache
def _client():
    """Return a TestClient bound to the auth server app.

    Returns:
        The shared ``TestClient``.
    """
    from fastapi.testclient import TestClient

    return TestClient(server_module.app, raise_server_exceptions=False)


def _sign(
    claims: dict[str, Any],
) -> str:
    """Sign ``claims`` with the test RSA key, valid for ten minutes.

    Args:
        claims: Token claims without ``iat``/``exp``.

    Returns:
        The encoded RS256 JWT.
    """
    now = int(time.time())
    return jwt.encode(
        {**claims, "iat": now, "exp": now + 600},
        _PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KID},
    )


def _drop_absent(
    claims: dict[str, Any],
) -> dict[str, Any]:
    """Remove claims whose value is None (an account with no subject).

    Args:
        claims: Claims that may hold None values.

    Returns:
        The claims without the None-valued entries.
    """
    return {k: v for k, v in claims.items() if v is not None}


def _id_claims(
    account_id: str | None,
    profile: dict[str, str],
) -> dict[str, Any]:
    """The claims an id_token or OIDC userInfo response carries for an account.

    Args:
        account_id: The account's immutable id, or None for no subject.
        profile: The account's mutable claims.

    Returns:
        The identity claims (no protocol claims such as ``iss``).
    """
    return _drop_absent({**profile, "sub": account_id})


def _access_claims(
    provider: str,
    account_id: str | None,
    profile: dict[str, str],
) -> dict[str, Any]:
    """The identity claims a user access token from ``provider`` carries.

    An Okta user access token puts the user's login in ``sub`` and the user id
    in ``uid``. A Cognito access token carries the Cognito username in
    ``username``. Every other provider puts the account id in ``sub``.

    Args:
        provider: Provider name.
        account_id: The account's immutable id, or None for no subject.
        profile: The account's mutable claims.

    Returns:
        The identity claims (no protocol claims such as ``iss``).
    """
    if provider == "okta":
        return _drop_absent({**profile, "sub": profile["login"], "uid": account_id})
    if provider == "cognito":
        return _drop_absent({**profile, "sub": account_id, "username": profile["cognito:username"]})
    return _id_claims(account_id, profile)


def _cognito_access_token(
    account_id: str | None,
    profile: dict[str, str],
) -> str:
    """Sign a Cognito user access token for the account.

    Args:
        account_id: The account's ``sub``, or None for no subject.
        profile: The account's mutable claims.

    Returns:
        The encoded access token.
    """
    return _sign(
        {
            **_access_claims("cognito", account_id, profile),
            "iss": _provider("cognito").issuer,
            "token_use": "access",
            "client_id": WEB_CLIENT_ID,
        }
    )


def _cognito_get_user_client(
    account_id: str | None,
    profile: dict[str, str],
) -> MagicMock:
    """A boto3 ``cognito-idp`` client whose ``get_user`` returns the account.

    Args:
        account_id: The account's ``sub`` attribute, or None for no subject.
        profile: The account's mutable claims.

    Returns:
        The mock client.
    """
    attributes = [{"Name": "email", "Value": profile["email"]}]
    if account_id is not None:
        attributes.append({"Name": "sub", "Value": account_id})
    client = MagicMock()
    client.get_user.return_value = {
        "Username": profile["cognito:username"],
        "UserAttributes": attributes,
        "UserStatus": "CONFIRMED",
    }
    return client


def _bearer_result(
    bearer_path: str,
    account_id: str | None,
    profile: dict[str, str],
    extra_claims: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the validation result a bearer path builds for the account.

    Args:
        bearer_path: Key of ``BEARER_PATHS``.
        account_id: The account's immutable id.
        profile: The account's mutable claims.
        extra_claims: Claims added to the token, overriding the account's.

    Returns:
        The validation result.
    """
    if bearer_path.startswith("cognito-validator-"):
        return _cognito_validator_result(bearer_path, account_id, profile, extra_claims)
    provider = BEARER_PATHS[bearer_path]
    instance = _provider(provider)
    claims: dict[str, Any] = _access_claims(provider, account_id, profile)
    if provider == "keycloak":
        claims.update(iss=instance.realm_url, aud=WEB_CLIENT_ID, azp=WEB_CLIENT_ID)
    elif provider == "entra":
        claims.update(iss=instance.issuer_v2, aud=WEB_CLIENT_ID, azp=WEB_CLIENT_ID)
    elif provider == "cognito":
        claims.update(iss=instance.issuer, token_use="access", client_id=WEB_CLIENT_ID)
    elif provider == "pingfederate":
        claims.update(iss=PINGFEDERATE_ISSUER, aud=WEB_CLIENT_ID)
    else:
        claims.update(iss=instance.issuer, aud=WEB_CLIENT_ID)
    claims.update(extra_claims or {})
    with patch.object(instance, "get_jwks", return_value=_JWKS):
        result = instance.validate_token(_sign(claims))
    assert result["valid"] is True, result
    return result


def _cognito_validator_result(
    bearer_path: str,
    account_id: str | None,
    profile: dict[str, str],
    extra_claims: dict[str, Any] | None,
) -> dict[str, Any]:
    """Run ``SimplifiedCognitoValidator.validate_token`` on the account's token.

    ``cognito-validator-jwt`` verifies a signed access token against the test
    JWKS. ``cognito-validator-boto3`` makes JWT verification fail so the
    validator falls back to boto3 ``GetUser``.

    Args:
        bearer_path: ``cognito-validator-jwt`` or ``cognito-validator-boto3``.
        account_id: The account's ``sub``.
        profile: The account's mutable claims.
        extra_claims: Claims added to the JWT (ignored on the boto3 branch).

    Returns:
        The validation result.
    """
    validator = server_module.SimplifiedCognitoValidator(COGNITO_REGION)
    claims = {
        **_access_claims("cognito", account_id, profile),
        "iss": _provider("cognito").issuer,
        "token_use": "access",
        "client_id": WEB_CLIENT_ID,
        **(extra_claims or {}),
    }
    token = _sign(claims)
    with ExitStack() as stack:
        stack.enter_context(patch.object(validator, "_get_jwks", return_value=_JWKS))
        if bearer_path == "cognito-validator-boto3":
            stack.enter_context(
                patch.object(
                    validator,
                    "validate_jwt_token",
                    side_effect=ValueError("JWKS unreachable"),
                )
            )
            stack.enter_context(
                patch.object(
                    validator,
                    "_get_cognito_client",
                    return_value=_cognito_get_user_client(account_id, profile),
                )
            )
        result = validator.validate_token(token, COGNITO_POOL_ID, WEB_CLIENT_ID, COGNITO_REGION)
    assert result["valid"] is True, result
    expected_method = "boto3" if bearer_path == "cognito-validator-boto3" else "jwt"
    assert result["method"] == expected_method, result
    return result


def _bearer_key(
    bearer_path: str,
    account_id: str | None,
    profile: dict[str, str],
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Return the vault key a bearer path derives for the account.

    Args:
        bearer_path: Key of ``BEARER_PATHS``.
        account_id: The account's immutable id.
        profile: The account's mutable claims.
        extra_claims: Claims added to the token, overriding the account's.

    Returns:
        ``_canonical_egress_user`` of the validation result.
    """
    result = _bearer_result(bearer_path, account_id, profile, extra_claims)
    return server_module._canonical_egress_user(result)


@contextmanager
def _session_store(
    store: _FakeSessionCollection,
):
    """Back the real ``session_store`` functions with ``store``.

    Args:
        store: The in-memory session collection.

    Yields:
        None.
    """
    with patch.object(session_store, "_get_collection", AsyncMock(return_value=store)):
        yield


def _login_patches(
    login_path: str,
    account_id: str | None,
    profile: dict[str, str],
    getuser_has_sub: bool = True,
) -> list[Any]:
    """Build the patches that make the IdP return the account at ``login_path``.

    The code exchange, the userInfo fetch, id_token verification and (on
    ``cognito-boto3``) the JWKS check are replaced so the claims arrive as
    verified. The Cognito access token is signed and verified for real. The
    callback's own mapping from claims to session fields runs unchanged.

    Args:
        login_path: Key of ``LOGIN_PATHS``.
        account_id: The account's immutable id, or None for no subject.
        profile: The account's mutable claims.
        getuser_has_sub: Whether the boto3 ``GetUser`` response on
            ``cognito-boto3`` carries the ``sub`` attribute.

    Returns:
        The patches to enter.
    """
    provider = LOGIN_PATHS[login_path]
    provider_config = _yml_provider_config(provider)
    userinfo_path = login_path.endswith("-userinfo") or login_path in NON_OIDC_LOGIN_PATHS

    userinfo = _id_claims(account_id, profile)
    if provider == "cognito":
        userinfo["username"] = profile["cognito:username"]
    subject_claim = provider_config.get("subject_claim")
    if subject_claim and "sub" in userinfo:
        userinfo[subject_claim] = userinfo.pop("sub")

    token_data: dict[str, Any] = {"access_token": "opaque-access-token"}
    if provider == "cognito" and not userinfo_path:
        token_data["access_token"] = _cognito_access_token(account_id, profile)
    elif not userinfo_path:
        token_data["id_token"] = "opaque-id-token"

    providers_by_name = {name: _provider(name) for name in PROVIDERS_WITH_BOTH_PATHS}
    config = dict(server_module.OAUTH2_CONFIG)
    config["providers"] = {**config.get("providers", {}), provider: provider_config}

    env = _clean_env()
    if provider == "cognito" and not userinfo_path:
        env.update(COGNITO_USER_POOL_ID=COGNITO_POOL_ID, AWS_REGION=COGNITO_REGION)
    else:
        env.pop("COGNITO_USER_POOL_ID", None)

    validator_cls = server_module.SimplifiedCognitoValidator
    patches: list[Any] = [
        patch.dict(os.environ, env, clear=True),
        patch.object(server_module, "OAUTH2_CONFIG", config),
        patch.object(server_module, "IDP_USER_GROUP_FALLBACK_ENABLED_PROVIDERS", []),
        patch.object(server_module, "exchange_code_for_token", AsyncMock(return_value=token_data)),
        patch.object(server_module, "get_user_info", AsyncMock(return_value=userinfo)),
        patch.object(
            server_module,
            "get_auth_provider",
            side_effect=lambda name=None: providers_by_name[name],
        ),
        patch.object(validator_cls, "_get_jwks", return_value=_JWKS),
        patch("group_filter.filter_session_groups", AsyncMock(side_effect=lambda g, **_: g)),
    ]
    if login_path == "cognito-boto3":
        patches.append(
            patch.object(
                validator_cls,
                "validate_jwt_token",
                side_effect=ValueError("JWKS unreachable"),
            )
        )
        patches.append(
            patch.object(
                validator_cls,
                "_get_cognito_client",
                return_value=_cognito_get_user_client(
                    account_id if getuser_has_sub else None, profile
                ),
            )
        )
    verified = _id_claims(account_id, profile)
    patches.extend(
        patch.object(instance, "validate_id_token", return_value=verified)
        for instance in providers_by_name.values()
    )
    return patches


def _login(
    login_path: str,
    account_id: str | None,
    profile: dict[str, str],
    getuser_has_sub: bool = True,
) -> _Login:
    """Drive ``/oauth2/callback/{provider}`` for the account.

    Args:
        login_path: Key of ``LOGIN_PATHS``.
        account_id: The account's immutable id, or None for no subject.
        profile: The account's mutable claims.
        getuser_has_sub: Whether the boto3 ``GetUser`` response on
            ``cognito-boto3`` carries the ``sub`` attribute.

    Returns:
        The response status, the session cookie it set (None when it set
        none) and the session store it wrote to.
    """
    provider = LOGIN_PATHS[login_path]
    temp_cookie = server_module.signer.dumps(
        {
            "state": "state-1",
            "provider": provider,
            "callback_uri": f"http://localhost:8888/oauth2/callback/{provider}",
            "nonce": "nonce-1",
            "code_verifier": "verifier-1",
        }
    )
    store = _FakeSessionCollection()
    client = _client()
    with ExitStack() as stack:
        for active in _login_patches(login_path, account_id, profile, getuser_has_sub):
            stack.enter_context(active)
        stack.enter_context(_session_store(store))
        response = client.get(
            f"/oauth2/callback/{provider}",
            params={"code": "code-1", "state": "state-1"},
            headers={"Cookie": f"oauth2_temp_session={temp_cookie}"},
            follow_redirects=False,
        )
    client.cookies.clear()
    return _Login(
        status_code=response.status_code,
        cookie=response.cookies.get(SESSION_COOKIE_NAME),
        store=store,
    )


def _cookie_result(
    login: _Login,
) -> dict[str, Any]:
    """Return the validation result the consent path builds from a login's cookie.

    Runs the auth server's own ``validate_session_cookie`` (what ``/validate``
    uses for a cookie) against the session the login wrote.

    Args:
        login: A login that created a session.

    Returns:
        The session-cookie validation result.
    """
    assert login.cookie, (login.status_code, login.store.documents)
    with (
        _session_store(login.store),
        patch.object(server_module, "map_groups_to_scopes", AsyncMock(return_value=[])),
    ):
        result = asyncio.run(server_module.validate_session_cookie(login.cookie))
    assert result["method"] == "session_cookie", result
    return result


def _cookie_key(
    login: _Login,
) -> str:
    """Return the vault key the consent path derives from a login's cookie.

    Args:
        login: A login that created a session.

    Returns:
        ``_canonical_egress_user`` of the session-cookie validation result.
    """
    return server_module._canonical_egress_user(_cookie_result(login))


def _login_key(
    login_path: str,
    account_id: str,
    profile: dict[str, str],
) -> str:
    """Log the account in at ``login_path`` and return its cookie-path key.

    Args:
        login_path: Key of ``LOGIN_PATHS``.
        account_id: The account's immutable id.
        profile: The account's mutable claims.

    Returns:
        The vault key of the resulting session.
    """
    login = _login(login_path, account_id, profile)
    assert login.status_code == 302, (login_path, login.status_code)
    return _cookie_key(login)


def _internal_auth_headers() -> dict[str, str]:
    """Return an Authorization header carrying a valid internal JWT.

    Returns:
        The header dict for ``/internal/tokens``.
    """
    from registry.auth.internal import generate_internal_token

    token = generate_internal_token(subject="test-suite", purpose="unit-test")
    return {"Authorization": f"Bearer {token}"}


def _minted_token_key(
    login: _Login,
) -> str:
    """Mint a user token from the login's session and return its vault key.

    Calls ``/internal/tokens`` the way the registry does for a session-backed
    user, then validates the token as the vend path would.

    Args:
        login: A login that created a session.

    Returns:
        ``_canonical_egress_user`` of the minted token's validation result.
    """
    session_id = server_module.signer.loads(login.cookie)
    document = login.store.documents[0]
    body = {
        "user_context": {
            "username": document["username"],
            "scopes": [],
            "groups": [],
            "auth_method": "oauth2",
            "provider": document["provider"],
            "session_id": session_id,
        },
        "requested_scopes": [],
        "expires_in_hours": 1,
        "description": "vault identity property test",
    }
    server_module.user_token_generation_counts.clear()
    with (
        _session_store(login.store),
        patch.object(server_module, "map_groups_to_scopes", AsyncMock(return_value=[])),
    ):
        response = _client().post("/internal/tokens", json=body, headers=_internal_auth_headers())
    assert response.status_code == 200, response.text
    result = server_module.validator.validate_self_signed_token(response.json()["access_token"])
    return server_module._canonical_egress_user(result)


@st.composite
def _distinct_accounts(
    draw: st.DrawFn,
) -> tuple[str, str, dict[str, str], dict[str, str]]:
    """Draw two distinct account ids and their profiles; often the profiles match.

    Args:
        draw: Hypothesis draw function.

    Returns:
        ``(id_a, id_b, profile_a, profile_b)`` with ``id_a != id_b``.
    """
    id_a = draw(_ACCOUNT_IDS)
    id_b = draw(_ACCOUNT_IDS.filter(lambda s: s != id_a))
    profile_a = draw(_PROFILES)
    profile_b = draw(st.one_of(st.just(profile_a), _PROFILES))
    return id_a, id_b, profile_a, profile_b


def _paths_for(
    provider: str,
) -> tuple[list[str], list[str]]:
    """Return the login paths and bearer paths of ``provider``.

    Args:
        provider: Provider name.

    Returns:
        ``(login_paths, bearer_paths)``.
    """
    logins = [path for path, name in LOGIN_PATHS.items() if name == provider]
    bearers = [path for path, name in BEARER_PATHS.items() if name == provider]
    return logins, bearers


@pytest.mark.parametrize("provider", PROVIDERS_WITH_BOTH_PATHS)
@HYPOTHESIS_SETTINGS
@given(account_id=_ACCOUNT_IDS, profile=_PROFILES)
@example(account_id="0f6c-uuid-new-account", profile=_COLLIDING_PROFILE)
@example(account_id="00u-alice-b", profile=_COLLIDING_PROFILE)
def test_every_path_derives_the_same_vault_key_for_one_account(provider, account_id, profile):
    """Cookie and bearer paths derive one vault key, the immutable account id.

    For every provider with both paths and every account, each login path's
    session-cookie key and each bearer path's key equal the account id.
    """
    logins, bearers = _paths_for(provider)
    keys = {f"login:{path}": _login_key(path, account_id, profile) for path in logins}
    keys.update({f"bearer:{path}": _bearer_key(path, account_id, profile) for path in bearers})
    assert set(keys.values()) == {account_id}, (provider, account_id, keys)


@pytest.mark.parametrize("bearer_path", list(BEARER_PATHS))
@HYPOTHESIS_SETTINGS
@given(accounts=_distinct_accounts())
@example(accounts=_COGNITO_USERNAME_REUSE)
@example(accounts=_OKTA_LOGIN_REASSIGNED)
def test_bearer_vault_key_injective_over_account_id(bearer_path, accounts):
    """Distinct account ids get distinct bearer-path vault keys.

    For every bearer path and every two accounts with distinct immutable ids,
    whatever their mutable claims (identical in the pinned reuse cases), the
    derived keys differ.
    """
    id_a, id_b, profile_a, profile_b = accounts
    key_a = _bearer_key(bearer_path, id_a, profile_a)
    key_b = _bearer_key(bearer_path, id_b, profile_b)
    assert key_a != key_b, (bearer_path, key_a, accounts)


@pytest.mark.parametrize("login_path", list(LOGIN_PATHS))
@HYPOTHESIS_SETTINGS
@given(accounts=_distinct_accounts())
@example(accounts=_COGNITO_USERNAME_REUSE)
@example(accounts=_OKTA_LOGIN_REASSIGNED)
def test_session_vault_key_injective_over_account_id(login_path, accounts):
    """Distinct account ids get distinct session-cookie vault keys.

    For every login path and every two accounts with distinct immutable ids,
    whatever their mutable claims, the sessions the logins create key the
    vault differently.
    """
    id_a, id_b, profile_a, profile_b = accounts
    key_a = _login_key(login_path, id_a, profile_a)
    key_b = _login_key(login_path, id_b, profile_b)
    assert key_a != key_b, (login_path, key_a, accounts)


@pytest.mark.parametrize("bearer_path", list(BEARER_PATHS))
@HYPOTHESIS_SETTINGS
@given(account_id=_ACCOUNT_IDS, before=_PROFILES, after=_PROFILES)
@example(account_id="00u-alice-a", before=_COLLIDING_PROFILE, after=_RENAMED_PROFILE)
def test_bearer_vault_key_stable_under_mutable_claim_edits(bearer_path, account_id, before, after):
    """Changing only mutable claims keeps the bearer-path vault key.

    For every bearer path, account id and two mutable-claim sets, the key is
    the same before and after the edit.
    """
    key_before = _bearer_key(bearer_path, account_id, before)
    key_after = _bearer_key(bearer_path, account_id, after)
    assert key_before == key_after, (bearer_path, key_before, key_after)


@pytest.mark.parametrize("login_path", list(LOGIN_PATHS))
@HYPOTHESIS_SETTINGS
@given(account_id=_ACCOUNT_IDS, before=_PROFILES, after=_PROFILES)
@example(account_id="00u-alice-a", before=_COLLIDING_PROFILE, after=_RENAMED_PROFILE)
def test_session_vault_key_stable_under_mutable_claim_edits(login_path, account_id, before, after):
    """Changing only mutable claims keeps the session-cookie vault key.

    For every login path, account id and two mutable-claim sets, the session
    created before the edit and the one created after key the vault the same.
    """
    key_before = _login_key(login_path, account_id, before)
    key_after = _login_key(login_path, account_id, after)
    assert key_before == key_after, (login_path, key_before, key_after)


@pytest.mark.parametrize(
    "login_path",
    [path for path in LOGIN_PATHS if path not in NON_OIDC_LOGIN_PATHS],
)
@HYPOTHESIS_SETTINGS
@given(profile=_PROFILES)
@example(profile=_COLLIDING_PROFILE)
def test_oidc_login_without_subject_is_refused(login_path, profile):
    """An OIDC login whose IdP response has no subject creates no session.

    For every OIDC login path and every set of mutable claims, a login whose
    token or userInfo response omits the subject returns 401, sets no session
    cookie and writes no session record.
    """
    login = _login(login_path, None, profile)
    assert login.status_code == 401, (login_path, login.status_code, login.store.documents)
    assert login.cookie is None
    assert login.store.documents == []


@pytest.mark.parametrize("login_path", sorted(NON_OIDC_LOGIN_PATHS))
@HYPOTHESIS_SETTINGS
@given(profile=_PROFILES)
def test_non_oidc_login_without_subject_still_creates_session(login_path, profile):
    """A non-OIDC login without a subject still logs in, with no subject stored.

    For GitHub and Google, whose userInfo responses are not OIDC, a response
    missing the configured ``subject_claim`` still creates a session, and the
    session record carries no ``subject``.
    """
    login = _login(login_path, None, profile)
    assert login.status_code == 302, (login_path, login.status_code)
    assert login.cookie
    assert len(login.store.documents) == 1
    assert "subject" not in login.store.documents[0]


@HYPOTHESIS_SETTINGS
@given(client_id=_ACCOUNT_IDS)
@example(client_id="0oa-machine-client")
def test_okta_client_credentials_token_keys_on_its_sub(client_id):
    """An Okta client-credentials token, which has no ``uid``, keys on ``sub``.

    For every client id, a machine token whose ``sub`` and ``cid`` are the
    client id derives the client id as its vault key.
    """
    instance = _provider("okta")
    token = _sign(
        {
            "iss": instance.issuer,
            "aud": WEB_CLIENT_ID,
            "sub": client_id,
            "cid": client_id,
            "scp": ["mcp-servers/read"],
        }
    )
    with patch.object(instance, "get_jwks", return_value=_JWKS):
        result = instance.validate_token(token)
    assert server_module._canonical_egress_user(result) == client_id


@pytest.mark.parametrize(
    "uid",
    [pytest.param("", id="empty"), pytest.param(123, id="int"), pytest.param(["x"], id="list")],
)
def test_okta_uid_counts_only_as_a_nonempty_string(uid):
    """An Okta token whose ``uid`` is empty or not a string keys on ``sub``."""
    key = _bearer_key("okta", "00u-alice", _COLLIDING_PROFILE, extra_claims={"uid": uid})
    assert key == _COLLIDING_PROFILE["login"]


@pytest.mark.parametrize(
    "bearer_path",
    [path for path in BEARER_PATHS if path not in ("okta", "cognito-validator-boto3")],
)
@HYPOTHESIS_SETTINGS
@given(account_id=_ACCOUNT_IDS, uid=_ACCOUNT_IDS)
@example(account_id="user-a", uid="user-b")
def test_uid_claim_ignored_outside_okta(bearer_path, account_id, uid):
    """A ``uid`` claim never changes the vault key of a non-Okta token.

    For every non-Okta bearer path, account id and ``uid`` value, the key is
    the account id.
    """
    key = _bearer_key(bearer_path, account_id, _COLLIDING_PROFILE, extra_claims={"uid": uid})
    assert key == account_id


@HYPOTHESIS_SETTINGS
@given(
    login_path=st.sampled_from(list(LOGIN_PATHS)),
    account_id=_ACCOUNT_IDS,
    profile=_PROFILES,
)
@example(login_path="cognito", account_id="0f6c-uuid-new-account", profile=_COLLIDING_PROFILE)
@example(login_path="okta", account_id="00u-alice-b", profile=_COLLIDING_PROFILE)
def test_token_minted_from_session_keys_like_the_session(login_path, account_id, profile):
    """A gateway-minted user token keys the vault like the session it came from.

    For every login path and account, the self-signed token ``/internal/tokens``
    mints from the session carries ``egress_user`` equal to the session's
    subject, so its vault key equals the session-cookie key.
    """
    login = _login(login_path, account_id, profile)
    assert login.status_code == 302, (login_path, login.status_code)
    cookie_key = _cookie_key(login)
    minted_key = _minted_token_key(login)
    assert minted_key == cookie_key == login.store.documents[0]["subject"], (
        login_path,
        minted_key,
        cookie_key,
    )


_AUDIT_PATHS: list[str] = [f"bearer:{path}" for path in BEARER_PATHS] + [
    f"login:{path}" for path in LOGIN_PATHS
]


@pytest.mark.parametrize("path", _AUDIT_PATHS)
@HYPOTHESIS_SETTINGS
@given(account_id=_ACCOUNT_IDS, profile=_PROFILES)
@example(account_id="00u-alice-b", profile=_COLLIDING_PROFILE)
@example(account_id="0f6c-uuid-new-account", profile=_COLLIDING_PROFILE)
def test_audit_subject_names_the_vault_key(path, account_id, profile):
    """The audit record's ``subject`` is the vault key of the same caller.

    For every bearer path and every login path's session-cookie result, and
    every account, ``_audit_identity_claims(result)["subject"]`` equals
    ``_canonical_egress_user(result)`` whenever that key is non-empty, so an
    audit record joins to the egress connection of the same human.
    """
    kind, name = path.split(":", 1)
    if kind == "bearer":
        result = _bearer_result(name, account_id, profile)
    else:
        login = _login(name, account_id, profile)
        assert login.status_code == 302, (name, login.status_code)
        result = _cookie_result(login)
    vault_key = server_module._canonical_egress_user(result)
    audit_subject = server_module._audit_identity_claims(result)["subject"]
    assert vault_key
    assert audit_subject == vault_key, (path, audit_subject, vault_key)


@HYPOTHESIS_SETTINGS
@given(profile=_PROFILES)
@example(profile=_COLLIDING_PROFILE)
def test_cognito_getuser_without_sub_fails_bearer_validation(profile):
    """A boto3 ``GetUser`` response without ``sub`` is not a valid bearer.

    For every Cognito username and attribute set, when JWT verification is
    unavailable and ``GetUser`` returns no ``sub`` attribute,
    ``SimplifiedCognitoValidator.validate_token`` raises a ``ValueError``
    naming ``sub`` instead of returning a result keyed on the username.
    """
    validator = server_module.SimplifiedCognitoValidator(COGNITO_REGION)
    with (
        patch.object(validator, "validate_jwt_token", side_effect=ValueError("JWKS unreachable")),
        patch.object(
            validator,
            "_get_cognito_client",
            return_value=_cognito_get_user_client(None, profile),
        ),
        pytest.raises(ValueError, match="sub"),
    ):
        validator.validate_token(
            "opaque-access-token", COGNITO_POOL_ID, WEB_CLIENT_ID, COGNITO_REGION
        )


@HYPOTHESIS_SETTINGS
@given(account_id=_ACCOUNT_IDS, profile=_PROFILES)
@example(account_id="0f6c-uuid-new-account", profile=_COLLIDING_PROFILE)
def test_cognito_login_without_getuser_sub_uses_userinfo_sub(account_id, profile):
    """A Cognito login whose ``GetUser`` lacks ``sub`` takes its subject from userInfo.

    For every account, when JWT verification is unavailable and ``GetUser``
    returns no ``sub``, the login falls back to the userInfo endpoint, whose
    ``sub`` becomes the session subject and the vault key.
    """
    login = _login("cognito-boto3", account_id, profile, getuser_has_sub=False)
    assert login.status_code == 302, login.status_code
    assert login.store.documents[0]["subject"] == account_id
    assert _cookie_key(login) == account_id
