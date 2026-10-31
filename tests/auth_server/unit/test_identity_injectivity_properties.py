"""Property tests: the ownership identity is injective over issuer and subject.

Ownership checks compare a record's ``owner_id`` with the caller's ``owner_id``.
That owner_id is derived from IdP claims on two paths: the OAuth2 login
callback writes it into the browser session (the cookie path), and each
provider's ``validate_token`` returns it for a bearer token (the bearer path).
The security property pinned here is that the derived owner_id behaves as an
owner key: two accounts with distinct ``(iss, sub)`` never share it, an account
keeps it when only its mutable profile claims (``preferred_username``,
``email``, ``nickname``, ``login``, ``upn``) change, and the cookie path and the
bearer path derive the same one from the same claims. ``username`` stays the
display name with its existing derivation, pinned separately. Signatures are
not under test: bearer tokens are really signed and verified against a test
JWKS, and on the login path the provider's id_token verification returns the
claims as verified.
"""

from __future__ import annotations

import functools
import json
import os
import string
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import (
    AsyncMock,
    patch,
)

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import (
    assume,
    example,
    given,
    settings,
)
from hypothesis import strategies as st
from jwt.algorithms import RSAAlgorithm

os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-definitely-long-enough-32b")

from providers.auth0 import Auth0Provider  # noqa: E402
from providers.cognito import CognitoProvider  # noqa: E402
from providers.entra import EntraIdProvider  # noqa: E402
from providers.keycloak import KeycloakProvider  # noqa: E402
from providers.okta import OktaProvider  # noqa: E402
from providers.pingfederate import PingFederateProvider  # noqa: E402

import auth_server.server as server_module  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.auth]


KID: str = "identity-injectivity-kid"
WEB_CLIENT_ID: str = "gateway-web"
COGNITO_POOL_ID: str = "us-east-1_TESTPOOL"
COGNITO_REGION: str = "us-east-1"
PINGFEDERATE_ISSUER: str = "https://pf.example.com"
OAUTH2_PROVIDERS_YML: Path = (
    Path(__file__).resolve().parents[3] / "auth_server" / "oauth2_providers.yml"
)

# Profile claims an account holder or IdP administrator can change, and that a
# different account can later hold.
MUTABLE_CLAIMS: tuple[str, ...] = (
    "preferred_username",
    "email",
    "nickname",
    "login",
    "upn",
)

# Providers with a bearer path (an ``AuthProvider`` with ``validate_token``).
BEARER_PROVIDERS: tuple[str, ...] = (
    "keycloak",
    "entra",
    "okta",
    "auth0",
    "cognito",
    "pingfederate",
)

# Login paths through ``/oauth2/callback/{provider}``: login path id -> provider.
# The bare provider names use the verified id_token (or, for Cognito, the
# verified access token). ``-userinfo`` paths are the userInfo fallback taken
# when the token response has no id_token (or Cognito has no pool configured);
# GitHub and Google only have the userInfo path.
LOGIN_PATHS: dict[str, str] = {
    "keycloak": "keycloak",
    "entra": "entra",
    "okta": "okta",
    "auth0": "auth0",
    "pingfederate": "pingfederate",
    "cognito": "cognito",
    "keycloak-userinfo": "keycloak",
    "okta-userinfo": "okta",
    "auth0-userinfo": "auth0",
    "pingfederate-userinfo": "pingfederate",
    "cognito-userinfo": "cognito",
    "github": "github",
    "google": "google",
}

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
    "login": "alice",
    "upn": "alice@example.com",
}

# The same account after a rename: every profile claim has a new value.
_RENAMED_PROFILE: dict[str, str] = {
    "preferred_username": "alice.smith",
    "email": "alice.smith@example.com",
    "nickname": "alice.smith",
    "login": "alice-smith",
    "upn": "alice.smith@example.com",
}

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

_SUBJECTS = st.text(alphabet=string.ascii_lowercase + string.digits + "-", min_size=1, max_size=16)
_CLAIM_VALUES = st.text(
    alphabet=string.ascii_lowercase + string.digits + "._@-", min_size=1, max_size=16
)
_PROFILES = st.dictionaries(
    keys=st.sampled_from(MUTABLE_CLAIMS),
    values=_CLAIM_VALUES,
    max_size=len(MUTABLE_CLAIMS),
)


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
        name: Provider name, one of ``BEARER_PROVIDERS``.

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


def _account_claims(
    provider: str,
    sub: str,
    profile: dict[str, str],
) -> dict[str, Any]:
    """Build the identity claims an account at ``provider`` presents.

    ``sub`` is the account's immutable subject. Cognito additionally carries a
    ``username`` claim, which Cognito fixes at account creation and keeps
    unique per pool, so it is derived from ``sub`` rather than drawn.

    Args:
        provider: Provider name.
        sub: The account's subject.
        profile: The account's mutable profile claims.

    Returns:
        The identity claims (no protocol claims such as ``iss`` or ``exp``).
    """
    claims: dict[str, Any] = {"sub": sub, **profile}
    if provider == "cognito":
        claims["username"] = f"pool-user-{sub}"
    return claims


def _bearer_result(
    provider: str,
    identity_claims: dict[str, Any],
) -> dict[str, Any]:
    """Return the provider's ``validate_token`` result for the claims.

    The claims are signed into a user access token that the provider accepts
    (issuer, audience and expiry set for it) and verified for real.

    Args:
        provider: Provider name, one of ``BEARER_PROVIDERS``.
        identity_claims: The account's identity claims.

    Returns:
        The validation result.
    """
    instance = _provider(provider)
    now = int(time.time())
    claims: dict[str, Any] = {**identity_claims, "iat": now, "exp": now + 600}
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
    token = jwt.encode(claims, _PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})
    with patch.object(instance, "get_jwks", return_value=_JWKS):
        result = instance.validate_token(token)
    assert result["valid"] is True, result
    return result


def _bearer_identity(
    provider: str,
    identity_claims: dict[str, Any],
) -> str | None:
    """Return the owner_id the provider's ``validate_token`` derives.

    Args:
        provider: Provider name, one of ``BEARER_PROVIDERS``.
        identity_claims: The account's identity claims.

    Returns:
        ``validation_result["owner_id"]``, or None when absent.
    """
    return _bearer_result(provider, identity_claims).get("owner_id")


def _cookie_session(
    login_path: str,
    identity_claims: dict[str, Any],
) -> dict[str, Any]:
    """Drive ``/oauth2/callback`` and return the fields written to the session.

    The code exchange, the userInfo fetch and id_token verification are
    replaced so the claims arrive as verified; the callback's own mapping from
    claims to session fields runs unchanged.

    Args:
        login_path: Key of ``LOGIN_PATHS``.
        identity_claims: The account's identity claims.

    Returns:
        The ``create_session`` keyword arguments, empty when the login created
        no session.
    """
    provider = LOGIN_PATHS[login_path]
    userinfo_path = login_path.endswith("-userinfo") or provider in ("github", "google")
    provider_config = _yml_provider_config(provider)

    userinfo = dict(identity_claims)
    subject_claim = provider_config.get("subject_claim")
    if subject_claim:
        userinfo[subject_claim] = userinfo.pop("sub")

    token_data: dict[str, Any] = {"access_token": "opaque-access-token"}
    if not userinfo_path and provider != "cognito":
        token_data["id_token"] = "opaque-id-token"

    temp_cookie = server_module.signer.dumps(
        {
            "state": "state-1",
            "provider": provider,
            "callback_uri": f"http://localhost:8888/oauth2/callback/{provider}",
            "nonce": "nonce-1",
            "code_verifier": "verifier-1",
        }
    )
    captured: dict[str, Any] = {}

    async def _create_session(**kwargs: Any) -> str:
        captured.update(kwargs)
        return "session-1"

    providers_by_name = {name: _provider(name) for name in BEARER_PROVIDERS}
    config = dict(server_module.OAUTH2_CONFIG)
    config["providers"] = {**config.get("providers", {}), provider: provider_config}

    env = _clean_env()
    if login_path == "cognito":
        env.update(COGNITO_USER_POOL_ID=COGNITO_POOL_ID, AWS_REGION=COGNITO_REGION)
    else:
        env.pop("COGNITO_USER_POOL_ID", None)

    verified = dict(identity_claims)
    patches = [
        patch.dict(os.environ, env, clear=True),
        patch.object(server_module, "OAUTH2_CONFIG", config),
        patch.object(server_module, "IDP_USER_GROUP_FALLBACK_ENABLED_PROVIDERS", []),
        patch.object(
            server_module,
            "exchange_code_for_token",
            AsyncMock(return_value=token_data),
        ),
        patch.object(server_module, "get_user_info", AsyncMock(return_value=userinfo)),
        patch.object(
            server_module,
            "get_auth_provider",
            side_effect=lambda name=None: providers_by_name[name],
        ),
        patch.object(
            server_module.SimplifiedCognitoValidator,
            "validate_jwt_token",
            return_value=verified,
        ),
        patch("group_filter.filter_session_groups", AsyncMock(side_effect=lambda g, **_: g)),
        patch("session_store.create_session", _create_session),
    ]
    patches.extend(
        patch.object(instance, "validate_id_token", return_value=verified)
        for instance in providers_by_name.values()
    )
    with ExitStack() as stack:
        for active in patches:
            stack.enter_context(active)
        _client().get(
            f"/oauth2/callback/{provider}",
            params={"code": "code-1", "state": "state-1"},
            headers={"Cookie": f"oauth2_temp_session={temp_cookie}"},
            follow_redirects=False,
        )
    return captured


def _cookie_identity(
    login_path: str,
    identity_claims: dict[str, Any],
) -> str | None:
    """Return the owner_id the login callback writes to the session.

    Args:
        login_path: Key of ``LOGIN_PATHS``.
        identity_claims: The account's identity claims.

    Returns:
        The session owner_id, or None when the login created no session or
        derived no owner_id.
    """
    return _cookie_session(login_path, identity_claims).get("owner_id") or None


@st.composite
def _distinct_accounts(
    draw: st.DrawFn,
) -> tuple[str, str, dict[str, str], dict[str, str]]:
    """Draw two distinct subjects and their profiles; often the profiles collide.

    Args:
        draw: Hypothesis draw function.

    Returns:
        ``(sub_a, sub_b, profile_a, profile_b)`` with ``sub_a != sub_b``.
    """
    sub_a = draw(_SUBJECTS)
    sub_b = draw(_SUBJECTS.filter(lambda s: s != sub_a))
    profile_a = draw(_PROFILES)
    profile_b = draw(st.one_of(st.just(profile_a), _PROFILES))
    return sub_a, sub_b, profile_a, profile_b


_COLLISION_EXAMPLE = ("user-a", "user-b", _COLLIDING_PROFILE, _COLLIDING_PROFILE)
# One account's subject equals another account's profile handle.
_NAMESPACE_MIX_EXAMPLE = ("alice", "user-b", {}, {"preferred_username": "alice", "login": "alice"})


@pytest.mark.parametrize(
    "provider",
    [pytest.param(p, id=p) for p in BEARER_PROVIDERS],
)
@HYPOTHESIS_SETTINGS
@given(accounts=_distinct_accounts())
@example(accounts=_COLLISION_EXAMPLE)
@example(accounts=_NAMESPACE_MIX_EXAMPLE)
def test_bearer_identity_injective_over_subject(provider, accounts):
    """Distinct subjects at one issuer get distinct bearer-path owner_ids.

    For every provider and every two accounts with distinct ``sub`` at the
    provider's issuer, whatever their profile claims (identical in the pinned
    collision), ``validate_token`` derives different owner_ids.
    """
    sub_a, sub_b, profile_a, profile_b = accounts
    identity_a = _bearer_identity(provider, _account_claims(provider, sub_a, profile_a))
    identity_b = _bearer_identity(provider, _account_claims(provider, sub_b, profile_b))
    assert identity_a != identity_b, (provider, identity_a, accounts)


@pytest.mark.parametrize(
    "provider",
    [pytest.param(p, id=p) for p in BEARER_PROVIDERS],
)
@HYPOTHESIS_SETTINGS
@given(sub=_SUBJECTS, before=_PROFILES, after=_PROFILES)
@example(sub="user-a", before=_COLLIDING_PROFILE, after=_RENAMED_PROFILE)
def test_bearer_identity_stable_under_profile_edits(provider, sub, before, after):
    """Editing only profile claims keeps the bearer-path owner_id.

    For every provider, account ``sub`` and two profile-claim sets, the
    owner_id ``validate_token`` derives is the same before and after the edit.
    """
    identity_before = _bearer_identity(provider, _account_claims(provider, sub, before))
    identity_after = _bearer_identity(provider, _account_claims(provider, sub, after))
    assert identity_before == identity_after, (provider, identity_before, identity_after)


@pytest.mark.parametrize(
    "login_path",
    [pytest.param(p, id=p) for p in LOGIN_PATHS],
)
@HYPOTHESIS_SETTINGS
@given(accounts=_distinct_accounts())
@example(accounts=_COLLISION_EXAMPLE)
@example(accounts=_NAMESPACE_MIX_EXAMPLE)
def test_session_identity_injective_over_subject(login_path, accounts):
    """Distinct subjects at one issuer get distinct session owner_ids.

    For every login path and every two accounts with distinct ``sub`` at that
    provider, whatever their profile claims, the logins that create a session
    store different owner_ids in it.
    """
    provider = LOGIN_PATHS[login_path]
    sub_a, sub_b, profile_a, profile_b = accounts
    identity_a = _cookie_identity(login_path, _account_claims(provider, sub_a, profile_a))
    identity_b = _cookie_identity(login_path, _account_claims(provider, sub_b, profile_b))
    assume(identity_a is not None and identity_b is not None)
    assert identity_a != identity_b, (login_path, identity_a, accounts)


@pytest.mark.parametrize(
    "login_path",
    [pytest.param(p, id=p) for p in LOGIN_PATHS],
)
@HYPOTHESIS_SETTINGS
@given(sub=_SUBJECTS, before=_PROFILES, after=_PROFILES)
@example(sub="user-a", before=_COLLIDING_PROFILE, after=_RENAMED_PROFILE)
def test_session_identity_stable_under_profile_edits(login_path, sub, before, after):
    """Editing only profile claims keeps the session owner_id.

    For every login path, account ``sub`` and two profile-claim sets that both
    produce a session, the session owner_id is the same before and after.
    """
    provider = LOGIN_PATHS[login_path]
    identity_before = _cookie_identity(login_path, _account_claims(provider, sub, before))
    identity_after = _cookie_identity(login_path, _account_claims(provider, sub, after))
    assume(identity_before is not None and identity_after is not None)
    assert identity_before == identity_after, (login_path, identity_before, identity_after)


@pytest.mark.parametrize(
    "provider",
    [pytest.param(p, id=p) for p in BEARER_PROVIDERS],
)
@HYPOTHESIS_SETTINGS
@given(sub=_SUBJECTS, profile=_PROFILES)
@example(sub="user-a", profile={"email": "alice@example.com"})
def test_session_identity_matches_bearer_identity(provider, sub, profile):
    """The cookie path and the bearer path derive the same owner_id.

    For every provider with both paths and every claim set, the owner_id the
    login callback stores in the session equals the owner_id
    ``validate_token`` returns for a bearer token carrying the same claims.
    """
    claims = _account_claims(provider, sub, profile)
    cookie_identity = _cookie_identity(provider, claims)
    bearer_identity = _bearer_identity(provider, claims)
    assert cookie_identity == bearer_identity, (provider, cookie_identity, bearer_identity, claims)


_CROSS_PROVIDER_PAIRS: list[tuple[str, str]] = [
    (a, b) for a in LOGIN_PATHS for b in LOGIN_PATHS if LOGIN_PATHS[a] < LOGIN_PATHS[b]
]


@HYPOTHESIS_SETTINGS
@given(
    pair=st.sampled_from(_CROSS_PROVIDER_PAIRS),
    sub_a=_SUBJECTS,
    sub_b=_SUBJECTS,
    profile=_PROFILES,
)
@example(pair=("github", "keycloak"), sub_a="1001", sub_b="1001", profile=_COLLIDING_PROFILE)
def test_session_identity_injective_across_issuers(pair, sub_a, sub_b, profile):
    """Accounts at two different issuers never share a session owner_id.

    Several login providers can be enabled at once. For every two login paths
    of different providers, any two subjects (equal or not) and the same
    profile claims, the session owner_ids differ, because ``(iss, sub)``
    differs.
    """
    path_a, path_b = pair
    identity_a = _cookie_identity(path_a, _account_claims(LOGIN_PATHS[path_a], sub_a, profile))
    identity_b = _cookie_identity(path_b, _account_claims(LOGIN_PATHS[path_b], sub_b, profile))
    assume(identity_a is not None and identity_b is not None)
    assert identity_a != identity_b, (pair, identity_a, sub_a, sub_b, profile)


# The display username each path derives for subject ``user-a`` with
# ``_COLLIDING_PROFILE``. Ownership moved to owner_id; username is unchanged.
_EXPECTED_BEARER_USERNAMES: dict[str, str] = {
    "keycloak": "alice",
    "entra": "alice",
    "okta": "user-a",
    "auth0": "alice",
    "cognito": "pool-user-user-a",
    "pingfederate": "user-a",
}
_EXPECTED_SESSION_USERNAMES: dict[str, str] = {
    "keycloak": "alice",
    "entra": "alice",
    "okta": "alice",
    "auth0": "alice",
    "pingfederate": "alice",
    "cognito": "pool-user-user-a",
    "keycloak-userinfo": "alice",
    "okta-userinfo": "alice",
    "auth0-userinfo": "alice",
    "pingfederate-userinfo": "alice",
    "cognito-userinfo": "alice@example.com",
    "github": "alice",
    "google": "alice@example.com",
}


@pytest.mark.parametrize("provider", BEARER_PROVIDERS)
def test_bearer_username_derivation_unchanged(provider):
    """``validate_token`` keeps its display username and also yields an owner_id."""
    result = _bearer_result(provider, _account_claims(provider, "user-a", _COLLIDING_PROFILE))
    assert result["username"] == _EXPECTED_BEARER_USERNAMES[provider]
    assert result.get("owner_id")


@pytest.mark.parametrize("login_path", list(LOGIN_PATHS))
def test_session_username_derivation_unchanged(login_path):
    """Every login path keeps its session username and stores an owner_id."""
    provider = LOGIN_PATHS[login_path]
    session = _cookie_session(login_path, _account_claims(provider, "user-a", _COLLIDING_PROFILE))
    assert session.get("username") == _EXPECTED_SESSION_USERNAMES[login_path]
    assert session.get("owner_id")
