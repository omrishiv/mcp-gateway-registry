"""Property tests: a token's ``groups`` claim is accepted only as a JSON array of strings.

``normalize_groups_claim`` is the single gate every self-signed and IdP token
path uses to read group membership, and groups decide scopes and admin rights.
For any JSON value it must return a list of strings unchanged, map a null or
absent claim to an empty list, and reject everything else. It must never coerce
a string into a one-element list, a dict into its keys, or drop non-string
members, because each of those would invent or reshape group membership. The
same holds end to end for every self-signed token validator that reads the
claim.
"""

from __future__ import annotations

import copy
import importlib
import os
import time
from collections.abc import Iterator
from contextlib import (
    ExitStack,
    contextmanager,
)
from types import ModuleType
from typing import Any
from unittest.mock import patch

import jwt as pyjwt
import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

pytestmark = [pytest.mark.unit, pytest.mark.auth]


SECRET: str = "groups-claim-properties-secret-key-for-unit-tests-only-not-production-0123"

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
# (``auth_server/`` is on ``sys.path``); those are the copies that run.
_PROVIDER_PACKAGE: str = "providers"

SELF_SIGNED_VALIDATORS: tuple[str, ...] = (
    "auth_server",
    *PROVIDERS,
)

# Marks a token minted with no ``groups`` claim at all.
_ABSENT = object()

HYPOTHESIS_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=12),
)

_JSON_VALUES = st.recursive(
    _JSON_SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=8), children, max_size=4),
    ),
    max_leaves=12,
)

# Values most likely to be coerced by a lenient implementation.
_COERCION_BAIT: tuple[Any, ...] = (
    "mcp-registry-admin",
    "",
    "a,b",
    ["admin", 1],
    ["admin", None],
    [["admin"]],
    {"admin": True},
    {"groups": ["admin"]},
    0,
    False,
    True,
    1.5,
)


def _is_list_of_str(
    value: Any,
) -> bool:
    """Return whether ``value`` is a list whose every element is a ``str``.

    Args:
        value: Any JSON value.

    Returns:
        True for a (possibly empty) list of strings.
    """
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


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


@contextmanager
def _shared_secret() -> Iterator[None]:
    """Pin ``SECRET_KEY`` for the auth server and every provider module.

    Yields:
        None, while the patches are active.
    """
    import auth_server.server as server_module

    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, {"SECRET_KEY": SECRET}))
        stack.enter_context(patch.object(server_module, "SECRET_KEY", SECRET))
        for name in PROVIDERS:
            stack.enter_context(patch.object(_provider_module(name), "SECRET_KEY", SECRET))
        yield


def _self_signed_token(
    groups: Any,
) -> str:
    """Encode a valid self-signed user token carrying ``groups``.

    Args:
        groups: The ``groups`` claim, or ``_ABSENT`` to omit it.

    Returns:
        The HS256 token, signed with ``SECRET``.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "mcp-auth-server",
        "aud": "mcp-registry",
        "sub": "alice",
        "scope": "servers-read",
        "token_use": "access",
        "iat": now,
        "exp": now + 600,
    }
    if groups is not _ABSENT:
        claims["groups"] = groups
    return pyjwt.encode(claims, SECRET, algorithm="HS256")


def _validate(
    validator: str,
    token: str,
) -> dict[str, Any]:
    """Run the named self-signed validator on ``token``.

    Args:
        validator: ``auth_server`` or a provider name.
        token: Encoded token.

    Returns:
        The validation result dict.

    Raises:
        ValueError: The validator rejected the token.
    """
    import auth_server.server as server_module

    if validator == "auth_server":
        return server_module.validator.validate_self_signed_token(token)
    cls = getattr(_provider_module(validator), _PROVIDER_CLASSES[validator])
    return cls.__new__(cls)._validate_self_signed_token(token)


@HYPOTHESIS_SETTINGS
@given(value=_JSON_VALUES)
@example(value=None)
@example(value=[])
@example(value=["mcp-registry-admin", ""])
@example(value="mcp-registry-admin")
@example(value=["admin", 1])
@example(value={"admin": True})
def test_normalize_groups_claim_accepts_only_string_arrays(value):
    """``normalize_groups_claim`` never coerces a claim into group membership.

    For any JSON value v: a list of strings is returned equal to v and v is not
    mutated; ``None`` returns ``[]``; anything else raises ``ValueError``.
    """
    from providers.base import normalize_groups_claim

    before = copy.deepcopy(value)
    if value is None:
        assert normalize_groups_claim(value, source="test") == []
    elif _is_list_of_str(value):
        result = normalize_groups_claim(value, source="test")
        assert result == before
        assert all(type(item) is str for item in result)
    else:
        with pytest.raises(ValueError):
            normalize_groups_claim(value, source="test")
    assert value == before, "normalize_groups_claim mutated its input"


@pytest.mark.parametrize("validator", SELF_SIGNED_VALIDATORS)
@pytest.mark.parametrize(
    "groups",
    [_ABSENT, None, [], ["developers"], ["a", ""], *_COERCION_BAIT],
    ids=lambda value: "absent" if value is _ABSENT else repr(value),
)
def test_self_signed_validators_reject_malformed_groups(validator, groups):
    """Every self-signed validator applies the groups gate to a signed token.

    For each validator and each claim shape: an absent or null claim yields
    ``[]``, a list of strings yields exactly that list, and any other shape
    makes the validator reject an otherwise valid, correctly signed token.
    """
    with _shared_secret():
        token = _self_signed_token(groups)
        if groups is _ABSENT or groups is None:
            assert _validate(validator, token)["groups"] == []
        elif _is_list_of_str(groups):
            assert _validate(validator, token)["groups"] == groups
        else:
            with pytest.raises(ValueError):
                _validate(validator, token)
