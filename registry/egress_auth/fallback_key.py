"""The vault ``user_id`` for a login that carries no account id.

Every identity provider shares one vault namespace, ``(oauth2, user_id)``. An
account id (an OIDC ``sub``, a GitHub numeric id, an Okta ``uid``) is unique
within its provider and does not collide with another provider's in practice.
A username is different: a GitHub, Google or custom login that maps no subject
keys the vault on whatever the provider's ``username_claim`` returns, and that
value can equal an account id another provider issues (a PingFederate ``sub``
that holds an email, for example). Only those fallback keys are namespaced
here, so no account-id key changes.

Both places that apply the fallback call :func:`username_fallback_key`: the
auth server's ``_canonical_egress_user`` (step 5, which every internal token
carries to the registry) and the registry's raw session-cookie path
(``registry.auth.dependencies.enhanced_auth``, which the consent callback
uses). One function keeps the consent write and the vend on one key.
"""

from urllib.parse import quote

# Marks a username-fallback key. An account id that starts with it is refused
# (no login, no vault key; see ``is_fallback_shaped``): a provider whose
# ``subject_claim`` names a user-chosen value could otherwise return the
# fallback key of another user.
FALLBACK_KEY_PREFIX: str = "name:"


def is_fallback_shaped(
    account_id: object,
) -> bool:
    """Return True when an account id has the shape of a username-fallback key.

    Every account id that would key the vault passes through this check, at
    login (``_require_login_subject``) and wherever a key is derived (the
    auth server's ``_canonical_egress_user`` and the registry's
    ``enhanced_auth``). Such an id keys nothing, so it can never read the
    connections of the subject-less login whose fallback key it equals.

    Args:
        account_id: The account id an identity provider returned.

    Returns:
        True for a string that starts with ``FALLBACK_KEY_PREFIX``.
    """
    return isinstance(account_id, str) and account_id.startswith(FALLBACK_KEY_PREFIX)


def username_fallback_key(
    provider: object,
    username: object,
) -> str:
    """Return the namespaced vault ``user_id`` for a login with no account id.

    The key is ``name:<quoted provider>:<username>``. The provider is
    percent-encoded with no safe characters, so it never contains ``:`` and the
    first ``:`` after the prefix always ends it. That makes the key injective
    over ``(provider, username)``: a provider name containing ``:`` cannot
    produce another provider's key. The username follows verbatim; the vault
    encodes each key segment separately (``registry/secrets/keys.py``), so the
    ``:`` characters are safe there.

    Args:
        provider: The login provider recorded on the session (``github``,
            ``google`` or an operator-added name). A non-string counts as ``""``.
        username: The session's username.

    Returns:
        The fallback key, or ``""`` when ``username`` is not a non-empty string,
        so the caller owns no per-user bucket.

    Example:
        >>> username_fallback_key("github", "alice")
        'name:github:alice'
    """
    if not isinstance(username, str) or not username:
        return ""
    provider_name = provider if isinstance(provider, str) else ""
    return f"{FALLBACK_KEY_PREFIX}{quote(provider_name, safe='')}:{username}"
