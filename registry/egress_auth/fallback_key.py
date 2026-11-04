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

# Marks a username-fallback key. No account id an identity provider issues
# starts with it (UUIDs, numeric ids, emails, ``auth0|...``, Okta ``00u...``).
FALLBACK_KEY_PREFIX: str = "name:"


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
