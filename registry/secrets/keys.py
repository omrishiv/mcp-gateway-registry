"""Deterministic, collision-free vault-key canonicalization.

The vault key is ``(auth_method, user_id, provider, server_path)`` (LLD B2-1).
The raw values are NOT safe to use verbatim as path/map segments:

- ``user_id`` varies by IdP. Cognito/Okta ``sub`` are UUID/alphanumeric (safe),
  but Keycloak ``preferred_username`` can contain spaces/accents, Entra UPNs
  contain ``@``/``+``, and **Auth0 ``sub`` is ``auth0|abc`` -- the ``|`` would
  collide with the Secrets Manager map delimiter and break OpenBao paths.**
- ``server_path`` contains ``/`` -- the OpenBao KV path separator.

The fix is ONE canonical encoding applied uniformly in every backend:
**Unicode-NFC-normalize, then percent-encode** each segment so no segment can
contain a separator (``/`` or ``|``) or a Unicode look-alike. NFC first
prevents NFC-vs-NFD silent collisions on non-ASCII usernames.

All three SecretStore backends MUST build keys through these helpers so they
agree byte-for-byte (asserted by the cross-store round-trip test).
"""

import unicodedata
from urllib.parse import quote

# Percent-encode EVERYTHING except unreserved RFC 3986 chars. In particular do
# NOT treat "/" or "|" as safe -- they are our segment/map separators and must
# be escaped inside a segment so they cannot be confused with a separator.
_SAFE_SEGMENT_CHARS = ""

# The map delimiter used by the one-secret-per-principal backends (Secrets
# Manager, dev-fernet) to join (provider, server_path) into a single JSON key.
# Encoding guarantees "|" never appears inside an encoded segment, so this is
# an unambiguous split point.
MAP_KEY_DELIMITER = "|"


def encode_segment(value: str) -> str:
    """NFC-normalize then percent-encode a single key segment.

    The result contains only RFC 3986 unreserved characters plus percent
    escapes -- never ``/`` or ``|`` -- so it is safe as an OpenBao path segment,
    a Secrets Manager name component, and a JSON map-key component.
    """
    normalized = unicodedata.normalize("NFC", value or "")
    return quote(normalized, safe=_SAFE_SEGMENT_CHARS)


def user_principal(auth_method: str, user_id: str) -> str:
    """Build the per-user namespace prefix ``enc(auth_method)/enc(user_id)``.

    This is the vault prefix under which all of one principal's connections
    live. ``LIST`` / iterate under it enumerates the principal's connections.
    Two segments joined by ``/``; each segment is separator-free after encoding.
    """
    return f"{encode_segment(auth_method)}/{encode_segment(user_id)}"


def map_key(provider: str, server_path: str) -> str:
    """Build the per-connection map key ``enc(provider)|enc(server_path)``.

    Used by the one-secret-per-principal backends to key the JSON map. Encoding
    guarantees the delimiter never appears inside either segment.
    """
    return f"{encode_segment(provider)}{MAP_KEY_DELIMITER}{encode_segment(server_path)}"


def openbao_path(
    prefix: str,
    auth_method: str,
    user_id: str,
    provider: str,
    server_path: str,
) -> str:
    """Build the OpenBao KV-v2 logical path for one connection.

    ``{prefix}/{enc(auth_method)}/{enc(user_id)}/{enc(provider)}/{enc(server_path)}``
    -- ``/`` only ever appears between encoded segments.
    """
    return (
        f"{prefix.strip('/')}/"
        f"{encode_segment(auth_method)}/{encode_segment(user_id)}/"
        f"{encode_segment(provider)}/{encode_segment(server_path)}"
    )
