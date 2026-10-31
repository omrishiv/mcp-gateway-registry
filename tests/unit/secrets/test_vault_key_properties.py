"""Injectivity of the vault-key encoders and of the credential AAD binding.

A per-user egress credential is addressed by ``(auth_method, user_id,
provider, server_path, purpose)``. Two addresses must share a vault path, map
key or AEAD associated data only when they are the same address up to Unicode
NFC normalization; otherwise one user's credential could be read, overwritten
or authenticated at another user's address. These tests decode each encoding
back to its NFC-normalized inputs (which proves injectivity), check the
``encode_segment`` collision rule both ways, and check that a ciphertext sealed
at one address never decrypts at a different one.
"""

import re
import unicodedata

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.egress_auth.schemas import StoredToken
from registry.secrets import keys
from registry.secrets.credential_codec import (
    _AAD_PREFIX,
    _ALGORITHM,
    _ENVELOPE_VERSION,
    _KEY_ID,
    CredentialCodec,
    build_credential_codec,
)
from registry.secrets.interfaces import SecretStoreError

_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_ROOT_KEY: str = "unit-test-egress-root-key-abcdefghijklmnop"

_PREFIX: str = "secret/data/egress"

_SEGMENT_RE = re.compile(r"[A-Za-z0-9_\-]*")

# Separators, base64 alphabet characters, and a decomposable letter with its
# combining mark, so NFC and NFD forms of one string are drawn often.
_TRICKY_ALPHABET: str = "/|=+%:aAe\u00e9\u0301\u00c5\u212b\ufb01 "

_FIELDS = st.one_of(
    st.text(alphabet=_TRICKY_ALPHABET, max_size=8),
    st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=16),
)

_PURPOSES = st.one_of(
    st.sampled_from([keys.EGRESS_PURPOSE, keys.DISCOVERY_PURPOSE, ""]),
    _FIELDS,
)

_ADDRESSES = st.tuples(_FIELDS, _FIELDS, _FIELDS, _FIELDS, _PURPOSES)

_TOKEN = StoredToken(
    access_token="gho_property_secret",
    refresh_token="rt_property_secret",
    scopes=["repo"],
)


def _nfc(
    value: str,
) -> str:
    """Return the NFC form of ``value``.

    Args:
        value: Any string.

    Returns:
        ``unicodedata.normalize("NFC", value)``.
    """
    return unicodedata.normalize("NFC", value)


def _canonical(
    address: tuple[str, ...],
) -> tuple[str, ...]:
    """Map an address to the form under which encodings must coincide.

    Args:
        address: Any tuple of key segments.

    Returns:
        The tuple with every segment NFC-normalized.
    """
    return tuple(_nfc(part) for part in address)


@st.composite
def _address_pairs(draw) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Draw two addresses that are often equal, NFC-equivalent or one field apart.

    Args:
        draw: Hypothesis draw function.

    Returns:
        A pair of 5-tuple addresses.
    """
    first = draw(_ADDRESSES)
    mode = draw(st.sampled_from(["nfd", "one-field", "independent"]))
    if mode == "nfd":
        second = tuple(unicodedata.normalize("NFD", part) for part in first)
    elif mode == "one-field":
        index = draw(st.integers(min_value=0, max_value=4))
        replacement = draw(_PURPOSES if index == 4 else _FIELDS)
        second = first[:index] + (replacement,) + first[index + 1 :]
    else:
        second = draw(_ADDRESSES)
    return first, second


def _decode_openbao_path(
    path: str,
) -> tuple[str, ...]:
    """Recover the NFC address from an ``openbao_path`` under ``_PREFIX``.

    Args:
        path: A path built by ``keys.openbao_path`` with ``_PREFIX``.

    Returns:
        ``(auth_method, user_id, provider, server_path, purpose)``.

    Raises:
        ValueError: If ``path`` does not have the expected shape.
    """
    head = _PREFIX + "/"
    if not path.startswith(head):
        raise ValueError(path)
    segments = path[len(head) :].split("/")
    if len(segments) == 4:
        purpose = keys.EGRESS_PURPOSE
    elif len(segments) == 5:
        purpose = keys.decode_segment(segments.pop(0))
    else:
        raise ValueError(path)
    return (*(keys.decode_segment(segment) for segment in segments), purpose)


def _decode_aad(
    aad: bytes,
) -> tuple[str, ...]:
    """Recover the NFC address from credential AAD with the current envelope.

    Args:
        aad: Bytes built by ``CredentialCodec._aad``.

    Returns:
        ``(auth_method, user_id, provider, server_path, purpose)``.

    Raises:
        ValueError: If ``aad`` does not have the expected shape.
    """
    if not aad.startswith(_AAD_PREFIX):
        raise ValueError(aad)
    fields = aad[len(_AAD_PREFIX) :].decode("ascii").split("|")
    if fields[:3] != [str(_ENVELOPE_VERSION), _ALGORITHM, _KEY_ID]:
        raise ValueError(aad)
    segments = fields[3:]
    if len(segments) == 4:
        purpose = keys.EGRESS_PURPOSE
    elif len(segments) == 5:
        purpose = keys.decode_segment(segments.pop())
    else:
        raise ValueError(aad)
    return (*(keys.decode_segment(segment) for segment in segments), purpose)


def _aad(
    address: tuple[str, ...],
) -> bytes:
    """Build the credential AAD for ``address`` with the current envelope.

    Args:
        address: ``(auth_method, user_id, provider, server_path, purpose)``.

    Returns:
        The associated data the codec binds the ciphertext to.
    """
    return CredentialCodec._aad(_ENVELOPE_VERSION, _ALGORITHM, _KEY_ID, *address)


def _openbao_path(
    address: tuple[str, ...],
) -> str:
    """Build the OpenBao path for ``address`` under ``_PREFIX``.

    Args:
        address: ``(auth_method, user_id, provider, server_path, purpose)``.

    Returns:
        The KV-v2 logical path.
    """
    *segments, purpose = address
    return keys.openbao_path(_PREFIX, *segments, purpose=purpose)


@pytest.mark.unit
class TestEncodeSegment:
    """``encode_segment`` collides exactly on NFC-equivalent inputs."""

    @_SETTINGS
    @given(pair=_address_pairs())
    @example(pair=(("\u00e9",) * 5, ("e\u0301",) * 5))
    @example(pair=(("\u00c5",) * 5, ("\u212b",) * 5))
    @example(pair=(("\ufb01",) * 5, ("fi",) * 5))
    def test_equal_iff_nfc_equal(self, pair):
        """Property: encode_segment(a) == encode_segment(b) iff NFC(a) == NFC(b)."""
        for left, right in zip(*pair, strict=True):
            same_encoding = keys.encode_segment(left) == keys.encode_segment(right)
            assert same_encoding == (_nfc(left) == _nfc(right)), (left, right)

    @_SETTINGS
    @given(value=_FIELDS)
    def test_decode_returns_nfc_form(self, value):
        """Property: decode_segment(encode_segment(a)) == NFC(a)."""
        assert keys.decode_segment(keys.encode_segment(value)) == _nfc(value)

    @_SETTINGS
    @given(value=_FIELDS)
    def test_alphabet_has_no_separator(self, value):
        """Property: an encoded segment uses only [A-Za-z0-9_-] (no '/', '|', '=')."""
        assert _SEGMENT_RE.fullmatch(keys.encode_segment(value))


@pytest.mark.unit
class TestVaultAddressInjectivity:
    """Vault paths and map keys decode back to the NFC address."""

    @_SETTINGS
    @given(address=_ADDRESSES)
    @example(address=("a", "b", "c", "d", keys.EGRESS_PURPOSE))
    @example(address=("a", "b", "c", "d", ""))
    @example(address=("", "", "", "", keys.DISCOVERY_PURPOSE))
    def test_openbao_path_decodes(self, address):
        """Property: openbao_path decodes to exactly NFC(address), so it is injective."""
        assert _decode_openbao_path(_openbao_path(address)) == _canonical(address)

    @_SETTINGS
    @given(pair=_address_pairs())
    @example(pair=(("a", "b", "c", "d", "egress"), ("a", "b", "c", "d", "discovery")))
    def test_openbao_path_equal_iff_nfc_equal(self, pair):
        """Property: two addresses share an OpenBao path iff they are NFC-equal."""
        first, second = pair
        same_path = _openbao_path(first) == _openbao_path(second)
        assert same_path == (_canonical(first) == _canonical(second)), pair

    @_SETTINGS
    @given(auth_method=_FIELDS, user_id=_FIELDS, provider=_FIELDS, server_path=_FIELDS)
    @example(auth_method="oauth2", user_id="auth0|abc", provider="a|b", server_path="/x")
    def test_principal_and_map_key_decode(self, auth_method, user_id, provider, server_path):
        """Property: user_principal and map_key split back into their NFC inputs."""
        principal = keys.user_principal(auth_method, user_id).split("/")
        assert [keys.decode_segment(s) for s in principal] == [_nfc(auth_method), _nfc(user_id)]
        map_key = keys.map_key(provider, server_path).split(keys.MAP_KEY_DELIMITER)
        assert [keys.decode_segment(s) for s in map_key] == [_nfc(provider), _nfc(server_path)]


@pytest.mark.unit
class TestCredentialAddressBinding:
    """The credential AEAD binds each ciphertext to one NFC address."""

    @_SETTINGS
    @given(address=_ADDRESSES)
    @example(address=("oauth2", "auth0|abc", "github", "/github", keys.EGRESS_PURPOSE))
    @example(address=("oauth2", "auth0|abc", "github", "/github", ""))
    def test_aad_decodes(self, address):
        """Property: the AAD decodes to exactly NFC(address), so it is injective."""
        assert _decode_aad(_aad(address)) == _canonical(address)

    @_SETTINGS
    @given(pair=_address_pairs())
    def test_aad_equal_iff_nfc_equal(self, pair):
        """Property: two addresses share AAD iff they are NFC-equal."""
        first, second = pair
        assert (_aad(first) == _aad(second)) == (_canonical(first) == _canonical(second)), pair

    @_SETTINGS
    @given(pair=_address_pairs())
    @example(pair=(("o", "u", "p", "/s", "egress"), ("o", "u", "p", "/s", "discovery")))
    @example(pair=(("o", "u", "p", "/s", "discovery"), ("o", "u", "p", "/s", "egress")))
    @example(pair=(("o", "alice", "p", "/s", "egress"), ("o", "bob", "p", "/s", "egress")))
    @example(pair=(("o", "u", "p", "/a", "egress"), ("o", "u", "p", "/b", "egress")))
    @example(pair=(("o", "\u00e9", "p", "/s", "egress"), ("o", "e\u0301", "p", "/s", "egress")))
    def test_decrypt_only_at_sealing_address(self, pair):
        """Property: a sealed credential opens at an NFC-equal address and nowhere else."""
        sealed_at, opened_at = pair
        codec = build_credential_codec(_ROOT_KEY)
        *seal_segments, seal_purpose = sealed_at
        *open_segments, open_purpose = opened_at
        document = codec.encode(*seal_segments, _TOKEN, purpose=seal_purpose)
        try:
            token = codec.decode(*open_segments, document, purpose=open_purpose)
        except SecretStoreError:
            opened = False
        else:
            opened = True
            assert token == _TOKEN
        assert opened == (_canonical(sealed_at) == _canonical(opened_at)), pair
