"""Integrity properties of the egress OAuth ``state`` codec.

The consent ``state`` blob round-trips through the browser and the upstream
provider, so an attacker can read and rewrite it. The codec must give back the
exact ``OAuthState`` it sealed, reject every blob whose decoded bytes differ by
even a single bit from a sealed one, and reject blobs sealed under a different
``SECRET_KEY``. Each rejection must be ``InvalidState``, never a partial or
attacker-chosen state.
"""

import base64
import os
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from hypothesis import (
    assume,
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.egress_auth import state_codec
from registry.egress_auth.schemas import OAuthState

_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_PRIMARY_KEY: str = "state-codec-property-primary-key"

_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40)

# Environment values cannot carry NUL or lone surrogates.
_SECRET_KEYS = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=40,
)

_STATES = st.builds(
    OAuthState,
    user_id=_TEXT,
    auth_method=_TEXT,
    client_id=_TEXT,
    provider=_TEXT,
    server_path=_TEXT,
    session_id=_TEXT,
    pkce_verifier=st.one_of(st.none(), _TEXT),
    nonce=_TEXT,
    issued_at=_TEXT,
    purpose=st.one_of(st.sampled_from(["egress", "discovery"]), _TEXT),
    approved_upstreams=st.lists(_TEXT, max_size=3),
    token_url=_TEXT,
)

_PINNED_STATE = OAuthState(
    user_id="alice",
    auth_method="oauth2",
    client_id="Iv1.x",
    provider="github",
    server_path="/github-mcp",
    session_id="sess-1",
    pkce_verifier="verifier-secret-value",
    nonce="nonce-abc",
    issued_at="2026-06-19T00:00:00+00:00",
    approved_upstreams=["https://api.github.com/mcp"],
    token_url="https://github.com/login/oauth/access_token",
)


@contextmanager
def _secret_key(
    value: str,
) -> Iterator[None]:
    """Run the block with ``SECRET_KEY`` set to ``value`` and a fresh cipher.

    Args:
        value: The secret to derive the state key from.

    Yields:
        Nothing; restores the previous ``SECRET_KEY`` and cipher on exit.
    """
    previous = os.environ.get("SECRET_KEY")
    os.environ["SECRET_KEY"] = value
    state_codec.reset_cipher_for_tests()
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("SECRET_KEY", None)
        else:
            os.environ["SECRET_KEY"] = previous
        state_codec.reset_cipher_for_tests()


def _flip_bit(
    blob: str,
    bit: int,
) -> str:
    """Flip one bit of the decoded bytes of ``blob`` and re-encode it.

    Args:
        blob: A state blob from ``encode_state``.
        bit: Bit index into the decoded bytes, taken modulo their bit length.

    Returns:
        The tampered blob in the same URL-safe base64 wire format.
    """
    raw = bytearray(base64.urlsafe_b64decode(blob.encode("ascii")))
    bit %= len(raw) * 8
    raw[bit // 8] ^= 1 << (bit % 8)
    return base64.urlsafe_b64encode(bytes(raw)).decode("ascii")


def _assert_rejected(
    blob: str,
    context: str,
) -> None:
    """Assert ``decode_state`` rejects ``blob`` with ``InvalidState``.

    Args:
        blob: The blob to decode.
        context: Description of how the blob was produced, for the failure.
    """
    try:
        decoded = state_codec.decode_state(blob)
    except state_codec.InvalidState:
        return
    raise AssertionError(f"{context}: decode_state accepted it as {decoded!r}")


@pytest.fixture(autouse=True)
def _reset_cipher():
    """Isolate each test from a cipher cached by any other test."""
    state_codec.reset_cipher_for_tests()
    yield
    state_codec.reset_cipher_for_tests()


@pytest.mark.unit
class TestStateCodecRoundTrip:
    """``decode_state`` inverts ``encode_state``."""

    @_SETTINGS
    @given(state=_STATES)
    @example(state=_PINNED_STATE)
    def test_round_trip(self, state):
        """Property: decode_state(encode_state(s)) == s."""
        with _secret_key(_PRIMARY_KEY):
            assert state_codec.decode_state(state_codec.encode_state(state)) == state


@pytest.mark.unit
class TestStateCodecTamper:
    """No single-bit change to a sealed blob is accepted."""

    @_SETTINGS
    @given(state=_STATES, bit=st.integers(min_value=0, max_value=1 << 20))
    @example(state=_PINNED_STATE, bit=0)
    def test_single_bit_flip_rejected(self, state, bit):
        """Property: flipping any one decoded bit makes decode_state raise InvalidState."""
        with _secret_key(_PRIMARY_KEY):
            blob = state_codec.encode_state(state)
            _assert_rejected(_flip_bit(blob, bit), f"bit {bit} of {blob!r}")

    def test_every_bit_flip_of_pinned_blob_rejected(self):
        """Property: each of the blob's bits, flipped alone, is rejected (exhaustive)."""
        with _secret_key(_PRIMARY_KEY):
            blob = state_codec.encode_state(_PINNED_STATE)
            bits = len(base64.urlsafe_b64decode(blob.encode("ascii"))) * 8
            for bit in range(bits):
                _assert_rejected(_flip_bit(blob, bit), f"bit {bit} of {blob!r}")


@pytest.mark.unit
class TestStateCodecKeyBinding:
    """A blob sealed under one ``SECRET_KEY`` does not open under another."""

    @_SETTINGS
    @given(state=_STATES, sealing_key=_SECRET_KEYS, opening_key=_SECRET_KEYS)
    @example(state=_PINNED_STATE, sealing_key="key-a", opening_key="key-b")
    def test_wrong_secret_key_rejected(self, state, sealing_key, opening_key):
        """Property: decode under a different SECRET_KEY raises InvalidState."""
        assume(sealing_key != opening_key)
        with _secret_key(sealing_key):
            blob = state_codec.encode_state(state)
        with _secret_key(opening_key):
            _assert_rejected(blob, f"sealed under {sealing_key!r}, opened under {opening_key!r}")
