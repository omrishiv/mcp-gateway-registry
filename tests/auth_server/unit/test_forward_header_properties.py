"""Property tests: the MCP proxy hop never forwards gateway credentials upstream.

``auth_server.server._forward_headers`` builds the header set the gateway sends
to a registered MCP backend. Whatever the incoming headers and however their
names are cased, the result must never carry the ingress session cookie, a
gateway-internal hop token (``X-Internal-Token`` and its variants), a
body-capture header (``X-Body`` and its variants) or the internal routing header
``X-Upstream-Url``. ``Authorization`` and ``X-Authorization`` are forwarded only
when the caller opts in with ``relay_authorization=True``, and then unchanged.
"""

from __future__ import annotations

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from auth_server.server import (
    _HOP_BY_HOP_HEADERS,
    _PROXY_CONTEXT_HEADERS,
    _forward_headers,
)

pytestmark = [pytest.mark.unit, pytest.mark.auth]


# Gateway credentials and internal headers that must never reach an upstream.
NEVER_FORWARDED: tuple[str, ...] = (
    "cookie",
    "x-internal-token",
    "x-internal-token-generic",
    "x-internal-token-registry",
    "x-body",
    "x-body-uninspectable",
    "x-upstream-url",
)

# Ingress bearer headers, forwarded only on an explicit relay opt-in.
INGRESS_AUTH_HEADERS: tuple[str, ...] = (
    "authorization",
    "x-authorization",
)

# Name families the gateway reserves for its own internal hops.
RESERVED_PREFIXES: tuple[str, ...] = (
    "x-internal-token",
    "x-body",
)

# Ordinary end-to-end headers an upstream legitimately receives, plus
# client-observability headers the policy deliberately leaves alone.
ORDINARY_HEADERS: tuple[str, ...] = (
    "accept",
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
    "user-agent",
    "x-request-id",
    "x-forwarded-for",
    "x-real-ip",
)

# Every name stripped regardless of relay: gateway credentials, plus the
# connection-scoped hop-by-hop and proxy-context sets httpx must set itself.
_STRIPPED_ALWAYS: frozenset[str] = frozenset(
    {
        *NEVER_FORWARDED,
        *_HOP_BY_HOP_HEADERS,
        *_PROXY_CONTEXT_HEADERS,
    }
)

HYPOTHESIS_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_HEADER_TOKEN_ALPHABET: str = "abcdefghijklmnopqrstuvwxyz0123456789-"

# A header that sits in the reserved internal-token family but is not one of
# the three names the gateway mints today.
_RESERVED_FAMILY_VARIANT: dict[str, str] = {"X-Internal-Token-Egress": "signed.jwt.value"}


@st.composite
def _random_case(
    draw: st.DrawFn,
    name: str,
) -> str:
    """Draw ``name`` with each letter independently upper- or lower-cased.

    Args:
        draw: Hypothesis draw function.
        name: Lower-case header name.

    Returns:
        The same name in a random mix of cases.
    """
    flips = draw(st.lists(st.booleans(), min_size=len(name), max_size=len(name)))
    return "".join(ch.upper() if flip else ch for ch, flip in zip(name, flips, strict=True))


def _header_values() -> st.SearchStrategy[str]:
    """Strategy for header values, including credential-looking ones.

    Returns:
        Strategy producing printable header values.
    """
    return st.text(
        alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
        max_size=40,
    )


@st.composite
def _incoming_headers(
    draw: st.DrawFn,
) -> dict[str, str]:
    """Draw an incoming header dict mixing sensitive, ordinary and random names.

    Names are randomly cased. Two spellings that fold to the same lower-case
    name may both appear, as they can in a raw dict.

    Args:
        draw: Hypothesis draw function.

    Returns:
        Mapping of header name to value.
    """
    base_names = st.one_of(
        st.sampled_from(
            NEVER_FORWARDED
            + INGRESS_AUTH_HEADERS
            + ORDINARY_HEADERS
            + tuple(sorted(_HOP_BY_HOP_HEADERS | _PROXY_CONTEXT_HEADERS))
        ),
        st.text(alphabet=_HEADER_TOKEN_ALPHABET, min_size=1, max_size=20),
    )
    names = draw(st.lists(base_names, max_size=12))
    headers: dict[str, str] = {}
    for name in names:
        headers[draw(_random_case(name))] = draw(_header_values())
    return headers


@st.composite
def _reserved_family_headers(
    draw: st.DrawFn,
) -> dict[str, str]:
    """Draw headers whose names extend a reserved internal prefix.

    Args:
        draw: Hypothesis draw function.

    Returns:
        Mapping of a randomly cased ``<prefix><suffix>`` name to a value.
    """
    prefix = draw(st.sampled_from(RESERVED_PREFIXES))
    suffix = draw(st.text(alphabet=_HEADER_TOKEN_ALPHABET, max_size=12))
    name = draw(_random_case(prefix + suffix))
    return {name: draw(_header_values())}


def _lower_names(
    headers: dict[str, str],
) -> set[str]:
    """Return the case-folded header names of ``headers``.

    Args:
        headers: Header mapping.

    Returns:
        Set of lower-case names.
    """
    return {name.lower() for name in headers}


@HYPOTHESIS_SETTINGS
@given(incoming=_incoming_headers(), relay=st.booleans())
@example(
    incoming={"Cookie": "session=abc", "X-INTERNAL-TOKEN": "jwt", "x-Body": "{}"},
    relay=True,
)
def test_gateway_credentials_never_forwarded(incoming, relay):
    """No cookie, internal hop token, body-capture or routing header is forwarded.

    For every incoming header dict under any name casing, and for both values
    of ``relay_authorization``, the forwarded headers contain none of the names
    in ``NEVER_FORWARDED``.
    """
    forwarded = _forward_headers(dict(incoming), relay_authorization=relay)

    leaked = sorted(_lower_names(forwarded) & set(NEVER_FORWARDED))
    assert not leaked, f"forwarded {leaked} from {sorted(incoming)} (relay={relay})"


@HYPOTHESIS_SETTINGS
@given(incoming=_incoming_headers(), relay=st.booleans())
@example(incoming={"Authorization": "Bearer a", "X-Authorization": "Bearer b"}, relay=False)
@example(incoming={"AUTHORIZATION": "Bearer a", "x-AUTHORIZATION": "Bearer b"}, relay=True)
def test_ingress_auth_forwarded_only_on_relay(incoming, relay):
    """Ingress bearer headers reach the upstream exactly when relay is requested.

    With ``relay_authorization=False`` no ``Authorization`` or
    ``X-Authorization`` header is forwarded under any casing. With
    ``relay_authorization=True`` every such header is forwarded under its
    original name and value.
    """
    forwarded = _forward_headers(dict(incoming), relay_authorization=relay)

    incoming_auth = {k: v for k, v in incoming.items() if k.lower() in INGRESS_AUTH_HEADERS}
    forwarded_auth = {k: v for k, v in forwarded.items() if k.lower() in INGRESS_AUTH_HEADERS}
    if relay:
        assert forwarded_auth == incoming_auth, (incoming_auth, forwarded_auth)
    else:
        assert not forwarded_auth, f"forwarded {sorted(forwarded_auth)} without relay"


@HYPOTHESIS_SETTINGS
@given(incoming=_incoming_headers(), relay=st.booleans())
def test_ordinary_headers_forwarded_verbatim(incoming, relay):
    """Every header outside the stripped sets is forwarded with its exact value.

    Stripping must remove only gateway-owned, hop-by-hop, proxy-context and
    (without relay) ingress-auth headers. Any other header keeps its name and
    value, and the forwarded dict holds no header that was not in the input.
    """
    forwarded = _forward_headers(dict(incoming), relay_authorization=relay)

    stripped = set(_STRIPPED_ALWAYS)
    if not relay:
        stripped |= set(INGRESS_AUTH_HEADERS)
    expected = {k: v for k, v in incoming.items() if k.lower() not in stripped}
    assert forwarded == expected


@HYPOTHESIS_SETTINGS
@given(reserved=_reserved_family_headers(), relay=st.booleans())
@example(reserved=_RESERVED_FAMILY_VARIANT, relay=False)
def test_reserved_internal_header_families_never_forwarded(reserved, relay):
    """No header in the reserved ``X-Internal-Token*`` or ``X-Body*`` family is forwarded.

    For any header whose name, case-folded, starts with a reserved internal
    prefix, the forwarded headers do not contain it, whatever the suffix.
    """
    forwarded = _forward_headers(dict(reserved), relay_authorization=relay)

    leaked = sorted(
        name for name in forwarded if any(name.lower().startswith(p) for p in RESERVED_PREFIXES)
    )
    assert not leaked, f"forwarded reserved-family header(s) {leaked}"
