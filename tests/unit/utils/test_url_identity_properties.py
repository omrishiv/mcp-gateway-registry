"""Property tests for url_guard target identity against what httpx dials.

``normalize_url_identity`` produces the identity string that exact outbound
identity checks and the reserved built-in hostname check compare against, so
its security property is that the identity names the same host and port that
httpx will actually connect to, is a fixed point, and that the reserved
``mcpgw-server`` hostname cannot be reached by an ordinary profile under any
spelling the resolver treats as the same name (case, trailing root dot).
"""

import asyncio
import ipaddress
import socket
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import httpx
import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.exceptions import UrlValidationError
from registry.utils import url_guard
from registry.utils.url_guard import (
    PROXY_PROFILE,
    GuardedAsyncTransport,
    normalize_url_identity,
    validate_url,
)

PROPERTY_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_RESERVED_HOST: str = "mcpgw-server"
_RESERVED_HOST_IP: str = "10.0.0.9"

# Non-ASCII characters whose IDNA2003 and IDNA2008 treatments differ (sharp s
# and final sigma are "deviation" characters), plus characters both standards
# map identically or that httpx rejects outright.
_DEVIATION_CHARACTERS: str = "\u00df\u03c2"
_OTHER_UNICODE: str = "\u00e9\u00fc\u017f\uff41\u00c1\u0130"
_LABEL_ALPHABET: str = "abcXYZ019-" + _DEVIATION_CHARACTERS + _OTHER_UNICODE
# U+3002 IDEOGRAPHIC FULL STOP is a label separator under both IDNA standards.
_SEPARATORS: tuple[str, ...] = (".", "\u3002")
_SCHEMES: tuple[str, ...] = ("http", "https", "HTTP", "Https")
_PORT_SUFFIXES: tuple[str, ...] = ("", ":", ":80", ":443", ":0080", ":8003")
_TAILS: tuple[str, ...] = ("", "/", "/p", "/a%20b?x=1", "?q")

_IDNA_REASON: str = (
    "Known defect: normalize_url_identity encodes hostnames with the IDNA2003 "
    "codec while httpx dials the IDNA2008 form, so deviation characters such as "
    "sharp s and final sigma name a different host than the one connected to."
)
_HOST_CHARACTER_REASON: str = (
    "Known defect: normalize_url_identity accepts host characters that httpx "
    "percent-encodes before dialling, so the identity names a different host."
)
_TRAILING_DOT_REASON: str = (
    "Known defect: the reserved built-in hostname check compares the host "
    "verbatim, so a trailing root dot reaches mcpgw-server from an ordinary profile."
)


def _settings(
    allow_private: bool = False,
) -> MagicMock:
    """Return a registry settings stub with an empty allowlist.

    Args:
        allow_private: Value of gateway_proxy_allow_private_targets.

    Returns:
        A MagicMock carrying the fields the allowlist factories read.
    """
    stub = MagicMock()
    stub.github_extra_hosts = ""
    stub.ssrf_allowed_hosts = ""
    stub.ssrf_allowed_cidrs = ""
    stub.gateway_proxy_allow_private_targets = allow_private
    stub.egress_oauth_trusted_idp_hosts = ""
    return stub


def _reset_caches() -> None:
    """Clear the cached allowlists and forward-proxy configuration."""
    url_guard._skill_allowlist.cache_clear()
    url_guard._proxy_allowlist.cache_clear()
    url_guard._builtin_airegistry_tools_allowlist.cache_clear()
    url_guard._credentialed_oauth_allowlist.cache_clear()
    url_guard._forward_proxy_config.cache_clear()


@pytest.fixture(autouse=True)
def _guard_state():
    """Run every test with an empty allowlist and fresh guard caches."""
    _reset_caches()
    with patch.object(url_guard, "settings", _settings()):
        yield
    _reset_caches()


@st.composite
def _hosts(draw: st.DrawFn) -> str:
    """Draw a hostname or IP literal as it might appear in a URL authority.

    Args:
        draw: Hypothesis draw function.

    Returns:
        A host, bracketed when it is an IPv6 literal.
    """
    kind = draw(st.sampled_from(("name", "name", "name", "ipv4", "ipv6")))
    if kind == "ipv4":
        return str(ipaddress.IPv4Address(draw(st.integers(min_value=0, max_value=2**32 - 1))))
    if kind == "ipv6":
        text = str(ipaddress.IPv6Address(draw(st.integers(min_value=0, max_value=2**128 - 1))))
        return "[" + (text.upper() if draw(st.booleans()) else text) + "]"
    labels = draw(
        st.lists(st.text(alphabet=_LABEL_ALPHABET, min_size=1, max_size=6), min_size=1, max_size=3)
    )
    separator = draw(st.sampled_from(_SEPARATORS))
    trailing = draw(st.sampled_from(("", *_SEPARATORS)))
    return separator.join(labels) + trailing


@st.composite
def _urls(draw: st.DrawFn) -> str:
    """Draw an http(s) URL with varied scheme case, host, port and tail.

    Args:
        draw: Hypothesis draw function.

    Returns:
        A URL string.
    """
    scheme = draw(st.sampled_from(_SCHEMES))
    port = draw(st.sampled_from(_PORT_SUFFIXES))
    tail = draw(st.sampled_from(_TAILS))
    return f"{scheme}://{draw(_hosts())}{port}{tail}"


def _default_port(
    scheme: str,
) -> int:
    """Return the default port for an http(s) scheme of any case."""
    return 443 if scheme.lower() == "https" else 80


def _same_host(
    left: str,
    right: str,
) -> bool:
    """Compare two hosts, as addresses when both are IP literals.

    Args:
        left: First host, without brackets.
        right: Second host, without brackets.

    Returns:
        True when both name the same address or the same lower-cased name.
    """
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return left.lower() == right.lower()


def _identity_and_dialled(
    url: str,
) -> tuple[tuple[str, int], tuple[str, int]] | None:
    """Return (identity host, port) and (httpx dialled host, port) for ``url``.

    Args:
        url: Candidate URL.

    Returns:
        None when either side rejects the URL, since a rejected URL is never
        dialled or never compared.
    """
    try:
        identity = urlsplit(normalize_url_identity(url))
    except UrlValidationError:
        return None
    try:
        dialled = httpx.URL(url)
    except httpx.InvalidURL:
        return None
    ours = (identity.hostname or "", identity.port or _default_port(identity.scheme))
    theirs = (
        dialled.raw_host.decode("ascii"),
        dialled.port or _default_port(dialled.scheme),
    )
    return ours, theirs


@pytest.mark.unit
class TestNormalizeUrlIdentity:
    """normalize_url_identity is a fixed point that names what httpx dials."""

    @PROPERTY_SETTINGS
    @given(url=_urls())
    @example(url="https://stra\u00dfe.example/")
    @example(url="http://mcpgw-server.:8003/")
    @example(url="HTTP://A.Example:080")
    def test_idempotent(self, url):
        """Property: normalizing an accepted URL's identity again changes nothing."""
        try:
            once = normalize_url_identity(url)
        except UrlValidationError:
            return
        assert normalize_url_identity(once) == once

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason=_IDNA_REASON)
    @PROPERTY_SETTINGS
    @given(url=_urls())
    @example(url="https://stra\u00dfe.example/")
    def test_host_and_port_match_httpx(self, url):
        """Property: when both accept a URL, the identity's host and effective
        port equal the host and port httpx dials."""
        pair = _identity_and_dialled(url)
        if pair is None:
            return
        (our_host, our_port), (their_host, their_port) = pair
        assert _same_host(our_host, their_host) and our_port == their_port, (
            f"{url!r}: identity {our_host}:{our_port}, httpx dials {their_host}:{their_port}"
        )

    @PROPERTY_SETTINGS
    @given(url=_urls().filter(lambda u: not any(c in u for c in _DEVIATION_CHARACTERS)))
    @example(url="http://mcpgw-server.:8003/")
    @example(url="https://\u00e9cole.example\u3002:0443/x")
    def test_host_and_port_match_httpx_without_deviation_characters(self, url):
        """Property: outside the IDNA deviation characters, the identity's host
        and effective port equal what httpx dials."""
        pair = _identity_and_dialled(url)
        if pair is None:
            return
        (our_host, our_port), (their_host, their_port) = pair
        assert _same_host(our_host, their_host) and our_port == their_port, (
            f"{url!r}: identity {our_host}:{our_port}, httpx dials {their_host}:{their_port}"
        )

    @pytest.mark.parametrize(
        "character",
        [
            pytest.param(
                c,
                id=f"U+{ord(c):04X}",
                marks=pytest.mark.xfail(
                    strict=True, raises=AssertionError, reason=_HOST_CHARACTER_REASON
                ),
            )
            for c in " <>^"
        ]
        + [pytest.param(c, id=f"U+{ord(c):04X}") for c in "%\\_|"],
    )
    def test_host_punctuation_matches_httpx(self, character):
        """Property: a host character normalize accepts is dialled unchanged."""
        url = f"http://a{character}b.example/"
        pair = _identity_and_dialled(url)
        assert pair is not None, f"{url!r} was rejected by one side"
        (our_host, _), (their_host, _) = pair
        assert our_host == their_host, f"{url!r}: identity {our_host!r}, httpx {their_host!r}"


def _reserved_spelling(
    case_mask: list[bool],
    trailing_dot: str,
    scheme: str,
    port: str,
) -> str:
    """Build a URL naming the reserved host with the given spelling.

    Args:
        case_mask: Per-character upper-case flags for the reserved host.
        trailing_dot: Root separator to append ('' for none).
        scheme: URL scheme as written.
        port: Port suffix as written, including the colon.

    Returns:
        The URL.
    """
    host = "".join(
        ch.upper() if upper else ch for ch, upper in zip(_RESERVED_HOST, case_mask, strict=True)
    )
    return f"{scheme}://{host}{trailing_dot}{port}/"


_CASE_MASKS = st.lists(st.booleans(), min_size=len(_RESERVED_HOST), max_size=len(_RESERVED_HOST))
_RESERVED_PORTS = st.sampled_from(("", ":8003", ":80", ":443"))
_RESERVED_SCHEMES = st.sampled_from(("http", "https", "HTTP"))


@pytest.mark.unit
class TestReservedHostSpellings:
    """The reserved built-in hostname is rejected under every equivalent spelling."""

    @PROPERTY_SETTINGS
    @given(
        case_mask=_CASE_MASKS,
        scheme=_RESERVED_SCHEMES,
        port=_RESERVED_PORTS,
    )
    def test_case_variants_are_rejected(self, case_mask, scheme, port):
        """Property: changing letter case never lets an ordinary profile accept
        the reserved hostname."""
        url = _reserved_spelling(case_mask, "", scheme, port)
        with pytest.raises(UrlValidationError):
            validate_url(url, profile=PROXY_PROFILE, resolve=False)

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason=_TRAILING_DOT_REASON)
    @PROPERTY_SETTINGS
    @given(
        case_mask=_CASE_MASKS,
        trailing_dot=st.sampled_from(_SEPARATORS),
        scheme=_RESERVED_SCHEMES,
        port=_RESERVED_PORTS,
    )
    @example(case_mask=[False] * len(_RESERVED_HOST), trailing_dot=".", scheme="http", port=":8003")
    def test_trailing_dot_variants_are_rejected(self, case_mask, trailing_dot, scheme, port):
        """Property: a trailing root dot, in any case, never lets an ordinary
        profile accept the reserved hostname."""
        url = _reserved_spelling(case_mask, trailing_dot, scheme, port)
        try:
            validate_url(url, profile=PROXY_PROFILE, resolve=False)
        except UrlValidationError:
            return
        raise AssertionError(f"{url!r} was accepted by the ordinary proxy profile")

    @pytest.mark.parametrize(
        "host",
        [
            "mcpgw-\u017ferver",  # long s, IDNA2003-maps to 's'
            "\uff4dcpgw-server",  # fullwidth m
        ],
    )
    def test_idna_equivalent_spellings_are_rejected(self, host):
        """Property: an IDNA-equivalent spelling of the reserved host is rejected."""
        with pytest.raises(UrlValidationError):
            validate_url(f"http://{host}:8003/", profile=PROXY_PROFILE, resolve=False)


class _RecordingParent(httpx.AsyncHTTPTransport):
    """Stands in for the network layer below the guard and records each dial."""

    dialled: list[str]

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        self.dialled.append(request.url.host)
        return httpx.Response(200)


class _RecordingGuardedTransport(GuardedAsyncTransport, _RecordingParent):
    """The real guard over a parent that records instead of connecting."""


async def _scripted_getaddrinfo(
    host: str,
    port: int,
    *args: object,
    **kwargs: object,
) -> list[tuple]:
    """Resolve every name to the reserved host's private address."""
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (_RESERVED_HOST_IP, port))]


async def _dialled_through_guard(
    url: str,
) -> list[str]:
    """Send ``url`` through the guarded transport and return what it dialled.

    Args:
        url: Target URL.

    Returns:
        Connect hosts that reached the network layer.
    """
    loop = asyncio.get_running_loop()
    transport = _RecordingGuardedTransport(guard_profile=PROXY_PROFILE)
    transport.dialled = []
    with patch.object(loop, "getaddrinfo", new=_scripted_getaddrinfo):
        async with httpx.AsyncClient(transport=transport) as client:
            try:
                await client.get(url)
            except UrlValidationError:
                pass
    return transport.dialled


@pytest.mark.unit
@pytest.mark.parametrize(
    "url",
    [
        "http://mcpgw-server:8003/",
        "http://MCPGW-Server:8003/",
        pytest.param(
            "http://mcpgw-server.:8003/",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_TRAILING_DOT_REASON
            ),
        ),
        pytest.param(
            "http://mcpgw-server\u3002:8003/",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_TRAILING_DOT_REASON
            ),
        ),
    ],
)
def test_reserved_host_is_never_dialled_with_private_targets_allowed(url):
    """Property: with private targets allowed, the ordinary proxy profile still
    never connects to the reserved built-in host, whatever its spelling."""
    with patch.object(url_guard, "settings", _settings(allow_private=True)):
        _reset_caches()
        dialled = asyncio.run(_dialled_through_guard(url))
    assert dialled == [], f"{url!r} reached the network at {dialled}"
