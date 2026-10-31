"""Property tests for the url_guard IP literal parser and SSRF classifier.

These pin two egress-control properties of ``registry.utils.url_guard``: the
IPv4 literal parser never assigns an address to a host string that the C
library would read differently (or not at all), and every special-purpose IP
block, bare or wrapped in an IPv4-embedding IPv6 transport, is denied in the
default (no private egress) mode, with ``allow_private`` only ever removing
denials.
"""

import ipaddress
import socket

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.utils.url_guard import (
    _CREDENTIAL_ENDPOINT_IPS,
    _ip_denial_reason,
    coerce_ip_literal,
)

_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

# Junk that a lenient parser (Python ``int``) accepts but no inet_aton does:
# digit-group underscores, a sign, Python radix prefixes and Unicode digits.
# Whitespace is handled separately (see ``_ipv4_like_hosts``).
_JUNK_ANYWHERE: tuple[str, ...] = ("_", "+", "0o", "0b", "\u0661")
_WHITESPACE_JUNK: str = " "

# Per-part value ceilings for inet_aton packing: leading parts are one byte,
# the last part absorbs every remaining low-order byte.
_LAST_PART_CEILING: dict[int, int] = {
    1: 1 << 32,
    2: 1 << 24,
    3: 1 << 16,
    4: 1 << 8,
}

_NAT64_PREFIX_INT: int = int(ipaddress.IPv6Address("64:ff9b::"))
_IPV4_MAPPED_PREFIX_INT: int = int(ipaddress.IPv6Address("::ffff:0:0"))

_SPECIAL_IPV4_BLOCKS: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

_SPECIAL_IPV6_BLOCKS: tuple[str, ...] = (
    "::1/128",
    "::/128",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
)


def _render_part(
    value: int,
    radix: str,
    leading_zeros: int,
    upper_prefix: bool,
    upper_digits: bool,
) -> str:
    """Spell one inet_aton part in the requested radix.

    Args:
        value: Non-negative integer value of the part.
        radix: One of ``"dec"``, ``"oct"`` or ``"hex"``.
        leading_zeros: Extra zeros to place after the radix prefix (octal and
            hex only; a leading zero would turn a decimal part into octal).
        upper_prefix: Use ``0X`` instead of ``0x`` for hex.
        upper_digits: Upper-case hex digits.

    Returns:
        The part as text, e.g. ``"192"``, ``"0300"`` or ``"0XC0"``.
    """
    if radix == "dec":
        return str(value)
    if radix == "oct":
        return "0" + "0" * leading_zeros + format(value, "o")
    digits = format(value, "X" if upper_digits else "x")
    return ("0X" if upper_prefix else "0x") + "0" * leading_zeros + digits


@st.composite
def _ipv4_like_hosts(draw: st.DrawFn, allow_overflow: bool = True) -> str:
    """Generate inet_aton-style IPv4 host strings, optionally with junk.

    Builds 1 to 4 dot-separated parts, each decimal, 0-prefixed octal or 0x
    hex (mixed case, leading zeros), with values optionally over the packing
    ceiling, an optional trailing dot, and up to two junk insertions.

    Whitespace is only inserted at the start of a part. glibc and macOS
    inet_aton stop at whitespace that follows a digit and accept the prefix
    (``"1 .2"`` parses as ``0.0.0.1``) while musl rejects it, so trailing or
    mid-part whitespace has no libc-independent answer. Whitespace before a
    part's first digit is rejected by glibc, musl and macOS alike. Every other
    junk token is rejected by all three wherever it lands.

    Args:
        draw: Hypothesis draw function.
        allow_overflow: Also draw part values at or above the packing ceiling.
            glibc and musl reject those, but macOS inet_aton wraps them
            (``"4294967296"`` parses as ``0.0.0.0``), so libc acceptance of an
            overflowing spelling is platform-dependent.

    Returns:
        A host string containing no ``:``.
    """
    count = draw(st.integers(min_value=1, max_value=4))
    parts: list[str] = []
    for index in range(count):
        is_last = index == count - 1
        ceiling = _LAST_PART_CEILING[count] if is_last else 1 << 8
        values = st.integers(min_value=0, max_value=ceiling - 1)
        if allow_overflow:
            values = st.one_of(
                values,
                st.integers(min_value=ceiling, max_value=ceiling * 4),
            )
        value = draw(values)
        part = _render_part(
            value=value,
            radix=draw(st.sampled_from(("dec", "oct", "hex"))),
            leading_zeros=draw(st.integers(min_value=0, max_value=3)),
            upper_prefix=draw(st.booleans()),
            upper_digits=draw(st.booleans()),
        )
        if draw(st.integers(min_value=0, max_value=9)) == 0:
            part = _WHITESPACE_JUNK + part
        parts.append(part)

    host = ".".join(parts)
    for _ in range(draw(st.integers(min_value=0, max_value=2))):
        junk = draw(st.sampled_from(_JUNK_ANYWHERE))
        position = draw(st.integers(min_value=0, max_value=len(host)))
        host = host[:position] + junk + host[position:]
    if draw(st.booleans()):
        host += "."
    return host


def _libc_ipv4(
    host: str,
) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address the C library's inet_aton reads from ``host``.

    One trailing dot is removed first. inet_aton itself rejects it, but the
    guard deliberately reads ``"a.b.c.d."`` as ``a.b.c.d`` (the existing
    classifier suite pins this) and resolvers treat such a name as absolute,
    so no search domain can redirect it.

    Args:
        host: IPv4-looking host string.

    Returns:
        The parsed address, or None when inet_aton rejects the string.
    """
    candidate = host[:-1] if host.endswith(".") else host
    try:
        return ipaddress.IPv4Address(socket.inet_aton(candidate))
    except OSError:
        return None


@pytest.mark.unit
class TestCoerceIpLiteralMatchesLibc:
    """``coerce_ip_literal`` agrees with inet_aton on IPv4-looking hosts."""

    @_SETTINGS
    @given(host=_ipv4_like_hosts())
    @example(host="9_3.184.216.34")
    @example(host="0o177.0.0.1")
    def test_coerced_address_is_libc_address(self, host):
        """Property: coerce(h) is None or equals the address libc parses from h."""
        assert ":" not in host
        coerced = coerce_ip_literal(host)
        libc = _libc_ipv4(host)
        assert coerced is None or coerced == libc, (
            f"coerce_ip_literal({host!r}) = {coerced}, inet_aton gives {libc}"
        )

    @_SETTINGS
    @given(host=_ipv4_like_hosts(allow_overflow=False))
    def test_every_libc_spelling_is_recognized(self, host):
        """Property: any in-range host inet_aton accepts coerces to that address."""
        libc = _libc_ipv4(host)
        if libc is not None:
            assert coerce_ip_literal(host) == libc


def _block_samples(
    cidr: str,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return the first, last and midpoint addresses of a CIDR block.

    Args:
        cidr: Network in CIDR notation.

    Returns:
        Distinct sample addresses, in ascending order.
    """
    net = ipaddress.ip_network(cidr)
    middle = net.network_address + net.num_addresses // 2
    return sorted({net.network_address, middle, net.broadcast_address})


def _ipv4_wrappers(
    ip: ipaddress.IPv4Address,
) -> list[tuple[str, ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    """Return ``ip`` bare, IPv4-mapped and NAT64-wrapped, with labels.

    Args:
        ip: IPv4 address to wrap.

    Returns:
        ``(label, address)`` pairs.
    """
    return [
        ("bare", ip),
        ("mapped", ipaddress.IPv6Address(_IPV4_MAPPED_PREFIX_INT | int(ip))),
        ("nat64", ipaddress.IPv6Address(_NAT64_PREFIX_INT | int(ip))),
    ]


def _denial_cases() -> list:
    """Build the exhaustive special-purpose address table as pytest params.

    Returns:
        ``pytest.param`` objects, one per (block, sample, wrapper).
    """
    cases = []
    ipv4_samples: list[tuple[str, ipaddress.IPv4Address]] = []
    for cidr in _SPECIAL_IPV4_BLOCKS:
        ipv4_samples.extend((cidr, ip) for ip in _block_samples(cidr))
    for literal in sorted(_CREDENTIAL_ENDPOINT_IPS):
        ip = ipaddress.ip_address(literal)
        if isinstance(ip, ipaddress.IPv4Address):
            ipv4_samples.append(("credential", ip))
        else:
            cases.append(pytest.param(ip, id=f"credential-{ip}"))
    for label, ip in ipv4_samples:
        for wrapper, wrapped in _ipv4_wrappers(ip):
            cases.append(pytest.param(wrapped, id=f"{label}-{ip}-{wrapper}"))
    for cidr in _SPECIAL_IPV6_BLOCKS:
        for ip in _block_samples(cidr):
            cases.append(pytest.param(ip, id=f"{cidr}-{ip}"))
    return cases


@pytest.mark.unit
class TestIpDenialReasonSpecialBlocks:
    """Special-purpose blocks are denied when private egress is not allowed."""

    @pytest.mark.parametrize("ip", _denial_cases())
    def test_special_purpose_address_denied(self, ip):
        """Property: every special-purpose address is denied with allow_private=False."""
        assert _ip_denial_reason(ip, allow_private=False) is not None, (
            f"{ip} was allowed in deny-private mode"
        )

    @_SETTINGS
    @given(ip=st.ip_addresses())
    def test_allow_private_never_adds_denial(self, ip):
        """Property: denied with allow_private=True implies denied without it."""
        if _ip_denial_reason(ip, allow_private=True) is not None:
            assert _ip_denial_reason(ip, allow_private=False) is not None
