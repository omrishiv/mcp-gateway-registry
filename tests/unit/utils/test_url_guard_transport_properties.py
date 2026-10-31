"""Stateful property tests for the guarded async transport across redirects.

These pin the per-hop egress identity of ``GuardedAsyncTransport`` when a real
``httpx.AsyncClient`` follows a redirect chain while DNS answers rebind and the
forward proxy is toggled: every hop dials only an address that was validated
for that hop's own host, the TLS server name and the ``Host`` header both name
that hop's host, and the caller's ``Authorization`` header never reaches an
origin other than the one it was sent to.
"""

import asyncio
import ipaddress
import os
import socket
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch

import httpx
import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    precondition,
    rule,
    run_state_machine_as_test,
)

from registry.exceptions import UrlValidationError
from registry.utils import url_guard
from registry.utils.url_guard import (
    PROXY_PROFILE,
    GuardedAsyncTransport,
)

STATEFUL_SETTINGS = settings(
    max_examples=50,
    stateful_step_count=15,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_PUBLIC_IP_A: str = "93.184.216.34"
_PUBLIC_IP_B: str = "93.184.216.35"
_PUBLIC_IP_C: str = "1.1.1.1"
_PRIVATE_IP: str = "10.0.0.5"
_LOOPBACK_IP: str = "127.0.0.1"
_LINK_LOCAL_IP: str = "169.254.10.10"
_CREDENTIAL_IP: str = "169.254.169.254"

_PUBLIC_IPS: frozenset[str] = frozenset({_PUBLIC_IP_A, _PUBLIC_IP_B, _PUBLIC_IP_C})
# Addresses an explicit hostname allowlist entry may relax. Link-local and the
# cloud credential endpoints are never in this set.
_RELAXABLE_IPS: frozenset[str] = frozenset({_PRIVATE_IP, _LOOPBACK_IP})

_HOST_A: str = "a.example"
_HOST_B: str = "b.example"
# Named in ssrf_allowed_hosts, so its private answers are permitted.
_INTERNAL_HOST: str = "internal.example"
_HOSTS: tuple[str, ...] = (_HOST_A, _HOST_B, _INTERNAL_HOST)

_INITIAL_DNS: dict[str, tuple[str, ...]] = {
    _HOST_A: (_PUBLIC_IP_A,),
    _HOST_B: (_PUBLIC_IP_B,),
    _INTERNAL_HOST: (_PRIVATE_IP,),
}

_ANSWER_SETS: tuple[tuple[str, ...], ...] = (
    (_PUBLIC_IP_A,),
    (_PUBLIC_IP_B,),
    (_PUBLIC_IP_A, _PUBLIC_IP_B),
    (_PRIVATE_IP,),
    (_LOOPBACK_IP,),
    (_LINK_LOCAL_IP,),
    (_CREDENTIAL_IP,),
    (_PUBLIC_IP_A, _PRIVATE_IP),
    (_PRIVATE_IP, _CREDENTIAL_IP),
)

# IP literals a redirect may point at. Includes the addresses the hostnames
# resolve to, so a redirect to the address just pinned is reachable.
_LITERAL_TARGETS: tuple[str, ...] = (
    _PUBLIC_IP_A,
    _PUBLIC_IP_B,
    _PUBLIC_IP_C,
    _PRIVATE_IP,
    _LINK_LOCAL_IP,
    _CREDENTIAL_IP,
)

_REDIRECT_STATUSES: tuple[int, ...] = (301, 302, 303, 307, 308)

_KIND_RELATIVE: str = "relative"
_KIND_SAME_HOST: str = "same_host"
_KIND_OTHER_HOST: str = "other_host"
_KIND_IP_LITERAL: str = "ip_literal"
_KIND_HTTP_DOWNGRADE: str = "http_downgrade"
_KIND_HTTPS_UPGRADE: str = "https_upgrade"
_ALL_KINDS: tuple[str, ...] = (
    _KIND_RELATIVE,
    _KIND_SAME_HOST,
    _KIND_OTHER_HOST,
    _KIND_IP_LITERAL,
    _KIND_HTTP_DOWNGRADE,
    _KIND_HTTPS_UPGRADE,
)
_KINDS_WITHOUT_IP_LITERAL: tuple[str, ...] = tuple(k for k in _ALL_KINDS if k != _KIND_IP_LITERAL)

_MAX_SCRIPTED_HOPS: int = 4

_PROXY_URL: str = "http://corp-proxy.internal:3128"
_BEARER: str = "Bearer hop-zero-token"
_PROXY_ENV_KEYS: tuple[str, ...] = (
    "EGRESS_FORWARD_PROXY_ENABLED",
    "EGRESS_FORWARD_PROXY_CA_BUNDLE",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
)

_ROUTE_DIRECT: str = "direct"
_ROUTE_PROXIED: str = "proxied"

_PINNED_URL_REASON: str = (
    "Known defect: the guarded transport rewrites request.url to the pinned IP, "
    "so httpx derives the next redirect hop's Host, SNI, Authorization and "
    "NO_PROXY decisions from that IP instead of from the hop's hostname."
)


def _settings() -> MagicMock:
    """Return a registry settings stub with one allowlisted internal hostname.

    Returns:
        A MagicMock carrying the fields the proxy allowlist factory reads.
    """
    stub = MagicMock()
    stub.github_extra_hosts = ""
    stub.ssrf_allowed_hosts = _INTERNAL_HOST
    stub.ssrf_allowed_cidrs = ""
    stub.gateway_proxy_allow_private_targets = False
    stub.egress_oauth_trusted_idp_hosts = ""
    return stub


def _reset_caches() -> None:
    """Clear every lru_cache the guard consults for policy and proxy config."""
    url_guard._skill_allowlist.cache_clear()
    url_guard._proxy_allowlist.cache_clear()
    url_guard._builtin_airegistry_tools_allowlist.cache_clear()
    url_guard._credentialed_oauth_allowlist.cache_clear()
    url_guard._forward_proxy_config.cache_clear()
    url_guard._forward_proxy_ssl_context.cache_clear()


def _is_ip_literal(
    host: str,
) -> bool:
    """Return True if ``host`` is a canonical IP literal.

    Args:
        host: Host as httpx reports it (IPv6 without brackets).

    Returns:
        True for an IPv4 or IPv6 literal.
    """
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _permitted(
    logical_host: str,
    ip: str,
) -> bool:
    """Return True if policy lets a hop for ``logical_host`` dial ``ip``.

    An independent oracle over the test's small address universe: public
    addresses are always permitted, and only the allowlisted hostname may reach
    the relaxable private and loopback addresses.

    Args:
        logical_host: The host the hop's URL names.
        ip: The address the hop dials.

    Returns:
        True when dialling ``ip`` for ``logical_host`` is allowed.
    """
    if ip in _PUBLIC_IPS:
        return True
    return logical_host == _INTERNAL_HOST and ip in _RELAXABLE_IPS


def _origin(
    url: httpx.URL,
) -> tuple[str, str, int]:
    """Return the (scheme, host, effective port) origin of ``url``.

    Args:
        url: Absolute URL.

    Returns:
        The origin triple, with the scheme default filled in for the port.
    """
    port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
    return (url.scheme, url.host, port)


def _authorization_may_reach(
    origin0: tuple[str, str, int],
    hop: tuple[str, str, int],
) -> bool:
    """Return True if a credential sent to ``origin0`` may ride to ``hop``.

    Same origin, or an http to https upgrade of the same host on default ports
    (the one cross-origin case httpx keeps the header for).

    Args:
        origin0: Origin of the request that carried the credential.
        hop: Origin of the hop under test.

    Returns:
        True when the hop is allowed to carry the credential.
    """
    if hop == origin0:
        return True
    return origin0 == ("http", hop[1], 80) and hop == ("https", origin0[1], 443)


@dataclass(frozen=True)
class _ScriptedRedirect:
    """One scripted redirect response and an optional DNS change after it."""

    kind: str
    status: int = 302
    target: str = ""
    rebind: tuple[str, tuple[str, ...]] | None = None


@dataclass(frozen=True)
class _HopRecord:
    """What one hop handed to the network, plus the URL the hop logically names."""

    route: str
    connect_host: str
    host_header: str | None
    sni_hostname: str | None
    has_authorization: bool
    logical_url: httpx.URL
    resolutions: tuple[tuple[str, tuple[str, ...]], ...]


def _location(
    redirect: _ScriptedRedirect,
    logical: httpx.URL,
    index: int,
) -> str:
    """Build the Location header for a scripted redirect.

    Args:
        redirect: The scripted redirect.
        logical: The URL the current hop logically names.
        index: Hop index, used to keep paths distinct.

    Returns:
        A relative or absolute Location value.
    """
    path = f"/hop{index}"
    if redirect.kind == _KIND_RELATIVE:
        return path
    if redirect.kind == _KIND_SAME_HOST:
        return str(logical.copy_with(path=path, query=None))
    if redirect.kind in (_KIND_OTHER_HOST, _KIND_IP_LITERAL):
        return f"{logical.scheme}://{redirect.target}{path}"
    if redirect.kind == _KIND_HTTP_DOWNGRADE:
        return f"http://{logical.host}{path}"
    return f"https://{logical.host}{path}"


def _hop_violations(
    origin0: tuple[str, str, int],
    hop: _HopRecord,
) -> list[str]:
    """Check one hop against the per-hop egress identity invariants.

    Args:
        origin0: Origin of the first request, which carried the credential.
        hop: The recorded hop.

    Returns:
        A human-readable line per violated invariant (empty when the hop is ok).
    """
    logical_host = hop.logical_url.host
    problems: list[str] = []
    tag = f"[{hop.route} hop for {hop.logical_url}]"

    validated_sets = [
        answers
        for host, answers in hop.resolutions
        if host == logical_host and all(_permitted(logical_host, ip) for ip in answers)
    ]
    if _is_ip_literal(logical_host):
        dial_ok = hop.connect_host == logical_host and _permitted(logical_host, logical_host)
    elif _is_ip_literal(hop.connect_host):
        dial_ok = any(hop.connect_host in answers for answers in validated_sets)
    else:
        # Only a proxied hop may leave name resolution to the proxy, and only
        # after the guard saw an all-public answer for that very name.
        latest = [answers for host, answers in hop.resolutions if host == logical_host]
        dial_ok = (
            hop.route == _ROUTE_PROXIED
            and hop.connect_host == logical_host
            and bool(latest)
            and all(ip in _PUBLIC_IPS for ip in latest[-1])
        )
    if not dial_ok:
        problems.append(f"{tag} dialled {hop.connect_host!r}, not validated for {logical_host!r}")

    expected_host_header = hop.logical_url.netloc.decode("ascii")
    if hop.host_header != expected_host_header:
        problems.append(f"{tag} Host header {hop.host_header!r} != {expected_host_header!r}")

    if hop.logical_url.scheme == "https":
        # httpcore uses the sni_hostname extension on a direct connection and
        # the request URL host inside a CONNECT tunnel.
        if hop.route == _ROUTE_DIRECT:
            effective_sni = hop.sni_hostname or hop.connect_host
        else:
            effective_sni = hop.connect_host
        if effective_sni != logical_host:
            problems.append(f"{tag} TLS server name {effective_sni!r} != {logical_host!r}")

    if hop.has_authorization and not _authorization_may_reach(origin0, _origin(hop.logical_url)):
        problems.append(f"{tag} Authorization for {origin0} sent to {_origin(hop.logical_url)}")
    return problems


class _RecordingParent(httpx.AsyncHTTPTransport):
    """Stands in for the network layer below the guard and records each hop."""

    on_hop: Callable[[httpx.Request, str], httpx.Response]

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        return self.on_hop(request, _ROUTE_DIRECT)


class _RecordingProxyDelegate:
    """Stands in for the forward-proxy delegate transport and records each hop."""

    def __init__(
        self,
        on_hop: Callable[[httpx.Request, str], httpx.Response],
    ) -> None:
        self._on_hop = on_hop

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        return self._on_hop(request, _ROUTE_PROXIED)

    async def aclose(self) -> None:
        return None


class _RecordingGuardedTransport(GuardedAsyncTransport, _RecordingParent):
    """The real guard, whose parent and proxy delegate record instead of dial."""

    def _proxy_delegate(
        self,
        proxy_url: str,
    ) -> _RecordingProxyDelegate:
        return _RecordingProxyDelegate(self.on_hop)


@dataclass
class _RedirectHarness:
    """Scripted DNS, redirects and proxy environment around the real guard."""

    dns: dict[str, tuple[str, ...]] = field(default_factory=lambda: dict(_INITIAL_DNS))
    script: list[_ScriptedRedirect] = field(default_factory=list)
    resolutions: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    hops: list[_HopRecord] = field(default_factory=list)
    _logical: httpx.URL | None = None
    _stack: ExitStack = field(default_factory=ExitStack)

    def __enter__(self) -> "_RedirectHarness":
        self._stack.enter_context(patch.dict(os.environ))
        for key in _PROXY_ENV_KEYS:
            os.environ.pop(key, None)
        self._stack.enter_context(patch.object(url_guard, "settings", _settings()))
        self._stack.callback(_reset_caches)
        _reset_caches()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stack.close()

    def set_forward_proxy(
        self,
        enabled: bool,
        no_proxy: str = "",
    ) -> None:
        """Turn the forward proxy on or off through the environment.

        Args:
            enabled: Whether EGRESS_FORWARD_PROXY_ENABLED is true with a proxy set.
            no_proxy: NO_PROXY value to set while enabled; empty leaves it unset.
        """
        for key in _PROXY_ENV_KEYS:
            os.environ.pop(key, None)
        if enabled:
            os.environ["EGRESS_FORWARD_PROXY_ENABLED"] = "true"
            os.environ["HTTP_PROXY"] = _PROXY_URL
            os.environ["HTTPS_PROXY"] = _PROXY_URL
            if no_proxy:
                os.environ["NO_PROXY"] = no_proxy
        url_guard._forward_proxy_config.cache_clear()

    async def _getaddrinfo(
        self,
        host: str,
        port: int,
        *args: object,
        **kwargs: object,
    ) -> list[tuple]:
        """Answer from the scripted DNS table and log what was answered."""
        answers = self.dns.get(host, ())
        self.resolutions.append((host, answers))
        if not answers:
            raise socket.gaierror(socket.EAI_NONAME, f"no scripted answer for {host}")
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
            for ip in answers
        ]

    def _on_hop(
        self,
        request: httpx.Request,
        route: str,
    ) -> httpx.Response:
        """Record the hop, then answer with the next scripted redirect or 200."""
        assert self._logical is not None
        index = len(self.hops)
        self.hops.append(
            _HopRecord(
                route=route,
                connect_host=request.url.host,
                host_header=request.headers.get("Host"),
                sni_hostname=request.extensions.get("sni_hostname"),
                has_authorization="Authorization" in request.headers,
                logical_url=self._logical,
                resolutions=tuple(self.resolutions),
            )
        )
        if index >= len(self.script):
            return httpx.Response(200)
        redirect = self.script[index]
        location = _location(redirect, self._logical, index)
        self._logical = self._logical.join(location)
        if redirect.rebind is not None:
            host, answers = redirect.rebind
            self.dns[host] = answers
        return httpx.Response(redirect.status, headers={"Location": location})

    async def _fetch_async(
        self,
        start_url: str,
    ) -> None:
        loop = asyncio.get_running_loop()
        with patch.object(loop, "getaddrinfo", new=self._getaddrinfo):
            transport = _RecordingGuardedTransport(guard_profile=PROXY_PROFILE)
            transport.on_hop = self._on_hop
            async with httpx.AsyncClient(transport=transport, follow_redirects=True) as client:
                try:
                    await client.get(start_url, headers={"Authorization": _BEARER})
                except UrlValidationError:
                    pass  # A blocked hop fails closed; that is always acceptable.

    def fetch(
        self,
        start_url: str,
    ) -> list[str]:
        """Follow the scripted chain from ``start_url`` and check every hop.

        Args:
            start_url: Absolute URL of the first request.

        Returns:
            Every invariant violation observed, one line each.
        """
        self.hops = []
        self._logical = httpx.URL(start_url)
        asyncio.run(self._fetch_async(start_url))
        origin0 = _origin(httpx.URL(start_url))
        violations = [line for hop in self.hops for line in _hop_violations(origin0, hop)]
        self.script = []
        return violations


def _redirect_machine(
    kinds: tuple[str, ...],
    no_proxy_choices: tuple[str, ...],
) -> type[RuleBasedStateMachine]:
    """Build a redirect state machine over the given redirect kinds.

    Args:
        kinds: Redirect kinds the machine may script.
        no_proxy_choices: NO_PROXY values the proxy toggle may choose.

    Returns:
        A RuleBasedStateMachine subclass.
    """

    class _GuardedRedirectMachine(RuleBasedStateMachine):
        """Rebinding DNS, scripted redirects and proxy toggles around one guard."""

        def __init__(self) -> None:
            super().__init__()
            self.harness = _RedirectHarness().__enter__()

        def teardown(self) -> None:
            self.harness.__exit__(None, None, None)

        @rule(host=st.sampled_from(_HOSTS), answers=st.sampled_from(_ANSWER_SETS))
        def rebind(
            self,
            host: str,
            answers: tuple[str, ...],
        ) -> None:
            self.harness.dns[host] = answers

        @rule(enabled=st.booleans(), no_proxy=st.sampled_from(no_proxy_choices))
        def toggle_forward_proxy(
            self,
            enabled: bool,
            no_proxy: str,
        ) -> None:
            self.harness.set_forward_proxy(enabled, no_proxy)

        @precondition(lambda self: len(self.harness.script) < _MAX_SCRIPTED_HOPS)
        @rule(
            kind=st.sampled_from(kinds),
            status=st.sampled_from(_REDIRECT_STATUSES),
            other_host=st.sampled_from(_HOSTS),
            literal=st.sampled_from(_LITERAL_TARGETS),
            rebind=st.none() | st.tuples(st.sampled_from(_HOSTS), st.sampled_from(_ANSWER_SETS)),
        )
        def script_redirect(
            self,
            kind: str,
            status: int,
            other_host: str,
            literal: str,
            rebind: tuple[str, tuple[str, ...]] | None,
        ) -> None:
            target = literal if kind == _KIND_IP_LITERAL else other_host
            self.harness.script.append(_ScriptedRedirect(kind, status, target, rebind))

        @precondition(lambda self: bool(self.harness.script))
        @rule(host=st.sampled_from(_HOSTS), scheme=st.sampled_from(("https", "http")))
        def fetch(
            self,
            host: str,
            scheme: str,
        ) -> None:
            violations = self.harness.fetch(f"{scheme}://{host}/start")
            assert not violations, "\n".join(violations)

    return _GuardedRedirectMachine


@pytest.mark.unit
def test_redirect_chain_identity_without_ip_literal_hops() -> None:
    """Property: with no redirect to an IP literal and NO_PROXY either empty or
    '*', every hop dials a validated address, names its own host in Host and
    TLS, and never carries Authorization across origins."""
    machine = _redirect_machine(_KINDS_WITHOUT_IP_LITERAL, ("", "*"))
    run_state_machine_as_test(machine, settings=STATEFUL_SETTINGS)


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=_PINNED_URL_REASON)
def test_redirect_chain_identity_state_machine() -> None:
    """Property: for every redirect chain, rebinding sequence and proxy setting,
    every hop dials a validated address for its own host, names that host in
    Host and TLS, and never carries Authorization across origins."""
    machine = _redirect_machine(_ALL_KINDS, ("", "*", _HOST_A, _HOST_B))
    run_state_machine_as_test(machine, settings=STATEFUL_SETTINGS)


def _single_redirect_violations(
    redirect: _ScriptedRedirect,
    start_url: str = f"https://{_HOST_A}/start",
    no_proxy: str | None = None,
) -> list[str]:
    """Follow one scripted redirect and return the invariant violations.

    Args:
        redirect: The redirect the first hop answers with.
        start_url: The first request's URL.
        no_proxy: When not None, enable the forward proxy with this NO_PROXY.

    Returns:
        Every invariant violation observed across both hops.
    """
    with _RedirectHarness() as harness:
        if no_proxy is not None:
            harness.set_forward_proxy(True, no_proxy)
        harness.script = [redirect]
        violations = harness.fetch(start_url)
        assert len(harness.hops) == 2, f"expected two hops, saw {harness.hops}"
    return violations


@pytest.mark.unit
@pytest.mark.parametrize(
    ("redirect", "no_proxy"),
    [
        pytest.param(
            _ScriptedRedirect(_KIND_IP_LITERAL, target=_PUBLIC_IP_C),
            None,
            id="other-public-ip-literal-keeps-previous-sni",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=_PINNED_URL_REASON),
        ),
        pytest.param(
            _ScriptedRedirect(_KIND_IP_LITERAL, target=_PUBLIC_IP_A),
            None,
            id="pinned-ip-literal-keeps-host-and-authorization",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=_PINNED_URL_REASON),
        ),
        pytest.param(
            _ScriptedRedirect(_KIND_RELATIVE),
            _HOST_A,
            id="relative-from-no-proxy-host-tunnels-to-ip",
            marks=pytest.mark.xfail(strict=True, raises=AssertionError, reason=_PINNED_URL_REASON),
        ),
        pytest.param(_ScriptedRedirect(_KIND_RELATIVE), None, id="relative-direct"),
        pytest.param(_ScriptedRedirect(_KIND_RELATIVE), "", id="relative-proxied"),
        pytest.param(
            _ScriptedRedirect(_KIND_OTHER_HOST, target=_HOST_B), None, id="other-host-direct"
        ),
        pytest.param(
            _ScriptedRedirect(_KIND_IP_LITERAL, target=_PUBLIC_IP_C), "", id="ip-literal-proxied"
        ),
        pytest.param(_ScriptedRedirect(_KIND_HTTP_DOWNGRADE), None, id="http-downgrade-direct"),
    ],
)
def test_single_redirect_hop_identity(
    redirect: _ScriptedRedirect,
    no_proxy: str | None,
) -> None:
    """Property: the hop after one redirect dials a validated address, names its
    own host in Host and TLS, and carries Authorization only within the origin."""
    violations = _single_redirect_violations(redirect, no_proxy=no_proxy)
    assert not violations, "\n".join(violations)


@pytest.mark.unit
@pytest.mark.parametrize(
    "kind",
    [_KIND_SAME_HOST, _KIND_RELATIVE],
)
@pytest.mark.parametrize(
    "rebound_to",
    [(_PRIVATE_IP,), (_CREDENTIAL_IP,), (_LINK_LOCAL_IP,), (_PUBLIC_IP_A, _LOOPBACK_IP)],
)
def test_rebinding_between_hops_never_reaches_a_blocked_address(
    kind: str,
    rebound_to: tuple[str, ...],
) -> None:
    """Property: when a public host rebinds to a blocked address between two
    redirect hops, no hop dials the blocked address."""
    redirect = _ScriptedRedirect(kind, rebind=(_HOST_A, rebound_to))
    with _RedirectHarness() as harness:
        harness.script = [redirect]
        violations = harness.fetch(f"https://{_HOST_A}/start")
        dialled = [hop.connect_host for hop in harness.hops]
    assert not violations, "\n".join(violations)
    assert not set(dialled) & set(rebound_to) - _PUBLIC_IPS, dialled
