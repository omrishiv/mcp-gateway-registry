"""Property tests: the /mcp-proxy hop dials exactly what the registry admits.

The registry validates and health-checks every MCP backend with
``validate_url(url, profile=proxy_profile_for_entity_target(...))``. nginx never
resolves a backend itself: every MCP location, virtual-server backends
included, proxies to the auth-server ``/mcp-proxy/`` hop, which forwards to the
upstream signed into its hop token. These tests pin that the hop applies the
registry's own policy on every request, with and without an injected egress
credential:

- the hop dials the backend if and only if the registry's validation, run
  against the same DNS answers and the same SSRF allowlist settings, accepts it;
- when it dials, the connection goes to an address that validation accepted,
  and a cloud/workload credential or link-local address is never dialled;
- a refused request answers 502 and sends nothing upstream;
- the built-in ``mcpgw-server`` backend is reachable only through its exact
  registered identity.

Everything below the hop's HTTP client is scripted: the resolver answers from a
table, and the network layer records the address each request would connect
to instead of connecting. No test opens a socket.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from contextlib import ExitStack
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    rule,
    run_state_machine_as_test,
)

from registry.egress_auth.upstream_binding import selected_upstream
from registry.exceptions import UrlValidationError
from registry.utils import url_guard
from registry.utils.url_guard import (
    proxy_profile_for_entity_target,
    validate_proxy_pass_url,
    validate_url,
)

pytestmark = [pytest.mark.unit, pytest.mark.auth]


HYPOTHESIS_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    deadline=None,
)
STATEFUL_SETTINGS = settings(
    max_examples=50,
    stateful_step_count=15,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    deadline=None,
)

BLOCKED_DETAIL: str = "Upstream MCP server blocked by egress policy"
VAULTED_TOKEN: str = "vaulted-upstream-token"

BACKEND_HOST: str = "mcp.backend.example"
OTHER_HOST: str = "other.example"
SERVER_PATH: str = "office-docs"

BUILTIN_PATH: str = "airegistry-tools"
BUILTIN_HOST: str = "mcpgw-server"
BUILTIN_TARGET: str = "http://mcpgw-server:8003/"
# The exact request identities the registry's MCP and health clients use for
# the built-in target. Stated here rather than imported so the oracle does not
# move with the code under test.
BUILTIN_IDENTITIES: frozenset[str] = frozenset(
    {
        "http://mcpgw-server:8003/",
        "http://mcpgw-server:8003/mcp",
        "http://mcpgw-server:8003/mcp/",
    }
)
DOCKER_BRIDGE_IP: str = "172.18.0.5"

_UPSTREAM_BODY: bytes = b'{"jsonrpc":"2.0","id":1,"result":{}}'
_INITIALIZE: dict = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}

_PROXY_ENV_KEYS: tuple[str, ...] = (
    "EGRESS_FORWARD_PROXY_ENABLED",
    "EGRESS_FORWARD_PROXY_CA_BUNDLE",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)

# Cloud/workload credential endpoints and link-local space. No configuration
# may ever make the hop connect to one of these.
_NEVER_DIALLED_IPS: frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address] = frozenset(
    ipaddress.ip_address(ip)
    for ip in (
        "169.254.169.254",
        "169.254.170.2",
        "169.254.170.23",
        "fd00:ec2::254",
        "fd00:ec2::23",
        "100.100.100.200",
    )
)
_NEVER_DIALLED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)
_NAT64_PREFIX: ipaddress.IPv6Network = ipaddress.ip_network("64:ff9b::/96")

# Special-purpose blocks a backend name may resolve into. Each draw picks an
# address inside the block, so the property covers whole ranges rather than
# one representative address.
_ADDRESS_BLOCKS: tuple[str, ...] = (
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "fe80::/10",
    "fc00::/7",
    "0.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "198.18.0.0/15",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "93.184.216.0/24",
)
_FIXED_ADDRESSES: tuple[str, ...] = (
    "169.254.169.254",
    "169.254.170.2",
    "169.254.170.23",
    "fd00:ec2::254",
    "fd00:ec2::23",
    "100.100.100.200",
    "93.184.216.34",
    "1.1.1.1",
    "8.8.8.8",
    "2606:4700:4700::1111",
    "127.0.0.1",
    "10.0.0.5",
)

_ALLOWED_HOSTS_CHOICES: tuple[str, ...] = (
    "",
    BACKEND_HOST,
    OTHER_HOST,
    f"{OTHER_HOST},{BACKEND_HOST}",
)
_ALLOWED_CIDRS_CHOICES: tuple[str, ...] = (
    "",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "100.64.0.0/10",
    "172.16.0.0/12,192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "0.0.0.0/0,::/0",
)

_ROUTE_DIRECT: str = "direct"
_ROUTE_VIRTUAL: str = "virtual"

# The rebinding cycle the state machine walks, one step per rule call.
_PUBLIC_ANSWER: tuple[str, ...] = ("93.184.216.34",)
_REBIND_CYCLE: tuple[tuple[str, ...], ...] = (
    _PUBLIC_ANSWER,
    ("127.0.0.1",),
    ("10.0.0.5",),
    ("169.254.169.254",),
    _PUBLIC_ANSWER,
)
_REBIND_ANSWERS: tuple[tuple[str, ...], ...] = (
    _PUBLIC_ANSWER,
    ("1.1.1.1", "93.184.216.34"),
    ("127.0.0.1",),
    ("::1",),
    ("10.0.0.5",),
    ("192.168.1.20",),
    ("100.64.0.9",),
    ("169.254.169.254",),
    ("169.254.170.2",),
    ("fd00:ec2::254",),
    ("93.184.216.34", "10.0.0.5"),
    ("10.0.0.5", "169.254.169.254"),
)


def _guard_settings() -> MagicMock:
    """Return a registry settings stub carrying every field the guard reads.

    Returns:
        A MagicMock with an empty SSRF allowlist and small pool limits.
    """
    stub = MagicMock()
    stub.github_extra_hosts = ""
    stub.ssrf_allowed_hosts = ""
    stub.ssrf_allowed_cidrs = ""
    stub.gateway_proxy_allow_private_targets = False
    stub.egress_oauth_trusted_idp_hosts = ""
    stub.egress_http_pool_max_connections = 10
    stub.egress_http_pool_max_keepalive = 5
    stub.egress_http_pool_keepalive_expiry_seconds = 5.0
    stub.egress_http_pool_connect_retries = 0
    return stub


def _reset_guard_caches() -> None:
    """Clear every lru_cache the guard consults for policy and proxy config."""
    url_guard._skill_allowlist.cache_clear()
    url_guard._proxy_allowlist.cache_clear()
    url_guard._builtin_airegistry_tools_allowlist.cache_clear()
    url_guard._credentialed_oauth_allowlist.cache_clear()
    url_guard._forward_proxy_config.cache_clear()
    url_guard._forward_proxy_ssl_context.cache_clear()


def _allow_all_scope_repo() -> AsyncMock:
    """Scope repository under which ``admin:all`` grants every server and method.

    Returns:
        An AsyncMock standing in for the scope repository.
    """
    repo = AsyncMock()

    async def _get_server_scopes(scope_name: str) -> list[dict]:
        if scope_name == "admin:all":
            return [{"server": "*", "methods": ["*"], "tools": ["*"]}]
        return []

    async def _get_server_scopes_bulk(scope_names: list[str]) -> dict:
        return {s: await _get_server_scopes(s) for s in scope_names if s == "admin:all"}

    repo.get_server_scopes.side_effect = _get_server_scopes
    repo.get_server_scopes_bulk.side_effect = _get_server_scopes_bulk
    return repo


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parse an address, dropping any IPv6 zone index."""
    return ipaddress.ip_address(value.split("%", 1)[0])


def _is_ip_literal(host: str) -> bool:
    """Return True if ``host`` parses as an IP address."""
    try:
        _ip(host)
    except ValueError:
        return False
    return True


def _embedded_ipv4(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return the IPv4 address an IPv4-mapped or NAT64 address carries, else ``ip``."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64_PREFIX:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def _never_dialled(address: str) -> bool:
    """Return True if ``address`` is a credential endpoint or link-local."""
    for ip in {_ip(address), _embedded_ipv4(_ip(address))}:
        if ip in _NEVER_DIALLED_IPS:
            return True
        if any(ip.version == net.version and ip in net for net in _NEVER_DIALLED_NETWORKS):
            return True
    return False


def _host_for_url(host: str) -> str:
    """Bracket an IPv6 literal for use in a URL authority."""
    return f"[{host}]" if ":" in host else host


@dataclass(frozen=True)
class _Dial:
    """One request the hop handed to the network layer."""

    address: str
    host_header: str | None
    authorization: str | None
    url: str


@dataclass(frozen=True)
class _Registration:
    """A registered MCP backend and the route a client reaches it through."""

    server_path: str
    proxy_pass_url: str
    route: str

    def signed_upstream(self) -> str:
        """The upstream nginx signs into the hop token for this route."""
        server = {
            "proxy_pass_url": self.proxy_pass_url,
            "supported_transports": ["streamable-http"],
        }
        return selected_upstream(server, self.route == _ROUTE_VIRTUAL)

    def outbound_url(self, suffix: str = "mcp") -> str:
        """The URL the hop sends the request to."""
        if self.route == _ROUTE_VIRTUAL:
            return self.signed_upstream()
        return self.proxy_pass_url.rstrip("/") + "/" + suffix

    def request_path(self, suffix: str = "mcp") -> str:
        """The /mcp-proxy path nginx forwards the client request to."""
        if self.route == _ROUTE_VIRTUAL:
            return f"/mcp-proxy/{self.server_path}/"
        return f"/mcp-proxy/{self.server_path}/{suffix}"


class _HopHarness:
    """The real /mcp-proxy handler over a scripted resolver and a recording network."""

    def __init__(self) -> None:
        self.dns: dict[str, tuple[str, ...]] = {}
        self.dials: list[_Dial] = []
        self.egress_injected = False
        self.guard_settings = _guard_settings()
        self._stack = ExitStack()
        self.client: TestClient | None = None

    def __enter__(self) -> _HopHarness:
        import auth_server.server as server_module

        harness = self

        def _getaddrinfo(host: str, port: int, *args: object, **kwargs: object) -> list[tuple]:
            answers = harness.dns.get(str(host).rstrip("."), ())
            if not answers:
                raise socket.gaierror(socket.EAI_NONAME, f"no scripted answer for {host}")
            records = []
            for ip in answers:
                if ":" in ip:
                    records.append(
                        (
                            socket.AF_INET6,
                            socket.SOCK_STREAM,
                            socket.IPPROTO_TCP,
                            "",
                            (ip, port, 0, 0),
                        )
                    )
                else:
                    records.append(
                        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
                    )
            return records

        async def _network(
            transport: httpx.AsyncHTTPTransport, request: httpx.Request
        ) -> httpx.Response:
            # Whatever client the hop builds ends at this layer. A pinned request
            # names an address; an unpinned one names a host the operating
            # system would resolve at connect time, so record its first answer.
            host = request.url.host
            if _is_ip_literal(host):
                address = host
            else:
                answers = harness.dns.get(host, ())
                if not answers:
                    raise httpx.ConnectError(f"no scripted answer for {host}", request=request)
                address = answers[0]
            harness.dials.append(
                _Dial(
                    address=address,
                    host_header=request.headers.get("Host"),
                    authorization=request.headers.get("Authorization"),
                    url=str(request.url),
                )
            )
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=_UPSTREAM_BODY,
                request=request,
            )

        async def _vend(token: str, server: str) -> dict | None:
            if harness.egress_injected:
                return {"access_token": VAULTED_TOKEN, "provider": "test"}
            return None

        stack = self._stack
        stack.enter_context(patch.dict(os.environ))
        for key in _PROXY_ENV_KEYS:
            os.environ.pop(key, None)
        stack.enter_context(patch.object(url_guard, "settings", self.guard_settings))
        stack.enter_context(patch.object(socket, "getaddrinfo", _getaddrinfo))
        stack.enter_context(
            patch.object(httpx.AsyncHTTPTransport, "handle_async_request", _network)
        )
        stack.enter_context(patch.object(server_module.settings, "egress_auth_enabled", True))
        stack.enter_context(patch.object(server_module, "_vend_egress_token", _vend))
        stack.enter_context(
            patch.object(server_module, "_read_mcp_filter_enabled", return_value=False)
        )
        stack.enter_context(
            patch("auth_server.server.get_scope_repository", return_value=_allow_all_scope_repo())
        )
        url_guard.reset_shared_clients_for_tests()
        stack.callback(url_guard.reset_shared_clients_for_tests)
        _reset_guard_caches()
        stack.callback(_reset_guard_caches)
        self.client = TestClient(server_module.app)
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stack.close()

    def configure(self, allowed_hosts: str, allowed_cidrs: str, allow_private: bool) -> None:
        """Set the SSRF allowlist both the registry and the hop read.

        Args:
            allowed_hosts: SSRF_ALLOWED_HOSTS.
            allowed_cidrs: SSRF_ALLOWED_CIDRS.
            allow_private: GATEWAY_PROXY_ALLOW_PRIVATE_TARGETS.
        """
        self.guard_settings.ssrf_allowed_hosts = allowed_hosts
        self.guard_settings.ssrf_allowed_cidrs = allowed_cidrs
        self.guard_settings.gateway_proxy_allow_private_targets = allow_private
        _reset_guard_caches()

    def registry_admits(self, registration: _Registration, suffix: str = "mcp") -> list[str] | None:
        """Run the registry's health-check validation for this backend.

        Args:
            registration: The registered backend and route.
            suffix: The transport suffix of a direct-route request.

        Returns:
            The validated addresses, or None if the registry refuses the URL.
        """
        outbound = registration.outbound_url(suffix)
        try:
            profile = proxy_profile_for_entity_target(
                "mcp_server",
                f"/{registration.server_path}/",
                registration.proxy_pass_url,
                outbound,
            )
            return validate_url(outbound, profile=profile)
        except UrlValidationError:
            return None

    def send(self, registration: _Registration, suffix: str = "mcp") -> httpx.Response:
        """Send one MCP request through the hop as nginx would.

        Args:
            registration: The registered backend and route.
            suffix: The transport suffix of a direct-route request.

        Returns:
            The hop's response.
        """
        from auth_server.internal_request_token import mint_mcp_proxy_token

        virtual = registration.route == _ROUTE_VIRTUAL
        token = mint_mcp_proxy_token(
            subject="test-user",
            scopes=["admin:all"],
            server_name=registration.server_path,
            upstream_url=registration.signed_upstream(),
            virtual_backend=virtual,
        )
        headers = {
            "X-Internal-Token": token,
            "X-Registered-Server-Path": "/" + registration.server_path,
            "X-Registered-Route-Mode": _ROUTE_VIRTUAL if virtual else _ROUTE_DIRECT,
        }
        assert self.client is not None
        self.dials = []
        return self.client.post(
            registration.request_path(suffix), json=_INITIALIZE, headers=headers
        )


def _request_violations(
    response: httpx.Response,
    dials: list[_Dial],
    admitted: list[str] | None,
    outbound_url: str,
    egress_injected: bool,
) -> list[str]:
    """Check one hop request against the data-plane-equals-control-plane invariants.

    Args:
        response: The hop's response.
        dials: Every request the hop handed to the network.
        admitted: Addresses the registry's validation accepted, or None if refused.
        outbound_url: The URL the hop was asked to forward to.
        egress_injected: Whether a vaulted credential was injected.

    Returns:
        One line per violated invariant.
    """
    problems: list[str] = []
    for dial in dials:
        if _never_dialled(dial.address):
            problems.append(f"dialled credential/link-local address {dial.address} ({dial.url})")
    if admitted is None:
        if dials:
            problems.append(
                f"dialled {[d.address for d in dials]} for {outbound_url} although the "
                "registry refuses it"
            )
        if response.status_code != 502:
            problems.append(f"refused request answered {response.status_code}, not 502")
        elif response.json().get("detail") != BLOCKED_DETAIL:
            problems.append(f"refused request detail {response.json().get('detail')!r}")
        return problems
    if response.status_code != 200:
        problems.append(
            f"admitted request to {outbound_url} answered {response.status_code}: {response.text}"
        )
    if len(dials) != 1:
        problems.append(f"admitted request made {len(dials)} dials, expected 1")
    validated = {_ip(a) for a in admitted}
    expected_host = httpx.URL(outbound_url).netloc.decode("ascii")
    for dial in dials:
        if _ip(dial.address) not in validated:
            problems.append(
                f"dialled {dial.address}, which is not among the validated addresses {admitted}"
            )
        if dial.host_header != expected_host:
            problems.append(f"Host header {dial.host_header!r} does not name {expected_host!r}")
        if egress_injected and dial.authorization != f"Bearer {VAULTED_TOKEN}":
            problems.append("injected credential missing from an admitted egress dial")
    return problems


@st.composite
def _addresses(draw: st.DrawFn) -> str:
    """Draw an address from a special-purpose block or a fixed notable address."""
    if draw(st.booleans()):
        return draw(st.sampled_from(_FIXED_ADDRESSES))
    network = ipaddress.ip_network(draw(st.sampled_from(_ADDRESS_BLOCKS)))
    offset = draw(st.integers(min_value=0, max_value=min(network.num_addresses - 1, 2**24)))
    return str(network[offset])


@dataclass(frozen=True)
class _Case:
    """One differential example."""

    answers: tuple[str, ...]
    literal_backend: bool
    scheme: str
    port: int | None
    route: str
    egress_injected: bool
    allowed_hosts: str
    allowed_cidrs: str
    allow_private: bool

    def registration(self) -> _Registration:
        """The registered backend this example describes."""
        host = _host_for_url(self.answers[0]) if self.literal_backend else BACKEND_HOST
        authority = host if self.port is None else f"{host}:{self.port}"
        return _Registration(
            server_path=SERVER_PATH,
            proxy_pass_url=f"{self.scheme}://{authority}/",
            route=self.route,
        )


@st.composite
def _cases(draw: st.DrawFn) -> _Case:
    """Draw DNS answers x allowlist configuration x route x egress injection."""
    answers = tuple(draw(st.lists(_addresses(), min_size=1, max_size=2, unique=True)))
    return _Case(
        answers=answers,
        literal_backend=draw(st.booleans()),
        scheme=draw(st.sampled_from(("http", "https"))),
        port=draw(st.sampled_from((None, 8080))),
        route=draw(st.sampled_from((_ROUTE_DIRECT, _ROUTE_VIRTUAL))),
        egress_injected=draw(st.booleans()),
        allowed_hosts=draw(st.sampled_from(_ALLOWED_HOSTS_CHOICES)),
        allowed_cidrs=draw(st.sampled_from(_ALLOWED_CIDRS_CHOICES)),
        allow_private=draw(st.booleans()),
    )


@HYPOTHESIS_SETTINGS
@given(case=_cases())
def test_hop_dials_exactly_what_the_registry_admits(case: _Case) -> None:
    """Property: for every resolved address, SSRF allowlist configuration, route
    and egress-injection state, the hop dials the backend if and only if the
    registry's own health-check validation accepts it, dials only an address
    that validation accepted, never dials a credential or link-local address,
    and answers a refused request with 502 without sending anything.
    """
    registration = case.registration()
    with _HopHarness() as hop:
        hop.configure(case.allowed_hosts, case.allowed_cidrs, case.allow_private)
        hop.dns = {BACKEND_HOST: case.answers}
        hop.egress_injected = case.egress_injected
        admitted = hop.registry_admits(registration)
        response = hop.send(registration)
        violations = _request_violations(
            response,
            hop.dials,
            admitted,
            registration.outbound_url(),
            case.egress_injected,
        )
    assert not violations, "\n".join(violations)


class _RebindingHopMachine(RuleBasedStateMachine):
    """A backend's DNS answers and the allowlist change between hop requests."""

    def __init__(self) -> None:
        super().__init__()
        self.hop = _HopHarness().__enter__()
        self.cycle_index = 0
        self.hop.dns = {BACKEND_HOST: _REBIND_CYCLE[0]}
        self.allowed_hosts = ""
        self.allowed_cidrs = ""
        self.allow_private = False
        self.violations: list[str] = []

    def _apply_allowlist(self) -> None:
        self.hop.configure(self.allowed_hosts, self.allowed_cidrs, self.allow_private)

    @rule()
    def rebind_next_in_cycle(self) -> None:
        """Advance public -> loopback -> private -> metadata -> public."""
        self.cycle_index = (self.cycle_index + 1) % len(_REBIND_CYCLE)
        self.hop.dns = {BACKEND_HOST: _REBIND_CYCLE[self.cycle_index]}

    @rule(answers=st.sampled_from(_REBIND_ANSWERS))
    def rebind(self, answers: tuple[str, ...]) -> None:
        """Point the backend name at an arbitrary answer set."""
        self.hop.dns = {BACKEND_HOST: answers}

    @rule()
    def toggle_host_allowlist(self) -> None:
        """Add or remove the backend from SSRF_ALLOWED_HOSTS."""
        self.allowed_hosts = "" if self.allowed_hosts else BACKEND_HOST
        self._apply_allowlist()

    @rule()
    def toggle_allow_private(self) -> None:
        """Flip GATEWAY_PROXY_ALLOW_PRIVATE_TARGETS."""
        self.allow_private = not self.allow_private
        self._apply_allowlist()

    @rule(cidrs=st.sampled_from(_ALLOWED_CIDRS_CHOICES))
    def set_allowed_cidrs(self, cidrs: str) -> None:
        """Replace SSRF_ALLOWED_CIDRS."""
        self.allowed_cidrs = cidrs
        self._apply_allowlist()

    @rule(
        route=st.sampled_from((_ROUTE_DIRECT, _ROUTE_VIRTUAL)),
        egress_injected=st.booleans(),
    )
    def send(self, route: str, egress_injected: bool) -> None:
        """Send one request through the hop and check it against the policy now."""
        registration = _Registration(
            server_path=SERVER_PATH,
            proxy_pass_url=f"http://{BACKEND_HOST}:8080/",
            route=route,
        )
        self.hop.egress_injected = egress_injected
        admitted = self.hop.registry_admits(registration)
        response = self.hop.send(registration)
        self.violations.extend(
            _request_violations(
                response,
                self.hop.dials,
                admitted,
                registration.outbound_url(),
                egress_injected,
            )
        )
        assert not self.violations, "\n".join(self.violations)

    def teardown(self) -> None:
        self.hop.__exit__(None, None, None)


def test_rebinding_across_requests_never_escapes_the_policy() -> None:
    """Property: across any sequence of DNS rebinds (public, loopback, private,
    metadata and back), allowlist changes and requests with or without an
    injected credential, every dial of every request goes to an address the
    registry's policy admits at that request, and every refused request answers
    502 with no upstream dial.
    """
    run_state_machine_as_test(_RebindingHopMachine, settings=STATEFUL_SETTINGS)


def _nginx_renders_virtual_route(registration: _Registration) -> bool:
    """Return True if nginx would render (and sign) a virtual route for this record.

    nginx builds a virtual backend location only after the registered
    proxy_pass_url passes ``validate_proxy_pass_url`` for its own path.
    """
    try:
        validate_proxy_pass_url(
            registration.proxy_pass_url, server_path=f"/{registration.server_path}/"
        )
    except (UrlValidationError, ValueError):
        return False
    return True


@HYPOTHESIS_SETTINGS
@given(
    server_path=st.sampled_from((BUILTIN_PATH, "other-tools", f"{BUILTIN_PATH}-v2")),
    proxy_pass_url=st.sampled_from(
        (BUILTIN_TARGET, "http://mcpgw-server:8003/tools/", "http://mcpgw-server:9000/")
    ),
    route=st.sampled_from((_ROUTE_DIRECT, _ROUTE_VIRTUAL)),
    suffix=st.sampled_from(("mcp", "mcp/", "sse", "messages/")),
    answers=st.sampled_from(
        ((DOCKER_BRIDGE_IP,), ("127.0.0.1",), ("169.254.169.254",), ("93.184.216.34",))
    ),
    allowed_hosts=st.sampled_from(("", BUILTIN_HOST)),
    allow_private=st.booleans(),
    egress_injected=st.booleans(),
)
def test_builtin_tools_server_is_reachable_only_through_its_exact_identity(
    server_path: str,
    proxy_pass_url: str,
    route: str,
    suffix: str,
    answers: tuple[str, ...],
    allowed_hosts: str,
    allow_private: bool,
    egress_injected: bool,
) -> None:
    """Property: the reserved mcpgw-server backend is dialled only when the hop
    token names the exact built-in registration (/airegistry-tools/ ->
    http://mcpgw-server:8003/) and the outbound URL is one of its exact request
    identities, whatever the allowlist says; when it is, a private bridge
    address is reachable, and a credential or link-local answer still is not.
    """
    registration = _Registration(
        server_path=server_path, proxy_pass_url=proxy_pass_url, route=route
    )
    assume(route == _ROUTE_DIRECT or _nginx_renders_virtual_route(registration))
    outbound = registration.outbound_url(suffix)
    exact_identity = (
        server_path == BUILTIN_PATH
        and proxy_pass_url == BUILTIN_TARGET
        and outbound in BUILTIN_IDENTITIES
    )
    with _HopHarness() as hop:
        hop.configure(allowed_hosts, "", allow_private)
        hop.dns = {BUILTIN_HOST: answers}
        hop.egress_injected = egress_injected
        response = hop.send(registration, suffix)
        dials = list(hop.dials)
        admitted = hop.registry_admits(registration, suffix)

    if not exact_identity:
        assert not dials, f"dialled {dials} for a non-built-in identity {outbound}"
        assert response.status_code == 502, response.text
        assert response.json()["detail"] == BLOCKED_DETAIL
        return
    assert all(not _never_dialled(d.address) for d in dials), dials
    if answers == (DOCKER_BRIDGE_IP,):
        assert response.status_code == 200, response.text
        assert [d.address for d in dials] == [DOCKER_BRIDGE_IP]
        assert dials[0].host_header == "mcpgw-server:8003"
    # The exact identity follows the registry's own decision in every case.
    assert bool(dials) == (admitted is not None), (dials, admitted)
