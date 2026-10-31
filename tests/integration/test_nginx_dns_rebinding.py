"""nginx must not re-resolve an MCP backend past the health check's pinned answer.

The registry validates an MCP ``proxy_pass_url`` without resolving it, and only a
backend whose pinned health check passed is rendered into nginx. The security
property pinned here: once the health check saw a public address for the
backend hostname, nginx never connects to a loopback or private address for
that backend, even when the hostname's DNS answer changes afterwards (DNS
rebinding with TTL 0). The test renders the real location blocks from
``NginxConfigService``, runs them in a pinned ``nginx:1.27`` container whose
only resolver is a scripted DNS responder written below with ``struct``, and
reads the address nginx dialled from ``$upstream_addr``.
"""

import asyncio
import inspect
import ipaddress
import re
import shutil
import socket
import struct
import subprocess
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from registry.constants import HealthStatus
from registry.core import nginx_service as nginx_service_module
from registry.core.config import settings
from registry.health.service import health_service

pytestmark = pytest.mark.integration

_NGINX_IMAGE: str = "nginx:1.27"
_PYTHON_IMAGE: str = "python:3.14.9-slim"
_SERVER_PATH: str = "/rebind"
_PUBLIC_ANSWER: str = "192.0.2.10"
_REBOUND_ANSWER: str = "127.0.0.1"
_DNS_PORT: int = 53
_BACKEND_PORT: int = 9100
_AUTH_HOP: str = "127.0.0.1:8888"
_GATEWAY_PORT: int = 8080
_PROBE_PATH: str = "/probe"
_READY_TIMEOUT_SECONDS: float = 30.0
_REQUEST_TIMEOUT_SECONDS: float = 15.0
_UPSTREAM_HEADER: str = "x-upstream-addr"
_UPSTREAM_SEPARATORS: re.Pattern[str] = re.compile(r"\s*,\s*|\s+:\s+")
_LOOPBACK_BODY: str = "LOOPBACK-BACKEND"
_LUA_DIRECTIVE_MARKER: str = "_by_lua_file"
_INTERNAL_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)
_NAMED_LOCATIONS: tuple[str, ...] = (
    "@auth_error",
    "@auth_internal_error",
    "@auth_subrequest_failed",
    "@forbidden_error",
    "@upstream_unavailable_jsonrpc",
)


def _dns_encode_name(
    name: str,
) -> bytes:
    """Encode a dotted host name as DNS wire-format labels.

    Args:
        name: Host name such as ``rebind.test``.

    Returns:
        The length-prefixed labels followed by the root label.
    """
    encoded = b""
    for label in name.strip(".").split("."):
        encoded += struct.pack("!B", len(label)) + label.encode("ascii")
    return encoded + b"\x00"


def _dns_question(
    packet: bytes,
) -> tuple[str, int, int]:
    """Read the first question of a DNS message.

    Args:
        packet: A DNS query or response.

    Returns:
        The lower-cased query name, the query type and the offset just past
        the question section.
    """
    offset = 12
    labels = []
    while packet[offset]:
        length = packet[offset]
        labels.append(packet[offset + 1 : offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    qtype = struct.unpack("!H", packet[offset + 1 : offset + 3])[0]
    return ".".join(labels).lower(), qtype, offset + 5


def _dns_response(
    query: bytes,
    answer_ip: str | None,
    rcode: int,
) -> bytes:
    """Build a response to ``query`` carrying at most one TTL 0 A record.

    Args:
        query: The DNS query being answered.
        answer_ip: IPv4 address for the A record, or None for no answer.
        rcode: DNS response code (0 for NOERROR, 3 for NXDOMAIN).

    Returns:
        The DNS response message.
    """
    _, _, question_end = _dns_question(query)
    transaction_id, flags = struct.unpack("!HH", query[:4])
    response_flags = 0x8080 | (flags & 0x0100) | rcode
    answers = 0 if answer_ip is None else 1
    header = struct.pack("!HHHHHH", transaction_id, response_flags, 1, answers, 0, 0)
    record = b""
    if answer_ip is not None:
        address = socket.inet_aton(answer_ip)
        record = struct.pack("!HHHIH", 0xC00C, 1, 1, 0, len(address)) + address
    return header + query[12:question_end] + record


def _dns_serve(
    name: str,
    first_ip: str,
    later_ip: str,
    port: int,
) -> None:
    """Answer A queries for ``name``: ``first_ip`` once, then ``later_ip``.

    Other query types for ``name`` get an empty NOERROR answer and every
    other name gets NXDOMAIN. Each query is printed as one ``QUERY`` line.

    Args:
        name: The rebinding host name.
        first_ip: Answer to the first A query (what the health check sees).
        later_ip: Answer to every later A query.
        port: UDP port to listen on, on 127.0.0.1.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print("READY", flush=True)
    answered = 0
    while True:
        query, peer = sock.recvfrom(4096)
        try:
            qname, qtype, _ = _dns_question(query)
        except (IndexError, struct.error):
            continue
        answer_ip, rcode = None, 3
        if qname == name:
            rcode = 0
            if qtype == 1:
                answer_ip = first_ip if answered == 0 else later_ip
                answered += 1
        print(f"QUERY {qname} {qtype} {answer_ip or '-'}", flush=True)
        sock.sendto(_dns_response(query, answer_ip, rcode), peer)


def _dns_query_a(
    name: str,
    port: int,
) -> str:
    """Resolve ``name`` once against the responder, as the health check does.

    Args:
        name: Host name to resolve.
        port: Responder UDP port on 127.0.0.1.

    Returns:
        The first A record address, or an empty string when there is none.
    """
    query = struct.pack("!HHHHHH", 0x5151, 0x0100, 1, 0, 0, 0)
    query += _dns_encode_name(name) + struct.pack("!HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, ("127.0.0.1", port))
    response, _ = sock.recvfrom(4096)
    _, _, offset = _dns_question(response)
    if struct.unpack("!H", response[6:8])[0] == 0:
        return ""
    rdlength = struct.unpack("!H", response[offset + 10 : offset + 12])[0]
    return socket.inet_ntoa(response[offset + 12 : offset + 12 + rdlength])


def _container_script(
    call: str,
) -> str:
    """Bundle the DNS helpers above into a script for ``python -c``.

    Args:
        call: The statement that runs the helpers, for example a serve call.

    Returns:
        Self-contained Python source.
    """
    helpers = (_dns_encode_name, _dns_question, _dns_response, _dns_serve, _dns_query_a)
    sources = [inspect.getsource(helper) for helper in helpers]
    return "\n".join(["import socket", "import struct", *sources, call])


def _docker(
    *args: str,
    timeout: float = 60.0,
) -> subprocess.CompletedProcess[str]:
    """Run one docker CLI command and capture its output.

    Args:
        *args: Arguments after ``docker``.
        timeout: Seconds before the command is abandoned.

    Returns:
        The completed process; the caller checks the return code.
    """
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _docker_checked(
    *args: str,
) -> str:
    """Run one docker CLI command and return stdout, raising on failure.

    Args:
        *args: Arguments after ``docker``.

    Returns:
        The command's stdout.
    """
    result = _docker(*args)
    if result.returncode != 0:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout


def _docker_unavailable_reason() -> str | None:
    """Explain why the rebinding lab cannot run here, or return None.

    Returns:
        A skip reason when the docker CLI, daemon or a pinned image is missing.
    """
    if shutil.which("docker") is None:
        return "docker CLI not found on PATH"
    try:
        if _docker("info", timeout=20).returncode != 0:
            return "docker daemon is not reachable (docker info failed)"
        for image in (_NGINX_IMAGE, _PYTHON_IMAGE):
            if _docker("image", "inspect", image, timeout=20).returncode != 0:
                return f"docker image {image} is not available locally"
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"docker probe failed: {error}"
    return None


@dataclass
class _Response:
    """One HTTP response from the gateway nginx.

    Attributes:
        status: HTTP status code.
        headers: Lower-cased header names mapped to values.
        body: Decoded response body.
    """

    status: int
    headers: dict[str, str]
    body: str


def _http_get(
    port: int,
    target: str,
    extra_headers: dict[str, str] | None = None,
) -> _Response:
    """Send one GET to the published gateway port and read the whole response.

    Args:
        port: Host port on 127.0.0.1.
        target: Request target.
        extra_headers: Extra request headers, such as client-forged routing headers.

    Returns:
        The parsed response.
    """
    extra = "".join(f"{name}: {value}\r\n" for name, value in (extra_headers or {}).items())
    request = f"GET {target} HTTP/1.1\r\nHost: gw.example\r\nConnection: close\r\n{extra}\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=_REQUEST_TIMEOUT_SECONDS) as conn:
        conn.sendall(request.encode("ascii"))
        chunks = []
        while chunk := conn.recv(65536):
            chunks.append(chunk)
    head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return _Response(int(lines[0].split(" ")[1]), headers, body.decode("utf-8", "replace"))


class _RebindingLab:
    """A DNS responder container and an nginx container sharing one network namespace.

    The responder owns the namespace and the 127.0.0.1-only published gateway
    port; nginx joins it, so 127.0.0.1 inside nginx is the namespace loopback,
    where a stand-in private service listens on the backend port.
    """

    def __init__(
        self,
        hostname: str,
    ) -> None:
        """Remember the rebinding host name and pick unique container names.

        Args:
            hostname: The backend host name the responder rebinds.
        """
        suffix = uuid.uuid4().hex[:12]
        self.hostname = hostname
        self.responder = f"mcpgw-rebind-dns-{suffix}"
        self.nginx = f"mcpgw-rebind-nginx-{suffix}"
        self.port = 0

    def start_responder(self) -> None:
        """Start the DNS responder and wait until it listens."""
        serve = (
            f"_dns_serve({self.hostname!r}, {_PUBLIC_ANSWER!r}, {_REBOUND_ANSWER!r}, {_DNS_PORT})"
        )
        _docker_checked(
            "run",
            "-d",
            "--name",
            self.responder,
            "-p",
            f"127.0.0.1::{_GATEWAY_PORT}",
            _PYTHON_IMAGE,
            "python",
            "-u",
            "-c",
            _container_script(serve),
        )
        deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
        while "READY" not in _docker("logs", self.responder).stdout:
            if time.monotonic() > deadline:
                raise RuntimeError(f"DNS responder never started: {self.logs(self.responder)}")
            time.sleep(0.2)
        for line in _docker_checked("port", self.responder, f"{_GATEWAY_PORT}/tcp").splitlines():
            host, _, port = line.strip().rpartition(":")
            if host == "127.0.0.1" and port.isdigit():
                self.port = int(port)
        if not self.port:
            raise RuntimeError("responder container has no 127.0.0.1 gateway port")

    def health_check_answer(self) -> str:
        """Resolve the backend once from inside the namespace, as the health check does.

        Returns:
            The address the pinned health check would validate and connect to.
        """
        probe = f"print(_dns_query_a({self.hostname!r}, {_DNS_PORT}))"
        return _docker_checked("exec", self.responder, "python", "-c", _container_script(probe))

    def start_nginx(
        self,
        config: str,
    ) -> None:
        """Start nginx in the responder's namespace with ``config`` and wait for it.

        Args:
            config: Full ``nginx.conf`` text.
        """
        _docker_checked(
            "run",
            "-d",
            "--name",
            self.nginx,
            "--network",
            f"container:{self.responder}",
            "-e",
            f"NGINX_CONF={config}",
            _NGINX_IMAGE,
            "sh",
            "-c",
            'printf "nameserver 127.0.0.1\\n" > /etc/resolv.conf'
            ' && printf "%s" "$NGINX_CONF" > /etc/nginx/nginx.conf'
            ' && exec nginx -g "daemon off;"',
        )
        deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            try:
                if _http_get(self.port, "/healthz").status == 200:
                    return
            except (OSError, IndexError, ValueError):
                pass
            time.sleep(0.2)
        raise RuntimeError(f"nginx never became ready: {self.logs(self.nginx)}")

    def dns_queries(self) -> list[str]:
        """Return the responder's ``QUERY`` lines in arrival order.

        Returns:
            Lines such as ``QUERY rebind.test 1 127.0.0.1``.
        """
        lines = _docker("logs", self.responder).stdout.splitlines()
        return [line for line in lines if line.startswith("QUERY ")]

    def logs(
        self,
        container: str,
    ) -> str:
        """Return a container's combined logs for diagnostics.

        Args:
            container: Container name.

        Returns:
            stdout and stderr of the container.
        """
        result = _docker("logs", container)
        return f"{result.stdout}{result.stderr}"

    def remove(self) -> None:
        """Kill and remove both containers.

        ``docker kill`` first, because the responder's Python process ignores
        SIGTERM and a plain forced removal can wait out a stop timeout.
        """
        _docker("kill", self.nginx, self.responder)
        _docker("rm", "-f", self.nginx, self.responder)


@pytest.fixture(scope="module")
def docker_unavailable_reason() -> str | None:
    """Probe docker once per module.

    Returns:
        The skip reason, or None when the lab can run.
    """
    return _docker_unavailable_reason()


@pytest.fixture
def rebinding_lab(
    docker_unavailable_reason: str | None,
) -> Iterator[Callable[[str], _RebindingLab]]:
    """Provide a factory for rebinding labs and remove their containers afterwards.

    Args:
        docker_unavailable_reason: Cached docker probe result.

    Yields:
        A callable that starts a responder for one host name and returns the lab.
    """
    if docker_unavailable_reason is not None:
        pytest.skip(docker_unavailable_reason)
    labs: list[_RebindingLab] = []

    def _start(hostname: str) -> _RebindingLab:
        lab = _RebindingLab(hostname)
        labs.append(lab)
        lab.start_responder()
        return lab

    try:
        yield _start
    finally:
        for lab in labs:
            lab.remove()


@pytest.fixture
def render_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Point rendered blocks at the in-namespace stubs instead of real services.

    The auth server URL becomes a literal loopback address so nginx needs no DNS
    for its own hop, and the location resolver becomes the scripted responder.
    """
    monkeypatch.setattr(settings, "auth_server_url", f"http://{_AUTH_HOP}")
    monkeypatch.setenv("NGINX_DNS_RESOLVER", "127.0.0.1")
    monkeypatch.setenv("NGINX_DNS_RESOLVER_TIMEOUT", "2")


def _server_info(
    hostname: str,
) -> dict:
    """Build a healthy, enabled MCP server record for ``hostname``.

    Args:
        hostname: Backend host name in the proxy_pass_url.

    Returns:
        The server document the renderer reads.
    """
    return {
        "path": _SERVER_PATH,
        "server_name": "rebind",
        "proxy_pass_url": f"http://{hostname}:{_BACKEND_PORT}/mcp",
        "supported_transports": ["streamable-http"],
        "is_enabled": True,
        "egress_auth_mode": "none",
    }


def _render_virtual_backend_blocks(
    service: nginx_service_module.NginxConfigService,
    server_info: dict,
) -> str:
    """Render the production virtual-backend locations for one MCP server.

    Args:
        service: The nginx config service.
        server_info: The backend's server document.

    Returns:
        The rendered ``/_vs_auth`` and ``/_vs_backend`` location blocks.
    """
    repository = SimpleNamespace(get=AsyncMock(return_value=server_info))
    virtual_server = SimpleNamespace(
        tool_mappings=[SimpleNamespace(backend_server_path=_SERVER_PATH, backend_version=None)]
    )
    active_route = [nginx_service_module._VersionRoute("", "", server_info)]
    with (
        patch("registry.repositories.factory.get_server_repository", return_value=repository),
        patch.object(service, "_resolve_version_routes", AsyncMock(return_value=active_route)),
    ):
        return asyncio.run(service._generate_virtual_backend_locations([virtual_server]))


def _plain_nginx_block(
    block: str,
) -> str:
    """Make a rendered block loadable by stock nginx.

    Substitutes the empty root path and drops the ``*_by_lua_file`` directives,
    which stock nginx does not have; nothing else in the block is changed.

    Args:
        block: Rendered location block text.

    Returns:
        The block as stock nginx can load it.
    """
    lines = block.replace("{{ROOT_PATH}}", "").splitlines()
    return "\n".join(line for line in lines if _LUA_DIRECTIVE_MARKER not in line)


def _gateway_config(
    locations: str,
    probe_target: str | None,
) -> str:
    """Wrap rendered locations in a minimal gateway config.

    The harness adds: rate-limit zones the direct block references, a stub
    ``/validate`` that allows every request, stub named error locations, a stub
    auth server that echoes the route it was asked for in ``X-Hop-*`` response
    headers, a stand-in private service on loopback, and an optional ``/probe``
    location that rewrites into an internal location the way the Lua virtual
    router's subrequest reaches it.

    Args:
        locations: Rendered location blocks.
        probe_target: Internal location to reach from ``/probe``, if any.

    Returns:
        The full ``nginx.conf`` text.
    """
    named = "\n".join(f"        location {name} {{ return 599; }}" for name in _NAMED_LOCATIONS)
    probe = (
        f"        location = {_PROBE_PATH} {{ rewrite ^ {probe_target} last; }}"
        if probe_target
        else ""
    )
    auth_host, _, auth_port = _AUTH_HOP.partition(":")
    return f"""
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {{}}
http {{
    access_log off;
    limit_req_zone $binary_remote_addr zone=mcp_gateway_edge:1m rate=50r/s;
    limit_conn_zone $binary_remote_addr zone=mcp_gateway_conn:1m;
    server {{
        listen {auth_host}:{auth_port};
        location / {{
            add_header X-Hop-Uri $request_uri always;
            add_header X-Hop-Server-Path $http_x_registered_server_path always;
            add_header X-Hop-Route-Mode $http_x_registered_route_mode always;
            add_header X-Hop-Upstream-Url $http_x_upstream_url always;
            return 200 "AUTH-HOP";
        }}
    }}
    server {{
        listen {_REBOUND_ANSWER}:{_BACKEND_PORT};
        location / {{ return 200 "{_LOOPBACK_BODY}"; }}
    }}
    server {{
        listen {_GATEWAY_PORT};
        proxy_connect_timeout 2s;
        add_header X-Upstream-Addr $upstream_addr always;
        location = /healthz {{ return 200 "ok"; }}
        location = /validate {{ internal; return 200; }}
{named}
{probe}
{locations}
    }}
}}
"""


def _dialled_addresses(
    response: _Response,
) -> list[str]:
    """Split ``$upstream_addr`` into the individual addresses nginx tried.

    Args:
        response: Gateway response carrying the upstream header.

    Returns:
        Addresses such as ``127.0.0.1:9100``.
    """
    raw = response.headers.get(_UPSTREAM_HEADER, "")
    return [part for part in _UPSTREAM_SEPARATORS.split(raw) if part]


def _is_internal(
    address: str,
) -> bool:
    """Return True when an ``ip:port`` address is loopback, private or link-local.

    Args:
        address: One ``$upstream_addr`` entry.

    Returns:
        Whether the address is an internal destination.
    """
    host = address.rsplit(":", 1)[0]
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return any(ip in network for network in _INTERNAL_NETWORKS)


def _backend_lookups(
    lab: _RebindingLab,
    hostname: str,
) -> list[str]:
    """Return the responder's queries for the backend host name, in order.

    Args:
        lab: The running lab.
        hostname: Backend host name.

    Returns:
        The ``QUERY`` lines whose question is ``hostname``.
    """
    return [line for line in lab.dns_queries() if line.split()[1:2] == [hostname.lower()]]


def _prepare_lab(
    rebinding_lab: Callable[[str], _RebindingLab],
    monkeypatch: pytest.MonkeyPatch,
    hostname: str,
) -> _RebindingLab:
    """Start the responder, run the pinned health check and record it as healthy.

    Args:
        rebinding_lab: Lab factory fixture.
        monkeypatch: Used to record the health result for the server path.
        hostname: Backend host name.

    Returns:
        The lab, with the health check already consuming the public answer.
    """
    lab = rebinding_lab(hostname)
    answer = lab.health_check_answer().strip()
    if answer != _PUBLIC_ANSWER:
        pytest.fail(f"health check should see {_PUBLIC_ANSWER}, saw {answer!r}")
    monkeypatch.setitem(health_service.server_health_status, _SERVER_PATH, HealthStatus.HEALTHY)
    return lab


@pytest.mark.parametrize(
    "hostname",
    [
        pytest.param("rebind.test", id="literal-proxy-pass"),
        pytest.param("rebind", id="resolver-variable"),
    ],
)
@pytest.mark.usefixtures("render_settings")
def test_virtual_backend_never_dials_internal_after_public_health_check(
    rebinding_lab: Callable[[str], _RebindingLab],
    monkeypatch: pytest.MonkeyPatch,
    hostname: str,
) -> None:
    """Property: a virtual backend that was public at health check is never dialled internally.

    The only loopback address nginx may dial is the configured auth-server hop
    (``_AUTH_HOP``, the value ``render_settings`` installs), which owns backend
    resolution, and nginx must not look the backend name up again itself. The
    hop must be asked for the nginx-selected registration, whatever routing
    headers the client sends.
    """
    lab = _prepare_lab(rebinding_lab, monkeypatch, hostname)
    health_check_lookups = _backend_lookups(lab, hostname)
    service = nginx_service_module.NginxConfigService()
    blocks = _render_virtual_backend_blocks(service, _server_info(hostname))
    backend_location = service._virtual_backend_location(_SERVER_PATH)
    lab.start_nginx(_gateway_config(_plain_nginx_block(blocks), backend_location))

    forged = {
        "X-Upstream-Url": f"http://{_REBOUND_ANSWER}:{_BACKEND_PORT}/mcp",
        "X-Registered-Server-Path": "/forged",
        "X-Registered-Route-Mode": "direct",
    }
    response = _http_get(lab.port, _PROBE_PATH, forged)
    dialled = _dialled_addresses(response)
    internal = [address for address in dialled if address != _AUTH_HOP and _is_internal(address)]
    assert not internal, (
        f"health check pinned {_PUBLIC_ANSWER} for {hostname}, nginx dialled {dialled} "
        f"and answered {response.status} {response.body!r}; DNS log {lab.dns_queries()}"
    )
    assert _backend_lookups(lab, hostname) == health_check_lookups, (
        f"nginx resolved {hostname} after the health check: {lab.dns_queries()}"
    )
    assert response.status == 200, f"backend location answered {response.status}"
    assert response.body == "AUTH-HOP"
    assert response.headers.get("x-hop-uri") == f"/mcp-proxy/{_SERVER_PATH.strip('/')}/"
    assert response.headers.get("x-hop-server-path") == _SERVER_PATH
    assert response.headers.get("x-hop-route-mode") == "virtual"
    assert "x-hop-upstream-url" not in response.headers


@pytest.mark.usefixtures("render_settings")
def test_direct_location_leaves_backend_resolution_to_the_auth_server_hop(
    rebinding_lab: Callable[[str], _RebindingLab],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Property: a direct MCP location dials only the auth-server hop and never resolves the backend."""
    hostname = "rebind.test"
    lab = _prepare_lab(rebinding_lab, monkeypatch, hostname)
    health_check_queries = lab.dns_queries()
    service = nginx_service_module.NginxConfigService()
    info = _server_info(hostname)
    block = service._create_location_block(
        _SERVER_PATH, info["proxy_pass_url"], "streamable-http", info
    )
    lab.start_nginx(_gateway_config(_plain_nginx_block(block), None))

    response = _http_get(lab.port, f"{_SERVER_PATH}/mcp")
    assert response.status == 200, f"direct location answered {response.status} {response.body!r}"
    assert _dialled_addresses(response) == [_AUTH_HOP]
    assert response.body == "AUTH-HOP"
    assert lab.dns_queries() == health_check_queries
