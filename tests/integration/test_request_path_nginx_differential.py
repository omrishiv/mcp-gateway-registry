"""The auth server's path binding must never claim a route nginx did not take.

``/validate`` decides whether the scope-bearing ``X-Original-URL`` belongs to the
registration whose nginx location forwarded the request. It does so by running
the raw path through ``normalize_request_path`` and then applying the prefix and
trailing-slash rule of ``auth_server.server._registered_proxy_url_matches``. The
security property pinned here is a differential one against a real nginx: for
every raw request target nginx answers, the binding never accepts a registration
unless nginx routed the request to that registration (or to a registration
nested under it, which shadows it in nginx). Disagreements in the other
direction fail closed and are not asserted.
"""

import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator
from urllib.parse import urlsplit

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.auth.resource_binding import normalize_request_path

pytestmark = pytest.mark.integration

_NGINX_IMAGE: str = "nginx:1.27"
_CONTAINER_PORT: int = 80
_GATEWAY_ORIGIN: str = "http://gw.example"
_REGISTRY_ROOT_PATH: str = ""
_REGISTRATIONS: tuple[str, ...] = ("/a", "/a/a", "/aa")
_PREFIXES: tuple[str, ...] = ("", "/a", "/a/a", "/aa", "/x/..", "/a/..")
_TOKENS: tuple[str, ...] = ("/", ".", "%", "%2e", "%2f", "%25", ";", "?", "#", "a")
_HEX_DIGITS: str = "0123456789abcdefABCDEF"
_MAX_TOKENS: int = 12
_READY_TIMEOUT_SECONDS: float = 30.0
_SOCKET_TIMEOUT_SECONDS: float = 5.0
_ROUTED_MARKER: str = "P:"
_CATCH_ALL_MARKER: str = "U:"
_ROUTED_VARIANTS: tuple[tuple[str, str], ...] = (
    ("//a//mcp", "/a"),
    ("/x/..%2fa/mcp", "/a"),
    ("/%61/mcp", "/a"),
    ("/a/%2e%2e/a/", "/a"),
    ("/a%2f", "/a"),
    ("/a/a/mcp?x=/aa/", "/a/a"),
)


def _binding_accepts(
    original_url: str,
    registered_path: str,
) -> bool:
    """Apply the direct-route binding rule of the auth server to one URL.

    Reproduces ``auth_server.server._registered_proxy_url_matches`` for
    ``route_mode="direct"`` with an empty registry root path: the URL path is
    taken with ``urlsplit``, canonicalized by ``normalize_request_path``, keeps a
    trailing slash the raw path had, and then must equal the registration or
    continue past ``<registration>/``.

    Args:
        original_url: The scope-bearing URL, as nginx sends it in X-Original-URL.
        registered_path: The registration path, for example ``/a``.

    Returns:
        True when the binding accepts ``original_url`` for ``registered_path``.
    """
    raw_path = urlsplit(original_url).path
    path = normalize_request_path(raw_path)
    if raw_path.endswith("/") and not path.endswith("/"):
        path += "/"
    base_path = f"{_REGISTRY_ROOT_PATH.rstrip('/')}/{registered_path.strip('/')}"
    return path == base_path or path.startswith(f"{base_path}/")


def _nginx_config() -> str:
    """Build an nginx config with one prefix and one exact location per registration.

    Each registration gets both the ``location <p>/`` prefix block and the
    ``location = <p>`` exact block the gateway renders for a root-endpoint
    server, because the binding accepts both forms. Everything else falls
    through to a catch-all that echoes ``$uri``.

    Returns:
        The full ``nginx.conf`` text.
    """
    locations = []
    for path in _REGISTRATIONS:
        reply = f'return 200 "{_ROUTED_MARKER}{path}|$uri";'
        locations.append(f"        location {path}/ {{ {reply} }}")
        locations.append(f"        location = {path} {{ {reply} }}")
    body = "\n".join(locations)
    return f"""
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events {{}}
http {{
    access_log off;
    server {{
        listen {_CONTAINER_PORT};
        location / {{ return 200 "{_CATCH_ALL_MARKER}$uri"; }}
{body}
    }}
}}
"""


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


def _docker_unavailable_reason() -> str | None:
    """Explain why the docker differential cannot run here, or return None.

    Returns:
        A skip reason when the docker CLI, daemon or pinned image is missing.
    """
    if shutil.which("docker") is None:
        return "docker CLI not found on PATH"
    try:
        if _docker("info", timeout=20).returncode != 0:
            return "docker daemon is not reachable (docker info failed)"
        if _docker("image", "inspect", _NGINX_IMAGE, timeout=20).returncode != 0:
            return f"docker image {_NGINX_IMAGE} is not available locally"
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"docker probe failed: {error}"
    return None


def _published_port(
    container: str,
) -> int:
    """Return the 127.0.0.1 host port docker published for the nginx listener.

    Args:
        container: Container name.

    Returns:
        The host port number.
    """
    result = _docker("port", container, f"{_CONTAINER_PORT}/tcp")
    for line in result.stdout.splitlines():
        host, _, port = line.strip().rpartition(":")
        if host == "127.0.0.1" and port.isdigit():
            return int(port)
    raise RuntimeError(f"no 127.0.0.1 port published for {container}: {result.stdout!r}")


def _send_raw(
    port: int,
    target: str,
) -> tuple[int, str]:
    """Send one GET with ``target`` as the verbatim request target.

    A raw socket is used so neither Python nor an HTTP client library can
    normalize, quote or reject the target before nginx sees it.

    Args:
        port: Host port of the nginx container.
        target: Request target, sent byte for byte.

    Returns:
        The response status code and decoded body.
    """
    request = f"GET {target} HTTP/1.1\r\nHost: gw.example\r\nConnection: close\r\n\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=_SOCKET_TIMEOUT_SECONDS) as conn:
        conn.sendall(request.encode("latin-1"))
        chunks = []
        while chunk := conn.recv(65536):
            chunks.append(chunk)
    head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    return int(status_line.split(" ")[1]), body.decode("utf-8", "replace")


def _wait_until_ready(
    container: str,
    port: int,
) -> None:
    """Block until nginx answers on ``port`` or fail with its logs.

    Args:
        container: Container name, for diagnostics.
        port: Host port of the nginx listener.
    """
    deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            status, _ = _send_raw(port, "/")
            if status == 200:
                return
        except (OSError, IndexError, ValueError):
            pass
        time.sleep(0.2)
    logs = _docker("logs", container).stderr
    raise RuntimeError(f"nginx container {container} never became ready: {logs}")


@pytest.fixture(scope="session")
def nginx_port() -> Iterator[int]:
    """Start one nginx container for the session and yield its host port.

    Yields:
        The 127.0.0.1 port that reaches the container's nginx listener.
    """
    reason = _docker_unavailable_reason()
    if reason is not None:
        pytest.skip(reason)
    name = f"mcpgw-uri-differential-{uuid.uuid4().hex[:12]}"
    started = _docker(
        "run",
        "-d",
        "--name",
        name,
        "-p",
        f"127.0.0.1::{_CONTAINER_PORT}",
        "-e",
        f"NGINX_CONF={_nginx_config()}",
        _NGINX_IMAGE,
        "sh",
        "-c",
        'printf "%s" "$NGINX_CONF" > /etc/nginx/nginx.conf && exec nginx -g "daemon off;"',
    )
    try:
        if started.returncode != 0:
            raise RuntimeError(f"docker run failed: {started.stderr}")
        port = _published_port(name)
        _wait_until_ready(name, port)
        yield port
    finally:
        _docker("rm", "-f", name)


def _routed_registration(
    body: str,
) -> str | None:
    """Return the registration nginx routed to, or None for the catch-all.

    Args:
        body: Response body from the differential config.

    Returns:
        The registration path, or None when the catch-all answered.
    """
    if body.startswith(_ROUTED_MARKER):
        return body[len(_ROUTED_MARKER) :].split("|", 1)[0]
    return None


def _covers(
    claimed: str,
    routed: str | None,
) -> bool:
    """Return True when a claim for ``claimed`` agrees with nginx's choice.

    A nested registration such as ``/a/a`` shadows ``/a`` in nginx, so the
    gateway only ever asks the binding about the nested one; a claim for the
    parent is therefore harmless.

    Args:
        claimed: Registration the binding accepted.
        routed: Registration nginx routed to, or None for the catch-all.

    Returns:
        Whether the claim is consistent with the routing decision.
    """
    if routed is None:
        return False
    return routed == claimed or routed.startswith(f"{claimed}/")


def _target_strategy() -> st.SearchStrategy[str]:
    """Generate raw origin-form request targets over the routing alphabet.

    Returns:
        A strategy of targets such as ``/a%2f..;#a`` that start with ``/``.
    """
    triplet = st.builds(
        lambda high, low: f"%{high}{low}",
        st.sampled_from(_HEX_DIGITS),
        st.sampled_from(_HEX_DIGITS),
    )
    token = st.one_of(st.sampled_from(_TOKENS), triplet)
    return st.builds(
        lambda prefix, tokens: "/" + (prefix + "".join(tokens)).lstrip("/"),
        st.sampled_from(_PREFIXES),
        st.lists(token, max_size=_MAX_TOKENS),
    )


def _false_claims(
    port: int,
    target: str,
) -> tuple[int, str, list[str]]:
    """Send ``target`` to nginx and list the registrations the binding wrongly claims.

    Args:
        port: Host port of the nginx container.
        target: Raw request target.

    Returns:
        The status, the response body and every claimed registration that
        nginx did not route to.
    """
    status, body = _send_raw(port, target)
    if status != 200:
        return status, body, []
    routed = _routed_registration(body)
    url = f"{_GATEWAY_ORIGIN}{target}"
    claims = [path for path in _REGISTRATIONS if _binding_accepts(url, path)]
    return status, body, [path for path in claims if not _covers(path, routed)]


@settings(
    max_examples=100,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    deadline=None,
)
@given(target=_target_strategy())
@example(target="/a;x")
@example(target="/a/a;x")
def test_binding_never_claims_a_registration_nginx_did_not_route(
    nginx_port: int,
    target: str,
) -> None:
    """Property: the binding accepts a registration only if nginx routed there."""
    status, body, false_claims = _false_claims(nginx_port, target)
    assert not false_claims, (
        f"target {target!r}: nginx answered {status} {body!r}, binding also claims {false_claims}"
    )


@pytest.mark.parametrize(("target", "registration"), _ROUTED_VARIANTS)
def test_binding_accepts_encoded_variants_nginx_routes(
    nginx_port: int,
    target: str,
    registration: str,
) -> None:
    """Property: slash, dot-segment and percent variants nginx routes to a registration bind to it."""
    status, body = _send_raw(nginx_port, target)
    assert status == 200, f"nginx refused {target!r}: {status} {body!r}"
    assert _routed_registration(body) == registration, f"nginx routed {target!r}: {body!r}"
    assert _binding_accepts(f"{_GATEWAY_ORIGIN}{target}", registration)
