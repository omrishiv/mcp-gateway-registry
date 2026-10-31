"""Business logic behind invoke_agent and get_agent_task (A2A agent invocation).

Pure business logic: no ``fastmcp`` import. Every function here accepts and
returns plain values, dicts and ``AgentInvocationResult`` (a pydantic model
with zero fastmcp dependency), so it is directly unit-testable and so
server.py's thin ``@mcp.tool()`` wrappers are the only place that needs to
know about ``Context``/``ToolResult``.

Entry points (called by server.py's tool wrappers, which already resolved
``headers = gateway_client.caller_headers(ctx)`` and
``deadline = gateway_client.Deadline(INVOKE_DEADLINE_SECONDS)`` before
calling in -- this module never calls ``caller_headers`` itself):

- ``invoke_agent_impl(agent_path, message, context_id, task_id, message_id,
  protocol_version, *, headers, deadline) -> AgentInvocationResult``
- ``get_agent_task_impl(agent_path, task_id, protocol_version, *, headers,
  deadline) -> AgentInvocationResult``

Every exception this module can raise is caught at the top of both entry
points and turned into a ``status="failed"`` result with one of a fixed set
of public-safe error strings (see the error-mapping section below); the
real exception is always logged first via
``gateway_client.redact_exception_text``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import unicodedata
from typing import Any

import gateway_client
import httpx
from a2a_dialects import DIALECTS
from models import AgentInvocationResult

logger = logging.getLogger(__name__)

REGISTRY_URL = os.getenv("REGISTRY_BASE_URL", "http://localhost")

# registry/core/nginx_service.py:AGENT_ROUTE_PREFIX ("/agent") is the
# canonical source of this value. It is NOT imported here: nginx_service.py
# imports registry.core.config at module scope, which eagerly constructs
# registry.core.config.Settings() -- and mcpgw has no registry Settings
# object (see gateway_client.py's module docstring). Confirmed by hand:
# `from registry.core.nginx_service import AGENT_ROUTE_PREFIX` raises
# `RuntimeError: SECRET_KEY is set to a well-known placeholder value...`
# outside a fully configured registry environment, which would make mcpgw
# fail to start (or need its own SECRET_KEY, which it has no business
# having). The value is therefore duplicated here as a constant; it is part
# of the registry's own nginx routing contract and changes only alongside a
# coordinated gateway routing change.
AGENT_ROUTE_PREFIX = "/agent"

# Max message length: fits inside the 256 KiB MCP
# request-body limit after JSON escaping, with room to spare.
MAX_AGENT_MESSAGE_CHARS: int = 32_000

# Bounded-read limits.
AGENT_CARD_MAX_BYTES: int = 256 * 1024
A2A_MESSAGE_MAX_BYTES: int = 1024 * 1024

# Polling schedule: 1, 2, 4, then every 4 seconds.
# The last value repeats forever once the tuple is exhausted (see
# `next(iterator, AGENT_POLL_SCHEDULE_SECONDS[-1])` in _send_and_poll).
AGENT_POLL_SCHEDULE_SECONDS: tuple[int, ...] = (1, 2, 4)

# task_id / context_id / message_id must match this pattern.
_ID_TOKEN_PATTERN = r"\A[A-Za-z0-9._:-]{1,128}\Z"  # nosec B105 - id validation regex, not a credential

_VALID_PROTOCOL_VERSIONS = ("0.3", "1.0")

# Characters rejected by name, beyond whitespace/control/
# non-ASCII (checked generically below).
_FORBIDDEN_AGENT_PATH_CHARS: dict[str, str] = {
    "%": "a '%' character",
    "?": "a '?' character",
    "#": "a '#' character",
}


class AgentInvocationError(Exception):
    """An A2A-invocation-specific failure whose ``.message`` is already public-safe.

    Raised by ``select_dialect`` when an agent's card offers no JSON-RPC
    binding. ``.message`` is returned verbatim by ``_map_error``; ``.kind``
    is a short machine-readable tag for callers that want to branch on it
    (only "no_jsonrpc" exists today).
    """

    def __init__(self, message: str, *, kind: str) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind


# ---------------------------------------------------------------------------
# Path and id rules
# ---------------------------------------------------------------------------


def validate_agent_path(path: str) -> str:
    """Validate and normalize an ``agent_path`` argument.

    Applies the registry's own agent-path rule
    (``registry/schemas/agent_models.py::_validate_path_format``, replicated
    inline rather than imported) plus the URL-safety checks that keep the
    path mcpgw builds equal to the path the caller named.

    Raises:
        ValueError: The path fails any rule, naming the problem.
    """
    path = path.strip()
    if not path.startswith("/"):
        raise ValueError("agent_path must start with '/', for example /flight-booking.")
    if "//" in path:
        raise ValueError("agent_path must not contain '//'.")
    if path.endswith("/") and path != "/":
        raise ValueError("agent_path must not end with '/' unless it is the root path.")

    for segment in path.split("/"):
        if segment in (".", ".."):
            raise ValueError(f"agent_path must not contain a '{segment}' path segment.")

    for ch in path:
        forbidden = _FORBIDDEN_AGENT_PATH_CHARS.get(ch)
        if forbidden is not None:
            raise ValueError(f"agent_path must not contain {forbidden}.")
        if ch.isspace():
            raise ValueError("agent_path must not contain whitespace.")
        if unicodedata.category(ch) == "Cc":
            raise ValueError("agent_path must not contain control characters.")
        if ord(ch) > 127:
            raise ValueError(f"agent_path must not contain the non-ASCII character {ch!r}.")

    return path


def validate_id_token(value: str, field_name: str) -> str:
    """Validate ``task_id``/``context_id``/``message_id`` against the shared id pattern."""
    if re.fullmatch(_ID_TOKEN_PATTERN, value) is None:
        raise ValueError(f"{field_name} must match [A-Za-z0-9._:-]{{1,128}}.")
    return value


def validate_protocol_version(value: str | None) -> str | None:
    """Validate an optional ``protocol_version`` argument."""
    if value is None:
        return None
    if value not in _VALID_PROTOCOL_VERSIONS:
        raise ValueError("protocol_version must be '0.3' or '1.0'.")
    return value


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


def _agent_url(path: str) -> str:
    """mcpgw always posts to exactly ``/agent/{path}/``."""
    return f"{REGISTRY_URL}{AGENT_ROUTE_PREFIX}/{path.lstrip('/')}/"


def _card_url(path: str) -> str:
    return f"{_agent_url(path)}.well-known/agent-card.json"


async def _post(
    url: str,
    headers: dict[str, str],
    body: dict[str, Any],
    deadline: gateway_client.Deadline,
) -> dict[str, Any]:
    """POST one JSON-RPC request through a fresh guarded client, bounded to 1 MiB."""
    async with gateway_client.gateway_http_client(deadline.remaining(), headers) as client:
        return await gateway_client.request_json_bounded(
            client, "POST", url, json_body=body, limit=A2A_MESSAGE_MAX_BYTES
        )


# ---------------------------------------------------------------------------
# Dialect selection
# ---------------------------------------------------------------------------


async def select_dialect(
    path: str,
    protocol_version: str | None,
    *,
    headers: dict[str, str],
    client: httpx.AsyncClient,
) -> str:
    """Return the A2A dialect version ("0.3" or "1.0") to use for ``path``.

    When ``protocol_version`` is given, it is returned directly and the
    agent card is never read. Otherwise the already-open ``client`` (which
    carries ``headers``) is used to GET the card, bounded to
    ``AGENT_CARD_MAX_BYTES``.

    Raises:
        AgentInvocationError: The card offers no JSON-RPC binding
            ("no_jsonrpc").
    """
    if protocol_version is not None:
        return protocol_version

    card = await gateway_client.request_json_bounded(
        client, "GET", _card_url(path), limit=AGENT_CARD_MAX_BYTES
    )

    for interface in card.get("supportedInterfaces") or []:
        if not isinstance(interface, dict):
            continue
        if interface.get("protocolBinding") != "JSONRPC":
            continue
        version = interface.get("protocolVersion")
        if isinstance(version, str) and version.startswith("1."):
            return "1.0"

    top_version = card.get("protocolVersion")
    preferred_transport = card.get("preferredTransport")
    if (
        isinstance(top_version, str)
        and top_version.startswith("0.3")
        and (preferred_transport is None or preferred_transport == "JSONRPC")
    ):
        return "0.3"

    raise AgentInvocationError(
        "This agent does not offer JSON-RPC, which invoke_agent needs.",
        kind="no_jsonrpc",
    )


async def _select_dialect_for(
    path: str, *, headers: dict[str, str], deadline: gateway_client.Deadline
) -> str:
    """Open a client and resolve the dialect via the agent card (protocol_version is None)."""
    async with gateway_client.gateway_http_client(deadline.remaining(), headers) as client:
        return await select_dialect(path, None, headers=headers, client=client)


# ---------------------------------------------------------------------------
# Timing: send, then poll
# ---------------------------------------------------------------------------


async def _send_and_poll(
    *,
    path: str,
    dialect: Any,
    dialect_version: str,
    message: str,
    context_id: str | None,
    task_id: str | None,
    message_id: str,
    headers: dict[str, str],
    deadline: gateway_client.Deadline,
) -> AgentInvocationResult:
    url = _agent_url(path)
    request_headers = {**headers, **dialect.extra_headers()}

    send_request_id = secrets.token_hex(8)
    send_body = dialect.build_send(message, context_id, task_id, message_id, send_request_id)
    try:
        response_body = await _post(url, request_headers, send_body, deadline)
    except httpx.TimeoutException:
        # The agent ignored the non-blocking flag and held the connection
        # open past the deadline: mcpgw never got ANY parsed reply, so there
        # is no task_id to report or to poll with.
        return AgentInvocationResult(
            status="failed",
            agent_path=path,
            protocol_version=dialect_version,
            error=(
                f"The agent did not answer within {round(deadline.total_seconds)} seconds. "
                f"If you retry, pass message_id {message_id} so the agent can "
                "recognize the repeat."
            ),
        )

    result = dialect.parse(response_body, send_request_id, agent_path=path)
    if result.status != "pending":
        return result

    # dialect.parse only returns status="pending" for a task result that has
    # both an id and a recognized-or-"unknown" state (a task missing
    # id/state is "failed", never "pending"), so task_id is
    # always present from here on -- the "no task_id" case above is strictly
    # a send-level timeout, never a poll-level one.
    delays = iter(AGENT_POLL_SCHEDULE_SECONDS)
    current_delay = next(delays)
    while True:
        if deadline.remaining() < current_delay + 1.0:
            break
        await asyncio.sleep(current_delay)

        poll_request_id = secrets.token_hex(8)
        poll_body = dialect.build_get(result.task_id, poll_request_id)
        response_body = await _post(url, request_headers, poll_body, deadline)
        result = dialect.parse(response_body, poll_request_id, agent_path=path)
        if result.status != "pending":
            return result

        current_delay = next(delays, AGENT_POLL_SCHEDULE_SECONDS[-1])

    return AgentInvocationResult(
        status="pending",
        agent_path=path,
        protocol_version=dialect_version,
        task_id=result.task_id,
        context_id=result.context_id,
    )


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def _map_http_status_error(exc: httpx.HTTPStatusError, path: str) -> str:
    response = exc.response
    status = response.status_code

    if status == 401:
        if 'realm="mcp"' in response.headers.get("WWW-Authenticate", ""):
            return "The gateway rejected your token. Refresh it and retry."
        return "The agent requires its own credential, which invoke_agent does not supply."

    if status == 403:
        body_text = response.text.strip()
        if body_text == '{"error": "Access forbidden"}':
            return f"You do not have invoke_agent on {path}."
        parts = ["The agent refused the request (HTTP 403)."]
        if body_text:
            parts.append(_cut_500(body_text))
        return " ".join(parts)

    if status == 404:
        return (
            f"No gateway route for {path}. The agent may be disabled, unhealthy or not "
            "an A2A agent, or A2A reverse-proxy mode may be off."
        )

    if status == 405:
        return f"The gateway route for {path} does not accept this request."

    if status == 429:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            return f"Rate limited. Retry after {retry_after} seconds."
        return "Rate limited."

    if status in (502, 503, 504):
        return "The agent backend did not answer."

    return gateway_client.public_error(exc)


def _cut_500(text: str) -> str:
    return text[:500]


def _map_error(exc: Exception, path: str) -> str:
    """Map any exception from the invocation flow to a public-safe message.

    Checked most-specific-first: ``json.JSONDecodeError`` is itself a
    ``ValueError`` subclass (raised only for a 2xx response whose body isn't
    JSON), so it must be checked before the generic ``ValueError`` branch
    that returns a validation rule's own message verbatim.
    """
    if isinstance(exc, json.JSONDecodeError):
        return (
            f"No gateway route for {path}. The agent may be disabled, unhealthy or not "
            "an A2A agent, or A2A reverse-proxy mode may be off."
        )
    if isinstance(exc, AgentInvocationError):
        return exc.message
    if isinstance(exc, gateway_client.ResponseTooLargeError):
        return "The agent's reply exceeded 1 MiB and was dropped."
    if isinstance(exc, httpx.HTTPStatusError):
        return _map_http_status_error(exc, path)
    if isinstance(exc, ValueError):
        # Covers path/id/version/message rule ValueErrors and
        # gateway_client.CallerIdentityError (a ValueError subclass): both
        # return the exception's own message verbatim.
        return str(exc)
    return gateway_client.public_error(exc)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


async def invoke_agent_impl(
    agent_path: str,
    message: str,
    context_id: str | None,
    task_id: str | None,
    message_id: str | None,
    protocol_version: str | None,
    *,
    headers: dict[str, str],
    deadline: gateway_client.Deadline,
) -> AgentInvocationResult:
    """Send a message to an A2A agent, polling a resulting task if needed.

    Never raises: every failure path returns ``AgentInvocationResult(status=
    "failed", ...)`` with a public-safe ``error``, after logging the real
    exception via ``gateway_client.redact_exception_text``.
    """
    resolved_message_id = message_id if message_id is not None else secrets.token_hex(16)
    resolved_task_id: str | None = None
    resolved_context_id: str | None = None

    try:
        if message_id is not None:
            resolved_message_id = validate_id_token(message_id, "message_id")

        if len(message) > MAX_AGENT_MESSAGE_CHARS:
            raise ValueError(f"message must be at most {MAX_AGENT_MESSAGE_CHARS} characters.")

        path = validate_agent_path(agent_path)

        if task_id is not None:
            resolved_task_id = validate_id_token(task_id, "task_id")
        if context_id is not None:
            resolved_context_id = validate_id_token(context_id, "context_id")
        protocol_version = validate_protocol_version(protocol_version)

        dialect_version = protocol_version
        if dialect_version is None:
            dialect_version = await _select_dialect_for(path, headers=headers, deadline=deadline)
        dialect = DIALECTS[dialect_version]

        result = await _send_and_poll(
            path=path,
            dialect=dialect,
            dialect_version=dialect_version,
            message=message,
            context_id=resolved_context_id,
            task_id=resolved_task_id,
            message_id=resolved_message_id,
            headers=headers,
            deadline=deadline,
        )
        result.message_id = resolved_message_id
        return result
    except Exception as exc:  # noqa: BLE001 - every failure must become a result, never raise
        logger.error(gateway_client.redact_exception_text(exc))
        return AgentInvocationResult(
            status="failed",
            agent_path=agent_path,
            error=_map_error(exc, agent_path),
            message_id=resolved_message_id,
            task_id=resolved_task_id,
            context_id=resolved_context_id,
        )


async def get_agent_task_impl(
    agent_path: str,
    task_id: str,
    protocol_version: str | None,
    *,
    headers: dict[str, str],
    deadline: gateway_client.Deadline,
) -> AgentInvocationResult:
    """Make one get-task call for an agent task, picking a dialect if needed.

    Never raises: see ``invoke_agent_impl``'s docstring.
    """
    resolved_task_id: str | None = None
    try:
        resolved_task_id = validate_id_token(task_id, "task_id")
        path = validate_agent_path(agent_path)
        protocol_version = validate_protocol_version(protocol_version)

        dialect_version = protocol_version
        if dialect_version is None:
            dialect_version = await _select_dialect_for(path, headers=headers, deadline=deadline)
        dialect = DIALECTS[dialect_version]

        url = _agent_url(path)
        request_headers = {**headers, **dialect.extra_headers()}
        request_id = secrets.token_hex(8)
        body = dialect.build_get(resolved_task_id, request_id)
        try:
            response_body = await _post(url, request_headers, body, deadline)
        except httpx.TimeoutException:
            # Equivalent to invoke_agent_impl's send-timeout case:
            # mcpgw never got a parsed reply, so there is nothing new to
            # report beyond the task_id the caller already has -- retry
            # get_agent_task with the same task_id.
            return AgentInvocationResult(
                status="failed",
                agent_path=path,
                protocol_version=dialect_version,
                task_id=resolved_task_id,
                error=(
                    f"The agent did not answer within {round(deadline.total_seconds)} "
                    f"seconds. Retry get_agent_task with task_id {resolved_task_id}."
                ),
            )
        return dialect.parse(response_body, request_id, agent_path=path)
    except Exception as exc:  # noqa: BLE001 - every failure must become a result, never raise
        logger.error(gateway_client.redact_exception_text(exc))
        return AgentInvocationResult(
            status="failed",
            agent_path=agent_path,
            error=_map_error(exc, agent_path),
            task_id=resolved_task_id,
        )
