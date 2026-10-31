"""Business logic behind ``invoke_mcp_tool``.

This module validates a server path and tool name, resolves the server path
to a gateway MCP endpoint, opens one MCP session through the gateway as the
caller, and bounds the size of the result it relays back. Every exception it
can raise is mapped to a public-safe ``ToolResult`` by
``invoke_mcp_tool_impl``, the single entry point `server.py`'s thin
``invoke_mcp_tool`` tool wrapper calls into.

This module takes no ``fastmcp.Context`` and does nothing with the MCP
client's session: callers pass already-built caller headers (see
``gateway_client.caller_headers``) and a ``gateway_client.Deadline``, so this
module itself needs no stub to import or to unit test its validation,
endpoint-resolution and error-mapping logic. ``fastmcp``'s own ``Client``,
``StreamableHttpTransport`` and ``tools.ToolResult`` are imported lazily,
inside the few functions that actually build or call them (``call_mcp_tool``,
``_bounded_tool_result``, and ``invoke_mcp_tool_impl``'s error branches), so a
plain ``import mcp_invoke`` never requires ``fastmcp`` to be installed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import unicodedata
from collections.abc import Callable
from typing import Any

import gateway_client
import httpx
from mcp import McpError
from mcp.types import TextContent

from registry.utils.url_guard import validate_server_path

logger = logging.getLogger(__name__)

REGISTRY_URL = os.getenv("REGISTRY_BASE_URL", "http://localhost")

# The server record lookup (GET /api/servers{path}) is bounded well below the
# registry's own 2 MiB default: a server record is a small JSON document, so
# anything bigger is already a sign of trouble worth refusing early.
SERVER_RECORD_MAX_BYTES: int = 256 * 1024

# The gateway's own /mcp-proxy hop refuses an upstream response over 2 MiB
# (MCP_PROXY_MAX_BODY_BYTES); the guarded factory applies the same cap to
# mcpgw's own read of the MCP response stream, aborting mid-stream rather than
# buffering an oversized body first.
MCP_RESPONSE_STREAM_MAX_BYTES: int = 2 * 1024 * 1024

# Below the 2 MiB hop limit on mcpgw's own reply to its caller, so a result
# this module accepts always fits back through that same hop.
MAX_INVOKE_RESULT_BYTES: int = 1024 * 1024

# A direct call to this path would relay the caller's token back into mcpgw
# itself (self-call loop protection); compared after lower-casing.
_SELF_PATH: str = "/airegistry-tools"


class ToolInvocationError(Exception):
    """Raised by ``resolve_endpoint`` when the lookup or the record rules out a call.

    ``message`` is always the exact public-safe text for the caller (see the
    Error Mapping section below);
    never build it from ``str(some_other_exception)``. ``kind`` is a short
    machine-readable tag (``"not_found"``, ``"local_server"``, ``"disabled"``)
    for the caller's own logging/status-code purposes only.
    """

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind


def validate_server_path_for_invoke(path: str) -> str:
    """Validate and normalize a server path for ``invoke_mcp_tool``.

    Applies the registry's own registration-time rule
    (``registry.utils.url_guard.validate_server_path``) plus the extra
    checks that make the path safe to interpolate into a URL mcpgw builds
    itself. Returns the normalized path.

    Raises:
        ValueError: A path rule mcpgw owns itself failed (missing leading
            slash, an empty/``.``/``..`` segment, a ``%``, ``?`` or
            non-ASCII character, or the self path). The message names the
            offending character or segment.
        registry.exceptions.UrlValidationError: The registry's own rule
            failed (nginx metacharacters, a slash-only path, a reserved
            name). Propagated unchanged; callers map it via
            ``gateway_client.public_error``.
    """
    stripped = path.strip()
    if not stripped.startswith("/"):
        raise ValueError(
            "server_path must start with '/', for example /context7 or /virtual/dev-tools."
        )
    if len(stripped) > 1 and stripped.endswith("/"):
        stripped = stripped[:-1]

    # The registry's own registration-time rule: rejects nginx metacharacters,
    # a slash-only path and reserved names. Propagate on failure; do not
    # catch and reword it.
    validate_server_path(stripped)

    for segment in stripped.split("/")[1:]:
        if segment == "":
            raise ValueError(
                f"server_path must not contain an empty segment ('//') in {stripped!r}."
            )
        if segment in (".", ".."):
            raise ValueError(f"server_path must not contain a {segment!r} segment.")

    for ch in stripped:
        if ch in ("%", "?"):
            raise ValueError(f"server_path must not contain {ch!r}.")
        if not ch.isascii():
            raise ValueError(f"server_path must not contain non-ASCII character {ch!r}.")

    if stripped.lower() == _SELF_PATH:
        raise ValueError("invoke_mcp_tool cannot call the AI Registry tools server itself.")

    return stripped


def validate_tool_name(tool_name: str) -> str:
    """Validate a tool name: 1 to 128 characters, no Unicode control characters.

    ``tool_name`` travels in the JSON body, which ``/validate`` authorizes
    byte for byte, so mcpgw does not second-guess which names are valid
    beyond length and control characters.

    Raises:
        ValueError: ``tool_name`` is empty, over 128 characters, or contains
            a Unicode category ``Cc`` control character.
    """
    if not isinstance(tool_name, str) or not (1 <= len(tool_name) <= 128):
        raise ValueError("tool_name must be 1 to 128 characters.")
    for ch in tool_name:
        if unicodedata.category(ch) == "Cc":
            raise ValueError(f"tool_name must not contain control character {ch!r}.")
    return tool_name


def is_virtual_path(path: str) -> bool:
    """Return whether ``path``'s first segment (after the leading slash) is ``virtual``."""
    first_segment = path.lstrip("/").split("/", 1)[0]
    return first_segment == "virtual"


async def resolve_endpoint(path: str, *, client: httpx.AsyncClient) -> str:
    """Resolve a validated, normalized server path to a gateway MCP endpoint.

    A virtual path needs no lookup: it is always served at
    ``{REGISTRY_URL}{path}/mcp``. A direct path is looked up as the caller
    (``GET {REGISTRY_URL}/api/servers{path}``), which costs one round trip
    and needs the same ``server_access`` rule the call itself needs.

    Args:
        path: An already-validated, normalized path (see
            ``validate_server_path_for_invoke``).
        client: An open ``gateway_client.gateway_http_client(...)`` used for
            the lookup, as the caller.

    Returns:
        The gateway MCP endpoint URL to open an MCP session against.

    Raises:
        ToolInvocationError: The lookup returned 403/404 (``kind="not_found"``),
            the server is a local/stdio deployment (``kind="local_server"``),
            or the server is disabled (``kind="disabled"``).
        httpx.HTTPStatusError: Any other non-2xx lookup response.
        gateway_client.ResponseTooLargeError: The server record exceeded
            ``SERVER_RECORD_MAX_BYTES``.
    """
    if is_virtual_path(path):
        return f"{REGISTRY_URL}{path}/mcp"

    url = f"{REGISTRY_URL}/api/servers{path}"
    try:
        record = await gateway_client.request_json_bounded(
            client, "GET", url, limit=SERVER_RECORD_MAX_BYTES
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (403, 404):
            raise ToolInvocationError(
                f"No server at {path}, or you do not have access to it.",
                "not_found",
            ) from exc
        raise

    if record.get("deployment") == "local":
        raise ToolInvocationError(
            f"{path} is a local (stdio) server; it has no gateway route and cannot be invoked.",
            "local_server",
        )
    if record.get("is_enabled") is False:
        raise ToolInvocationError(f"{path} is disabled in the registry.", "disabled")

    if record.get("append_mcp_path") is False:
        return f"{REGISTRY_URL}{path}/"
    return f"{REGISTRY_URL}{path}/mcp"


class _BoundedAsyncByteStream(httpx.AsyncByteStream):
    """Wraps an ``httpx.AsyncByteStream``, aborting once the running byte count
    read from it exceeds ``limit``, without buffering the body first.

    Mirrors ``gateway_client.read_bounded`` at the transport layer, for the
    MCP client's own response stream, which fastmcp/mcp reads through the
    ``httpx_client_factory`` this module supplies rather than through
    ``client.stream(...)``.
    """

    def __init__(self, stream: httpx.AsyncByteStream, limit: int) -> None:
        self._stream = stream
        self._limit = limit

    async def __aiter__(self):
        total = 0
        async for chunk in self._stream:
            total += len(chunk)
            if total > self._limit:
                await self._stream.aclose()
                raise gateway_client.ResponseTooLargeError(
                    f"MCP response stream exceeded the {self._limit}-byte limit"
                )
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class _ByteCountingTransport(httpx.AsyncBaseTransport):
    """Wraps an ``httpx.AsyncBaseTransport`` so every response it returns is
    read through ``_BoundedAsyncByteStream``.

    ``handle_async_request`` calls the wrapped transport, then re-wraps the
    response's ``.stream`` (not ``.aiter_bytes()``'s decoded view, but the
    raw byte stream every read path -- ``aread``, ``aiter_bytes``,
    ``aiter_raw``, ``aclose`` -- ultimately delegates to), so the cap applies
    no matter how fastmcp/mcp ends up reading the body.
    """

    def __init__(self, wrapped: httpx.AsyncBaseTransport, limit: int) -> None:
        self._wrapped = wrapped
        self._limit = limit

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._wrapped.handle_async_request(request)
        response.stream = _BoundedAsyncByteStream(response.stream, self._limit)
        return response

    async def aclose(self) -> None:
        await self._wrapped.aclose()


def _guarded_factory(
    deadline: gateway_client.Deadline,
    default_headers: dict[str, str],
) -> Callable[..., httpx.AsyncClient]:
    """Build the ``httpx_client_factory`` fastmcp's ``StreamableHttpTransport`` calls.

    fastmcp calls the returned callable once per session with ``headers``
    (the same dict passed to the transport's constructor), ``auth`` and
    ``timeout``, plus ``follow_redirects=True``. The callable ignores
    ``auth`` and ``follow_redirects`` -- mcpgw never uses fastmcp's own auth
    machinery, and ``gateway_client.gateway_http_client`` already pins
    ``follow_redirects=False`` -- and opens a fresh guarded client per call,
    whose transport is wrapped in ``_ByteCountingTransport`` so a response
    over ``MCP_RESPONSE_STREAM_MAX_BYTES`` aborts while streaming.
    """

    def factory(
        *,
        headers: dict[str, str] | None = None,
        auth: Any = None,
        timeout: Any = None,
        **kwargs: Any,
    ) -> httpx.AsyncClient:
        client = gateway_client.gateway_http_client(
            deadline.remaining(), headers=headers if headers is not None else default_headers
        )
        client._transport = _ByteCountingTransport(  # noqa: SLF001
            client._transport, MCP_RESPONSE_STREAM_MAX_BYTES
        )
        return client

    return factory


async def call_mcp_tool(
    path: str,
    tool_name: str,
    arguments: dict[str, Any] | None,
    *,
    headers: dict[str, str],
    deadline: gateway_client.Deadline,
):
    """Resolve ``path``, open one MCP session through the gateway, and call ``tool_name``.

    Args:
        path: An already-validated, normalized server path.
        tool_name: An already-validated tool name.
        arguments: The tool's arguments, or ``None`` for no arguments.
        headers: Caller headers (``gateway_client.caller_headers(ctx)``).
        deadline: The call's overall deadline; every inner timeout is set to
            the remaining budget, never the full budget.

    Returns:
        A bounded ``fastmcp.tools.ToolResult`` (see ``_bounded_tool_result``).

    Raises:
        ToolInvocationError: See ``resolve_endpoint``.
        httpx.HTTPStatusError: A non-2xx gateway response, from the lookup
            or from the MCP call itself.
        mcp.McpError: A JSON-RPC error from the backend.
        gateway_client.ResponseTooLargeError: The server record or the MCP
            response stream exceeded its limit.
        TimeoutError: The deadline elapsed before the call finished.
    """
    from fastmcp.client import Client
    from fastmcp.client.transports import StreamableHttpTransport

    async with gateway_client.gateway_http_client(
        deadline.remaining(), headers=headers
    ) as lookup_client:
        endpoint = await resolve_endpoint(path, client=lookup_client)

    transport = StreamableHttpTransport(
        endpoint,
        headers=headers,
        httpx_client_factory=_guarded_factory(deadline, headers),
    )
    async with asyncio.timeout(deadline.remaining()):
        async with Client(
            transport, timeout=deadline.remaining(), init_timeout=deadline.remaining()
        ) as client:
            result = await client.call_tool_mcp(
                tool_name, arguments or {}, timeout=deadline.remaining()
            )
    return _bounded_tool_result(path, tool_name, result)


def _bounded_tool_result(path: str, tool_name: str, result: Any):
    """Bound an MCP ``CallToolResult`` to ``MAX_INVOKE_RESULT_BYTES`` before relaying it.

    The backend's own ``_meta`` is dropped on purpose: it is
    registrant-controlled data outside the tool contract, and relaying it
    would hand that data to clients that act on it.
    """
    from fastmcp.tools import ToolResult

    serialized = json.dumps(
        {
            "content": [block.model_dump() for block in result.content],
            "structuredContent": result.structuredContent,
        },
        default=str,
    )
    size = len(serialized.encode("utf-8"))

    if size <= MAX_INVOKE_RESULT_BYTES:
        return ToolResult(
            content=result.content,
            structured_content=result.structuredContent,
            meta={"mcpgw": {"server_path": path, "tool": tool_name}},
            is_error=result.isError,
        )

    return ToolResult(
        content=[
            TextContent(
                type="text",
                text=(
                    f"The tool's result was {size} bytes, over the 1 MiB limit "
                    "for results relayed through invoke_mcp_tool."
                ),
            )
        ],
        is_error=True,
    )


def _is_access_forbidden_body(response: httpx.Response) -> bool:
    """Return whether ``response`` carries the gateway's fixed 403 refusal body."""
    try:
        payload = response.json()
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("error") == "Access forbidden"


def _map_gateway_status_error(exc: httpx.HTTPStatusError, path: str, tool_name: str) -> str | None:
    """Map a gateway HTTP status from the MCP call to its public-safe text.

    Returns ``None`` when no specific rule applies (401 and the gateway's
    own 403 body are the only codes with a dedicated message when the body
    doesn't match; the caller falls back to ``gateway_client.public_error``).
    """
    status = exc.response.status_code
    if status == 401:
        return "The gateway rejected your token. Refresh it and retry."
    if status == 403:
        if _is_access_forbidden_body(exc.response):
            return (
                f"The gateway refused {tool_name} on {path}. You may lack a grant "
                "for this server or tool, the tool may be blocked, or your quota "
                "may be suspended."
            )
        return None
    if status in (404, 405):
        return (
            f"The gateway has no working route for {path} right now. It may have "
            "become unhealthy since it was looked up; retry later."
        )
    if status == 413:
        return (
            "The request was over 256 KiB, or the server's response was too large for the gateway."
        )
    if status == 429:
        retry_after = exc.response.headers.get("retry-after")
        if retry_after:
            return f"Rate limited. Retry after {retry_after} seconds."
        return "Rate limited. Retry later."
    if status == 500:
        return "The gateway could not authorize the request."
    if status in (502, 503, 504):
        return "The server did not answer in time or is unavailable."
    return None


def _map_mcp_error(exc: McpError) -> str:
    """Map a JSON-RPC ``McpError`` from the MCP call to its public-safe text."""
    error = exc.error
    code = error.code
    message = error.message or ""

    if code == -32042:
        data = error.data
        elicitations = data.get("elicitations") if isinstance(data, dict) else None
        first = elicitations[0] if isinstance(elicitations, list) and elicitations else None
        url = first.get("url") if isinstance(first, dict) else None
        if url:
            return (
                f"Connect your account: open {url} in a browser, approve access, "
                "then call this tool again."
            )
    elif code == -32603:
        # Only a virtual route produces -32603 for this scenario (a direct
        # route's refusal arrives as an HTTP 403 "Access forbidden" instead);
        # the message already says the backend tool is blocked/unavailable.
        return message

    return f"Server error {code}: {message[:500]}"


async def invoke_mcp_tool_impl(
    path: str,
    tool_name: str,
    arguments: dict[str, Any] | None,
    *,
    headers: dict[str, str],
    deadline: gateway_client.Deadline,
):
    """Validate, call and map errors for ``invoke_mcp_tool``. The single public entry point.

    Callers (the ``invoke_mcp_tool`` tool wrapper in ``server.py``) build
    ``headers`` via ``gateway_client.caller_headers(ctx)`` and a fresh
    ``gateway_client.Deadline`` before calling this; a ``CallerIdentityError``
    from that call happens before this function runs and is the wrapper's own
    responsibility to map (it is a ``ValueError`` subclass, so it fits the
    same ``except ValueError`` pattern every other mcpgw tool already uses).

    Every failure this function can reach is mapped to an ``is_error=True``
    ``fastmcp.tools.ToolResult`` with one text block (see the Error Mapping
    section above); the real exception
    is always logged server-side first via
    ``gateway_client.redact_exception_text``.

    Returns:
        A ``fastmcp.tools.ToolResult``, success or mapped error.
    """
    from fastmcp.tools import ToolResult

    total_seconds = deadline.total_seconds

    def _error(text: str) -> ToolResult:
        return ToolResult(content=[TextContent(type="text", text=text)], is_error=True)

    try:
        normalized_path = validate_server_path_for_invoke(path)
        normalized_tool = validate_tool_name(tool_name)
    except ValueError as exc:
        logger.error(gateway_client.redact_exception_text(exc))
        return _error(str(exc))

    try:
        return await call_mcp_tool(
            normalized_path,
            normalized_tool,
            arguments,
            headers=headers,
            deadline=deadline,
        )
    except gateway_client.CallerIdentityError as exc:
        # Unreachable under the current signature (headers already arrive
        # built), kept because the error-mapping table lists it explicitly
        # and ``CallerIdentityError`` is a plain ``ValueError`` subclass this
        # branch can handle identically to the validation branch above.
        logger.error(gateway_client.redact_exception_text(exc))
        return _error(str(exc))
    except ToolInvocationError as exc:
        logger.error(gateway_client.redact_exception_text(exc))
        return _error(exc.message)
    except httpx.HTTPStatusError as exc:
        logger.error(gateway_client.redact_exception_text(exc))
        mapped = _map_gateway_status_error(exc, normalized_path, normalized_tool)
        return _error(mapped if mapped is not None else gateway_client.public_error(exc))
    except McpError as exc:
        logger.error(gateway_client.redact_exception_text(exc))
        return _error(_map_mcp_error(exc))
    except gateway_client.ResponseTooLargeError as exc:
        logger.error(gateway_client.redact_exception_text(exc))
        return _error("The server's response was too large.")
    except TimeoutError as exc:
        logger.error(gateway_client.redact_exception_text(exc))
        return _error(f"The tool did not finish within {round(total_seconds)} seconds.")
    except Exception as exc:  # noqa: BLE001 - last-resort public mapping, never str(exc)
        logger.error(gateway_client.redact_exception_text(exc))
        return _error(gateway_client.public_error(exc))
