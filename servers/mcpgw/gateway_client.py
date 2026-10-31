"""Caller identity, guarded egress, and shared primitives for mcpgw.

Every mcpgw tool calls the registry and the gateway as the calling user,
never with a service credential of its own: the target's own grants, audit
and rate limits must apply to the user who is actually calling, not to
mcpgw (see docs/SECURITY_GUIDELINES.md and AGENTS.md's security invariants).
This module is the one place that:

- builds the caller's headers (``caller_headers``);
- opens the one guarded client every mcpgw egress request uses
  (``gateway_http_client``), locked to ``REGISTRY_BASE_URL``'s origin via
  ``registry.utils.url_guard.MCPGW_GATEWAY_PROFILE``;
- bounds how much of a response body mcpgw ever holds in memory
  (``read_bounded``, ``request_json_bounded``);
- maps an exception to a message safe to return to an MCP client
  (``public_error``);
- tracks one deadline across every step of a tool call (``Deadline``).

Importing this module must not require ``registry.core.config``: mcpgw has
no registry ``Settings`` object, and a later change that pulls settings into
the guard profile must fail a unit test, not fail at runtime in production.
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlparse

import httpx

from registry.common.log_redaction import redact_url
from registry.exceptions import UrlValidationError
from registry.utils.url_guard import MCPGW_GATEWAY_PROFILE, guarded_async_client

logger = logging.getLogger(__name__)

REGISTRY_EXTERNAL_URL = os.getenv("REGISTRY_EXTERNAL_URL", "")
OIDC_ENABLED = os.getenv("OIDC_ENABLED", "").lower() in ("true", "1", "yes")

# Every existing tool's own registry read is bounded to this limit. The
# invoke_mcp_tool and invoke_agent tools use their own, smaller limits
# for server records, agent cards and A2A messages.
MAX_REGISTRY_RESPONSE_BYTES: int = 2 * 1024 * 1024  # 2 MiB


class CallerIdentityError(ValueError):
    """mcpgw cannot determine, or must refuse, the caller's identity.

    Subclasses ValueError so every existing tool's ``except ValueError``
    branch keeps returning ``{"status": "failed", ...}`` unchanged.
    """


class ResponseTooLargeError(RuntimeError):
    """A response body exceeded the caller-specified byte limit."""


def _caller_bearer_token(ctx: Any) -> str:
    """Extract the caller's bearer token from the inbound MCP request.

    Checks ``X-Authorization`` first, then ``Authorization``, matching the
    order the auth server's ``/validate`` endpoint uses, so the token mcpgw
    forwards is the same one the gateway already authorized this call with.

    Raises:
        CallerIdentityError: No context, no request, or no bearer token.
    """
    if not ctx:
        raise CallerIdentityError("Authentication required: Context is None")
    try:
        if hasattr(ctx, "request_context") and ctx.request_context:
            request = ctx.request_context.request
            if request and hasattr(request, "headers"):
                auth_header = request.headers.get("x-authorization")
                if not auth_header:
                    auth_header = request.headers.get("authorization")
                if auth_header and auth_header.lower().startswith("bearer "):
                    return auth_header.split(" ", 1)[1]
                raise CallerIdentityError(
                    "Bearer token not found in X-Authorization or Authorization header"
                )
            raise CallerIdentityError("Request object or headers not found in request_context")
        raise CallerIdentityError("request_context not available in Context")
    except CallerIdentityError:
        raise
    except Exception as exc:
        logger.error(f"Failed to extract caller bearer token: {exc}", exc_info=True)
        raise CallerIdentityError(f"Failed to extract bearer token: {exc}") from exc


def _forwarded_host_headers() -> dict[str, str]:
    """Return X-Forwarded-Host/-Proto derived from REGISTRY_EXTERNAL_URL.

    Empty when REGISTRY_EXTERNAL_URL is unset or has no hostname, matching
    the registry's own external-URL handling.
    """
    if not REGISTRY_EXTERNAL_URL:
        return {}
    parsed = urlparse(REGISTRY_EXTERNAL_URL)
    if not parsed.hostname:
        return {}
    return {
        "X-Forwarded-Host": parsed.netloc,
        "X-Forwarded-Proto": parsed.scheme or "https",
    }


def caller_headers(ctx: Any) -> dict[str, str]:
    """Headers for any mcpgw call to the registry or gateway, as the caller.

    mcpgw never acts with a service credential of its own: every outbound
    call carries only the requesting user's own bearer token, so the target
    applies that user's own grants, audit and rate limits.

    Args:
        ctx: The tool's FastMCP ``Context``, or None.

    Returns:
        Headers to pass to ``gateway_http_client``: ``X-Authorization``
        carrying the caller's token, plus ``X-Forwarded-Host``/``-Proto``
        when ``REGISTRY_EXTERNAL_URL`` is set.

    Raises:
        CallerIdentityError: No caller token was found, or
            ``OIDC_ENABLED=true`` (mcpgw cannot yet act for the caller in
            that mode; see issue #895).
    """
    if OIDC_ENABLED:
        raise CallerIdentityError(
            "mcpgw cannot act for the caller while OIDC_ENABLED=true; see issue #895"
        )
    token = _caller_bearer_token(ctx)
    headers = {"X-Authorization": f"Bearer {token}"}
    headers.update(_forwarded_host_headers())
    return headers


def gateway_http_client(
    timeout: float,
    headers: dict[str, str] | None = None,
) -> httpx.AsyncClient:
    """Open a guarded client for registry/gateway egress.

    Every mcpgw request to the registry or the gateway must go through this
    factory; never ``httpx.AsyncClient(...)`` directly. The client is locked
    to ``REGISTRY_BASE_URL``'s origin by ``MCPGW_GATEWAY_PROFILE``, and
    redirects stay off: the gateway routes mcpgw calls do not redirect, and
    the guarded transport rewrites the request URL to the pinned IP, so a
    relative redirect would arrive as an IP-literal URL the origin lock
    rejects.

    Args:
        timeout: Request timeout in seconds.
        headers: Headers to send on every request from this client, usually
            ``caller_headers(ctx)``.

    Returns:
        A new ``httpx.AsyncClient``. The caller is responsible for closing
        it (``async with``); a new client must be opened per call.
    """
    return guarded_async_client(
        profile=MCPGW_GATEWAY_PROFILE,
        timeout=timeout,
        headers=headers,
        follow_redirects=False,
    )


async def read_bounded(response: httpx.Response, limit: int) -> bytes:
    """Read a streamed response body, aborting the moment it exceeds limit.

    Must be used with ``client.stream(...)``, never ``client.get(...)``
    followed by a size check: this stops reading mid-body on an over-limit
    response, so the oversized body never fully buffers in memory. Counts
    decoded bytes from ``aiter_bytes()``, so a compressed body cannot expand
    past the limit after this check.

    Args:
        response: An open streamed response (inside ``client.stream(...)``).
        limit: Maximum number of decoded bytes to accept.

    Returns:
        The full body, when it is at or under ``limit``.

    Raises:
        ResponseTooLargeError: A declared ``Content-Length`` or the number
            of bytes actually read exceeds ``limit``.
    """
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError:
            declared = None
        if declared is not None and declared > limit:
            raise ResponseTooLargeError(
                f"declared Content-Length {declared} exceeds the {limit}-byte limit"
            )

    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit:
            raise ResponseTooLargeError(f"response body exceeds the {limit}-byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


@asynccontextmanager
async def _stream_bounded(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    limit: int,
):
    """Stream a request, yielding the response after raise_for_status.

    Internal helper for request_json_bounded: reads the body bounded by
    ``limit`` before raising for a non-2xx status, so an oversized error
    body cannot be fully buffered either, then raises for status, then
    yields the body for the caller to parse.
    """
    async with client.stream(method, url, params=params, json=json_body) as response:
        body = await read_bounded(response, limit)
        response.raise_for_status()
        yield body


async def request_json_bounded(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    limit: int = MAX_REGISTRY_RESPONSE_BYTES,
) -> Any:
    """Make one request and return its parsed JSON body, bounded to limit.

    Every mcpgw call to a JSON registry endpoint goes through this, not
    ``client.get(...).json()`` / ``client.post(...).json()``, so the body
    is read through ``read_bounded`` rather than fully buffered by httpx
    before any size check runs.

    Args:
        client: An open ``gateway_http_client(...)``.
        method: HTTP method ("GET" or "POST").
        url: Full request URL.
        params: Query parameters, GET only.
        json_body: JSON request body, POST only.
        limit: Maximum response body size in bytes.

    Returns:
        The parsed JSON body.

    Raises:
        httpx.HTTPStatusError: Non-2xx response.
        ResponseTooLargeError: The response body exceeds ``limit``.
    """
    async with _stream_bounded(
        client, method, url, params=params, json_body=json_body, limit=limit
    ) as body:
        return json.loads(body)


def redact_exception_text(exc: Exception) -> str:
    """Return exception text safe to write to the mcpgw log (URLs redacted).

    ``UrlValidationError`` embeds the full rejected URL in its message; every
    other exception this module expects (httpx errors, ``CallerIdentityError``,
    ``ResponseTooLargeError``, plain ``ValueError``) carries no URL, so its
    ordinary ``str()`` is already safe to log.
    """
    url = getattr(exc, "url", None)
    if url is not None:
        reason = getattr(exc, "reason", "")
        return f"{type(exc).__name__}: {redact_url(url)}: {reason}"
    return f"{type(exc).__name__}: {exc}"


def public_error(exc: Exception) -> str:
    """Map an exception to a message safe to return to an MCP client.

    The full exception is logged server-side by the caller via
    ``redact_exception_text``, which this function must never be the only
    caller of: never return ``str(exc)`` here. A guard failure
    (``UrlValidationError`` carries the full URL), a DNS error or a pinning
    error must not hand internal hostnames or addresses to the MCP client.

    This covers the generic catch-all branch in each tool. The narrower
    ``except ValueError`` branches for argument validation (and
    ``CallerIdentityError``, a ``ValueError`` subclass) keep returning their
    own message directly: those are deliberately informative and carry no
    internal URL or address.
    """
    if isinstance(exc, httpx.HTTPStatusError):
        return f"The registry rejected the request (HTTP {exc.response.status_code})."
    if isinstance(exc, httpx.TimeoutException):
        return "The registry did not answer in time."
    if isinstance(exc, httpx.TransportError):
        return "The registry could not be reached."
    if isinstance(exc, UrlValidationError):
        return "The request was refused by the egress guard."
    return "Unexpected error; see the mcpgw log."


class Deadline:
    """Tracks one deadline across every step of a tool call.

    A single deadline is created at tool entry and consulted by every inner
    step (server/card lookup, connection setup, the call itself, polling,
    result parsing, client/session close), so no single step can outlive the
    overall budget by using its own fixed timeout.
    """

    def __init__(self, total_seconds: float) -> None:
        self.total_seconds = total_seconds
        self._deadline = time.monotonic() + total_seconds

    def remaining(self) -> float:
        """Seconds left before the deadline, floored at 0.0."""
        return max(0.0, self._deadline - time.monotonic())

    def expired(self) -> bool:
        return self.remaining() <= 0.0
