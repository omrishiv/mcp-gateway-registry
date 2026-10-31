"""Unit tests for servers/mcpgw/mcp_invoke.py (``invoke_mcp_tool`` logic).

``mcp_invoke`` itself needs no ``fastmcp`` stub to import: it lazily imports
``fastmcp.client.Client``/``StreamableHttpTransport`` and
``fastmcp.tools.ToolResult`` only inside the functions that build or call
them. A real ``fastmcp.client.Client`` session against a mocked transport is
far more involved than this module's own httpx-level pieces, so per the
assignment this file:

- exercises ``resolve_endpoint``'s gateway lookup with a plain
  ``httpx.AsyncClient(transport=httpx.MockTransport(...))`` (no ``respx``
  needed; ``httpx.MockTransport`` already ships with the ``httpx`` dependency
  every mcpgw module uses);
- exercises the byte-counting transport/stream mcpgw wraps every MCP
  response in, directly and through ``_guarded_factory``, proving the cap
  aborts mid-stream rather than buffering an oversized body first;
- exercises ``_bounded_tool_result`` and the full ``invoke_mcp_tool_impl``
  error-mapping dispatch against a minimal stand-in for
  ``fastmcp.tools.ToolResult`` (installed into ``sys.modules`` only for the
  functions that need it) and, for the gateway/MCP failure paths, a
  monkeypatched ``mcp_invoke.call_mcp_tool`` raising the exception each
  error-mapping row names -- the same "mock at the level of
  the call-making function" strategy the assignment calls out as the
  practical alternative to a full fastmcp session.
"""

import json
import sys
import types
from pathlib import Path

import httpx
import pytest
from mcp import McpError
from mcp.types import ErrorData, TextContent

_mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
if _mcpgw_path not in sys.path:
    sys.path.insert(0, _mcpgw_path)


class _FakeToolResult:
    """Stands in for ``fastmcp.tools.ToolResult``'s constructor contract:
    ``content``/``structured_content``/``meta``/``is_error`` attributes, and
    the same "one of content or structured_content required" check.
    """

    def __init__(self, content=None, structured_content=None, meta=None, is_error=False):
        if content is None and structured_content is None:
            raise ValueError("Either content or structured_content must be provided")
        self.content = content
        self.structured_content = structured_content
        self.meta = meta
        self.is_error = is_error


# mcp_invoke lazily imports fastmcp.tools.ToolResult only inside the few
# functions that build one (_bounded_tool_result, invoke_mcp_tool_impl);
# fastmcp is not installed in this venv (servers/mcpgw/pyproject.toml pulls
# it in for the real server, which runs from its own venv). Install a
# minimal stub before any test calls those functions. Matches the
# sys.modules stub test_get_skill_content.py installs for server.py's own
# (unrelated) fastmcp.Context/FastMCP dependency, augmenting rather than
# replacing a stub a sibling test module may have already installed.
if "fastmcp" not in sys.modules:
    sys.modules["fastmcp"] = types.ModuleType("fastmcp")
_fastmcp_stub = sys.modules["fastmcp"]
if not hasattr(_fastmcp_stub, "tools"):
    _fastmcp_tools_stub = types.ModuleType("fastmcp.tools")
    _fastmcp_tools_stub.ToolResult = _FakeToolResult
    _fastmcp_stub.tools = _fastmcp_tools_stub
    sys.modules["fastmcp.tools"] = _fastmcp_tools_stub

import gateway_client  # noqa: E402
import mcp_invoke  # noqa: E402

from registry.exceptions import UrlValidationError  # noqa: E402


class _FakeCallToolResult:
    """Stands in for ``mcp.types.CallToolResult``: just the three attributes
    ``_bounded_tool_result`` reads."""

    def __init__(self, content, structuredContent=None, isError=False):
        self.content = content
        self.structuredContent = structuredContent
        self.isError = isError


def _deadline(seconds: float = 10.0) -> gateway_client.Deadline:
    return gateway_client.Deadline(seconds)


# ---------------------------------------------------------------------------
# validate_server_path_for_invoke
# ---------------------------------------------------------------------------


def test_validate_server_path_accepts_simple_path():
    assert mcp_invoke.validate_server_path_for_invoke("/context7") == "/context7"


def test_validate_server_path_strips_whitespace_and_trailing_slash():
    assert mcp_invoke.validate_server_path_for_invoke("  /context7/  ") == "/context7"


def test_validate_server_path_accepts_virtual_path():
    assert mcp_invoke.validate_server_path_for_invoke("/virtual/dev-tools") == "/virtual/dev-tools"


def test_validate_server_path_requires_leading_slash():
    with pytest.raises(ValueError, match="must start with '/'"):
        mcp_invoke.validate_server_path_for_invoke("context7")


def test_validate_server_path_rejects_empty_segment():
    with pytest.raises(ValueError, match=r"empty segment \('//'\)"):
        mcp_invoke.validate_server_path_for_invoke("/foo//bar")


def test_validate_server_path_rejects_dot_segment():
    with pytest.raises(ValueError, match=r"'\.' segment"):
        mcp_invoke.validate_server_path_for_invoke("/foo/./bar")


def test_validate_server_path_rejects_dotdot_segment():
    with pytest.raises(ValueError, match=r"'\.\.' segment"):
        mcp_invoke.validate_server_path_for_invoke("/foo/../bar")


def test_validate_server_path_rejects_percent():
    with pytest.raises(ValueError, match="'%'"):
        mcp_invoke.validate_server_path_for_invoke("/foo%2fbar")


def test_validate_server_path_rejects_question_mark():
    with pytest.raises(ValueError, match=r"'\?'"):
        mcp_invoke.validate_server_path_for_invoke("/foo?x=1")


def test_validate_server_path_rejects_non_ascii():
    with pytest.raises(ValueError, match="non-ASCII"):
        mcp_invoke.validate_server_path_for_invoke("/caf\u00e9")


def test_validate_server_path_rejects_self_path():
    with pytest.raises(
        ValueError,
        match=r"^invoke_mcp_tool cannot call the AI Registry tools server itself\.$",
    ):
        mcp_invoke.validate_server_path_for_invoke("/airegistry-tools")


def test_validate_server_path_rejects_self_path_case_insensitive_with_slash():
    with pytest.raises(
        ValueError,
        match=r"^invoke_mcp_tool cannot call the AI Registry tools server itself\.$",
    ):
        mcp_invoke.validate_server_path_for_invoke("/AIREGISTRY-TOOLS/")


def test_validate_server_path_propagates_registry_rule_failure():
    # "/all" is the registry's own reserved cross-server wildcard sentinel;
    # validate_server_path (not mcpgw's own rules) rejects it, and that
    # exception type must propagate unchanged, not be reworded.
    with pytest.raises(UrlValidationError):
        mcp_invoke.validate_server_path_for_invoke("/all")


# ---------------------------------------------------------------------------
# validate_tool_name
# ---------------------------------------------------------------------------


def test_validate_tool_name_accepts_normal_name():
    assert mcp_invoke.validate_tool_name("search_web") == "search_web"


def test_validate_tool_name_rejects_empty():
    with pytest.raises(ValueError, match="1 to 128 characters"):
        mcp_invoke.validate_tool_name("")


def test_validate_tool_name_rejects_too_long():
    with pytest.raises(ValueError, match="1 to 128 characters"):
        mcp_invoke.validate_tool_name("a" * 129)


def test_validate_tool_name_accepts_128_chars():
    assert mcp_invoke.validate_tool_name("a" * 128) == "a" * 128


def test_validate_tool_name_rejects_control_character():
    with pytest.raises(ValueError, match="control character"):
        mcp_invoke.validate_tool_name("search\x00web")


# ---------------------------------------------------------------------------
# is_virtual_path
# ---------------------------------------------------------------------------


def test_is_virtual_path_true_for_virtual_prefix():
    assert mcp_invoke.is_virtual_path("/virtual/dev-tools") is True
    assert mcp_invoke.is_virtual_path("/virtual") is True


def test_is_virtual_path_false_for_direct_path():
    assert mcp_invoke.is_virtual_path("/context7") is False


def test_is_virtual_path_false_for_lookalike_segment():
    assert mcp_invoke.is_virtual_path("/virtualfoo") is False


# ---------------------------------------------------------------------------
# resolve_endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_endpoint_virtual_skips_lookup():
    called = False

    def handler(request):
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        endpoint = await mcp_invoke.resolve_endpoint("/virtual/dev-tools", client=client)
    finally:
        await client.aclose()

    assert endpoint == f"{mcp_invoke.REGISTRY_URL}/virtual/dev-tools/mcp"
    assert called is False


@pytest.mark.asyncio
async def test_resolve_endpoint_direct_default_append_mcp_path():
    def handler(request):
        assert request.url.path == "/api/servers/context7"
        return httpx.Response(200, json={"is_enabled": True, "deployment": "gateway"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        endpoint = await mcp_invoke.resolve_endpoint("/context7", client=client)
    finally:
        await client.aclose()

    assert endpoint == f"{mcp_invoke.REGISTRY_URL}/context7/mcp"


@pytest.mark.asyncio
async def test_resolve_endpoint_append_mcp_path_false():
    def handler(request):
        return httpx.Response(
            200, json={"is_enabled": True, "deployment": "gateway", "append_mcp_path": False}
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        endpoint = await mcp_invoke.resolve_endpoint("/rootserver", client=client)
    finally:
        await client.aclose()

    assert endpoint == f"{mcp_invoke.REGISTRY_URL}/rootserver/"


@pytest.mark.parametrize("status", [403, 404])
@pytest.mark.asyncio
async def test_resolve_endpoint_lookup_forbidden_or_not_found(status):
    def handler(request):
        return httpx.Response(status, json={"detail": "nope"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(mcp_invoke.ToolInvocationError) as exc_info:
            await mcp_invoke.resolve_endpoint("/ghost", client=client)
    finally:
        await client.aclose()

    assert exc_info.value.kind == "not_found"
    assert exc_info.value.message == "No server at /ghost, or you do not have access to it."


@pytest.mark.asyncio
async def test_resolve_endpoint_lookup_other_status_propagates():
    def handler(request):
        return httpx.Response(500, json={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await mcp_invoke.resolve_endpoint("/flaky", client=client)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_resolve_endpoint_local_deployment():
    def handler(request):
        return httpx.Response(200, json={"is_enabled": True, "deployment": "local"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(mcp_invoke.ToolInvocationError) as exc_info:
            await mcp_invoke.resolve_endpoint("/stdio-server", client=client)
    finally:
        await client.aclose()

    assert exc_info.value.kind == "local_server"
    assert exc_info.value.message == (
        "/stdio-server is a local (stdio) server; it has no gateway route and cannot be invoked."
    )


@pytest.mark.asyncio
async def test_resolve_endpoint_disabled():
    def handler(request):
        return httpx.Response(200, json={"is_enabled": False, "deployment": "gateway"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(mcp_invoke.ToolInvocationError) as exc_info:
            await mcp_invoke.resolve_endpoint("/off", client=client)
    finally:
        await client.aclose()

    assert exc_info.value.kind == "disabled"
    assert exc_info.value.message == "/off is disabled in the registry."


# ---------------------------------------------------------------------------
# Byte-counting stream/transport: the MCP response stream cap (2 MiB)
# ---------------------------------------------------------------------------


class _AssertingStream:
    """An async byte stream that fails the test if it is asked for a chunk
    past the point the byte cap should already have aborted the read --
    proving the wrapper aborts mid-stream instead of buffering the full body
    first."""

    def __init__(self, first: bytes, second: bytes):
        self._first = first
        self._second = second
        self.aclose_called = False

    async def __aiter__(self):
        yield self._first
        yield self._second
        raise AssertionError("asked to yield past the point the cap should have aborted")

    async def aclose(self) -> None:
        self.aclose_called = True


@pytest.mark.asyncio
async def test_bounded_async_byte_stream_aborts_without_full_buffering():
    limit = 10
    stream = _AssertingStream(first=b"12345", second=b"678901")  # 5 + 6 = 11 > 10
    bounded = mcp_invoke._BoundedAsyncByteStream(stream, limit)

    with pytest.raises(gateway_client.ResponseTooLargeError):
        async for _chunk in bounded:
            pass

    assert stream.aclose_called is True


class _SimpleStream:
    """A finite async byte stream with no sentinel -- used to prove the
    under-limit case passes every byte through untouched."""

    def __init__(self, chunks):
        self._chunks = chunks
        self.aclose_called = False

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        self.aclose_called = True


@pytest.mark.asyncio
async def test_bounded_async_byte_stream_passes_through_under_limit():
    stream = _SimpleStream([b"12", b"34"])
    bounded = mcp_invoke._BoundedAsyncByteStream(stream, limit=10)

    collected = b""
    async for chunk in bounded:
        collected += chunk

    assert collected == b"1234"
    assert stream.aclose_called is False


class _ChunkStream(httpx.AsyncByteStream):
    """A response-side async byte stream built from explicit chunks.

    ``httpx.Response(content=...)`` eagerly reads and closes the body
    inside ``__init__`` (it detects a plain ``ByteStream`` and pre-caches
    ``._content``), which would make any later read bypass the wrapper this
    module installs on ``.stream`` and quietly "pass" without exercising
    it. Passing an explicit ``stream=`` skips that eager read.
    """

    def __init__(self, chunks):
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        pass


@pytest.mark.asyncio
async def test_byte_counting_transport_wraps_response_stream():
    class _FakeTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(200, stream=_ChunkStream([b"hel", b"lo"]), request=request)

    transport = mcp_invoke._ByteCountingTransport(_FakeTransport(), limit=1000)
    request = httpx.Request("GET", "http://example.test/")
    response = await transport.handle_async_request(request)

    assert isinstance(response.stream, mcp_invoke._BoundedAsyncByteStream)
    body = await response.aread()
    assert body == b"hello"


# ---------------------------------------------------------------------------
# _guarded_factory
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_guarded_factory_enforces_cap_on_oversized_response(monkeypatch):
    big_body = b"x" * (mcp_invoke.MCP_RESPONSE_STREAM_MAX_BYTES + 100)

    def handler(request):
        return httpx.Response(200, stream=_ChunkStream([big_body]))

    def fake_gateway_http_client(timeout, headers=None):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(gateway_client, "gateway_http_client", fake_gateway_http_client)

    deadline = _deadline(5.0)
    factory = mcp_invoke._guarded_factory(deadline, {"X-Authorization": "Bearer t"})
    client = factory(
        headers={"X-Authorization": "Bearer t"}, auth=None, timeout=None, follow_redirects=True
    )

    assert isinstance(client._transport, mcp_invoke._ByteCountingTransport)

    async with client:
        with pytest.raises(gateway_client.ResponseTooLargeError):
            async with client.stream("GET", "http://example.test/mcp") as response:
                async for _chunk in response.aiter_raw():
                    pass


@pytest.mark.asyncio
async def test_guarded_factory_falls_back_to_default_headers(monkeypatch):
    captured = {}

    def fake_gateway_http_client(timeout, headers=None):
        captured["headers"] = headers
        return httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))

    monkeypatch.setattr(gateway_client, "gateway_http_client", fake_gateway_http_client)

    deadline = _deadline(5.0)
    factory = mcp_invoke._guarded_factory(deadline, {"X-Authorization": "Bearer default"})
    client = factory(headers=None, auth=None, timeout=None)
    try:
        assert captured["headers"] == {"X-Authorization": "Bearer default"}
    finally:
        await client.aclose()


# ---------------------------------------------------------------------------
# _bounded_tool_result
# ---------------------------------------------------------------------------


def _serialization_overhead_bytes() -> int:
    """The serialized size of a single empty-text content block with no
    structured content, i.e. the fixed cost ``_bounded_tool_result`` adds
    around a tool's actual text."""
    return len(
        json.dumps(
            {
                "content": [TextContent(type="text", text="").model_dump()],
                "structuredContent": None,
            },
            default=str,
        ).encode("utf-8")
    )


def test_bounded_tool_result_well_under_limit_passes_through():
    result = _FakeCallToolResult(
        content=[TextContent(type="text", text="hi")], structuredContent={"a": 1}, isError=False
    )
    bounded = mcp_invoke._bounded_tool_result("/context7", "echo", result)

    assert bounded.content == result.content
    assert bounded.structured_content == {"a": 1}
    assert bounded.is_error is False
    assert bounded.meta == {"mcpgw": {"server_path": "/context7", "tool": "echo"}}


def test_bounded_tool_result_exactly_at_limit_passes_through():
    overhead = _serialization_overhead_bytes()
    text = "x" * (mcp_invoke.MAX_INVOKE_RESULT_BYTES - overhead)
    result = _FakeCallToolResult(content=[TextContent(type="text", text=text)])

    bounded = mcp_invoke._bounded_tool_result("/context7", "echo", result)

    assert bounded.is_error is False
    assert bounded.content == result.content


def test_bounded_tool_result_one_byte_over_limit_is_rejected():
    overhead = _serialization_overhead_bytes()
    text = "x" * (mcp_invoke.MAX_INVOKE_RESULT_BYTES - overhead + 1)
    result = _FakeCallToolResult(content=[TextContent(type="text", text=text)], isError=False)

    bounded = mcp_invoke._bounded_tool_result("/context7", "echo", result)

    assert bounded.is_error is True
    assert len(bounded.content) == 1
    expected_size = mcp_invoke.MAX_INVOKE_RESULT_BYTES + 1
    assert bounded.content[0].text == (
        f"The tool's result was {expected_size} bytes, over the 1 MiB limit for "
        "results relayed through invoke_mcp_tool."
    )


def test_bounded_tool_result_drops_backend_meta_and_preserves_is_error():
    result = _FakeCallToolResult(content=[TextContent(type="text", text="failed")], isError=True)
    bounded = mcp_invoke._bounded_tool_result("/context7", "echo", result)

    assert bounded.is_error is True
    assert bounded.meta == {"mcpgw": {"server_path": "/context7", "tool": "echo"}}


# ---------------------------------------------------------------------------
# invoke_mcp_tool_impl: validation and self-path mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_validation_error_mapped():
    result = await mcp_invoke.invoke_mcp_tool_impl(
        "bad-path", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.is_error is True
    assert "must start with '/'" in result.content[0].text


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_self_path_mapped():
    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/airegistry-tools", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.is_error is True
    assert (
        result.content[0].text == "invoke_mcp_tool cannot call the AI Registry tools server itself."
    )


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_normalizes_before_calling(monkeypatch):
    captured = {}

    async def fake_call(path, tool_name, arguments, *, headers, deadline):
        captured["path"] = path
        captured["tool_name"] = tool_name
        captured["arguments"] = arguments
        return _FakeToolResult(content=[TextContent(type="text", text="ok")])

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    await mcp_invoke.invoke_mcp_tool_impl(
        "/context7/", "echo", {"x": 1}, headers={"H": "1"}, deadline=_deadline()
    )

    assert captured["path"] == "/context7"
    assert captured["tool_name"] == "echo"
    assert captured["arguments"] == {"x": 1}


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_success_passthrough(monkeypatch):
    fake_result = _FakeToolResult(content=[TextContent(type="text", text="ok")], is_error=False)

    async def fake_call(*args, **kwargs):
        return fake_result

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result is fake_result


# ---------------------------------------------------------------------------
# invoke_mcp_tool_impl: ToolInvocationError and CallerIdentityError mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_tool_invocation_error_mapped(monkeypatch):
    async def fake_call(*args, **kwargs):
        raise mcp_invoke.ToolInvocationError(
            "No server at /x, or you do not have access to it.", "not_found"
        )

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == "No server at /x, or you do not have access to it."
    assert result.is_error is True


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_caller_identity_error_mapped(monkeypatch):
    async def fake_call(*args, **kwargs):
        raise gateway_client.CallerIdentityError(
            "mcpgw cannot act for the caller while OIDC_ENABLED=true"
        )

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == "mcpgw cannot act for the caller while OIDC_ENABLED=true"


# ---------------------------------------------------------------------------
# invoke_mcp_tool_impl: gateway HTTP status mapping (2.7 table)
# ---------------------------------------------------------------------------


def _status_error(status: int, *, json_body=None, headers=None) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://registry.internal/x/mcp")
    response = httpx.Response(status, request=request, json=json_body, headers=headers)
    return httpx.HTTPStatusError("boom", request=request, response=response)


@pytest.mark.parametrize(
    "status,expected",
    [
        (401, "The gateway rejected your token. Refresh it and retry."),
        (
            404,
            "The gateway has no working route for /x right now. It may have "
            "become unhealthy since it was looked up; retry later.",
        ),
        (
            405,
            "The gateway has no working route for /x right now. It may have "
            "become unhealthy since it was looked up; retry later.",
        ),
        (
            413,
            "The request was over 256 KiB, or the server's response was too large for the gateway.",
        ),
        (500, "The gateway could not authorize the request."),
        (502, "The server did not answer in time or is unavailable."),
        (503, "The server did not answer in time or is unavailable."),
        (504, "The server did not answer in time or is unavailable."),
    ],
)
@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_gateway_status_mapping(monkeypatch, status, expected):
    exc = _status_error(status)

    async def fake_call(*args, **kwargs):
        raise exc

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.is_error is True
    assert result.content[0].text == expected


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_403_access_forbidden_body(monkeypatch):
    exc = _status_error(403, json_body={"error": "Access forbidden"})

    async def fake_call(*args, **kwargs):
        raise exc

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == (
        "The gateway refused echo on /x. You may lack a grant for this server "
        "or tool, the tool may be blocked, or your quota may be suspended."
    )


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_403_other_body_falls_back_to_public_error(monkeypatch):
    exc = _status_error(403, json_body={"detail": "nope"})

    async def fake_call(*args, **kwargs):
        raise exc

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == "The registry rejected the request (HTTP 403)."


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_429_with_retry_after(monkeypatch):
    exc = _status_error(429, headers={"Retry-After": "7"})

    async def fake_call(*args, **kwargs):
        raise exc

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == "Rate limited. Retry after 7 seconds."


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_429_without_retry_after(monkeypatch):
    exc = _status_error(429)

    async def fake_call(*args, **kwargs):
        raise exc

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == "Rate limited. Retry later."


# ---------------------------------------------------------------------------
# invoke_mcp_tool_impl: JSON-RPC McpError mapping (2.7 table)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_mcp_error_minus_32042_consent(monkeypatch):
    error = ErrorData(
        code=-32042,
        message="consent needed",
        data={"elicitations": [{"url": "https://idp.example/connect"}]},
    )
    exc = McpError(error)

    async def fake_call(*args, **kwargs):
        raise exc

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == (
        "Connect your account: open https://idp.example/connect in a browser, "
        "approve access, then call this tool again."
    )


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_mcp_error_minus_32603_virtual_route(monkeypatch):
    error = ErrorData(code=-32603, message="Tool is blocked for this server.")
    exc = McpError(error)

    async def fake_call(*args, **kwargs):
        raise exc

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/virtual/dev-tools", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == "Tool is blocked for this server."


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_mcp_error_generic_truncated(monkeypatch):
    error = ErrorData(code=-32000, message="x" * 600)
    exc = McpError(error)

    async def fake_call(*args, **kwargs):
        raise exc

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    text = result.content[0].text
    assert text.startswith("Server error -32000: ")
    assert text == "Server error -32000: " + "x" * 500


# ---------------------------------------------------------------------------
# invoke_mcp_tool_impl: oversized response and deadline mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_response_too_large_mapped(monkeypatch):
    async def fake_call(*args, **kwargs):
        raise gateway_client.ResponseTooLargeError("stream exceeded limit")

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == "The server's response was too large."


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_deadline_exceeded_uses_original_total(monkeypatch):
    async def fake_call(*args, **kwargs):
        raise TimeoutError()

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    deadline = _deadline(17)
    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=deadline
    )
    assert result.content[0].text == "The tool did not finish within 17 seconds."


@pytest.mark.asyncio
async def test_invoke_mcp_tool_impl_anything_else_falls_back_without_leaking_detail(monkeypatch):
    async def fake_call(*args, **kwargs):
        raise RuntimeError("internal detail with secret-token-abc123")

    monkeypatch.setattr(mcp_invoke, "call_mcp_tool", fake_call)

    result = await mcp_invoke.invoke_mcp_tool_impl(
        "/x", "echo", None, headers={}, deadline=_deadline()
    )
    assert result.content[0].text == "Unexpected error; see the mcpgw log."
    assert "secret-token" not in result.content[0].text
