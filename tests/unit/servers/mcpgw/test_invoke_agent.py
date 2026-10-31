"""Unit tests for servers/mcpgw/a2a_invoke.py.

a2a_invoke is pure business logic (no fastmcp import), so it needs no stub --
only servers/mcpgw on sys.path so `import a2a_invoke` resolves its sibling
imports (`gateway_client`, `a2a_dialects`, `models`) the way server.py's own
flat imports do.

Network calls are mocked by monkeypatching `a2a_invoke.gateway_client.
gateway_http_client` (the one factory a2a_invoke ever calls for egress) to
return an `httpx.AsyncClient` wired to an `httpx.MockTransport`, consistent
with how `tests/unit/servers/mcpgw/test_gateway_client.py` mocks the same
layer. `asyncio.sleep` is monkeypatched for the polling tests so they run
without any real wall-clock delay; a `FakeDeadline` advances in lockstep
with the mocked sleep so deadline-expiry assertions are exact and
deterministic rather than timing-dependent.
"""

import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

_mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
if _mcpgw_path not in sys.path:
    sys.path.insert(0, _mcpgw_path)

import a2a_invoke  # noqa: E402

AGENT_PATH = "/flight-booking"


class FakeDeadline:
    """A controllable stand-in for gateway_client.Deadline.

    a2a_invoke reads `.total_seconds` (the original budget, stored verbatim
    by the real Deadline) for its two timeout messages, and calls
    `.remaining()` everywhere else (never `.expired()`). `.remaining()` is
    backed by a mutable "elapsed" counter the tests advance explicitly --
    via the monkeypatched `asyncio.sleep` below -- rather than real
    wall-clock time.
    """

    def __init__(self, total_seconds: float) -> None:
        self.total_seconds = total_seconds
        self.elapsed = 0.0

    def remaining(self) -> float:
        return max(0.0, self.total_seconds - self.elapsed)

    def expired(self) -> bool:
        return self.remaining() <= 0.0

    def advance(self, seconds: float) -> None:
        self.elapsed += seconds


def _patch_sleep_advancing(monkeypatch, deadline: FakeDeadline) -> list[float]:
    """Make `asyncio.sleep` advance `deadline` instead of actually sleeping.

    Returns the list of delays `asyncio.sleep` was called with, in order,
    so a test can assert the exact 1/2/4/4... schedule.
    """
    calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        calls.append(seconds)
        deadline.advance(seconds)

    monkeypatch.setattr(a2a_invoke.asyncio, "sleep", fake_sleep)
    return calls


class FakeTransport:
    """Routes mocked HTTP requests by shape: agent card, JSON-RPC send, JSON-RPC get.

    Records every request so a test can assert the card endpoint was (or
    was not) hit, and supports a per-call poll handler so a test can vary
    the task's reported state across successive `tasks/get`/`GetTask` calls.
    """

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.card_response: httpx.Response | Exception | None = None
        self.send_response: Any = None  # httpx.Response | Exception | callable(body) -> Response
        self.poll_responses: list[Any] = []  # consumed in order across tasks/get calls
        self._poll_index = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if url.endswith(".well-known/agent-card.json"):
            return self._resolve(self.card_response, None)

        body = json.loads(request.content)
        method = body.get("method")
        if method in ("message/send", "SendMessage"):
            return self._resolve(self.send_response, body)

        # tasks/get or GetTask
        response = self.poll_responses[self._poll_index]
        self._poll_index += 1
        return self._resolve(response, body)

    @staticmethod
    def _resolve(value: Any, body: dict[str, Any] | None) -> httpx.Response:
        if isinstance(value, Exception):
            raise value
        if callable(value) and not isinstance(value, httpx.Response):
            return value(body)
        return value

    def factory(self):
        def _factory(timeout: float, headers: dict[str, str] | None) -> httpx.AsyncClient:
            return httpx.AsyncClient(transport=httpx.MockTransport(self.handle), headers=headers)

        return _factory


def _jsonrpc_result(result: dict[str, Any]):
    def _build(body: dict[str, Any]) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    return _build


def _bare_message_result(text: str = "hello") -> dict[str, Any]:
    return {"kind": "message", "role": "agent", "parts": [{"kind": "text", "text": text}]}


def _task_result(task_id: str, state: str, context_id: str = "ctx-1") -> dict[str, Any]:
    return {
        "kind": "task",
        "id": task_id,
        "contextId": context_id,
        "status": {"state": state},
        "artifacts": [],
    }


CARD_0_3 = {"protocolVersion": "0.3", "preferredTransport": "JSONRPC"}
CARD_1_0 = {
    "supportedInterfaces": [{"protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
}
CARD_NO_JSONRPC = {"protocolVersion": "0.3", "preferredTransport": "GRPC"}


# ---------------------------------------------------------------------------
# Path / id / version / message validation
# ---------------------------------------------------------------------------


class TestValidateAgentPath:
    def test_accepts_a_valid_path(self):
        assert a2a_invoke.validate_agent_path("/flight-booking") == "/flight-booking"

    def test_strips_whitespace(self):
        assert a2a_invoke.validate_agent_path("  /flight-booking  ") == "/flight-booking"

    def test_rejects_missing_leading_slash(self):
        with pytest.raises(ValueError, match="must start with '/'"):
            a2a_invoke.validate_agent_path("flight-booking")

    def test_rejects_double_slash(self):
        with pytest.raises(ValueError, match="must not contain '//'"):
            a2a_invoke.validate_agent_path("/flight//booking")

    def test_rejects_trailing_slash(self):
        with pytest.raises(ValueError, match="must not end with '/'"):
            a2a_invoke.validate_agent_path("/flight-booking/")

    def test_accepts_bare_root(self):
        assert a2a_invoke.validate_agent_path("/") == "/"

    def test_rejects_dot_segment(self):
        with pytest.raises(ValueError, match="path segment"):
            a2a_invoke.validate_agent_path("/./flight-booking")

    def test_rejects_dot_dot_segment(self):
        with pytest.raises(ValueError, match="path segment"):
            a2a_invoke.validate_agent_path("/../flight-booking")

    def test_rejects_percent(self):
        with pytest.raises(ValueError, match="'%'"):
            a2a_invoke.validate_agent_path("/flight%20booking")

    def test_rejects_question_mark(self):
        with pytest.raises(ValueError, match="'\\?'"):
            a2a_invoke.validate_agent_path("/flight-booking?x=1")

    def test_rejects_hash(self):
        with pytest.raises(ValueError, match="'#'"):
            a2a_invoke.validate_agent_path("/flight-booking#frag")

    def test_rejects_whitespace_inside_path(self):
        with pytest.raises(ValueError, match="whitespace"):
            a2a_invoke.validate_agent_path("/flight booking")

    def test_rejects_control_character(self):
        with pytest.raises(ValueError, match="control characters"):
            a2a_invoke.validate_agent_path("/flight\x00booking")

    def test_rejects_non_ascii(self):
        with pytest.raises(ValueError, match="non-ASCII"):
            a2a_invoke.validate_agent_path("/flïght-booking")


class TestValidateIdToken:
    def test_accepts_a_valid_token(self):
        assert a2a_invoke.validate_id_token("task-123_abc.def:ghi", "task_id") == (
            "task-123_abc.def:ghi"
        )

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError, match="task_id must match"):
            a2a_invoke.validate_id_token("", "task_id")

    def test_rejects_disallowed_character(self):
        with pytest.raises(ValueError, match="context_id must match"):
            a2a_invoke.validate_id_token("has a space", "context_id")

    def test_rejects_over_128_characters(self):
        with pytest.raises(ValueError, match="message_id must match"):
            a2a_invoke.validate_id_token("a" * 129, "message_id")

    def test_accepts_exactly_128_characters(self):
        value = "a" * 128
        assert a2a_invoke.validate_id_token(value, "task_id") == value


class TestValidateProtocolVersion:
    def test_none_passes_through(self):
        assert a2a_invoke.validate_protocol_version(None) is None

    def test_accepts_0_3_and_1_0(self):
        assert a2a_invoke.validate_protocol_version("0.3") == "0.3"
        assert a2a_invoke.validate_protocol_version("1.0") == "1.0"

    def test_rejects_anything_else(self):
        with pytest.raises(ValueError, match="protocol_version must be"):
            a2a_invoke.validate_protocol_version("0.2")


# ---------------------------------------------------------------------------
# Dialect selection
# ---------------------------------------------------------------------------


class TestSelectDialect:
    async def test_protocol_version_given_is_returned_directly(self):
        transport = FakeTransport()
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport.handle)) as client:
            version = await a2a_invoke.select_dialect(AGENT_PATH, "1.0", headers={}, client=client)
        assert version == "1.0"
        assert transport.requests == []  # the card was never read

    async def test_1_0_supported_interfaces_shape(self):
        transport = FakeTransport()
        transport.card_response = httpx.Response(200, json=CARD_1_0)
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport.handle)) as client:
            version = await a2a_invoke.select_dialect(AGENT_PATH, None, headers={}, client=client)
        assert version == "1.0"

    async def test_0_3_protocol_version_shape(self):
        transport = FakeTransport()
        transport.card_response = httpx.Response(200, json=CARD_0_3)
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport.handle)) as client:
            version = await a2a_invoke.select_dialect(AGENT_PATH, None, headers={}, client=client)
        assert version == "0.3"

    async def test_no_jsonrpc_raises_agent_invocation_error(self):
        transport = FakeTransport()
        transport.card_response = httpx.Response(200, json=CARD_NO_JSONRPC)
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport.handle)) as client:
            with pytest.raises(a2a_invoke.AgentInvocationError) as exc_info:
                await a2a_invoke.select_dialect(AGENT_PATH, None, headers={}, client=client)
        assert exc_info.value.kind == "no_jsonrpc"
        assert exc_info.value.message == (
            "This agent does not offer JSON-RPC, which invoke_agent needs."
        )


# ---------------------------------------------------------------------------
# invoke_agent_impl: protocol_version skips the card read
# ---------------------------------------------------------------------------


class TestProtocolVersionSkipsCardRead:
    async def test_card_endpoint_is_never_called(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = _jsonrpc_result(_bare_message_result("hi"))
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH,
            "hello",
            None,
            None,
            None,
            "0.3",
            headers={},
            deadline=FakeDeadline(30),
        )

        assert result.status == "success"
        assert all(not str(r.url).endswith("agent-card.json") for r in transport.requests)


# ---------------------------------------------------------------------------
# invoke_agent_impl: immediate (non-polling) outcomes
# ---------------------------------------------------------------------------


class TestImmediateOutcomes:
    async def test_bare_message_result_returns_immediately(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = _jsonrpc_result(_bare_message_result("booked!"))
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH, "book it", None, None, None, "0.3", headers={}, deadline=FakeDeadline(30)
        )

        assert result.status == "success"
        assert result.text == "booked!"

    async def test_terminal_task_result_returns_immediately(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = _jsonrpc_result(_task_result("task-1", "completed"))
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH, "book it", None, None, None, "0.3", headers={}, deadline=FakeDeadline(30)
        )

        assert result.status == "success"
        assert result.state == "completed"
        assert result.task_id == "task-1"

    async def test_input_required_task_returns_immediately_without_polling(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = _jsonrpc_result(_task_result("task-1", "input-required"))
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH, "book it", None, None, None, "0.3", headers={}, deadline=FakeDeadline(30)
        )

        assert result.status == "success"
        assert result.state == "input-required"
        # Only the one send request; no tasks/get call was made.
        assert len(transport.requests) == 1


# ---------------------------------------------------------------------------
# invoke_agent_impl: polling
# ---------------------------------------------------------------------------


class TestPolling:
    async def test_polls_1_2_4_4_and_stops_at_a_terminal_state(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = _jsonrpc_result(_task_result("task-1", "working"))
        transport.poll_responses = [
            _jsonrpc_result(_task_result("task-1", "working")),
            _jsonrpc_result(_task_result("task-1", "working")),
            _jsonrpc_result(_task_result("task-1", "working")),
            _jsonrpc_result(_task_result("task-1", "completed")),
        ]
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())
        deadline = FakeDeadline(100)
        sleep_calls = _patch_sleep_advancing(monkeypatch, deadline)

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH, "book it", None, None, None, "0.3", headers={}, deadline=deadline
        )

        assert sleep_calls == [1, 2, 4, 4]
        assert result.status == "success"
        assert result.state == "completed"

    async def test_deadline_reached_mid_poll_returns_pending_with_ids(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = _jsonrpc_result(_task_result("task-1", "working", "ctx-1"))
        transport.poll_responses = [
            _jsonrpc_result(_task_result("task-1", "working", "ctx-1")),
            _jsonrpc_result(_task_result("task-1", "working", "ctx-1")),
            _jsonrpc_result(_task_result("task-1", "working", "ctx-1")),
        ]
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())
        # 1 + 2 + 4 = 7 consumed; the 4th (repeat) delay needs 4 + 1 = 5 more,
        # and only 10 - 7 = 3 remain, so polling stops before that 4th sleep.
        deadline = FakeDeadline(10)
        _patch_sleep_advancing(monkeypatch, deadline)

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH, "book it", None, None, "msg-1", "0.3", headers={}, deadline=deadline
        )

        assert result.status == "pending"
        assert result.task_id == "task-1"
        assert result.context_id == "ctx-1"
        assert result.message_id == "msg-1"
        assert result.error is None

    async def test_no_task_id_at_deadline_returns_failed_with_retry_hint(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = httpx.ReadTimeout("simulated agent timeout")
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH,
            "book it",
            None,
            None,
            "retry-me",
            "0.3",
            headers={},
            deadline=FakeDeadline(25),
        )

        assert result.status == "failed"
        assert result.task_id is None
        assert result.message_id == "retry-me"
        assert result.error == (
            "The agent did not answer within 25 seconds. If you retry, pass message_id "
            "retry-me so the agent can recognize the repeat."
        )


class TestGetAgentTaskTimeout:
    async def test_timeout_on_the_single_request_reports_total_seconds_and_task_id(
        self, monkeypatch
    ):
        transport = FakeTransport()
        transport.poll_responses = [httpx.ReadTimeout("simulated agent timeout")]
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())

        result = await a2a_invoke.get_agent_task_impl(
            AGENT_PATH, "task-1", "0.3", headers={}, deadline=FakeDeadline(25)
        )

        assert result.status == "failed"
        assert result.task_id == "task-1"
        assert result.error == (
            "The agent did not answer within 25 seconds. Retry get_agent_task with task_id task-1."
        )


# ---------------------------------------------------------------------------
# message_id: defaulted when absent, echoed on success and failure
# ---------------------------------------------------------------------------


class TestMessageIdHandling:
    async def test_defaulted_when_absent_and_echoed_on_success(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = _jsonrpc_result(_bare_message_result("hi"))
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH, "book it", None, None, None, "0.3", headers={}, deadline=FakeDeadline(30)
        )

        assert result.status == "success"
        assert result.message_id is not None
        assert len(result.message_id) > 0

    async def test_given_message_id_is_echoed_on_success(self, monkeypatch):
        transport = FakeTransport()
        transport.send_response = _jsonrpc_result(_bare_message_result("hi"))
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())

        result = await a2a_invoke.invoke_agent_impl(
            AGENT_PATH,
            "book it",
            None,
            None,
            "my-message-id",
            "0.3",
            headers={},
            deadline=FakeDeadline(30),
        )

        assert result.message_id == "my-message-id"

    async def test_message_id_is_echoed_on_failure_too(self, monkeypatch):
        # agent_path validation fails before any network call; message_id
        # (defaulted here, since none was given) must still come back.
        result = await a2a_invoke.invoke_agent_impl(
            "not-a-path", "book it", None, None, None, None, headers={}, deadline=FakeDeadline(30)
        )

        assert result.status == "failed"
        assert result.message_id is not None


# ---------------------------------------------------------------------------
# Error mapping, exercised end to end via get_agent_task_impl
# (a single request, no card read -- protocol_version="0.3" is passed).
# ---------------------------------------------------------------------------


class TestErrorMapping:
    async def _run_get_task(self, monkeypatch, response_or_exc):
        transport = FakeTransport()
        transport.poll_responses = [response_or_exc]
        monkeypatch.setattr(a2a_invoke.gateway_client, "gateway_http_client", transport.factory())
        return await a2a_invoke.get_agent_task_impl(
            AGENT_PATH, "task-1", "0.3", headers={}, deadline=FakeDeadline(30)
        )

    async def test_401_with_gateway_marker(self, monkeypatch):
        response = httpx.Response(
            401,
            headers={"WWW-Authenticate": 'Bearer realm="mcp", resource_metadata="https://x"'},
            json={"error": "Authentication required"},
        )
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == "The gateway rejected your token. Refresh it and retry."

    async def test_401_without_gateway_marker(self, monkeypatch):
        response = httpx.Response(401, headers={"WWW-Authenticate": "Bearer"}, json={})
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == (
            "The agent requires its own credential, which invoke_agent does not supply."
        )

    async def test_403_exact_gateway_body(self, monkeypatch):
        response = httpx.Response(403, text='{"error": "Access forbidden"}')
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == f"You do not have invoke_agent on {AGENT_PATH}."

    async def test_403_other_body(self, monkeypatch):
        response = httpx.Response(403, text="nope, not today")
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == "The agent refused the request (HTTP 403). nope, not today"

    async def test_404(self, monkeypatch):
        response = httpx.Response(404, text="not found")
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == (
            f"No gateway route for {AGENT_PATH}. The agent may be disabled, unhealthy or "
            "not an A2A agent, or A2A reverse-proxy mode may be off."
        )

    async def test_non_json_2xx_body_maps_like_404(self, monkeypatch):
        response = httpx.Response(200, text="not json at all")
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == (
            f"No gateway route for {AGENT_PATH}. The agent may be disabled, unhealthy or "
            "not an A2A agent, or A2A reverse-proxy mode may be off."
        )

    async def test_405(self, monkeypatch):
        response = httpx.Response(405, text="method not allowed")
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == f"The gateway route for {AGENT_PATH} does not accept this request."

    async def test_429_with_retry_after(self, monkeypatch):
        response = httpx.Response(429, headers={"Retry-After": "30"}, text="slow down")
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == "Rate limited. Retry after 30 seconds."

    async def test_429_without_retry_after(self, monkeypatch):
        response = httpx.Response(429, text="slow down")
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == "Rate limited."

    @pytest.mark.parametrize("status", [502, 503, 504])
    async def test_5xx_backend_unavailable(self, monkeypatch, status):
        response = httpx.Response(status, text="bad gateway")
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == "The agent backend did not answer."

    async def test_mismatched_jsonrpc_id(self, monkeypatch):
        def _wrong_id(body):
            return httpx.Response(
                200, json={"jsonrpc": "2.0", "id": "not-the-request-id", "result": {}}
            )

        result = await self._run_get_task(monkeypatch, _wrong_id)

        assert result.status == "failed"
        assert result.error == "The agent's reply did not match the request."

    async def test_response_over_1_mib_is_dropped(self, monkeypatch):
        response = httpx.Response(
            200,
            headers={"content-length": str(2 * 1024 * 1024)},
            json={"jsonrpc": "2.0", "id": "x", "result": {}},
        )
        result = await self._run_get_task(monkeypatch, response)

        assert result.error == "The agent's reply exceeded 1 MiB and was dropped."

    async def test_task_id_is_echoed_on_get_agent_task_failure(self, monkeypatch):
        response = httpx.Response(404, text="not found")
        result = await self._run_get_task(monkeypatch, response)

        assert result.task_id == "task-1"
