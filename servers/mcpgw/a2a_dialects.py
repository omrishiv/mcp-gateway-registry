"""A2A JSON-RPC wire-format builders and parsers for invoke_agent / get_agent_task.

Pure wire-format code: builds and parses JSON-RPC request/response bodies for
the two A2A dialects mcpgw supports ("0.3" and "1.0"). No I/O, no id
generation (the caller passes the JSON-RPC request id in) and no
``gateway_client`` import -- this module has zero dependency on fastmcp or on
how the bytes got here, which is what makes it directly unit-testable.

Two dialects are exposed through the module-level ``DIALECTS`` dict, keyed by
version string ("0.3" or "1.0"), each a ``SimpleNamespace`` with:

- ``build_send(message, context_id, task_id, message_id, request_id)``
- ``build_get(task_id, request_id)``
- ``parse(response_body, expected_id, *, agent_path)``
- ``extra_headers()``

Two deliberate design choices worth calling out explicitly:

- ``build_send``/``build_get`` take the already-generated JSON-RPC ``id`` as
  their last argument and return the FULL envelope (``jsonrpc``/``id``/
  ``method``/``params``), rather than the caller wrapping an envelope around
  a partial body. This way each function's return value is exactly the JSON
  an agent would receive, directly comparable in a test.
- ``parse`` additionally takes ``agent_path`` as a keyword-only argument.
  ``AgentInvocationResult.agent_path`` is a required field, and ``parse`` is
  the only place that builds the one result object for a given outcome, so
  it needs this value in hand rather than the caller constructing a
  placeholder result and mutating it immediately after.

Content-Type sniffing (a non-JSON response body) is out of
scope here on purpose: by the time a response reaches ``parse`` it is already
a decoded ``dict`` (``gateway_client.request_json_bounded`` did the
``json.loads``), so a non-JSON body never reaches this module at all --
``json.JSONDecodeError`` surfaces to ``a2a_invoke.py`` instead, which maps it
to the same "no working route" text as an HTTP 404.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from models import AgentInvocationResult, AgentPart

_MAX_ERROR_MESSAGE_CHARS = 500

# A2A task states that end a task's lifecycle or hand control back to the
# user (0.3 spelling; the 1.0 parser maps its own enum onto these same
# strings via _1_0_STATE_MAP). Reaching one of these is a "success" outcome
# for the *call* -- a task itself in "failed" still means invoke_agent/
# get_agent_task worked; `state` says what happened to the task.
TERMINAL_OR_INTERRUPTED_STATES: frozenset[str] = frozenset(
    {"completed", "failed", "canceled", "rejected", "input-required", "auth-required"}
)
# Still running, or an unrecognized state (treated as "still running" since
# mcpgw cannot know a state it doesn't recognize has finished).
PENDING_STATES: frozenset[str] = frozenset({"submitted", "working", "unknown"})

_KNOWN_0_3_STATES: frozenset[str] = TERMINAL_OR_INTERRUPTED_STATES | PENDING_STATES

_1_0_STATE_MAP: dict[str, str] = {
    "TASK_STATE_SUBMITTED": "submitted",
    "TASK_STATE_WORKING": "working",
    "TASK_STATE_INPUT_REQUIRED": "input-required",
    "TASK_STATE_AUTH_REQUIRED": "auth-required",
    "TASK_STATE_COMPLETED": "completed",
    "TASK_STATE_FAILED": "failed",
    "TASK_STATE_CANCELED": "canceled",
    "TASK_STATE_REJECTED": "rejected",
    "TASK_STATE_UNSPECIFIED": "unknown",
}


def _cut(text: str) -> str:
    """Cut an agent-supplied error message to the shared 500-char limit."""
    return text[:_MAX_ERROR_MESSAGE_CHARS]


def _outcome_status(state: str) -> str:
    """Map a (0.3-spelled) task state to the call's own success/pending status."""
    return "success" if state in TERMINAL_OR_INTERRUPTED_STATES else "pending"


# Standard JSON-RPC 2.0 "Method not found" code. mcpgw only ever calls
# message/send, tasks/get (0.3) or SendMessage, GetTask (1.0), so receiving
# this from either dialect means the agent no longer recognizes THAT
# dialect's method names: a terminal failure for
# the call, never a reason to retry with the other dialect.
_METHOD_NOT_FOUND_CODE = -32601


def _is_dialect_rejection(code: Any, error_obj: dict[str, Any], message: str) -> bool:
    """True when `error_obj` means "this agent no longer supports this dialect".

    Covers a standard -32601 ("Method not found") on either dialect, and a
    1.0 VersionNotSupportedError, which the A2A 1.0 spec does not assign a
    fixed JSON-RPC code -- it is recognized here by name, wherever a server
    happens to expose it (an error `name` field, if present, or embedded in
    `message`), since that is the only inspectable signal available from a
    JSON-RPC error body.
    """
    if code == _METHOD_NOT_FOUND_CODE:
        return True
    name = str(error_obj.get("name", ""))
    haystack = f"{name} {message}".lower()
    return "versionnotsupported" in haystack.replace(" ", "")


def _check_envelope(
    response_body: dict[str, Any],
    expected_id: str,
    agent_path: str,
    protocol_version: str,
) -> AgentInvocationResult | None:
    """Validate the JSON-RPC envelope shared by both dialects.

    Returns a failed ``AgentInvocationResult`` when the envelope itself is
    bad (id mismatch, neither/both of ``result``/``error`` present, or an
    ``error`` member present), else ``None`` to signal "the envelope is
    fine, go parse ``result``".
    """
    if response_body.get("id") != expected_id:
        return AgentInvocationResult(
            status="failed",
            agent_path=agent_path,
            protocol_version=protocol_version,
            error="The agent's reply did not match the request.",
        )

    has_result = "result" in response_body
    has_error = "error" in response_body
    if has_result == has_error:  # neither, or both
        return AgentInvocationResult(
            status="failed",
            agent_path=agent_path,
            protocol_version=protocol_version,
            error="The agent's reply was not a valid JSON-RPC response.",
        )

    if has_error:
        error_obj = response_body.get("error")
        if not isinstance(error_obj, dict):
            error_obj = {}
        code = error_obj.get("code")
        message = str(error_obj.get("message", ""))
        if _is_dialect_rejection(code, error_obj, message):
            # mcpgw does not retry with a different dialect: an agent that
            # no longer recognizes this dialect's method name (JSON-RPC
            # -32601 "Method not found" -- the only method mcpgw ever calls
            # is message/send, tasks/get, SendMessage or GetTask, so a
            # -32601 here can only mean "this dialect's method name"), or
            # that reports a 1.0 VersionNotSupportedError, ends the call.
            return AgentInvocationResult(
                status="failed",
                agent_path=agent_path,
                protocol_version=protocol_version,
                error=f"The agent no longer supports A2A {protocol_version} for this task.",
            )
        return AgentInvocationResult(
            status="failed",
            agent_path=agent_path,
            protocol_version=protocol_version,
            error=f"Agent error {code}: {_cut(message)}",
        )

    return None


def _no_message_or_task(agent_path: str, protocol_version: str) -> AgentInvocationResult:
    return AgentInvocationResult(
        status="failed",
        agent_path=agent_path,
        protocol_version=protocol_version,
        error="The agent's reply had no message or task.",
    )


# ---------------------------------------------------------------------------
# Part assembly: the join/skip rules are shared; only the part *shape* (how
# to recognize a text/data/file part) differs per dialect.
# ---------------------------------------------------------------------------


def _collect_parts_0_3(
    parts: list[Any] | None,
) -> tuple[list[str], list[AgentPart], list[AgentPart]]:
    """Split a 0.3 ``parts`` array into text strings, data parts and file parts.

    0.3 parts carry an explicit ``kind`` discriminator ("text"/"file"/"data");
    anything else is an unrecognized part type and is skipped silently.
    """
    texts: list[str] = []
    data_parts: list[AgentPart] = []
    file_parts: list[AgentPart] = []
    for part in parts or []:
        if not isinstance(part, dict):
            continue
        kind = part.get("kind")
        if kind == "text":
            text = part.get("text")
            if isinstance(text, str):
                texts.append(text)
        elif kind == "data":
            data_parts.append(AgentPart(kind="data", data=part.get("data")))
        elif kind == "file":
            file_obj = part.get("file")
            if not isinstance(file_obj, dict):
                file_obj = {}
            file_parts.append(
                AgentPart(
                    kind="file",
                    name=file_obj.get("name"),
                    mime_type=file_obj.get("mimeType"),
                    uri=file_obj.get("uri"),
                )
            )
        # else: unknown part kind, skipped silently.
    return texts, data_parts, file_parts


def _collect_parts_1_0(
    parts: list[Any] | None,
) -> tuple[list[str], list[AgentPart], list[AgentPart]]:
    """Split a 1.0 ``parts`` array into text strings, data parts and file parts.

    1.0 parts carry no ``kind`` discriminator (the proto ``oneof`` collapses
    to whichever of "text"/"data"/"file" is present in the JSON mapping), so
    the part type is recognized by which key is present. Any part with none
    of those three keys is skipped silently.
    """
    texts: list[str] = []
    data_parts: list[AgentPart] = []
    file_parts: list[AgentPart] = []
    for part in parts or []:
        if not isinstance(part, dict):
            continue
        if "text" in part:
            text = part.get("text")
            if isinstance(text, str):
                texts.append(text)
        elif "data" in part:
            data_parts.append(AgentPart(kind="data", data=part.get("data")))
        elif "file" in part:
            file_obj = part.get("file")
            if not isinstance(file_obj, dict):
                file_obj = {}
            file_parts.append(
                AgentPart(
                    kind="file",
                    name=file_obj.get("name"),
                    mime_type=file_obj.get("mimeType"),
                    uri=file_obj.get("fileWithUri"),
                )
            )
        # else: unknown part shape, skipped silently.
    return texts, data_parts, file_parts


def _assemble_task_text(
    status_message: dict[str, Any] | None,
    artifacts: list[Any] | None,
    collect_parts: Any,
) -> tuple[str, list[AgentPart], list[AgentPart]]:
    """Assemble a task's text/data/file parts: status.message first, then artifacts in order."""
    texts: list[str] = []
    data_parts: list[AgentPart] = []
    file_parts: list[AgentPart] = []
    if isinstance(status_message, dict):
        t, dp, fp = collect_parts(status_message.get("parts"))
        texts += t
        data_parts += dp
        file_parts += fp
    for artifact in artifacts or []:
        if not isinstance(artifact, dict):
            continue
        t, dp, fp = collect_parts(artifact.get("parts"))
        texts += t
        data_parts += dp
        file_parts += fp
    return "\n\n".join(texts), data_parts, file_parts


# ---------------------------------------------------------------------------
# 0.3 dialect
# ---------------------------------------------------------------------------


def _build_send_0_3(
    message: str,
    context_id: str | None,
    task_id: str | None,
    message_id: str,
    request_id: str,
) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "role": "user",
        "messageId": message_id,
        "parts": [{"kind": "text", "text": message}],
    }
    if task_id is not None:
        msg["taskId"] = task_id
    if context_id is not None:
        msg["contextId"] = context_id
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "message/send",
        "params": {"message": msg, "configuration": {"blocking": False}},
    }


def _build_get_0_3(task_id: str, request_id: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": "tasks/get", "params": {"id": task_id}}


def _parse_0_3(
    response_body: dict[str, Any], expected_id: str, *, agent_path: str
) -> AgentInvocationResult:
    envelope_error = _check_envelope(response_body, expected_id, agent_path, "0.3")
    if envelope_error is not None:
        return envelope_error

    result = response_body.get("result")
    kind = result.get("kind") if isinstance(result, dict) else None

    if kind == "message":
        texts, data_parts, file_parts = _collect_parts_0_3(result.get("parts"))
        return AgentInvocationResult(
            status="success",
            agent_path=agent_path,
            protocol_version="0.3",
            task_id=result.get("taskId"),
            context_id=result.get("contextId"),
            text="\n\n".join(texts),
            data_parts=data_parts,
            file_parts=file_parts,
        )

    if kind == "task":
        task_id = result.get("id")
        status = result.get("status")
        state_raw = status.get("state") if isinstance(status, dict) else None
        if not task_id or not state_raw:
            return _no_message_or_task(agent_path, "0.3")
        state = state_raw if state_raw in _KNOWN_0_3_STATES else "unknown"
        status_message = status.get("message") if isinstance(status, dict) else None
        text, data_parts, file_parts = _assemble_task_text(
            status_message, result.get("artifacts"), _collect_parts_0_3
        )
        return AgentInvocationResult(
            status=_outcome_status(state),
            agent_path=agent_path,
            protocol_version="0.3",
            task_id=task_id,
            context_id=result.get("contextId"),
            state=state,
            text=text,
            data_parts=data_parts,
            file_parts=file_parts,
        )

    return _no_message_or_task(agent_path, "0.3")


# ---------------------------------------------------------------------------
# 1.0 dialect
# ---------------------------------------------------------------------------


def _build_send_1_0(
    message: str,
    context_id: str | None,
    task_id: str | None,
    message_id: str,
    request_id: str,
) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "role": "ROLE_USER",
        "messageId": message_id,
        "parts": [{"text": message}],
    }
    if task_id is not None:
        msg["taskId"] = task_id
    if context_id is not None:
        msg["contextId"] = context_id
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "SendMessage",
        "params": {"message": msg, "configuration": {"returnImmediately": True}},
    }


def _build_get_1_0(task_id: str, request_id: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": "GetTask", "params": {"id": task_id}}


def _parse_1_0(
    response_body: dict[str, Any], expected_id: str, *, agent_path: str
) -> AgentInvocationResult:
    envelope_error = _check_envelope(response_body, expected_id, agent_path, "1.0")
    if envelope_error is not None:
        return envelope_error

    result = response_body.get("result")
    if not isinstance(result, dict):
        return _no_message_or_task(agent_path, "1.0")

    has_message = "message" in result
    has_task = "task" in result
    if has_message == has_task:  # neither, or both
        return _no_message_or_task(agent_path, "1.0")

    if has_message:
        message = result.get("message")
        if not isinstance(message, dict):
            message = {}
        texts, data_parts, file_parts = _collect_parts_1_0(message.get("parts"))
        return AgentInvocationResult(
            status="success",
            agent_path=agent_path,
            protocol_version="1.0",
            task_id=message.get("taskId"),
            context_id=message.get("contextId"),
            text="\n\n".join(texts),
            data_parts=data_parts,
            file_parts=file_parts,
        )

    task = result.get("task")
    if not isinstance(task, dict):
        task = {}
    task_id = task.get("id")
    status = task.get("status")
    state_raw = status.get("state") if isinstance(status, dict) else None
    if not task_id or not state_raw:
        return _no_message_or_task(agent_path, "1.0")
    state = _1_0_STATE_MAP.get(state_raw, "unknown")
    status_message = status.get("message") if isinstance(status, dict) else None
    text, data_parts, file_parts = _assemble_task_text(
        status_message, task.get("artifacts"), _collect_parts_1_0
    )
    return AgentInvocationResult(
        status=_outcome_status(state),
        agent_path=agent_path,
        protocol_version="1.0",
        task_id=task_id,
        context_id=task.get("contextId"),
        state=state,
        text=text,
        data_parts=data_parts,
        file_parts=file_parts,
    )


DIALECTS: dict[str, SimpleNamespace] = {
    "0.3": SimpleNamespace(
        version="0.3",
        build_send=_build_send_0_3,
        build_get=_build_get_0_3,
        parse=_parse_0_3,
        extra_headers=lambda: {},
    ),
    "1.0": SimpleNamespace(
        version="1.0",
        build_send=_build_send_1_0,
        build_get=_build_get_1_0,
        parse=_parse_1_0,
        extra_headers=lambda: {"A2A-Version": "1.0"},
    ),
}
