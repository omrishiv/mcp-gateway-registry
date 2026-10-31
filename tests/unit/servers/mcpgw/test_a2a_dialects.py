"""Unit tests for servers/mcpgw/a2a_dialects.py.

a2a_dialects is pure wire-format code (no I/O, no fastmcp), so it needs no
stub -- only servers/mcpgw on sys.path so `import a2a_dialects` resolves
`from models import ...` the same way the module itself does.
"""

import sys
from pathlib import Path

_mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
if _mcpgw_path not in sys.path:
    sys.path.insert(0, _mcpgw_path)

import a2a_dialects  # noqa: E402

DIALECTS = a2a_dialects.DIALECTS
AGENT_PATH = "/flight-booking"


# ---------------------------------------------------------------------------
# build_send / build_get: exact documented JSON shapes
# ---------------------------------------------------------------------------


class TestBuildSend0_3:
    def test_builds_the_full_jsonrpc_envelope(self):
        body = DIALECTS["0.3"].build_send(
            "Book LHR to JFK", None, None, "5b1e...", "9f2c41aa07b3d6e1"
        )

        assert body == {
            "jsonrpc": "2.0",
            "id": "9f2c41aa07b3d6e1",
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "messageId": "5b1e...",
                    "parts": [{"kind": "text", "text": "Book LHR to JFK"}],
                },
                "configuration": {"blocking": False},
            },
        }

    def test_adds_task_id_and_context_id_when_given(self):
        body = DIALECTS["0.3"].build_send("hello", "ctx-1", "task-1", "msg-1", "req-1")

        message = body["params"]["message"]
        assert message["taskId"] == "task-1"
        assert message["contextId"] == "ctx-1"

    def test_omits_task_id_and_context_id_when_absent(self):
        body = DIALECTS["0.3"].build_send("hello", None, None, "msg-1", "req-1")

        message = body["params"]["message"]
        assert "taskId" not in message
        assert "contextId" not in message


class TestBuildGet0_3:
    def test_matches_the_documented_shape(self):
        body = DIALECTS["0.3"].build_get("task-123", "req-1")

        assert body == {
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "tasks/get",
            "params": {"id": "task-123"},
        }


class TestBuildSend1_0:
    def test_builds_the_full_jsonrpc_envelope(self):
        body = DIALECTS["1.0"].build_send(
            "Book LHR to JFK", None, None, "5b1e...", "9f2c41aa07b3d6e1"
        )

        assert body == {
            "jsonrpc": "2.0",
            "id": "9f2c41aa07b3d6e1",
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": "ROLE_USER",
                    "messageId": "5b1e...",
                    "parts": [{"text": "Book LHR to JFK"}],
                },
                "configuration": {"returnImmediately": True},
            },
        }

    def test_adds_task_id_and_context_id_when_given(self):
        body = DIALECTS["1.0"].build_send("hello", "ctx-1", "task-1", "msg-1", "req-1")

        message = body["params"]["message"]
        assert message["taskId"] == "task-1"
        assert message["contextId"] == "ctx-1"


class TestBuildGet1_0:
    def test_matches_the_documented_shape(self):
        body = DIALECTS["1.0"].build_get("task-123", "req-1")

        assert body == {
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "GetTask",
            "params": {"id": "task-123"},
        }


class TestExtraHeaders:
    def test_0_3_adds_no_headers(self):
        assert DIALECTS["0.3"].extra_headers() == {}

    def test_1_0_adds_the_version_header(self):
        assert DIALECTS["1.0"].extra_headers() == {"A2A-Version": "1.0"}


# ---------------------------------------------------------------------------
# parse: envelope rules (shared by both dialects)
# ---------------------------------------------------------------------------


class TestParseEnvelope:
    def test_mismatched_id_is_rejected_0_3(self):
        body = {"jsonrpc": "2.0", "id": "wrong", "result": {"kind": "message", "parts": []}}

        result = DIALECTS["0.3"].parse(body, "expected", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply did not match the request."

    def test_mismatched_id_is_rejected_1_0(self):
        body = {"jsonrpc": "2.0", "id": "wrong", "result": {"message": {"parts": []}}}

        result = DIALECTS["1.0"].parse(body, "expected", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply did not match the request."

    def test_neither_result_nor_error_is_invalid(self):
        body = {"jsonrpc": "2.0", "id": "req-1"}

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply was not a valid JSON-RPC response."

    def test_both_result_and_error_is_invalid(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {"kind": "message", "parts": []},
            "error": {"code": -1, "message": "boom"},
        }

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply was not a valid JSON-RPC response."

    def test_error_member_produces_failed_with_code_and_message(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "error": {"code": -32603, "message": "Internal error"},
        }

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "Agent error -32603: Internal error"

    def test_method_not_found_is_a_dialect_rejection_0_3(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "error": {"code": -32601, "message": "Method not found"},
        }

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent no longer supports A2A 0.3 for this task."

    def test_method_not_found_is_a_dialect_rejection_1_0(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "error": {"code": -32601, "message": "Method not found"},
        }

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent no longer supports A2A 1.0 for this task."

    def test_version_not_supported_error_is_a_dialect_rejection_1_0(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "error": {
                "code": -32000,
                "message": "VersionNotSupportedError: 1.0 is no longer offered",
            },
        }

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent no longer supports A2A 1.0 for this task."

    def test_error_message_is_cut_to_500_characters(self):
        long_message = "x" * 600
        body = {"jsonrpc": "2.0", "id": "req-1", "error": {"code": -1, "message": long_message}}

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.error == f"Agent error -1: {'x' * 500}"
        assert len(result.error) < 520

    def test_parse_sets_agent_path_and_protocol_version_on_every_outcome(self):
        body = {"jsonrpc": "2.0", "id": "req-1", "error": {"code": -1, "message": "boom"}}

        result_0_3 = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)
        result_1_0 = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result_0_3.agent_path == AGENT_PATH
        assert result_0_3.protocol_version == "0.3"
        assert result_1_0.agent_path == AGENT_PATH
        assert result_1_0.protocol_version == "1.0"


# ---------------------------------------------------------------------------
# parse: 0.3 message/task detection and part assembly
# ---------------------------------------------------------------------------


class TestParse0_3Message:
    def test_bare_message_result_is_success(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {
                "kind": "message",
                "role": "agent",
                "parts": [{"kind": "text", "text": "Hello"}],
            },
        }

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "success"
        assert result.text == "Hello"
        assert result.state is None

    def test_message_text_parts_are_joined_with_blank_lines_in_order(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {
                "kind": "message",
                "parts": [
                    {"kind": "text", "text": "first"},
                    {"kind": "text", "text": "second"},
                ],
            },
        }

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.text == "first\n\nsecond"

    def test_unrecognized_kind_is_rejected(self):
        body = {"jsonrpc": "2.0", "id": "req-1", "result": {"kind": "weird"}}

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply had no message or task."


class TestParse0_3Task:
    def _task_body(self, state="completed", artifacts=None, status_message=None, **overrides):
        status = {"state": state}
        if status_message is not None:
            status["message"] = status_message
        result = {
            "kind": "task",
            "id": "task-1",
            "contextId": "ctx-1",
            "status": status,
            "artifacts": artifacts or [],
        }
        result.update(overrides)
        return {"jsonrpc": "2.0", "id": "req-1", "result": result}

    def test_terminal_state_is_success(self):
        result = DIALECTS["0.3"].parse(
            self._task_body(state="completed"), "req-1", agent_path=AGENT_PATH
        )

        assert result.status == "success"
        assert result.state == "completed"
        assert result.task_id == "task-1"
        assert result.context_id == "ctx-1"

    def test_input_required_is_success_not_pending(self):
        result = DIALECTS["0.3"].parse(
            self._task_body(state="input-required"), "req-1", agent_path=AGENT_PATH
        )

        assert result.status == "success"
        assert result.state == "input-required"

    def test_working_state_is_pending(self):
        result = DIALECTS["0.3"].parse(
            self._task_body(state="working"), "req-1", agent_path=AGENT_PATH
        )

        assert result.status == "pending"
        assert result.state == "working"

    def test_unknown_state_string_is_treated_as_unknown_and_pending(self):
        result = DIALECTS["0.3"].parse(
            self._task_body(state="some-future-state"), "req-1", agent_path=AGENT_PATH
        )

        assert result.state == "unknown"
        assert result.status == "pending"

    def test_task_missing_id_is_failed(self):
        body = self._task_body(state="completed")
        del body["result"]["id"]

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply had no message or task."

    def test_task_missing_state_is_failed(self):
        body = self._task_body()
        del body["result"]["status"]["state"]

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply had no message or task."

    def test_text_assembly_order_message_then_artifacts(self):
        body = self._task_body(
            state="completed",
            status_message={"parts": [{"kind": "text", "text": "status text"}]},
            artifacts=[
                {"parts": [{"kind": "text", "text": "artifact one"}]},
                {"parts": [{"kind": "text", "text": "artifact two"}]},
            ],
        )

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.text == "status text\n\nartifact one\n\nartifact two"

    def test_data_part_is_collected(self):
        body = self._task_body(
            state="completed",
            artifacts=[{"parts": [{"kind": "data", "data": {"foo": "bar"}}]}],
        )

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert len(result.data_parts) == 1
        assert result.data_parts[0].kind == "data"
        assert result.data_parts[0].data == {"foo": "bar"}

    def test_file_part_keeps_name_mime_and_uri_never_bytes(self):
        body = self._task_body(
            state="completed",
            artifacts=[
                {
                    "parts": [
                        {
                            "kind": "file",
                            "file": {
                                "name": "out.png",
                                "mimeType": "image/png",
                                "uri": "https://example.com/out.png",
                                "bytes": "should-never-appear",
                            },
                        }
                    ]
                }
            ],
        )

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert len(result.file_parts) == 1
        file_part = result.file_parts[0]
        assert file_part.kind == "file"
        assert file_part.name == "out.png"
        assert file_part.mime_type == "image/png"
        assert file_part.uri == "https://example.com/out.png"
        assert not hasattr(file_part, "bytes")

    def test_unknown_part_type_is_skipped_silently(self):
        body = self._task_body(
            state="completed",
            artifacts=[
                {
                    "parts": [
                        {"kind": "text", "text": "kept"},
                        {"kind": "something-new", "value": 1},
                    ]
                }
            ],
        )

        result = DIALECTS["0.3"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.text == "kept"
        assert result.data_parts == []
        assert result.file_parts == []


# ---------------------------------------------------------------------------
# parse: 1.0 message/task detection, state-name mapping, and part assembly
# ---------------------------------------------------------------------------


class TestParse1_0Message:
    def test_bare_message_result_is_success(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {"message": {"role": "ROLE_AGENT", "parts": [{"text": "Hello"}]}},
        }

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "success"
        assert result.text == "Hello"

    def test_neither_message_nor_task_is_rejected(self):
        body = {"jsonrpc": "2.0", "id": "req-1", "result": {}}

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply had no message or task."

    def test_both_message_and_task_is_rejected(self):
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {"message": {"parts": []}, "task": {"id": "t", "status": {"state": "x"}}},
        }

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply had no message or task."


class TestParse1_0Task:
    def _task_body(self, state, artifacts=None, status_message=None):
        status = {"state": state}
        if status_message is not None:
            status["message"] = status_message
        task = {
            "id": "task-1",
            "contextId": "ctx-1",
            "status": status,
            "artifacts": artifacts or [],
        }
        return {"jsonrpc": "2.0", "id": "req-1", "result": {"task": task}}

    def test_state_name_mapping_to_0_3_spelling(self):
        cases = {
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
        for raw_state, expected in cases.items():
            result = DIALECTS["1.0"].parse(
                self._task_body(raw_state), "req-1", agent_path=AGENT_PATH
            )
            assert result.state == expected, raw_state

    def test_a_task_failed_state_is_still_status_success(self):
        result = DIALECTS["1.0"].parse(
            self._task_body("TASK_STATE_FAILED"), "req-1", agent_path=AGENT_PATH
        )

        assert result.status == "success"
        assert result.state == "failed"

    def test_working_state_is_pending(self):
        result = DIALECTS["1.0"].parse(
            self._task_body("TASK_STATE_WORKING"), "req-1", agent_path=AGENT_PATH
        )

        assert result.status == "pending"

    def test_unrecognized_state_string_maps_to_unknown_and_pending(self):
        result = DIALECTS["1.0"].parse(
            self._task_body("TASK_STATE_SOMETHING_NEW"), "req-1", agent_path=AGENT_PATH
        )

        assert result.state == "unknown"
        assert result.status == "pending"

    def test_task_missing_id_is_failed(self):
        body = self._task_body("TASK_STATE_COMPLETED")
        del body["result"]["task"]["id"]

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply had no message or task."

    def test_task_missing_state_is_failed(self):
        body = self._task_body("TASK_STATE_COMPLETED")
        del body["result"]["task"]["status"]["state"]

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.status == "failed"
        assert result.error == "The agent's reply had no message or task."

    def test_text_assembly_order_message_then_artifacts(self):
        body = self._task_body(
            "TASK_STATE_COMPLETED",
            status_message={"parts": [{"text": "status text"}]},
            artifacts=[
                {"parts": [{"text": "artifact one"}]},
                {"parts": [{"text": "artifact two"}]},
            ],
        )

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.text == "status text\n\nartifact one\n\nartifact two"

    def test_data_part_is_collected_from_data_field(self):
        body = self._task_body(
            "TASK_STATE_COMPLETED",
            artifacts=[{"parts": [{"data": {"foo": "bar"}}]}],
        )

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert len(result.data_parts) == 1
        assert result.data_parts[0].data == {"foo": "bar"}

    def test_file_part_keeps_name_and_mime_never_bytes(self):
        body = self._task_body(
            "TASK_STATE_COMPLETED",
            artifacts=[
                {
                    "parts": [
                        {
                            "file": {
                                "name": "out.png",
                                "mimeType": "image/png",
                                "fileWithUri": "https://example.com/out.png",
                                "fileWithBytes": "should-never-appear",
                            }
                        }
                    ]
                }
            ],
        )

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert len(result.file_parts) == 1
        file_part = result.file_parts[0]
        assert file_part.name == "out.png"
        assert file_part.mime_type == "image/png"
        assert file_part.uri == "https://example.com/out.png"
        assert not hasattr(file_part, "bytes")

    def test_unknown_part_shape_is_skipped_silently(self):
        body = self._task_body(
            "TASK_STATE_COMPLETED",
            artifacts=[{"parts": [{"text": "kept"}, {"somethingElse": True}]}],
        )

        result = DIALECTS["1.0"].parse(body, "req-1", agent_path=AGENT_PATH)

        assert result.text == "kept"
        assert result.data_parts == []
        assert result.file_parts == []
