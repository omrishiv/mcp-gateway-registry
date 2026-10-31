"""Unit tests for the leftover-service-credential startup warning in
servers/mcpgw/server.py.

mcpgw now always acts as the calling user; REGISTRY_API_TOKEN and the M2M
client env vars are read ONCE at import time, only to warn that they are no
longer used for auth -- never to build a credential. This is the regression
test for "removed, not revived": an operator's leftover value must produce a
log warning at startup, not a silent credential pickup.

Isolation note: importing servers.mcpgw.server has two side effects that
would otherwise break sibling test files or this file's own caplog capture:

- it imports ``fastmcp`` (absent from the main venv), stubbed the same way
  every other mcpgw test file stubs it;
- it calls ``setup_mcpgw_logging()``, which replaces every handler on the
  ROOT logger (including pytest's caplog capture handler). ``logging_setup``
  is stubbed out here too so a fresh import does not strip caplog's handler
  before the warning this test is checking for is even logged.

Both stubs, and the real server module, are removed from ``sys.modules``
afterward so sibling test files re-import cleanly.
"""

import logging
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock


class _ToolResultStub:
    """Matches fastmcp.tools.ToolResult's constructor contract exactly, so
    whichever mcpgw test module's sys.modules["fastmcp.tools"] stub wins the
    cross-file install race behaves identically either way."""

    def __init__(self, content=None, structured_content=None, meta=None, is_error=False):
        if content is None and structured_content is None:
            raise ValueError("Either content or structured_content must be provided")
        self.content = content
        self.structured_content = structured_content
        self.meta = meta
        self.is_error = is_error


def _import_server_fresh(monkeypatch, **env):
    """Import servers.mcpgw.server fresh under the given environment."""
    saved = {
        name: sys.modules.get(name)
        for name in (
            "fastmcp",
            "fastmcp.tools",
            "logging_setup",
            "servers.mcpgw.server",
            "server",
            "gateway_client",
            "mcp_invoke",
            "a2a_invoke",
        )
    }

    for key in (
        "REGISTRY_API_TOKEN",
        "M2M_CLIENT_ID",
        "M2M_CLIENT_SECRET",
        "OIDC_ENABLED",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    fastmcp_stub = types.ModuleType("fastmcp")
    fastmcp_stub.Context = type("Context", (), {})
    mock_mcp = MagicMock()
    mock_mcp.tool.return_value = lambda fn: fn  # decorator is a no-op
    fastmcp_stub.FastMCP = MagicMock(return_value=mock_mcp)
    sys.modules["fastmcp"] = fastmcp_stub
    # server.py also does `from fastmcp.tools import ToolResult` at module
    # scope (the invoke_mcp_tool wrapper); register the submodule too.
    fastmcp_tools_stub = types.ModuleType("fastmcp.tools")
    fastmcp_tools_stub.ToolResult = _ToolResultStub
    fastmcp_stub.tools = fastmcp_tools_stub
    sys.modules["fastmcp.tools"] = fastmcp_tools_stub

    logging_setup_stub = types.ModuleType("logging_setup")
    logging_setup_stub.setup_mcpgw_logging = MagicMock(return_value=None)
    sys.modules["logging_setup"] = logging_setup_stub

    sys.modules.pop("servers.mcpgw.server", None)
    sys.modules.pop("gateway_client", None)

    mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
    if mcpgw_path not in sys.path:
        sys.path.insert(0, mcpgw_path)

    try:
        import servers.mcpgw.server as fresh_server

        return fresh_server
    finally:
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod


def test_registry_api_token_set_logs_a_warning(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        _import_server_fresh(monkeypatch, REGISTRY_API_TOKEN="leftover-token-value")

    assert "REGISTRY_API_TOKEN is set but ignored" in caplog.text
    assert "leftover-token-value" not in caplog.text  # the value itself must never be logged


def test_m2m_credentials_set_log_a_warning(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        _import_server_fresh(
            monkeypatch, M2M_CLIENT_ID="custom-client", M2M_CLIENT_SECRET="leftover-secret"
        )

    assert "M2M_CLIENT_ID/M2M_CLIENT_SECRET are set but ignored" in caplog.text
    assert "leftover-secret" not in caplog.text


def test_no_leftover_vars_logs_no_warning(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        _import_server_fresh(monkeypatch)

    assert "is set but ignored" not in caplog.text
