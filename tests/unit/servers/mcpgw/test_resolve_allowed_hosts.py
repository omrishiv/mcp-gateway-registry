"""Unit tests for _resolve_allowed_hosts in servers/mcpgw/server.py.

Covers the FastMCP DNS-rebinding host-protection resolution that fixes the
airegistry-tools 421 -> unhealthy -> 405 chain: the mcpgw server is reached
through the registry front door as Host "mcpgw-server", which FastMCP 3.x's
default host protection rejected. The default keeps protection ON and allowlists
that service name; "*" is an opt-in escape hatch that disables protection.

Isolation note: servers/mcpgw/server.py imports `fastmcp` (absent from the main
venv), so it must be stubbed before import. A sibling test file stubs it too and
force-re-imports the module; to avoid cross-file interference we import the
function inside a fixture that snapshots and restores sys.modules, leaving no
cached server module or fastmcp stub behind for other files.
"""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


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


@pytest.fixture
def resolve_allowed_hosts():
    """Import _resolve_allowed_hosts under an isolated, restored module state."""
    saved = {
        name: sys.modules.get(name)
        for name in ("fastmcp", "fastmcp.tools", "servers.mcpgw.server", "server")
    }

    fastmcp_stub = types.ModuleType("fastmcp")
    fastmcp_stub.Context = type("Context", (), {})
    mock_mcp = MagicMock()
    mock_mcp.tool.return_value = lambda fn: fn  # decorator no-op
    fastmcp_stub.FastMCP = MagicMock(return_value=mock_mcp)
    sys.modules["fastmcp"] = fastmcp_stub
    # server.py also does `from fastmcp.tools import ToolResult` at module
    # scope (the invoke_mcp_tool wrapper); register the submodule too.
    fastmcp_tools_stub = types.ModuleType("fastmcp.tools")
    fastmcp_tools_stub.ToolResult = _ToolResultStub
    fastmcp_stub.tools = fastmcp_tools_stub
    sys.modules["fastmcp.tools"] = fastmcp_tools_stub
    sys.modules.pop("servers.mcpgw.server", None)

    mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
    if mcpgw_path not in sys.path:
        sys.path.insert(0, mcpgw_path)

    from servers.mcpgw.server import _resolve_allowed_hosts

    try:
        yield _resolve_allowed_hosts
    finally:
        # Restore prior module state so sibling test files re-import cleanly.
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod


class TestResolveAllowedHosts:
    def test_default_service_name_keeps_protection_on(self, resolve_allowed_hosts) -> None:
        # The shipped default: protection ON, allowlisting the front-door host.
        protection, hosts = resolve_allowed_hosts("mcpgw-server")
        assert protection is True
        assert hosts == ["mcpgw-server"]

    def test_star_disables_protection(self, resolve_allowed_hosts) -> None:
        # Opt-in escape hatch: "*" turns protection OFF (allowed_hosts=None).
        protection, hosts = resolve_allowed_hosts("*")
        assert protection is False
        assert hosts is None

    def test_empty_disables_protection(self, resolve_allowed_hosts) -> None:
        protection, hosts = resolve_allowed_hosts("")
        assert protection is False
        assert hosts is None

    def test_whitespace_only_disables_protection(self, resolve_allowed_hosts) -> None:
        protection, hosts = resolve_allowed_hosts("   ")
        assert protection is False
        assert hosts is None

    def test_comma_separated_list_is_parsed_and_trimmed(self, resolve_allowed_hosts) -> None:
        protection, hosts = resolve_allowed_hosts("mcpgw-server, my-mcpgw.svc ,other")
        assert protection is True
        assert hosts == ["mcpgw-server", "my-mcpgw.svc", "other"]

    def test_star_among_other_hosts_still_disables(self, resolve_allowed_hosts) -> None:
        # If any entry is "*", protection is off regardless of the others.
        protection, hosts = resolve_allowed_hosts("mcpgw-server,*")
        assert protection is False
        assert hosts is None

    def test_single_custom_host(self, resolve_allowed_hosts) -> None:
        protection, hosts = resolve_allowed_hosts("my-mcpgw.internal")
        assert protection is True
        assert hosts == ["my-mcpgw.internal"]
