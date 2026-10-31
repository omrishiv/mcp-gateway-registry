"""Property tests for the gateway's per-tool authorization decision.

These pin the rule that a scope's ``tools`` grant authorizes a ``tools/call``
for exactly the named tools, or for every tool only through the explicit
``"*"`` / ``"all"`` wildcard, whether the grant is stored as a list or as a
single string, and that a blocked tool is denied under every grant shape.
"""

import asyncio
import os
from collections.abc import Callable
from typing import Any
from unittest.mock import (
    AsyncMock,
    patch,
)

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-definitely-long-enough-32b")

from auth_server.server import validate_server_tool_access  # noqa: E402

pytestmark = pytest.mark.unit

_SERVER = "github"
_SCOPE = "tool-scope"
_TOOL_CALL = "tools/call"
_WILDCARDS = frozenset({"*", "all"})
_TOOL_ALPHABET = "acdeilnorstuy_*"
_KNOWN_NAMES = (
    "*",
    "all",
    "install_all",
    "create_issue",
    "delete_repo",
    "issue",
    "list_all_repos",
)


def _scope_repo(tools: Any) -> AsyncMock:
    """Build a scope repository whose single scope grants ``tools`` on the server.

    Args:
        tools: The ``tools`` value of the server access rule (list or string).

    Returns:
        An ``AsyncMock`` standing in for the scope repository.
    """
    repo = AsyncMock()

    async def _get(scope_name: str) -> list[dict]:
        if scope_name != _SCOPE:
            return []
        return [{"server": _SERVER, "methods": [_TOOL_CALL], "tools": tools}]

    repo.get_server_scopes.side_effect = _get
    return repo


def _may_call(
    tools: Any,
    tool_name: str,
    blocked: set[str] | None = None,
) -> bool:
    """Run ``validate_server_tool_access`` for one ``tools/call`` decision.

    Args:
        tools: The ``tools`` value of the only matching server access rule.
        tool_name: The tool the caller invokes.
        blocked: The server's blocked-tool set (empty when omitted).

    Returns:
        The access decision.
    """
    blocked_lookup = AsyncMock(return_value=set(blocked or ()))
    with (
        patch("auth_server.server.get_scope_repository", return_value=_scope_repo(tools)),
        patch("auth_server.server._get_blocked_tools", blocked_lookup),
    ):
        return asyncio.run(validate_server_tool_access(_SERVER, _TOOL_CALL, tool_name, [_SCOPE]))


def _expected(granted: str, tool_name: str) -> bool:
    """Reference decision for a grant naming the single tool ``granted``.

    Args:
        granted: The single tool name (or wildcard) the grant carries.
        tool_name: The tool the caller invokes.

    Returns:
        True exactly when the grant names the tool or is a full wildcard.
    """
    return tool_name == granted or granted in _WILDCARDS


@st.composite
def _grant_and_tool(draw: st.DrawFn) -> tuple[str, str]:
    """Draw a granted name and a requested tool name, biased toward substrings.

    Args:
        draw: Hypothesis draw function.

    Returns:
        A ``(granted, tool_name)`` pair with a non-empty ``tool_name``.
    """
    granted = draw(
        st.one_of(
            st.sampled_from(_KNOWN_NAMES),
            st.text(alphabet=_TOOL_ALPHABET, max_size=12),
        )
    )
    candidates = [
        st.sampled_from(_KNOWN_NAMES),
        st.text(alphabet=_TOOL_ALPHABET, min_size=1, max_size=12),
    ]
    if granted:
        start = draw(st.integers(min_value=0, max_value=len(granted) - 1))
        end = draw(st.integers(min_value=start + 1, max_value=len(granted)))
        candidates.append(st.just(granted[start:end]))
        candidates.append(st.just(granted))
    tool_name = draw(st.one_of(*candidates))
    return granted, tool_name


@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(pair=_grant_and_tool())
@example(pair=("install_all", "delete_repo"))
@example(pair=("create_issue", "issue"))
def test_string_tools_grant_allows_exactly_named_tool(pair: tuple[str, str]) -> None:
    """A string ``tools`` grant t allows tool n iff n == t or t is a wildcard."""
    granted, tool_name = pair
    assert _may_call(granted, tool_name) is _expected(granted, tool_name), (
        f"tools={granted!r} tool={tool_name!r}"
    )


@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(pair=_grant_and_tool())
@example(pair=("install_all", "delete_repo"))
@example(pair=("create_issue", "issue"))
def test_list_tools_grant_allows_exactly_named_tool(pair: tuple[str, str]) -> None:
    """A list ``tools`` grant [t] allows tool n iff n == t or t is a wildcard."""
    granted, tool_name = pair
    assert _may_call([granted], tool_name) is _expected(granted, tool_name), (
        f"tools={[granted]!r} tool={tool_name!r}"
    )


_GRANT_SHAPES: dict[str, Callable[[str], Any]] = {
    "list_exact": lambda name: [name],
    "string_exact": lambda name: name,
    "string_star": lambda name: "*",
    "string_all": lambda name: "all",
    "list_star": lambda name: ["*"],
    "list_all": lambda name: ["all"],
}


@pytest.mark.parametrize("shape", sorted(_GRANT_SHAPES))
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(tool_name=st.text(alphabet=_TOOL_ALPHABET, min_size=1, max_size=12))
@example(tool_name="delete_repo")
def test_blocked_tool_denied_under_every_grant_shape(shape: str, tool_name: str) -> None:
    """A blocked tool is denied for ``tools/call`` whatever the grant shape."""
    tools = _GRANT_SHAPES[shape](tool_name)
    assert _may_call(tools, tool_name) is True, f"grant {tools!r} should cover {tool_name!r}"
    assert _may_call(tools, tool_name, blocked={tool_name}) is False, (
        f"blocked tool {tool_name!r} allowed under tools={tools!r}"
    )
