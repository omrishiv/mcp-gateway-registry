"""Property tests for the security scanner verdict.

Pins the fail-closed property of the MCP security scanner verdict: a server is
reported safe only when no tool result says ``is_safe: false`` and every
finding parses with a known severity below ``high``. Anything the scanner
cannot classify (missing or misspelled severity, analyzer results that are not
dicts) must yield an unsafe verdict, because this verdict gates registration.
"""

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import (
    strategies as st,
)

from registry.services.security_scanner import (
    SecurityScannerService,
    _organize_findings_by_analyzer,
)

KNOWN_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})
BLOCKING_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})
SEVERITY_CHOICES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "unknown",
    "",
    "CRITICAL ",
    "severe",
)
MISSING = object()

FINDING_17_REASON = (
    "Known defect: the scanner verdict is safe whenever it counts no critical or "
    "high finding, so unclassifiable output and tool is_safe false pass as safe."
)


def _make_service() -> SecurityScannerService:
    """Build a SecurityScannerService with its repository dependency mocked.

    Returns:
        Scanner service instance that never touches a real repository.
    """
    with patch("registry.services.security_scanner.get_security_scan_repository"):
        service = SecurityScannerService()
    service._scan_repo = MagicMock()
    service._scan_repo.create = AsyncMock(return_value=None)
    return service


def _verdict(
    tool_results: list[dict[str, Any]],
) -> bool:
    """Run the scanner's parse-then-analyze pipeline and return ``is_safe``.

    Mirrors how ``_run_mcp_scanner`` builds ``raw_output`` from the parsed
    tool results before ``_analyze_scan_results`` decides the verdict.

    Args:
        tool_results: Parsed mcp-scanner tool results.

    Returns:
        The ``is_safe`` verdict.
    """
    raw_output = {
        "analysis_results": _organize_findings_by_analyzer(tool_results),
        "tool_results": tool_results,
    }
    is_safe, *_counts = _make_service()._analyze_scan_results(raw_output)
    return is_safe


def _fail_closed_allows_safe(
    tool_results: list[dict[str, Any]],
) -> bool:
    """Return True when the fail-closed policy permits a safe verdict.

    Args:
        tool_results: Parsed mcp-scanner tool results.

    Returns:
        True only if no tool reports ``is_safe: false`` and every analyzer
        result is a dict with a known severity below ``high``.
    """
    for tool_result in tool_results:
        if tool_result.get("is_safe", True) is False:
            return False
        for analyzer_findings in tool_result.get("findings", {}).values():
            if not isinstance(analyzer_findings, dict):
                return False
            severity = analyzer_findings.get("severity")
            if not isinstance(severity, str):
                return False
            normalized = severity.lower()
            if normalized not in KNOWN_SEVERITIES or normalized in BLOCKING_SEVERITIES:
                return False
    return True


@st.composite
def _analyzer_result(draw: st.DrawFn) -> Any:
    """Draw one analyzer result: a finding dict, a list or a scalar."""
    shape = draw(st.sampled_from(("dict", "list", "scalar")))
    if shape == "list":
        return [{"severity": draw(st.sampled_from(SEVERITY_CHOICES))}]
    if shape == "scalar":
        return draw(st.one_of(st.text(max_size=8), st.integers(), st.none()))
    finding: dict[str, Any] = {"threat_names": [], "threat_summary": ""}
    severity = draw(st.sampled_from((*SEVERITY_CHOICES, MISSING)))
    if severity is not MISSING:
        finding["severity"] = severity
    return finding


@st.composite
def _tool_result(draw: st.DrawFn) -> dict[str, Any]:
    """Draw one mcp-scanner tool result with optional ``is_safe``."""
    result: dict[str, Any] = {
        "tool_name": draw(st.text(max_size=12)),
        "findings": draw(
            st.dictionaries(
                st.sampled_from(("yara_analyzer", "llm_analyzer", "api_analyzer")),
                _analyzer_result(),
                max_size=3,
            )
        ),
    }
    is_safe = draw(st.sampled_from((True, False, MISSING)))
    if is_safe is not MISSING:
        result["is_safe"] = is_safe
    return result


@pytest.mark.unit
@pytest.mark.xfail(strict=True, raises=AssertionError, reason=FINDING_17_REASON)
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(tool_results=st.lists(_tool_result(), max_size=4))
@example(tool_results=[{"tool_name": "t", "is_safe": True, "findings": {"yara_analyzer": {}}}])
@example(
    tool_results=[
        {"tool_name": "t", "is_safe": False, "findings": {"yara_analyzer": {"severity": "low"}}}
    ]
)
@example(
    tool_results=[
        {
            "tool_name": "t",
            "is_safe": True,
            "findings": {"yara_analyzer": [{"severity": "high"}]},
        }
    ]
)
def test_scanner_verdict_fails_closed(
    tool_results: list[dict[str, Any]],
) -> None:
    """Property: the verdict is safe only if the fail-closed policy permits it."""
    if _verdict(tool_results):
        assert _fail_closed_allows_safe(tool_results), (
            f"scanner reported safe for unclassifiable or unsafe output: {tool_results!r}"
        )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("severity", "expected_safe"),
    [
        pytest.param("high", False, id="high-is-unsafe"),
        pytest.param("low", True, id="low-is-safe"),
    ],
)
def test_scanner_verdict_known_severity(
    severity: str,
    expected_safe: bool,
) -> None:
    """Property: a single high finding is unsafe and a single low finding is safe."""
    tool_results = [
        {
            "tool_name": "t",
            "is_safe": True,
            "findings": {"yara_analyzer": {"severity": severity}},
        }
    ]
    assert _verdict(tool_results) is expected_safe
