"""Fail-closed classification of security scanner output.

The MCP, skill and A2A agent scanners each turn a CLI's JSON output into a
safe or unsafe verdict that can gate registration. The verdict is safe only
when the output has the expected shape, every finding carries a known severity
below ``high`` and nothing in the output reports ``is_safe: false``. Anything
the registry cannot classify (a missing, misspelled or non-string severity, a
finding that is not an object, an unexpected container type) is unsafe.
"""

from typing import Any

BLOCKING_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})
# "info" and "safe" are emitted by the Cisco scanners for findings that carry
# no risk (mcp-scanner reports "SAFE" for an analyzer that found nothing).
NON_BLOCKING_SEVERITIES: frozenset[str] = frozenset({"medium", "low", "info", "safe"})


def classify_severity(
    value: Any,
) -> str | None:
    """Return the lower-case severity when it is a known level, else None.

    Args:
        value: The severity value a scanner reported.

    Returns:
        A member of BLOCKING_SEVERITIES or NON_BLOCKING_SEVERITIES, or None
        for anything else (non-strings, unknown or misspelled levels).
    """
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    if normalized in BLOCKING_SEVERITIES or normalized in NON_BLOCKING_SEVERITIES:
        return normalized
    return None


def _reports_unsafe(
    record: dict,
) -> bool:
    """Return True when a record carries an ``is_safe`` value other than True."""
    return "is_safe" in record and record["is_safe"] is not True


def finding_allows_safe(
    finding: Any,
) -> bool:
    """Return True when one finding is classified and below the blocking level.

    Args:
        finding: One finding from scanner output.

    Returns:
        True only for a dict whose severity is a known non-blocking level and
        which does not report ``is_safe`` as anything but True.
    """
    if not isinstance(finding, dict):
        return False
    if _reports_unsafe(finding):
        return False
    return classify_severity(finding.get("severity")) in NON_BLOCKING_SEVERITIES


def result_document_allows_safe(
    document: Any,
) -> bool:
    """Return True when a skill or A2A scanner result document permits a safe verdict.

    Args:
        document: The JSON object the scanner printed.

    Returns:
        True only for a dict that does not report ``is_safe`` as anything but
        True, whose ``high_severity_count`` (when present) is the integer 0, and
        whose ``findings`` (when present) is a list in which every finding
        allows a safe verdict.
    """
    if not isinstance(document, dict):
        return False
    if _reports_unsafe(document):
        return False
    if "high_severity_count" in document:
        count = document["high_severity_count"]
        if isinstance(count, bool) or not isinstance(count, int) or count != 0:
            return False
    findings = document.get("findings", [])
    if not isinstance(findings, list):
        return False
    return all(finding_allows_safe(finding) for finding in findings)


def mcp_tool_results_allow_safe(
    tool_results: Any,
) -> bool:
    """Return True when mcp-scanner tool results permit a safe verdict.

    Args:
        tool_results: The parsed list of per-tool results mcp-scanner printed.

    Returns:
        True only for a list of dicts in which no tool reports ``is_safe`` as
        anything but True, and each tool's ``findings`` (when present) maps
        analyzer names to finding dicts that allow a safe verdict.
    """
    if not isinstance(tool_results, list):
        return False
    for tool_result in tool_results:
        if not isinstance(tool_result, dict):
            return False
        if _reports_unsafe(tool_result):
            return False
        findings = tool_result.get("findings", {})
        if not isinstance(findings, dict):
            return False
        if not all(finding_allows_safe(finding) for finding in findings.values()):
            return False
    return True
