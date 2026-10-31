"""Property tests that the skill and agent scanner verdicts fail closed.

The skill scanner and the A2A agent scanner each turn a CLI's stdout into a
safe or unsafe verdict that can gate registration. The security property is
fail-closed classification: a verdict is safe only when the output parses as a
scanner result, every finding carries a known severity below ``high``, no
finding or result reports ``is_safe: false`` and the scanner counted no high
finding. Unparseable, truncated or unclassifiable output, and a scan that asked
for the LLM analyzer when it cannot run, must yield unsafe.
"""

import asyncio
import json
import subprocess  # nosec B404 - only CompletedProcess is used, to mimic subprocess.run
from typing import Any
from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
)

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.services import scanner_llm_analyzer
from registry.services.agent_scanner import AgentScannerService
from registry.services.skill_scanner import SkillScannerService

KNOWN_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})
BLOCKING_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})
SEVERITY_CHOICES: tuple[Any, ...] = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "low",
    "High",
    "unknown",
    "",
    "CRITICAL ",
    "severe",
    None,
    3,
)
ANALYZER_NAMES: tuple[str, ...] = ("static", "behavioral", "yara", "spec")
UNKNOWN_FIELDS: tuple[str, ...] = ("scanner_version", "notes", "elapsed_ms")
PROSE_PHRASES: tuple[str, ...] = (
    "Scan complete. No issues found.",
    "Error: analyzer crashed",
    "Traceback (most recent call last):",
    "SAFE",
    "",
)
STDOUT_KINDS: tuple[str, ...] = (
    "json",
    "json_unknown_fields",
    "log_prefixed",
    "ansi",
    "truncated",
    "prose",
    "empty",
    "array",
    "scalar",
)
MISSING: Any = object()
# Output that is not a classifiable scanner result, as (id, stdout).
UNPARSEABLE_STDOUT: tuple[tuple[str, str], ...] = (
    ("empty", ""),
    ("newline", "\n"),
    ("prose", "Scan complete. No issues found."),
    ("truncated", '{"findings": [{"severity": "LOW"}'),
    ("json-null", "null"),
    ("json-true", "true"),
    ("json-string", '"safe"'),
    ("null-findings", '{"findings": null}'),
    ("null-severity", '{"findings": [{"severity": null}]}'),
    ("string-finding", '{"findings": ["HIGH"]}'),
)
AGENT_NON_OBJECT_IDS: frozenset[str] = frozenset({"json-null", "json-true", "json-string"})

SKILL_PATH: str = "/skills/demo"
SKILL_CONTENT_DIR: str = "/nonexistent/skill-content"
AGENT_PATH: str = "/weather-agent"
AGENT_CARD: dict[str, Any] = {
    "name": "Weather Agent",
    "description": "Answers questions about the weather.",
    "url": "https://agent.example.com/a2a",
    "path": AGENT_PATH,
}
SCAN_TIMEOUT_SECONDS: int = 5
USE_LLM_FLAG: str = "--use-llm"

PROPERTY_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_SKILL_VERDICT_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: the skill scanner verdict is safe whenever it counts no "
        "critical or high finding, so findings with a missing or unknown severity, "
        "is_safe false, or a non-list findings value pass as safe."
    ),
)
_AGENT_VERDICT_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: the agent scanner verdict is safe whenever it counts no "
        "critical or high finding, so findings with a missing or unknown severity, "
        "a non-list findings value, or a JSON array or scalar result pass as safe."
    ),
)
_AGENT_NON_OBJECT_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: the agent scanner ignores a JSON result that is not an "
        "object, so a scanner that prints null, true or a string is reported safe."
    ),
)
_LLM_FLAG_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: the skill scanner adds --use-llm only for a lower-case "
        "'llm' entry while the availability check matches 'llm' case-insensitively, "
        "so 'LLM' scans without the LLM analyzer."
    ),
)


def _make_skill_service() -> SkillScannerService:
    """Build a SkillScannerService whose scan repository is a mock.

    Returns:
        Skill scanner service that never touches a real repository.
    """
    service = SkillScannerService()
    service._scan_repo = MagicMock(create=AsyncMock(return_value=None))
    return service


def _make_agent_service() -> AgentScannerService:
    """Build an AgentScannerService whose scan repository is a mock.

    Returns:
        Agent scanner service that never touches a real repository.
    """
    with patch("registry.services.agent_scanner.get_security_scan_repository"):
        service = AgentScannerService()
    service._scan_repo = MagicMock(create=AsyncMock(return_value=None))
    return service


def _unparseable_params(
    xfail_ids: frozenset[str],
    mark: Any,
) -> list[Any]:
    """Build pytest params for output that is not a classifiable scanner result.

    Args:
        xfail_ids: Case ids that fail today and carry `mark`.
        mark: The xfail mark for those cases, or None when there are none.

    Returns:
        One pytest.param per entry of UNPARSEABLE_STDOUT.
    """
    return [
        pytest.param(stdout, id=case_id, marks=mark if case_id in xfail_ids else ())
        for case_id, stdout in UNPARSEABLE_STDOUT
    ]


def _completed(
    stdout: str,
    returncode: int = 0,
) -> subprocess.CompletedProcess:
    """Build the object subprocess.run returns for a mocked scanner CLI.

    Args:
        stdout: What the CLI printed.
        returncode: The CLI exit code.

    Returns:
        A CompletedProcess carrying the given output.
    """
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def _skill_scan(
    stdout: str,
    analyzers: str = "static",
):
    """Run scan_skill against a mocked skill-scanner CLI.

    Args:
        stdout: What the CLI printed.
        analyzers: The analyzers argument.

    Returns:
        The SkillSecurityScanResult.
    """
    service = _make_skill_service()
    with patch(
        "registry.services.skill_scanner.subprocess.run",
        return_value=_completed(stdout),
    ):
        return asyncio.run(
            service.scan_skill(
                skill_path=SKILL_PATH,
                skill_content_path=SKILL_CONTENT_DIR,
                analyzers=analyzers,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        )


def _agent_scan(
    stdout: str,
    returncode: int = 0,
    analyzers: str = "yara",
):
    """Run scan_agent against a mocked a2a-scanner CLI.

    Args:
        stdout: What the CLI printed.
        returncode: The CLI exit code.
        analyzers: The analyzers argument.

    Returns:
        The AgentSecurityScanResult.
    """
    service = _make_agent_service()
    with patch(
        "registry.services.agent_scanner.subprocess.run",
        return_value=_completed(stdout, returncode),
    ):
        return asyncio.run(
            service.scan_agent(
                agent_card=AGENT_CARD,
                agent_path=AGENT_PATH,
                analyzers=analyzers,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        )


def _finding_allows_safe(
    finding: Any,
) -> bool:
    """Return True when one finding is classified and below the blocking level.

    Args:
        finding: One finding from scanner output.

    Returns:
        True only for a dict whose string severity is known and below ``high``
        and which does not report ``is_safe: false``.
    """
    if not isinstance(finding, dict):
        return False
    if finding.get("is_safe", True) is False:
        return False
    severity = finding.get("severity")
    if not isinstance(severity, str):
        return False
    normalized = severity.lower()
    return normalized in KNOWN_SEVERITIES and normalized not in BLOCKING_SEVERITIES


def _document_allows_safe(
    document: Any,
) -> bool:
    """Return True when the fail-closed policy permits a safe verdict for a result.

    Args:
        document: The parsed scanner result.

    Returns:
        True only for an object that reports neither ``is_safe: false`` nor a
        positive ``high_severity_count``, whose findings (if present) are a
        list in which every finding allows a safe verdict.
    """
    if isinstance(document, list):
        return all(_finding_allows_safe(finding) for finding in document)
    if not isinstance(document, dict):
        return False
    if document.get("is_safe", True) is False:
        return False
    if document.get("high_severity_count", 0) != 0:
        return False
    findings = document.get("findings", [])
    if not isinstance(findings, list):
        return False
    return all(_finding_allows_safe(finding) for finding in findings)


@st.composite
def _finding(draw: st.DrawFn) -> Any:
    """Draw one finding: usually a dict with an optional severity and is_safe."""
    if draw(st.integers(min_value=0, max_value=9)) == 0:
        return draw(st.one_of(st.text(max_size=4), st.integers(), st.none()))
    finding: dict[str, Any] = {
        "analyzer": draw(st.sampled_from(ANALYZER_NAMES)),
        "threat_names": [],
    }
    severity = draw(st.sampled_from((*SEVERITY_CHOICES, MISSING)))
    if severity is not MISSING:
        finding["severity"] = severity
    is_safe = draw(st.sampled_from((True, False, MISSING)))
    if is_safe is not MISSING:
        finding["is_safe"] = is_safe
    return finding


@st.composite
def _document(draw: st.DrawFn) -> dict[str, Any]:
    """Draw a scanner result object with findings of any shape."""
    document: dict[str, Any] = {"scan_status": "completed"}
    findings = draw(
        st.one_of(
            st.lists(_finding(), max_size=4),
            st.sampled_from(({}, "", None, 0, MISSING)),
        )
    )
    if findings is not MISSING:
        document["findings"] = findings
    for key, choices in (("is_safe", (True, False)), ("high_severity_count", (0, 1))):
        value = draw(st.sampled_from((*choices, MISSING)))
        if value is not MISSING:
            document[key] = value
    return document


@st.composite
def _scanner_stdout(draw: st.DrawFn) -> tuple[str, bool]:
    """Draw scanner stdout and whether the fail-closed policy permits a safe verdict.

    Covers valid results, results with unknown fields, log lines or ANSI codes
    around the JSON, truncated JSON, prose, empty output, JSON arrays and JSON
    scalars.
    """
    kind = draw(st.sampled_from(STDOUT_KINDS))
    document = draw(_document())
    if kind == "json":
        return json.dumps(document), _document_allows_safe(document)
    if kind == "json_unknown_fields":
        extras = draw(st.dictionaries(st.sampled_from(UNKNOWN_FIELDS), st.text(max_size=4)))
        return json.dumps({**extras, **document}), _document_allows_safe(document)
    if kind == "log_prefixed":
        return "INFO scanning target\n" + json.dumps(document), _document_allows_safe(document)
    if kind == "ansi":
        return "\x1b[32m" + json.dumps(document) + "\x1b[0m", _document_allows_safe(document)
    if kind == "truncated":
        text = json.dumps(document)
        cut = draw(st.integers(min_value=0, max_value=len(text) - 1))
        return text[:cut], False
    if kind == "prose":
        tail = draw(st.text(alphabet="abc .:", max_size=12))
        return draw(st.sampled_from(PROSE_PHRASES)) + tail, False
    if kind == "empty":
        return draw(st.sampled_from(("", " ", "\n", "\n\n"))), False
    if kind == "array":
        findings = draw(st.lists(_finding(), max_size=3))
        return json.dumps(findings), _document_allows_safe(findings)
    scalar = draw(st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=6)))
    return json.dumps(scalar), False


# ---------------------------------------------------------------------------
# Skill scanner
# ---------------------------------------------------------------------------


@pytest.mark.unit
@_SKILL_VERDICT_XFAIL
@PROPERTY_SETTINGS
@given(case=_scanner_stdout())
@example(case=('{"findings": [{"analyzer": "static", "threat_names": []}]}', False))
@example(case=('{"is_safe": false, "findings": []}', False))
@example(case=('{"findings": [{"severity": "LOW", "is_safe": false}]}', False))
@example(case=('{"findings": {}}', False))
def test_skill_scanner_verdict_fails_closed(
    case: tuple[str, bool],
) -> None:
    """Property: the skill verdict is safe only if the fail-closed policy permits it."""
    stdout, allows_safe = case
    result = _skill_scan(stdout)
    if result.is_safe:
        assert allows_safe, f"skill scanner reported safe for {stdout!r}"


@pytest.mark.unit
@pytest.mark.parametrize("stdout", _unparseable_params(frozenset(), None))
def test_skill_scanner_unparseable_output_is_unsafe(
    stdout: str,
) -> None:
    """Property: output the skill scanner cannot parse as a result is never safe."""
    assert _skill_scan(stdout).is_safe is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("severity", "expected_safe"),
    [
        pytest.param("HIGH", False, id="high-is-unsafe"),
        pytest.param("critical", False, id="critical-is-unsafe"),
        pytest.param("LOW", True, id="low-is-safe"),
    ],
)
def test_skill_scanner_known_severity(
    severity: str,
    expected_safe: bool,
) -> None:
    """Property: a single high finding is unsafe and a single low finding is safe."""
    stdout = json.dumps({"findings": [{"analyzer": "static", "severity": severity}]})
    assert _skill_scan(stdout).is_safe is expected_safe


# ---------------------------------------------------------------------------
# Agent scanner
# ---------------------------------------------------------------------------


@pytest.mark.unit
@_AGENT_VERDICT_XFAIL
@PROPERTY_SETTINGS
@given(case=_scanner_stdout(), returncode=st.sampled_from((0, 1)))
@example(case=('[{"analyzer": "yara", "severity": "HIGH"}]', False), returncode=0)
@example(case=('{"findings": [{"analyzer": "yara"}]}', False), returncode=0)
@example(case=('{"findings": [{"analyzer": "yara", "severity": "severe"}]}', False), returncode=0)
def test_agent_scanner_verdict_fails_closed(
    case: tuple[str, bool],
    returncode: int,
) -> None:
    """Property: the agent verdict is safe only if the fail-closed policy permits it."""
    stdout, allows_safe = case
    result = _agent_scan(stdout, returncode)
    if result.is_safe:
        assert allows_safe, f"agent scanner reported safe for {stdout!r} (exit {returncode})"


@pytest.mark.unit
@pytest.mark.parametrize(
    "stdout",
    _unparseable_params(AGENT_NON_OBJECT_IDS, _AGENT_NON_OBJECT_XFAIL),
)
def test_agent_scanner_unparseable_output_is_unsafe(
    stdout: str,
) -> None:
    """Property: output the agent scanner cannot parse as a result is never safe."""
    assert _agent_scan(stdout).is_safe is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("severity", "expected_safe"),
    [
        pytest.param("HIGH", False, id="high-is-unsafe"),
        pytest.param("critical", False, id="critical-is-unsafe"),
        pytest.param("LOW", True, id="low-is-safe"),
    ],
)
def test_agent_scanner_known_severity(
    severity: str,
    expected_safe: bool,
) -> None:
    """Property: a single high finding is unsafe and a single low finding is safe."""
    stdout = json.dumps({"findings": [{"analyzer": "yara", "severity": severity}]})
    assert _agent_scan(stdout).is_safe is expected_safe


# ---------------------------------------------------------------------------
# LLM analyzer availability
# ---------------------------------------------------------------------------

_ANALYZER_LISTS = st.lists(
    st.sampled_from(("static", "yara", "llm", "LLM", " llm ", "Llm", "llm2", "l lm", "")),
    min_size=1,
    max_size=4,
).map(",".join)


def _reference_requests_llm(
    analyzers: str,
) -> bool:
    """Return True when an analyzer list names the LLM analyzer.

    Entries are compared after trimming whitespace and ignoring case.

    Args:
        analyzers: Comma-separated analyzer list.

    Returns:
        Whether any entry is "llm".
    """
    return any(entry.strip().lower() == "llm" for entry in analyzers.split(","))


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(analyzers=_ANALYZER_LISTS)
@example(analyzers=" LLM ")
def test_scan_requesting_unavailable_llm_analyzer_is_unsafe(
    analyzers: str,
) -> None:
    """Property: with LiteLLM absent, a scan that names the LLM analyzer is a failed, unsafe scan.

    A scan that does not name it is unaffected by LiteLLM's absence.
    """
    clean = json.dumps({"findings": []})
    with patch.object(scanner_llm_analyzer, "_litellm_installed", return_value=False):
        skill_result = _skill_scan(clean, analyzers=analyzers)
        agent_result = _agent_scan(clean, analyzers=analyzers)

    if _reference_requests_llm(analyzers):
        for result in (skill_result, agent_result):
            assert result.is_safe is False
            assert result.scan_failed is True
    else:
        assert skill_result.scan_failed is False
        assert agent_result.scan_failed is False


@pytest.mark.unit
@pytest.mark.parametrize(
    "analyzers",
    [
        pytest.param("static", id="no-llm"),
        pytest.param("llm", id="llm"),
        pytest.param("static, llm ", id="llm-with-whitespace"),
        pytest.param("static,LLM", id="upper-case-llm", marks=_LLM_FLAG_XFAIL),
        pytest.param("Llm", id="mixed-case-llm", marks=_LLM_FLAG_XFAIL),
    ],
)
def test_skill_scanner_runs_llm_analyzer_when_requested(
    analyzers: str,
) -> None:
    """Property: skill-scanner gets --use-llm exactly when the availability check sees 'llm'."""
    commands: list[list[str]] = []

    def _run(cmd, *args, **kwargs):
        commands.append(list(cmd))
        return _completed(json.dumps({"findings": []}))

    service = _make_skill_service()
    with patch("registry.services.skill_scanner.subprocess.run", side_effect=_run):
        service._run_skill_scanner(
            skill_path=SKILL_PATH,
            skill_content_path=SKILL_CONTENT_DIR,
            analyzers=analyzers,
            timeout=SCAN_TIMEOUT_SECONDS,
        )

    assert len(commands) == 1
    requested = scanner_llm_analyzer._requests_llm_analyzer(analyzers)
    assert (USE_LLM_FLAG in commands[0]) is requested, (
        f"analyzers={analyzers!r}: llm requested={requested}, command={commands[0]}"
    )
