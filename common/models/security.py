"""Base security scan models shared across MCP server, agent, and skill scanning.

These base models capture the common fields used across all three security scan
hierarchies (server, agent, skill), reducing duplication while allowing each
domain to extend with its own specific fields.
"""

from pydantic import BaseModel, Field


class BaseScanFinding(BaseModel):
    """Base class for individual security findings from any scanner."""

    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, SAFE")
    threat_names: list[str] = Field(
        default_factory=list, description="List of detected threat names"
    )
    threat_summary: str = Field(default="", description="Summary of threats found")
    is_safe: bool = Field(..., description="Whether the component is considered safe")


class BaseScanAnalyzerResult(BaseModel):
    """Base class for results from a specific security analyzer.

    Subclasses should override the ``findings`` field with a typed list
    of their domain-specific finding class.
    """

    analyzer_name: str = Field(..., description="Name of the analyzer")


class BaseScanResult(BaseModel):
    """Base class for complete security scan results."""

    scan_timestamp: str = Field(..., description="ISO timestamp of the scan")
    is_safe: bool = Field(..., description="Overall safety assessment")
    critical_issues: int = Field(default=0, description="Count of critical severity issues")
    high_severity: int = Field(default=0, description="Count of high severity issues")
    medium_severity: int = Field(default=0, description="Count of medium severity issues")
    low_severity: int = Field(default=0, description="Count of low severity issues")
    analyzers_used: list[str] = Field(
        default_factory=list, description="List of analyzers used in scan"
    )
    raw_output: dict = Field(default_factory=dict, description="Full scanner output")
    output_file: str | None = Field(None, description="Path to detailed JSON output file")
    scan_failed: bool = Field(default=False, description="Whether the scan failed to complete")
    error_message: str | None = Field(None, description="Error message if scan failed")


class BaseScanConfig(BaseModel):
    """Base class for security scanning configuration."""

    enabled: bool = Field(default=True, description="Enable/disable security scanning")
    scan_on_registration: bool = Field(
        default=True, description="Scan during registration"
    )
    analyzers: str = Field(default="yara", description="Comma-separated list of analyzers to use")
    scan_timeout_seconds: int = Field(
        default=300, description="Timeout for security scans in seconds"
    )
    llm_api_key: str | None = Field(None, description="API key for LLM-based analysis")
    add_security_pending_tag: bool = Field(
        default=True, description="Add 'security-pending' tag to unsafe items"
    )


class BaseSecurityStatus(BaseModel):
    """Base class for security status summaries."""

    is_safe: bool = Field(..., description="Whether the item passed security scan")
    last_scan_timestamp: str | None = Field(None, description="ISO timestamp of last scan")
    critical_issues: int = Field(default=0, description="Count of critical issues")
    high_severity: int = Field(default=0, description="Count of high severity issues")
    scan_status: str = Field(default="pending", description="Status: pending, completed, failed")
    is_disabled_for_security: bool = Field(
        default=False, description="Whether item is disabled due to security issues"
    )
