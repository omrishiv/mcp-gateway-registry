"""
Skill security schema models for skill-scanner integration.

This module defines Pydantic models for skill security scan results, configurations,
and related data structures used throughout the skill security scanning workflow.
"""

from pydantic import Field

from common.models.security import (
    BaseScanConfig,
    BaseScanFinding,
    BaseScanResult,
    BaseSecurityStatus,
)


class SkillSecurityScanFinding(BaseScanFinding):
    """Individual security finding from skill scanner."""

    file_path: str | None = Field(None, description="File where finding was detected")
    line_number: int | None = Field(None, description="Line number of finding")
    analyzer: str = Field(
        ...,
        description="Analyzer that detected the finding: static, behavioral, llm, meta, virustotal, ai-defense",
    )


class SkillSecurityScanResult(BaseScanResult):
    """Complete security scan result for a skill."""

    skill_path: str = Field(..., description="Path of the scanned skill")
    skill_md_url: str | None = Field(None, description="URL to SKILL.md")


class SkillSecurityScanConfig(BaseScanConfig):
    """Configuration for skill security scanning."""

    block_unsafe_skills: bool = Field(
        default=True, description="Disable skills that fail security scan"
    )
    analyzers: str = Field(default="static", description="Comma-separated list of analyzers to use")
    scan_timeout_seconds: int = Field(
        default=120, description="Timeout for security scans in seconds"
    )
    virustotal_api_key: str | None = Field(None, description="API key for VirusTotal integration")
    ai_defense_api_key: str | None = Field(None, description="API key for Cisco AI Defense")


class SkillSecurityStatus(BaseSecurityStatus):
    """Security status summary for a skill."""

    skill_path: str = Field(..., description="Skill path (e.g., /pdf-processing)")
    skill_name: str = Field(..., description="Display name of the skill")
