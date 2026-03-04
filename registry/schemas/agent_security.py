"""
Agent security schema models for A2A scanner integration.

This module defines Pydantic models for agent security scan results, configurations,
and related data structures used throughout the A2A security scanning workflow.
"""


from pydantic import Field

from common.models.security import (
    BaseScanAnalyzerResult,
    BaseScanConfig,
    BaseScanFinding,
    BaseScanResult,
    BaseSecurityStatus,
)


class AgentSecurityScanFinding(BaseScanFinding):
    """Individual security finding from A2A scanner."""

    skill_name: str | None = Field(
        None, description="Name of the skill that was scanned (if applicable)"
    )
    agent_component: str = Field(
        "agent_card", description="Component scanned: agent_card, skill, endpoint"
    )


class AgentSecurityScanAnalyzerResult(BaseScanAnalyzerResult):
    """Results from a specific A2A security analyzer."""

    findings: list[AgentSecurityScanFinding] = Field(
        default_factory=list, description="List of findings from this analyzer"
    )


class AgentSecurityScanResult(BaseScanResult):
    """Complete security scan result for an A2A agent."""

    agent_path: str = Field(..., description="Path of the scanned agent")
    agent_url: str | None = Field(None, description="URL of the scanned agent endpoint")


class AgentSecurityScanConfig(BaseScanConfig):
    """Configuration for A2A agent security scanning."""

    block_unsafe_agents: bool = Field(
        default=True, description="Disable agents that fail security scan"
    )
    analyzers: str = Field(
        default="yara,spec", description="Comma-separated list of analyzers to use"
    )


class AgentSecurityStatus(BaseSecurityStatus):
    """Security status summary for an agent."""

    agent_path: str = Field(..., description="Agent path (e.g., /code-reviewer)")
    agent_name: str = Field(..., description="Display name of the agent")
