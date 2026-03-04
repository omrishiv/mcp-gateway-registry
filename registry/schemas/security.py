"""
Security schema models for MCP server scanning.

This module defines Pydantic models for security scan results, configurations,
and related data structures used throughout the security scanning workflow.
"""


from pydantic import Field

from common.models.security import (
    BaseScanAnalyzerResult,
    BaseScanConfig,
    BaseScanFinding,
    BaseScanResult,
    BaseSecurityStatus,
)


class SecurityScanFinding(BaseScanFinding):
    """Individual security finding from a scanner."""

    tool_name: str = Field(..., description="Name of the tool that was scanned")


class SecurityScanAnalyzerResult(BaseScanAnalyzerResult):
    """Results from a specific security analyzer."""

    findings: list[SecurityScanFinding] = Field(
        default_factory=list, description="List of findings from this analyzer"
    )


class SecurityScanResult(BaseScanResult):
    """Complete security scan result for an MCP server."""

    server_url: str = Field(..., description="URL of the scanned MCP server")
    server_path: str = Field(..., description="Registry path of the MCP server (e.g., /context7)")


class SecurityScanConfig(BaseScanConfig):
    """Configuration for security scanning."""

    block_unsafe_servers: bool = Field(
        default=True, description="Disable servers that fail security scan"
    )


class ServerSecurityStatus(BaseSecurityStatus):
    """Security status summary for a server."""

    server_path: str = Field(..., description="Server path (e.g., /mcpgw)")
    server_name: str = Field(..., description="Display name of the server")
