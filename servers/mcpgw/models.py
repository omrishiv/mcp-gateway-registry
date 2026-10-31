"""Pydantic models for mcpgw MCP server.

These models define the data structures returned by the registry API
and used by the MCP tools.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field


class ServerInfo(BaseModel):
    """Information about a registered MCP server."""

    model_config = {"populate_by_name": True}

    server_name: str | None = Field(
        None, alias="display_name", description="Display name of the server"
    )
    path: str = Field(..., description="URL path for the server (e.g., '/currenttime')")
    description: str | None = Field(None, description="Server description")
    enabled: bool = Field(..., alias="is_enabled", description="Whether the server is enabled")
    tags: list[str] = Field(default_factory=list, description="Server tags")
    tool_count: int | None = Field(None, alias="num_tools", description="Number of tools provided")
    metadata: dict[str, Any] | None = Field(
        None,
        description=(
            "Free-form metadata the registrant attached to the server, e.g. ownership "
            "or provenance. Null unless the caller names the keys to return with "
            "metadata_fields"
        ),
    )


class AgentInfo(BaseModel):
    """Information about a registered agent."""

    name: str | None = Field(None, description="Name of the agent")
    description: str | None = Field(None, description="Agent description")
    tags: list[str] = Field(default_factory=list, description="Agent tags")
    created_at: str | None = Field(None, description="Creation timestamp")
    path: str | None = Field(None, description="Registered agent path; pass to invoke_agent")
    url: str | None = Field(None, description="Advertised agent URL")
    supported_protocol: str | None = Field(
        None, description="'a2a' for agents invoke_agent can call"
    )
    metadata: dict[str, Any] | None = Field(
        None, description="Free-form metadata the registrant attached to the agent"
    )


class SkillInfo(BaseModel):
    """Information about a registered skill."""

    path: str = Field(..., description="Skill path")
    name: str | None = Field(None, description="Name of the skill")
    description: str | None = Field(None, description="Skill description")
    skill_md_url: str | None = Field(None, description="URL to the SKILL.md file")
    skill_md_raw_url: str | None = Field(None, description="Raw URL for fetching SKILL.md content")
    tags: list[str] = Field(default_factory=list, description="Skill tags")
    target_agents: list[str] = Field(default_factory=list, description="Target agent platforms")
    created_at: str | None = Field(None, description="Creation timestamp")
    health_status: str | None = Field(
        None,
        description="Result of the last SKILL.md reachability check: healthy, unhealthy, or unknown",
    )
    last_checked_time: str | None = Field(
        None, description="When the registry last observed SKILL.md reachability"
    )
    metadata: dict[str, Any] | None = Field(
        None,
        description=(
            "Skill metadata: author, version, and any free-form keys under extra, "
            "e.g. ownership or provenance"
        ),
    )


class ToolSearchResult(BaseModel):
    """Search result for semantic tool search."""

    model_config = {"populate_by_name": True}

    tool_name: str = Field(..., description="Name of the tool")
    server_name: str = Field(..., description="Server providing the tool")
    description: str | None = Field(None, description="Tool description")
    score: float | None = Field(None, description="Relevance score (0-1)")
    path: str | None = Field(None, description="Server path")
    input_schema: dict[str, Any] | None = Field(
        None,
        alias="inputSchema",
        serialization_alias="inputSchema",
        description="JSON Schema for the tool's arguments; pass to invoke_mcp_tool",
    )


class AgentPart(BaseModel):
    """One data or file part of an A2A message/task result.

    Text parts are not modeled here: invoke_agent assembles them into
    AgentInvocationResult.text directly (see a2a_dialects.py). Inline file
    bytes are never carried: only name, MIME type and URI are kept.
    """

    kind: Literal["data", "file"]
    data: dict[str, Any] | None = None
    name: str | None = None
    mime_type: str | None = None
    uri: str | None = None


class AgentInvocationResult(BaseModel):
    """Result of invoke_agent or get_agent_task.

    status is "success" (a message, or a task in a terminal/interrupted
    state -- a task that is itself "failed" is still a successful call, see
    `state`), "pending" (still running at the deadline; poll again with
    get_agent_task using task_id), or "failed" (no usable result; see error).
    """

    status: Literal["success", "pending", "failed"]
    agent_path: str
    protocol_version: Literal["0.3", "1.0"] | None = None
    message_id: str | None = None
    task_id: str | None = None
    context_id: str | None = None
    state: str | None = None
    text: str = ""
    data_parts: list[AgentPart] = Field(default_factory=list)
    file_parts: list[AgentPart] = Field(default_factory=list)
    error: str | None = None


class RegistryStats(BaseModel):
    """Registry statistics and health information.

    Accepts any fields from the health endpoint response.
    """

    class Config:
        extra = "allow"


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str = Field(..., description="Error message")
    status: str = Field(default="failed", description="Status indicator")
    details: dict | None = Field(None, description="Additional error details")
