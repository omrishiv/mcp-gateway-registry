"""Shared search response models used across agents, API client, and registry.

Provides canonical Pydantic models for semantic search results. Server-side
code (registry/api/search_routes.py) extends these with deployment-specific
fields like endpoint_url and proxy_pass_url.
"""

from typing import Any

from pydantic import BaseModel, Field


class MatchingTool(BaseModel):
    """Tool matching result from semantic search."""

    tool_name: str = Field(..., description="Name of the matching tool")
    description: str | None = Field(None, description="Tool description")
    relevance_score: float = Field(0.0, ge=0.0, le=1.0, description="Relevance score")
    match_context: str | None = Field(None, description="Match context")
    inputSchema: dict[str, Any] | None = Field(
        None, description="JSON Schema for tool input parameters"
    )


class ServerSearchResult(BaseModel):
    """MCP Server search result from semantic search."""

    path: str = Field(..., description="Server path in registry")
    server_name: str = Field(..., description="Server name")
    description: str | None = Field(None, description="Server description")
    tags: list[str] = Field(default_factory=list, description="Server tags")
    num_tools: int = Field(0, description="Number of tools")
    is_enabled: bool = Field(False, description="Whether server is enabled")
    relevance_score: float = Field(0.0, ge=0.0, le=1.0, description="Relevance score")
    match_context: str | None = Field(None, description="Match context")
    matching_tools: list[MatchingTool] = Field(
        default_factory=list, description="Tools matching the query"
    )


class ToolSearchResult(BaseModel):
    """Tool search result from semantic search."""

    server_path: str = Field(..., description="Server path in registry")
    server_name: str = Field(..., description="Server name")
    tool_name: str = Field(..., description="Tool name")
    description: str | None = Field(None, description="Tool description")
    inputSchema: dict[str, Any] | None = Field(None, description="JSON Schema for tool input")
    relevance_score: float = Field(0.0, ge=0.0, le=1.0, description="Relevance score")
    match_context: str | None = Field(None, description="Match context")


class SearchResponse(BaseModel):
    """Response from semantic search API."""

    query: str = Field(..., description="Original query")
    servers: list[ServerSearchResult] = Field(default_factory=list, description="Matching servers")
    tools: list[ToolSearchResult] = Field(default_factory=list, description="Matching tools")
    total_servers: int = Field(0, description="Total matching servers")
    total_tools: int = Field(0, description="Total matching tools")
