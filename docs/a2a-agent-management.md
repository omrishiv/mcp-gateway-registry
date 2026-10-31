# A2A Agent Management Guide

> **This guide has been merged into the single [A2A Protocol Support](a2a.md) document.**
>
> A2A registration, the CRUD and discovery APIs (CLI and `curl`), access control / invoke roles, and reverse-proxy routing now all live in one place:
>
> - [Getting Started (token, register an agent)](a2a.md#getting-started)
> - [CRUD and Discovery APIs](a2a.md#crud-and-discovery-apis)
> - [Access Control](a2a.md#access-control)
> - [Reverse-Proxy Mode](a2a.md#reverse-proxy-mode-routing-a2a-traffic-through-the-gateway)
> - [Invoking Agents from an MCP-Only Client](a2a.md#invoking-agents-from-an-mcp-only-client)
>
> A registered, enabled agent with reverse-proxy routing on becomes
> reachable through `invoke_agent` as soon as an operator turns on
> `MCPGW_INVOKE_TOOLS_ENABLED`. There is no separate registration step for
> this access path.
>
> For Keycloak service-account and M2M details, see [Keycloak: Agent M2M & Operations Guide](keycloak-agent-m2m.md).
