# AI Registry Tools

An MCP server that provides AI agents with tools to discover and query MCP servers, tools, agents, and skills registered in the MCP Gateway Registry.

See the [What's New section](../README.md#whats-new) in the main README for the latest updates and features.

## What This Server Does

**AI Registry Tools** gives your AI coding assistants the ability to:
- **Search for MCP tools** using natural language queries
- **List all available MCP servers** in the registry
- **Discover AI agents** that can help with specific tasks
- **Find skills** (like Claude Code skills) available in the ecosystem
- **Check registry health** and statistics

This server is **automatically registered** in the MCP Gateway Registry and ready to use.

## Adding to Your AI Agent

To use AI Registry Tools with your coding assistant (Claude Code, Roo Code, Cline, etc.):

1. **Navigate to the registry web UI** at your registry URL
2. **Find the AI Registry Tools server card** in the servers list
3. **Click the gear icon** on the server card
4. **Follow the configuration instructions** to add it to your AI agent

The gear icon will provide ready-to-use configuration snippets for popular AI coding assistants.

## Available Tools

### intelligent_tool_finder

Search for MCP tools using natural language semantic search.

**Parameters:**
- `query` (string, required) - Natural language description of what you want to do
- `top_n` (integer, optional) - Number of results to return (default: 5, max: 100)

**Returns:**
```typescript
{
  results: Array<{
    tool_name: string;          // Name of the tool
    server_name: string;         // Server providing the tool
    description: string | null;  // Tool description
    score: number | null;        // Relevance score (0-1)
    path: string | null;         // Server path
  }>;
  query: string;                 // Your search query
  total_results: number;         // Number of results found
  status: "success" | "failed";
}
```

**Example Query:** "find tools to help me work with databases"

---

### list_services

List all MCP servers registered in the gateway.

**Parameters:** None

**Returns:**
```typescript
{
  services: Array<{
    server_name: string | null;  // Display name of the server
    path: string;                // URL path (e.g., '/weather-api')
    description: string | null;   // Server description
    enabled: boolean;            // Whether server is active
    tags: string[];              // Server tags
    tool_count: number | null;   // Number of tools provided
  }>;
  total_count: number;           // Total servers
  enabled_count: number;         // Number of enabled servers
  status: "success" | "failed";
}
```

---

### list_agents

List all AI agents registered in the gateway.

**Parameters:** None

**Returns:**
```typescript
{
  agents: Array<{
    name: string | null;         // Agent name
    description: string | null;  // Agent description
    tags: string[];              // Agent tags
    created_at: string | null;   // ISO timestamp
  }>;
  total_count: number;           // Total agents
  status: "success" | "failed";
}
```

---

### list_skills

List all skills (Claude Code skills, etc.) registered in the gateway.

**Parameters:** None

**Returns:**
```typescript
{
  skills: Array<{
    path: string;                // Skill path
    name: string | null;         // Skill name
    description: string | null;  // Skill description
    tags: string[];              // Skill tags
    created_at: string | null;   // ISO timestamp
  }>;
  total_count: number;           // Total skills
  status: "success" | "failed";
}
```

---

### healthcheck

Get registry health status and statistics.

**Parameters:** None

**Returns:**
```typescript
{
  // Dynamic fields from registry health endpoint
  // May include: total_servers, enabled_servers,
  // total_tools, uptime, version, etc.
  [key: string]: any;
  status: "success" | "failed";
}
```

---

### invoke_mcp_tool

*Exists only when `MCPGW_INVOKE_TOOLS_ENABLED=true`.*

Calls a tool on a registered MCP server or virtual server, as you. Find
`server_path`, `tool_name`, and the tool's `inputSchema` with
`search_registry` or `intelligent_tool_finder` first.

**Parameters:**
- `server_path` (string, required) - The server's path, such as `/context7`, or a virtual server path such as `/virtual/dev-tools`
- `tool_name` (string, required) - The tool's name as listed for that server
- `arguments` (object, optional) - Arguments matching the tool's `inputSchema`

**Returns:**
```typescript
{
  content: Array<{ type: string; [key: string]: any }>;  // The backend tool's content blocks
  structuredContent?: object;                              // The backend tool's structured result, if present
  isError: boolean;                                         // True when the backend tool itself reported an error
}
```

A result over 1 MiB comes back as an error naming the limit, not the
backend's content. The backend's own `_meta` field never comes through: it
carries registrant-controlled data outside the tool contract, and relaying
it could hand UI resource pointers or similar controls to a client that
did not expect them.

---

### invoke_agent

*Exists only when `MCPGW_INVOKE_TOOLS_ENABLED=true`.*

Sends a message to a registered A2A agent, as you, through the registry's
A2A reverse-proxy route. The call returns as soon as it can: with a
finished result, or with `status: "pending"` if the agent is still working.

**Parameters:**
- `agent_path` (string, required) - The agent's registered path, such as `/flight-booking`, from `list_agents` or `search_registry`
- `message` (string, required) - Text sent as one part, at most 32,000 characters
- `context_id` (string, optional) - A context id from an earlier result, to continue a conversation
- `task_id` (string, optional) - A task id, to answer an agent that returned `input-required`
- `message_id` (string, optional) - The `message_id` from an earlier result, to retry a send whose outcome was unclear; mcpgw generates one when you omit it
- `protocol_version` (string, optional) - `0.3` or `1.0`; pass back the value from an earlier result so a follow-up call uses the same A2A version as the task it refers to

**Returns:**
```typescript
{
  status: "success" | "pending" | "failed";
  task_id?: string;          // Present once the agent creates a task
  context_id?: string;
  message_id: string;        // The message_id you sent, or the one mcpgw generated
  protocol_version: string;  // The A2A version used for this call
  state?: string;             // Task state, when status is "success" or "pending"
  text?: string;               // Text assembled from the agent's reply
  data_parts?: any[];         // Structured data parts from the agent's reply
  error?: string;              // Present when status is "failed"
}
```

On `status: "pending"`, call `get_agent_task` with the returned `task_id`.
If a send's outcome was unclear, retry it with the same `message_id`; an
agent that deduplicates by `message_id` treats the retry as the original
send.

---

### get_agent_task

*Exists only when `MCPGW_INVOKE_TOOLS_ENABLED=true`.*

Polls a task that `invoke_agent` returned as `pending`.

**Parameters:**
- `agent_path` (string, required) - The same agent path passed to `invoke_agent`
- `task_id` (string, required) - The task id from an `invoke_agent` result
- `protocol_version` (string, optional) - The protocol version from an earlier result

**Returns:** The same shape as `invoke_agent`.

## Use Cases

### For AI Coding Assistants

**Discover new capabilities:**
```
You: "What tools are available for working with AWS?"
AI: *calls intelligent_tool_finder(query="AWS tools")*
AI: "I found 12 AWS-related tools including aws-kb for documentation,
     aws-bedrock for AI models, and cloudformation for infrastructure..."
```

**Check what's available:**
```
You: "Show me all MCP servers in the registry"
AI: *calls list_services()*
AI: "There are 47 MCP servers registered, including weather-api,
     github-mcp, slack-tools, and more..."
```

**Find specialized agents:**
```
You: "Are there any agents that can help with travel planning?"
AI: *calls list_agents()*
AI: "Yes, there's a travel-assistant-agent that can help with
     flight bookings, hotel searches, and itinerary planning."
```

### For Development Workflows

- **Tool discovery during development** - Find the right MCP tool before building custom solutions
- **Registry exploration** - Understand what's available in your organization's MCP ecosystem
- **Integration planning** - Identify which servers and tools to integrate into your projects
- **Capability mapping** - Map business requirements to available MCP tools

## Authentication

Every tool call runs as you, not as a shared service account. AI Registry
Tools (mcpgw) carries no credential of its own: it reads the bearer token
your AI agent sent and forwards exactly that token to the registry API, so
the registry applies your own grants, audit, and rate limits to every call
it makes on your behalf.

**How authentication works:**
1. Your AI agent includes an `Authorization: Bearer <token>` header with each request.
2. AI Registry Tools forwards that same token to the registry as your identity, never as a static token or a machine-to-machine credential.
3. The registry checks your token's grants for the resource you asked about and returns the requested data, or denies it.

**Grants you need:**

Your scope needs:
- `ui_permissions.list_service` naming `"all"` or the servers `list_services` should list.
- `ui_permissions.list_agents` naming `"all"` or the agents `list_agents` should list.
- `ui_permissions.list_skills` naming `"all"` or the skills `list_skills` should list.
- A `server_access` rule naming each MCP server or agent you want `search_registry`, `intelligent_tool_finder`, `get_skill_content`, or `healthcheck` to reach.

See [`cli/examples/public-mcp-users.json`](../cli/examples/public-mcp-users.json)
for a worked scope: it grants all three `ui_permissions` plus `server_access`
rules for two MCP servers and an agent.

**If you see authentication errors:**
- Verify your token is valid and not expired.
- Check that your scope's `ui_permissions`/`server_access` names the resource you asked for.
- mcpgw refuses every call while the registry runs with `OIDC_ENABLED=true`: it cannot yet act on your behalf in that mode (tracked in issue #895).
- Contact your registry administrator if issues persist.

## Network

Reaching mcpgw directly, bypassing nginx and the gateway's own authorization,
is restricted on every supported surface, because mcpgw trusts that nginx
and the auth server have already checked the caller:

- **ECS:** the mcpgw security group admits inbound traffic only from the
  auth server and the registry, on port 8003.
- **Helm:** a `NetworkPolicy` in `charts/mcpgw/templates/` admits only the
  auth server and the registry pods to mcpgw's application port. This takes
  effect only where the cluster enforces `NetworkPolicy` resources at all:
  EKS needs the VPC CNI's network policy agent (or an equivalent CNI such as
  Calico) turned on, or the policy is accepted but never enforced.
- **Compose:** mcpgw runs on its own Docker network, shared only with the
  services it needs to reach and be reached by; its container port is no
  longer published to the host.

### Local debugging

To reach mcpgw directly while developing (for example, to call a tool with
`curl` without going through nginx), republish its port. Add a
`docker-compose.override.yml` next to `docker-compose.yml`:

```yaml
services:
  mcpgw-server:
    ports:
      - "127.0.0.1:8003:8003"
```

Compose merges override files automatically, so `docker compose up` picks
this up with no extra flag. Keep the bind on `127.0.0.1`: a LAN-wide bind
reopens the same direct-access hole the network isolation closes.

## Enabling the invocation tools

`invoke_mcp_tool`, `invoke_agent`, and `get_agent_task` do not exist until
an operator sets `MCPGW_INVOKE_TOOLS_ENABLED=true` in mcpgw's own
environment and restarts it. With the default `false`, the three tools are
absent from `tools/list`; no caller, direct or through the gateway, can
call a tool that was never registered.

The environment variable is the only switch, and no caller can reach
around it: it lives in mcpgw's process, not in a header or parameter a
request carries.

Turning it on exposes two destructive tools, `invoke_mcp_tool` and
`invoke_agent`, to every client already approved to call AI Registry Tools
as a whole. A client approved only for read-only discovery gains the
ability to run arbitrary tools on other servers and send messages to
agents, as the calling user. Review each client's tool-approval settings
before enabling the switch. Most MCP clients let an operator approve or
block individual tools on a connected server, not just the server as a
whole; set per-tool approval on `invoke_mcp_tool` and `invoke_agent`
specifically, since both carry `destructiveHint: true`.

## Technical Architecture

```
AI Agent → AI Registry Tools → MCP Gateway Registry
         (MCP Protocol)      (HTTP/JSON API)
         Bearer Token        Token Forwarding
```

**Design principles:**
- **Lightweight** - Minimal dependencies, fast startup
- **Stateless** - No session management, horizontally scalable
- **Pass-through authentication** - Tokens forwarded to registry
- **Protocol adapter** - Translates MCP tool calls to HTTP API requests

## Configuration

AI Registry Tools is configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRY_BASE_URL` | `http://localhost` | Registry API endpoint |
| `HOST` | `127.0.0.1` | Bind host (use `0.0.0.0` for Docker/K8s) |
| `PORT` | `8003` | Server port |

For Docker/Kubernetes deployments, the registry automatically configures these variables.

## Troubleshooting

Calls to `invoke_mcp_tool`, `invoke_agent`, and `get_agent_task` cross the
same gateway hop as every other mcpgw call, and can fail in these ways:

- **HTTP 413, request over 256 KiB.** The gateway inspects MCP request
  bodies up to 256 KiB. When a call's `arguments` push the request past
  that limit, the gateway refuses it before it reaches the backend. Pass
  smaller arguments, or split the call.
- **HTTP 429, rate limited.** All of mcpgw's inner calls share one nginx
  rate-limit bucket keyed on mcpgw's own address, the same bucket every
  other MCP location uses. A burst of invocations from any number of users
  can trip it. The tool's error includes the `Retry-After` value nginx
  sent.
- **HTTP 504, or a task that stays `pending`.** `MCP_PROXY_TIMEOUT`
  (default 30 seconds) bounds how long the gateway waits for any backend,
  MCP tool or A2A agent. mcpgw sets its own deadline 5 seconds under that
  value, so it always returns before the gateway's own hop times out. If a
  backend tool or agent routinely needs longer, raise `MCP_PROXY_TIMEOUT`.
- **What `status` and `error` mean.** `invoke_agent` and `get_agent_task`
  return `status: "success"` for a message or a finished task, even one
  that ended in a `failed` task state (the `state` field says what
  happened; the call itself still succeeded). They return `status:
  "pending"` when the task is still running at the deadline, and `status:
  "failed"` with an `error` string only when the call produced no usable
  result at all. `invoke_mcp_tool` reports a backend tool's own error
  through `isError: true` on its result, not through a separate `status`
  field.

## Support

- **Documentation**: See the MCP Gateway Registry docs
- **Issues**: Report issues in the main registry repository
- **Configuration help**: Use the gear icon on the server card for setup guidance

---

**Server Status**: Auto-registered and ready to use
**Protocol**: Model Context Protocol (MCP)
**Transport**: Streamable HTTP
**Authentication**: Bearer token (forwarded to registry)
