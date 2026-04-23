# How do I restrict which agents a user can see based on their group?

The registry supports group-based access control for agents through the `visibility` and `allowed_groups` fields on the agent card. This allows you to register agents that are only visible to users belonging to specific IdP groups (Entra ID, Cognito, Keycloak, etc.).

## Visibility Options

Every agent has a `visibility` field that accepts one of three fixed values:

| Value | Behavior |
|-------|----------|
| `public` | Visible to all authenticated users (default) |
| `private` | Visible only to admin users |
| `group-restricted` | Visible only to users whose groups overlap with the agent's `allowed_groups` list. Admins can always see all agents. |

These values are enforced by the API. Any other value is rejected with a validation error.

## Option A: Register a Group-Restricted Agent

When registering a new agent, set `visibility` to `group-restricted` and provide an `allowed_groups` list:

```bash
curl -X POST "https://your-registry/api/agents/register" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Internal Finance Agent",
    "description": "Agent for internal finance operations",
    "url": "https://finance-agent.internal.example.com",
    "path": "/agents/finance-agent",
    "version": "1.0.0",
    "supportedProtocol": "A2A",
    "visibility": "group-restricted",
    "allowed_groups": ["finance-team", "finance-admins"]
  }'
```

Only users whose IdP groups include `finance-team` or `finance-admins` will see this agent. Admin users always see all agents regardless of visibility.

## Option B: Update an Existing Agent to Group-Restricted

```bash
curl -X PUT "https://your-registry/api/agents/finance-agent" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Internal Finance Agent",
    "description": "Agent for internal finance operations",
    "url": "https://finance-agent.internal.example.com",
    "version": "1.0.0",
    "visibility": "group-restricted",
    "allowed_groups": ["finance-team", "finance-admins"]
  }'
```

## Option C: Via the Web UI

The agent edit form in the dashboard includes a Visibility dropdown with the "Group Restricted" option. However, the UI does not currently provide an input field for specifying `allowed_groups`. To set group-restricted visibility with allowed groups, use the API (Option A or B above).

A future UI update will add the allowed groups input field to the agent edit form.

## Filtering Agents by Visibility

The `GET /api/agents` endpoint supports a `visibility` query parameter to return only agents with a specific visibility level:

```bash
# List only group-restricted agents
curl "https://your-registry/api/agents?visibility=group-restricted" \
  -H "Authorization: Bearer $TOKEN"

# List only public agents
curl "https://your-registry/api/agents?visibility=public" \
  -H "Authorization: Bearer $TOKEN"

# List only private agents (admin only)
curl "https://your-registry/api/agents?visibility=private" \
  -H "Authorization: Bearer $TOKEN"
```

The filter still respects the caller's group membership. A non-admin user filtering by `group-restricted` will only see agents whose `allowed_groups` overlap with their own groups.

## How Group Matching Works

When a user calls `GET /api/agents`:

1. **Public agents** are returned to all authenticated users
2. **Private agents** are returned only to admin users
3. **Group-restricted agents** are returned only if the user's groups (from their IdP token) overlap with the agent's `allowed_groups` list. Admin users bypass this check and see all agents.

The group names in `allowed_groups` must match the group names or identifiers that come through in the user's IdP token claims. For Entra ID, this is typically the Group Object ID or the group display name, depending on your claims configuration.

## IdP Independence

The `allowed_groups` field on the agent card works with any IdP (Entra ID, Cognito, Keycloak, Okta) because the matching is done against the groups present in the authenticated user's token. The registry does not call any IdP API to verify group membership; it relies on the groups already present in the JWT claims.

## Related Documentation

- [Filtering Agents by Tags and Fields](filtering-agents-by-tags-and-fields.md) -- all agent filtering options
- [Restrict Server Visibility by Entra Group](restrict-server-visibility-by-entra-group.md) -- similar setup for MCP servers
- [Registering M2M Clients without IdP Admin Token](registering-m2m-client-without-idp-admin-token.md) -- register M2M client-id-to-group mappings locally
