# User and Group Management Guide

This guide provides the correct sequence of operations for managing users, groups, and scopes in the MCP Gateway Registry.

## Prerequisites

Set up environment variables for easier command execution:

```bash
export REGISTRY_URL="https://registry.us-east-1.aroraai.people.aws.dev"
export AWS_REGION="us-east-1"
export KEYCLOAK_URL="https://kc.us-east-1.aroraai.people.aws.dev"
```

## Architecture Overview

The system has two layers of configuration:

1. **Keycloak IAM Groups**: User membership and authentication (who belongs to which group)
2. **DocumentDB Scopes**: Authorization rules (what each group can access)

Both must be configured for users to have proper access.

## Complete Workflow

### Step 1: Import Group Scope Configuration

Import the group's authorization rules (scopes) into DocumentDB. This defines what servers/tools the group can access.

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  import-group \
  --file cli/examples/currenttime-users.json
```

**What this does:**
- Creates scope configuration in DocumentDB
- If `"create_in_idp": true` is in the JSON, it also creates the IdP group (Keycloak/Entra)
- Defines server access rules, UI permissions, and group mappings

**Example JSON structure** (cli/examples/currenttime-users.json):
```json
{
  "scope_name": "currenttime-users",
  "description": "Users with access to currenttime server",
  "server_access": [
    {
      "server": "currenttime",
      "methods": ["initialize", "tools/list", "tools/call"],
      "tools": ["current_time_by_timezone"]
    }
  ],
  "group_mappings": ["currenttime-users"],
  "ui_permissions": {
    "list_service": ["currenttime"],
    "health_check_service": ["currenttime"]
  },
  "create_in_idp": true
}
```

### Step 2: Create IAM Group (if not auto-created)

If the group wasn't auto-created in Step 1 (no `"create_in_idp": true`), create it manually:

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  group-create \
  --name currenttime-users \
  --description "Users with access to currenttime server"
```

**Note:** If the group already exists, this will fail with "Group already exists" error. You can verify with:

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  group-list
```

### Step 3: Create Human User Account

Create a human user and assign them to the group:

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  user-create-human \
  --username ctuser \
  --email ctuser@example.com \
  --first-name Current \
  --last-name Time \
  --password riv2025 \
  --groups currenttime-users
```

**Important:**
- Password is only set during creation
- If user already exists, this fails with "User already exists"
- Users can be assigned to multiple groups by comma-separating them: `--groups group1,group2`

### Step 4: Create M2M Service Account

Create a machine-to-machine service account for programmatic access:

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  user-create-m2m \
  --name currenttime-service-bot \
  --groups currenttime-users \
  --description "Service account for currenttime server automation"
```

**Important:**
- Save the client_id and client_secret immediately - the secret is only shown once
- Service accounts use OAuth2 client credentials flow

## Verification Commands

### List All Users

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  user-list
```

### List All Groups

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  group-list
```

### List Scope Groups (DocumentDB)

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  list-groups
```

### Describe Specific Group

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  describe-group \
  --group-name currenttime-users
```

## Troubleshooting

### User Already Exists

If you get "User already exists" error:

1. Check if user exists:
   ```bash
   uv run python api/registry_management.py \
     --registry-url $REGISTRY_URL \
     --aws-region $AWS_REGION \
     --keycloak-url $KEYCLOAK_URL \
     user-list | grep username
   ```

2. Either use the existing user or delete and recreate:
   ```bash
   # Delete existing user
   uv run python api/registry_management.py \
     --registry-url $REGISTRY_URL \
     --aws-region $AWS_REGION \
     --keycloak-url $KEYCLOAK_URL \
     user-delete \
     --username ctuser

   # Then recreate
   uv run python api/registry_management.py ... user-create-human ...
   ```

### Group Already Exists

If you get "Group already exists" error, the group is already configured. Verify with:

```bash
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  group-list | grep currenttime-users
```

### Password Reset

Currently, password reset must be done through Keycloak admin UI or by deleting and recreating the user with a new password.

**Note:** For the existing user `ctuser`, if the password is unknown, you'll need to either:
- Delete and recreate the user with a known password
- Use Keycloak admin UI to reset the password
- Contact an administrator

## Current Status for ctuser

The user `ctuser` currently exists with:
- **Username:** ctuser
- **Email:** ctuser@example.com
- **Name:** CT User
- **Groups:** currenttime-users
- **Status:** Enabled
- **Password:** Unknown (was set during initial creation)

If you need to use this account and don't know the password, delete and recreate it:

```bash
# Delete existing user
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  user-delete \
  --username ctuser

# Recreate with known password
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  user-create-human \
  --username ctuser \
  --email ctuser@example.com \
  --first-name Current \
  --last-name Time \
  --password riv2025 \
  --groups currenttime-users
```

## Quick Reference

### Create Everything from Scratch

```bash
# 1. Import group scope configuration (creates IdP group if create_in_idp=true)
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  import-group --file cli/examples/currenttime-users.json

# 2. Create human user (if group doesn't auto-create users)
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  user-create-human \
  --username ctuser \
  --email ctuser@example.com \
  --first-name Current \
  --last-name Time \
  --password riv2025 \
  --groups currenttime-users

# 3. Create M2M service account
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  user-create-m2m \
  --name currenttime-service-bot \
  --groups currenttime-users \
  --description "Service account for currenttime automation"
```

## Federation Management

For importing servers from Anthropic's registry:

```bash
# Save federation configuration
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  federation-save \
  --config cli/examples/federation-config-example.json

# Sync federated servers
uv run python api/registry_management.py \
  --registry-url $REGISTRY_URL \
  --aws-region $AWS_REGION \
  --keycloak-url $KEYCLOAK_URL \
  federation-sync
```
