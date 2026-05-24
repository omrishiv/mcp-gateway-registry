#!/bin/bash
# Upgrade an existing Keycloak realm to support MCP Dynamic Client Registration
#
# This standalone script applies the three configuration changes required for
# MCP clients (Claude Code, Claude.ai connectors, Cursor) to register dynamically
# and produce tokens with a `groups` claim for per-user authorization at the
# gateway. Use this on existing deployments where the realm was created before
# these changes landed in init-keycloak.sh.
#
# The script is idempotent: re-running it is safe.
#
# Usage:
#   bash keycloak/setup/upgrade-realm-for-dcr.sh
#
# Reads .env from repo root for KEYCLOAK_ADMIN_URL, KEYCLOAK_ADMIN, and
# KEYCLOAK_ADMIN_PASSWORD.

set -e

REALM="mcp-gateway"
KEYCLOAK_URL=""
KEYCLOAK_ADMIN=""
KEYCLOAK_ADMIN_PASSWORD=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}MCP DCR upgrade for existing Keycloak realm '${REALM}'${NC}"
echo "============================================================"

get_admin_token() {
    local response=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${KEYCLOAK_ADMIN}" \
        -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
        -d "grant_type=password" \
        -d "client_id=admin-cli")

    echo "$response" | jq -r '.access_token // empty'
}

setup_dcr_groups_mapper() {
    local token=$1

    echo ""
    echo "[1/4] Attaching Groups protocol mapper to the 'basic' client-scope..."

    local basic_scope_id=$(curl -s -H "Authorization: Bearer ${token}" \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes" | \
        jq -r '.[] | select(.name=="basic") | .id')

    if [ -z "$basic_scope_id" ] || [ "$basic_scope_id" = "null" ]; then
        echo -e "${RED}Error: Could not find 'basic' client-scope in realm '${REALM}'${NC}"
        return 1
    fi

    local existing=$(curl -s -H "Authorization: Bearer ${token}" \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes/${basic_scope_id}" | \
        jq -r '.protocolMappers[]? | select(.name=="groups") | .id')

    if [ -n "$existing" ] && [ "$existing" != "null" ]; then
        echo -e "${YELLOW}Groups mapper already attached to 'basic' scope. Skipping.${NC}"
        return 0
    fi

    local groups_mapper_json='{
        "name": "groups",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-group-membership-mapper",
        "consentRequired": false,
        "config": {
            "full.path": "false",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "claim.name": "groups",
            "userinfo.token.claim": "true"
        }
    }'

    local response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes/${basic_scope_id}/protocol-mappers/models" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$groups_mapper_json")

    if [ "$response" = "201" ]; then
        echo -e "${GREEN}OK: groups mapper attached to 'basic'.${NC}"
    else
        echo -e "${RED}FAILED: HTTP status ${response}${NC}"
        return 1
    fi
}

setup_dcr_audience_mapper() {
    local token=$1

    echo ""
    echo "[2/4] Attaching Audience protocol mapper to the 'basic' client-scope..."

    local basic_scope_id=$(curl -s -H "Authorization: Bearer ${token}" \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes" | \
        jq -r '.[] | select(.name=="basic") | .id')

    if [ -z "$basic_scope_id" ] || [ "$basic_scope_id" = "null" ]; then
        echo -e "${RED}Error: Could not find 'basic' client-scope${NC}"
        return 1
    fi

    local existing=$(curl -s -H "Authorization: Bearer ${token}" \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes/${basic_scope_id}" | \
        jq -r '.protocolMappers[]? | select(.name=="mcp-gateway-audience") | .id')

    if [ -n "$existing" ] && [ "$existing" != "null" ]; then
        echo -e "${YELLOW}Audience mapper already attached. Skipping.${NC}"
        return 0
    fi

    local audience_mapper_json='{
        "name": "mcp-gateway-audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": false,
        "config": {
            "included.custom.audience": "mcp-gateway",
            "id.token.claim": "false",
            "access.token.claim": "true"
        }
    }'

    local response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes/${basic_scope_id}/protocol-mappers/models" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$audience_mapper_json")

    if [ "$response" = "201" ]; then
        echo -e "${GREEN}OK: audience mapper attached. DCR'd-client tokens will carry aud=\"mcp-gateway\".${NC}"
    else
        echo -e "${RED}FAILED: HTTP status ${response}${NC}"
        return 1
    fi
}

configure_dcr_allowed_scopes() {
    local token=$1

    echo ""
    echo "[3/4] Widening anonymous-DCR 'Allowed Client Scopes' policy..."

    local components=$(curl -s -H "Authorization: Bearer ${token}" \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy")

    local policy_id=$(echo "$components" | \
        jq -r '.[] | select(.name=="Allowed Client Scopes" and .subType=="anonymous") | .id')
    local parent_id=$(echo "$components" | \
        jq -r '.[] | select(.name=="Allowed Client Scopes" and .subType=="anonymous") | .parentId')

    if [ -z "$policy_id" ] || [ "$policy_id" = "null" ]; then
        echo -e "${RED}Error: Could not find anonymous 'Allowed Client Scopes' policy${NC}"
        return 1
    fi

    local all_scope_names=$(curl -s -H "Authorization: Bearer ${token}" \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes" | \
        jq -c '[.[].name]')

    local policy_json=$(jq -n \
        --arg name "Allowed Client Scopes" \
        --arg providerId "allowed-client-templates" \
        --arg providerType "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" \
        --arg parentId "$parent_id" \
        --arg subType "anonymous" \
        --argjson allowedScopes "$all_scope_names" \
        '{
            name: $name,
            providerId: $providerId,
            providerType: $providerType,
            parentId: $parentId,
            subType: $subType,
            config: {
                "allow-default-scopes": ["true"],
                "allowed-client-scopes": $allowedScopes
            }
        }')

    local response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "${KEYCLOAK_URL}/admin/realms/${REALM}/components/${policy_id}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$policy_json")

    if [ "$response" = "204" ]; then
        echo -e "${GREEN}OK: Allowed Client Scopes policy includes all realm scopes.${NC}"
    else
        echo -e "${RED}FAILED: HTTP status ${response}${NC}"
        return 1
    fi
}

configure_dcr_trusted_hosts() {
    local token=$1

    echo ""
    echo "[4/4] Relaxing anonymous-DCR 'Trusted Hosts' policy..."

    local components=$(curl -s -H "Authorization: Bearer ${token}" \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/components?type=org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy")

    local policy_id=$(echo "$components" | \
        jq -r '.[] | select(.name=="Trusted Hosts" and .subType=="anonymous") | .id')
    local parent_id=$(echo "$components" | \
        jq -r '.[] | select(.name=="Trusted Hosts" and .subType=="anonymous") | .parentId')

    if [ -z "$policy_id" ] || [ "$policy_id" = "null" ]; then
        echo -e "${RED}Error: Could not find anonymous 'Trusted Hosts' policy${NC}"
        return 1
    fi

    local policy_json='{
        "name": "Trusted Hosts",
        "providerId": "trusted-hosts",
        "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
        "parentId": "'"$parent_id"'",
        "subType": "anonymous",
        "config": {
            "host-sending-registration-request-must-match": ["false"],
            "client-uris-must-match": ["true"],
            "trusted-hosts": ["localhost"]
        }
    }'

    local response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "${KEYCLOAK_URL}/admin/realms/${REALM}/components/${policy_id}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$policy_json")

    if [ "$response" = "204" ]; then
        echo -e "${GREEN}OK: Trusted Hosts policy relaxed (IP check off, URI check on, localhost allowed).${NC}"
    else
        echo -e "${RED}FAILED: HTTP status ${response}${NC}"
        return 1
    fi
}

main() {
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
    ENV_FILE="$PROJECT_ROOT/.env"

    if [ -f "$ENV_FILE" ]; then
        echo "Loading environment from $ENV_FILE..."
        set -a
        source "$ENV_FILE"
        set +a
    else
        echo -e "${RED}Error: .env not found at $ENV_FILE${NC}"
        exit 1
    fi

    KEYCLOAK_URL="${KEYCLOAK_ADMIN_URL:-http://localhost:8080}"
    KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"

    if [ -z "$KEYCLOAK_ADMIN_PASSWORD" ]; then
        echo -e "${RED}Error: KEYCLOAK_ADMIN_PASSWORD must be set in .env${NC}"
        exit 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${RED}Error: this script requires 'jq'. Install with: sudo apt-get install jq${NC}"
        exit 1
    fi

    echo "Using Keycloak API URL: $KEYCLOAK_URL"
    echo "Realm: $REALM"

    echo ""
    echo "Authenticating as Keycloak admin..."
    TOKEN=$(get_admin_token)
    if [ -z "$TOKEN" ]; then
        echo -e "${RED}Error: failed to obtain admin token${NC}"
        exit 1
    fi
    echo -e "${GREEN}Authentication successful.${NC}"

    setup_dcr_groups_mapper "$TOKEN"
    setup_dcr_audience_mapper "$TOKEN"
    configure_dcr_allowed_scopes "$TOKEN"
    configure_dcr_trusted_hosts "$TOKEN"

    echo ""
    echo -e "${GREEN}DCR upgrade complete.${NC}"
    echo ""
    echo "What was applied:"
    echo "  - Groups protocol mapper added to 'basic' client-scope"
    echo "  - Audience mapper added to 'basic' client-scope (aud=mcp-gateway)"
    echo "  - Allowed Client Scopes policy widened to all realm scopes"
    echo "  - Trusted Hosts policy: IP check OFF, URI check ON, 'localhost' trusted"
    echo ""
    echo "Existing DCR'd clients will get the groups+audience claims on their next"
    echo "/authorize round-trip. New DCR registrations are unaffected by these changes"
    echo "for clients that already complete registration successfully."
}

main "$@"
