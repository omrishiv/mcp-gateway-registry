#!/bin/bash
# Test script for mcpgw MCP server - exercises all 5 tools via FastMCP streamable-http protocol
# This demonstrates WHY the Mcp-Session-Id header is required for session management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MCPGW_URL="${MCPGW_URL:-https://mcpgateway.ddns.net/airegistry-tools/mcp}"
TOKEN_FILE="${TOKEN_FILE:-.token}"

echo -e "${BLUE}=== MCP Gateway Tools Test Script ===${NC}"
echo "MCPGW URL: $MCPGW_URL"
echo

# Read token from .token file
if [[ ! -f "$TOKEN_FILE" ]]; then
    echo -e "${RED}ERROR: Token file not found: $TOKEN_FILE${NC}"
    echo "Create a .token file with your bearer token (without 'Bearer ' prefix)"
    exit 1
fi

# Try to parse as JSON first (if it's a token response object)
TOKEN=$(cat "$TOKEN_FILE" | jq -r '.tokens.access_token // empty' 2>/dev/null)

# If not JSON or no access_token field, treat entire file as raw token
if [[ -z "$TOKEN" ]]; then
    TOKEN=$(cat "$TOKEN_FILE" | tr -d '\n\r')
fi

if [[ -z "$TOKEN" ]]; then
    echo -e "${RED}ERROR: Token file is empty or invalid${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Token loaded from $TOKEN_FILE${NC}"
echo

# Temp file for capturing response headers
HEADER_FILE=$(mktemp)
trap "rm -f $HEADER_FILE" EXIT

# Helper to extract response and update SESSION_ID from make_request output
extract_response() {
    local output="$1"
    # Extract session ID from last line
    local new_session=$(echo "$output" | tail -1 | grep "^SESSION_ID=" | cut -d= -f2)
    if [[ -n "$new_session" ]]; then
        SESSION_ID="$new_session"
    fi
    # Return everything except last line (the SESSION_ID= line)
    echo "$output" | head -n -1
}

# Function to make JSON-RPC request
make_request() {
    local method=$1
    local params=$2
    local request_id=$3

    local payload=$(jq -n \
        --arg method "$method" \
        --argjson params "$params" \
        --arg id "$request_id" \
        '{jsonrpc: "2.0", method: $method, params: $params, id: $id}')

    echo -e "${BLUE}→ Request: $method (id=$request_id)${NC}" >&2
    echo "$payload" | jq -C '.' >&2

    # Make request with session ID if available
    local curl_args=(-s -D "$HEADER_FILE" -X POST "$MCPGW_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Authorization: Bearer $TOKEN" \
        -d "$payload")

    if [[ -n "$SESSION_ID" ]]; then
        curl_args+=(-H "Mcp-Session-Id: $SESSION_ID")
        echo -e "${YELLOW}  Using session: $SESSION_ID${NC}" >&2
    fi

    local response=$(curl "${curl_args[@]}")
    local http_status=$(grep "^HTTP" "$HEADER_FILE" | tail -1 | awk '{print $2}')

    # Extract session ID from response headers if present (case-insensitive)
    if [[ -z "$SESSION_ID" ]]; then
        SESSION_ID=$(grep -i "^mcp-session-id:" "$HEADER_FILE" | head -1 | cut -d' ' -f2 | tr -d '\r\n' || true)
        if [[ -n "$SESSION_ID" ]]; then
            echo -e "${GREEN}  Session created: $SESSION_ID${NC}" >&2
        fi
    fi

    echo -e "${BLUE}← Response (HTTP $http_status):${NC}" >&2

    # Check if response is SSE format (starts with "event:" or "data:")
    if echo "$response" | grep -q "^event:\|^data:"; then
        # Extract JSON from SSE data: line
        local json_data=$(echo "$response" | grep "^data:" | sed 's/^data: //')
        if [[ -n "$json_data" ]]; then
            echo "$json_data" | jq -C '.' >&2
            response="$json_data"
        else
            echo "$response" >&2
        fi
    else
        # Try to parse as JSON, if fails show raw response
        if echo "$response" | jq -C '.' >&2 2>/dev/null; then
            :  # Successfully parsed and displayed
        else
            echo -e "${YELLOW}Raw response (not JSON):${NC}" >&2
            echo "$response" >&2
        fi
    fi
    echo >&2

    # Check HTTP status
    if [[ "$http_status" != "200" && "$http_status" != "202" ]]; then
        echo -e "${RED}✗ HTTP error: $http_status${NC}" >&2
        return 1
    fi

    # Check for JSON-RPC errors
    if echo "$response" | jq -e '.error' > /dev/null 2>&1; then
        echo -e "${RED}✗ JSON-RPC error in response${NC}" >&2
        return 1
    fi

    # Return response JSON and session ID on separate lines
    echo "$response"
    echo "SESSION_ID=$SESSION_ID"
}

# 1. Initialize MCP session
echo -e "${GREEN}=== Step 1: Initialize MCP Session ===${NC}"
INIT_PARAMS=$(jq -n '{
    protocolVersion: "2024-11-05",
    capabilities: {
        tools: {}
    },
    clientInfo: {
        name: "mcpgw-test-script",
        version: "1.0.0"
    }
}')

INIT_OUTPUT=$(make_request "initialize" "$INIT_PARAMS" "init-1")

# Extract session ID from last line of output
SESSION_ID=$(echo "$INIT_OUTPUT" | tail -1 | grep "^SESSION_ID=" | cut -d= -f2)
INIT_RESPONSE=$(echo "$INIT_OUTPUT" | head -n -1)

if [[ -z "$SESSION_ID" ]]; then
    echo -e "${RED}ERROR: Failed to get session ID from initialize response${NC}"
    echo "This proves that Mcp-Session-Id header forwarding is REQUIRED!"
    exit 1
fi

echo -e "${GREEN}✓ Session initialized successfully${NC}"
echo

# 2. Send initialized notification
echo -e "${GREEN}=== Step 2: Send Initialized Notification ===${NC}"
INITIALIZED_PAYLOAD=$(jq -n '{
    jsonrpc: "2.0",
    method: "notifications/initialized"
}')

curl -s -X POST "$MCPGW_URL" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -d "$INITIALIZED_PAYLOAD" > /dev/null

echo -e "${GREEN}✓ Initialization complete${NC}"
echo

# 3. List available tools
echo -e "${GREEN}=== Step 3: List Available Tools ===${NC}"
TOOLS_OUTPUT=$(make_request "tools/list" "{}" "tools-list-1")
TOOLS_RESPONSE=$(extract_response "$TOOLS_OUTPUT")

TOOL_NAMES=$(echo "$TOOLS_RESPONSE" | jq -r '.result.tools[].name' | tr '\n' ', ' | sed 's/,$//')
TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | jq '.result.tools | length')

echo -e "${GREEN}✓ Found $TOOL_COUNT tools: $TOOL_NAMES${NC}"
echo

# 4. Test each tool
echo -e "${GREEN}=== Step 4: Test All Tools ===${NC}"

# Tool 1: list_services
echo -e "${YELLOW}--- Testing: list_services ---${NC}"
LIST_SERVICES_PARAMS=$(jq -n '{
    name: "list_services",
    arguments: {}
}')

LIST_SERVICES_OUTPUT=$(make_request "tools/call" "$LIST_SERVICES_PARAMS" "call-1")
LIST_SERVICES_RESPONSE=$(extract_response "$LIST_SERVICES_OUTPUT")
SERVICE_COUNT=$(echo "$LIST_SERVICES_RESPONSE" | jq -r '.result.content[0].text' | jq '.total_count')
echo -e "${GREEN}✓ list_services: Found $SERVICE_COUNT services${NC}"
echo

# Tool 2: list_agents
echo -e "${YELLOW}--- Testing: list_agents ---${NC}"
LIST_AGENTS_PARAMS=$(jq -n '{
    name: "list_agents",
    arguments: {}
}')

LIST_AGENTS_OUTPUT=$(make_request "tools/call" "$LIST_AGENTS_PARAMS" "call-2")
LIST_AGENTS_RESPONSE=$(extract_response "$LIST_AGENTS_OUTPUT")
AGENT_COUNT=$(echo "$LIST_AGENTS_RESPONSE" | jq -r '.result.content[0].text' | jq '.total_count')
echo -e "${GREEN}✓ list_agents: Found $AGENT_COUNT agents${NC}"
echo

# Tool 3: list_skills
echo -e "${YELLOW}--- Testing: list_skills ---${NC}"
LIST_SKILLS_PARAMS=$(jq -n '{
    name: "list_skills",
    arguments: {}
}')

LIST_SKILLS_OUTPUT=$(make_request "tools/call" "$LIST_SKILLS_PARAMS" "call-3")
LIST_SKILLS_RESPONSE=$(extract_response "$LIST_SKILLS_OUTPUT")
SKILL_COUNT=$(echo "$LIST_SKILLS_RESPONSE" | jq -r '.result.content[0].text' | jq '.total_count')
echo -e "${GREEN}✓ list_skills: Found $SKILL_COUNT skills${NC}"
echo

# Tool 4: intelligent_tool_finder
echo -e "${YELLOW}--- Testing: intelligent_tool_finder ---${NC}"
SEARCH_PARAMS=$(jq -n '{
    name: "intelligent_tool_finder",
    arguments: {
        query: "find weather information",
        top_n: 3
    }
}')

SEARCH_OUTPUT=$(make_request "tools/call" "$SEARCH_PARAMS" "call-4")
SEARCH_RESPONSE=$(extract_response "$SEARCH_OUTPUT")
RESULT_COUNT=$(echo "$SEARCH_RESPONSE" | jq -r '.result.content[0].text' | jq '.total_results')
echo -e "${GREEN}✓ intelligent_tool_finder: Found $RESULT_COUNT results${NC}"
echo

# Tool 5: healthcheck
echo -e "${YELLOW}--- Testing: healthcheck ---${NC}"
HEALTH_PARAMS=$(jq -n '{
    name: "healthcheck",
    arguments: {}
}')

HEALTH_OUTPUT=$(make_request "tools/call" "$HEALTH_PARAMS" "call-5")
HEALTH_RESPONSE=$(extract_response "$HEALTH_OUTPUT")
HEALTH_STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.result.content[0].text' | jq -r '.status')
echo -e "${GREEN}✓ healthcheck: Status=$HEALTH_STATUS${NC}"
echo

# 5. Test session persistence - call same tool again with same session
echo -e "${GREEN}=== Step 5: Verify Session Persistence ===${NC}"
echo "Calling list_services again with the SAME session ID..."
echo "This proves that Mcp-Session-Id must be forwarded by nginx!"
echo

LIST_SERVICES_OUTPUT_2=$(make_request "tools/call" "$LIST_SERVICES_PARAMS" "call-6")
LIST_SERVICES_RESPONSE_2=$(extract_response "$LIST_SERVICES_OUTPUT_2")
SERVICE_COUNT_2=$(echo "$LIST_SERVICES_RESPONSE_2" | jq -r '.result.content[0].text' | jq '.total_count')
echo -e "${GREEN}✓ Session persistence verified: Found $SERVICE_COUNT_2 services${NC}"
echo

# Summary
echo -e "${GREEN}=== Test Summary ===${NC}"
echo -e "${GREEN}✓ Session ID: $SESSION_ID${NC}"
echo -e "${GREEN}✓ All 5 tools tested successfully${NC}"
echo -e "${GREEN}✓ Session persistence verified${NC}"
