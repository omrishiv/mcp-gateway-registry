#!/bin/bash
# Local Compose smoke test for the mcpgw invocation tools (issues #1426/#1927).
#
# Runs a subset of .scratchpad/gateway-invoke-tools/testing.md against a
# running local stack (./build_and_run.sh): tests 1.1.1, 1.2.0 (setup),
# 1.2.1, 1.2.2, 1.2.5, 1.2.6, 1.2.7, and 5.2. Prints one PASS or FAIL line per
# check plus the median latency for a direct and a virtual invoke_mcp_tool
# call, and removes every test resource it created (group, M2M user, virtual
# server) on exit, success or failure.
#
# invoke_agent/get_agent_task is NOT exercised here: no A2A agent
# ships in the Compose stack (testing.md 1.3's "Local agent" note). Set
# AGENT_PATH to a registered agent's path to add tests 1.3.1 and 1.3.2.
#
# Prerequisites (see testing.md "Prerequisites"):
#   - A running local stack: ./build_and_run.sh
#   - .token at the repo root with an admin JWT (docs/quickstart.md Step 10)
#   - MCPGW_INVOKE_TOOLS_ENABLED=true and SSRF_ALLOWED_HOSTS=currenttime-server
#     in .env, with mcpgw-server and registry restarted after setting them
#
# Usage:
#   bash -n scripts/smoke-mcpgw-invoke.sh   # syntax check only
#   REGISTRY_URL=http://localhost ./scripts/smoke-mcpgw-invoke.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

REGISTRY_URL="${REGISTRY_URL:-http://localhost}"
TOKEN_FILE="${TOKEN_FILE:-${REPO_ROOT}/.token}"
RUN_ID="$(date +%s)"
GROUP_NAME="invoke-test-${RUN_ID}"
VS_PATH="/virtual/invoke-test-${RUN_ID}"
API_DIR="${REPO_ROOT}/api"

PASS_COUNT=0
FAIL_COUNT=0

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "PASS: $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "FAIL: $1"
}

cleanup() {
    log "Cleaning up test resources (group=${GROUP_NAME}, virtual server=${VS_PATH})"
    (
        cd "${API_DIR}"
        uv run --frozen python registry_management.py --registry-url "${REGISTRY_URL}" \
            --token-file "${TOKEN_FILE}" vs-delete --path "${VS_PATH}" --force >/dev/null 2>&1 || true
        if [[ -n "${CLIENT_ID:-}" ]]; then
            uv run --frozen python registry_management.py --registry-url "${REGISTRY_URL}" \
                --token-file "${TOKEN_FILE}" m2m-client-delete --client-id "${CLIENT_ID}" --force >/dev/null 2>&1 || true
        fi
        uv run --frozen python registry_management.py --registry-url "${REGISTRY_URL}" \
            --token-file "${TOKEN_FILE}" group-delete --name "${GROUP_NAME}" --force >/dev/null 2>&1 || true
    )
    rm -f "/tmp/vs-${RUN_ID}.json" "${API_DIR}/.m2m_client_secret_${GROUP_NAME}.txt"
}
trap cleanup EXIT

if [[ ! -f "${TOKEN_FILE}" ]]; then
    echo "Admin token file not found: ${TOKEN_FILE}" >&2
    echo "See docs/quickstart.md Step 10 to create one." >&2
    exit 1
fi
ADMIN_TOKEN="$(jq -r '.tokens.access_token // empty' "${TOKEN_FILE}")"
if [[ -z "${ADMIN_TOKEN}" ]]; then
    ADMIN_TOKEN="$(tr -d '\n\r' <"${TOKEN_FILE}")"
fi
if [[ -z "${ADMIN_TOKEN}" ]]; then
    echo "Could not read an access token from ${TOKEN_FILE}" >&2
    exit 1
fi

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:18080}"
REALM="${REALM:-mcp-gateway}"

MCPGW_RULE='{"server": "airegistry-tools", "methods": ["initialize", "notifications/initialized", "ping", "tools/list", "tools/call"], "tools": ["*"]}'

# One JSON-RPC call to the AI Registry tools server. mcpgw runs stateless, so
# no initialize or session id is needed. Handles both JSON and SSE responses.
mcpgw() { # mcpgw <token> <method> <params-json>
    curl -sS -X POST "${REGISTRY_URL}/airegistry-tools/mcp" \
        -H "X-Authorization: Bearer $1" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" |
        sed -n -e 's/^data: //' -e '/^{/p' | jq
}

call() { mcpgw "$1" tools/call "{\"name\":\"$2\",\"arguments\":$3}"; } # call <token> <tool> <args-json>

grant() { # grant <scope_config-json>: replace the test group's grants
    curl -sS -X PATCH "${REGISTRY_URL}/api/management/iam/groups/${GROUP_NAME}" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" \
        -d "{\"scope_config\": $1}" >/dev/null
}

user_token() {
    curl -sS -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -d grant_type=client_credentials -d client_id="${CLIENT_ID}" -d client_secret="${CLIENT_SECRET}" |
        jq -r .access_token
}

median() { # median <n1> <n2> ... : prints the median of the given numbers (seconds)
    printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END {print (NR%2==1) ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2}'
}

log "Smoke test run ${RUN_ID} against ${REGISTRY_URL}"

log "Creating restricted test identity: group=${GROUP_NAME}"
(
    cd "${API_DIR}"
    uv run --frozen python registry_management.py --registry-url "${REGISTRY_URL}" --token-file "${TOKEN_FILE}" \
        group-create --name "${GROUP_NAME}" --description "invoke tools smoke test"
    uv run --frozen python registry_management.py --registry-url "${REGISTRY_URL}" --token-file "${TOKEN_FILE}" \
        user-create-m2m --name "${GROUP_NAME}" --groups "${GROUP_NAME}"
)
# shellcheck disable=SC1090
source "${API_DIR}/.m2m_client_secret_${GROUP_NAME}.txt" # sets CLIENT_ID and CLIENT_SECRET

log "Ensuring currenttime is registered and enabled (test 1.2.0)"
(
    cd "${API_DIR}"
    uv run --frozen python registry_management.py --registry-url "${REGISTRY_URL}" --token-file "${TOKEN_FILE}" \
        register --config ../cli/examples/currenttime.json >/dev/null 2>&1 || true
)
SERVER_INFO="$(curl -sS "${REGISTRY_URL}/api/servers/currenttime" -H "Authorization: Bearer ${ADMIN_TOKEN}")"
if [[ "$(echo "${SERVER_INFO}" | jq -r '.is_enabled // false')" != "true" ]]; then
    (
        cd "${API_DIR}"
        uv run --frozen python registry_management.py --registry-url "${REGISTRY_URL}" --token-file "${TOKEN_FILE}" \
            toggle --path /currenttime
    )
fi

# ---------------------------------------------------------------------------
# Test 1.1.1: listings follow the caller's grants.
# ---------------------------------------------------------------------------
log "Test 1.1.1: listings follow the caller's grants"
grant "{\"server_access\": [${MCPGW_RULE}], \"ui_permissions\": {\"list_service\": []}}"
USER_TOKEN="$(user_token)"
RESTRICTED_PATHS="$(call "${USER_TOKEN}" list_services '{}' | jq -r '.result.structuredContent.services[]?.path // .result.content[0].text | try (fromjson | .services[]?.path) catch empty')"
if echo "${RESTRICTED_PATHS}" | grep -qx "/currenttime/" 2>/dev/null || echo "${RESTRICTED_PATHS}" | grep -qx "/currenttime" 2>/dev/null; then
    fail "1.1.1 restricted user should not see /currenttime"
else
    pass "1.1.1 restricted user does not see /currenttime"
fi

# ---------------------------------------------------------------------------
# Test 1.2.1: refused without a grant on the target.
# ---------------------------------------------------------------------------
log "Test 1.2.1: refused without a grant on the target"
grant "{\"server_access\": [${MCPGW_RULE}]}"
USER_TOKEN="$(user_token)"
RESULT_1_2_1="$(call "${USER_TOKEN}" invoke_mcp_tool '{"server_path": "/currenttime", "tool_name": "current_time_by_timezone", "arguments": {"tz_name": "UTC"}}')"
TEXT_1_2_1="$(echo "${RESULT_1_2_1}" | jq -r '.result.content[0].text // empty')"
if [[ "${TEXT_1_2_1}" == "No server at /currenttime, or you do not have access to it." ]]; then
    pass "1.2.1 ungranted call refused with the expected message"
else
    fail "1.2.1 expected the no-access message, got: ${TEXT_1_2_1}"
fi

# ---------------------------------------------------------------------------
# Test 1.2.2: succeeds with the grant; record direct-route latency.
# ---------------------------------------------------------------------------
log "Test 1.2.2: succeeds with the grant"
grant "{\"server_access\": [${MCPGW_RULE}, {\"server\": \"currenttime\", \"methods\": [\"initialize\", \"notifications/initialized\", \"ping\", \"tools/list\", \"tools/call\"], \"tools\": [\"current_time_by_timezone\"]}]}"
USER_TOKEN="$(user_token)"
DIRECT_LATENCIES=()
DIRECT_OK=true
for _ in 1 2 3 4 5; do
    START="$(date +%s.%N)"
    RESULT_1_2_2="$(call "${USER_TOKEN}" invoke_mcp_tool '{"server_path": "/currenttime", "tool_name": "current_time_by_timezone", "arguments": {"tz_name": "UTC"}}')"
    END="$(date +%s.%N)"
    DIRECT_LATENCIES+=("$(echo "${END} - ${START}" | bc)")
    IS_ERROR="$(echo "${RESULT_1_2_2}" | jq -r '.result.isError // false')"
    META_PATH="$(echo "${RESULT_1_2_2}" | jq -r '.result._meta.mcpgw.server_path // empty')"
    if [[ "${IS_ERROR}" != "false" || "${META_PATH}" != "/currenttime" ]]; then
        DIRECT_OK=false
    fi
done
if [[ "${DIRECT_OK}" == true ]]; then
    pass "1.2.2 direct invoke_mcp_tool call succeeds (median latency $(median "${DIRECT_LATENCIES[@]}")s)"
else
    fail "1.2.2 direct invoke_mcp_tool call did not succeed cleanly"
fi
SESSION_WARNINGS="$(docker compose logs mcpgw-server --since 2m 2>/dev/null | grep -c "Session termination failed" || true)"
if [[ "${SESSION_WARNINGS}" == "0" ]]; then
    pass "1.2.2 session-close warning filter: 0 'Session termination failed' lines"
else
    fail "1.2.2 session-close warning filter: expected 0, found ${SESSION_WARNINGS}"
fi

# ---------------------------------------------------------------------------
# Test 1.2.5: virtual server route; record virtual-route latency.
# ---------------------------------------------------------------------------
log "Test 1.2.5: virtual server"
cat >"/tmp/vs-${RUN_ID}.json" <<EOF
{"path": "${VS_PATH}", "server_name": "invoke test ${RUN_ID}", "description": "invoke_mcp_tool smoke test",
 "tool_mappings": [{"tool_name": "current_time_by_timezone", "alias": "now", "backend_server_path": "/currenttime/"}],
 "supported_transports": ["streamable-http"]}
EOF
(
    cd "${API_DIR}"
    uv run --frozen python registry_management.py --registry-url "${REGISTRY_URL}" --token-file "${TOKEN_FILE}" \
        vs-create --config "/tmp/vs-${RUN_ID}.json"
)
VIRTUAL_LATENCIES=()
VIRTUAL_OK=true
for _ in 1 2 3 4 5; do
    START="$(date +%s.%N)"
    RESULT_1_2_5="$(call "${ADMIN_TOKEN}" invoke_mcp_tool "{\"server_path\": \"${VS_PATH}\", \"tool_name\": \"now\", \"arguments\": {\"tz_name\": \"UTC\"}}")"
    END="$(date +%s.%N)"
    VIRTUAL_LATENCIES+=("$(echo "${END} - ${START}" | bc)")
    if [[ "$(echo "${RESULT_1_2_5}" | jq -r '.result.isError // false')" != "false" ]]; then
        VIRTUAL_OK=false
    fi
done
if [[ "${VIRTUAL_OK}" == true ]]; then
    pass "1.2.5 virtual-route invoke_mcp_tool call succeeds (median latency $(median "${VIRTUAL_LATENCIES[@]}")s)"
else
    fail "1.2.5 virtual-route invoke_mcp_tool call did not succeed cleanly"
fi

# ---------------------------------------------------------------------------
# Test 1.2.6: path rules and self-call.
# ---------------------------------------------------------------------------
log "Test 1.2.6: path rules and self-call"
PATH_RULE_OK=true
for p in '/airegistry-tools' '/AIRegistry-Tools/' '/../api/servers' '/currenttime/%2e%2e' '/a//b' '/.hidden'; do
    TEXT="$(call "${ADMIN_TOKEN}" invoke_mcp_tool "{\"server_path\": \"${p}\", \"tool_name\": \"x\", \"arguments\": {}}" | jq -r '.result.content[0].text // empty')"
    if [[ -z "${TEXT}" ]]; then
        PATH_RULE_OK=false
        echo "  no rejection text for path: ${p}"
    fi
done
NGINX_SELF_CALLS="$(docker compose logs registry --since 1m 2>/dev/null | grep -c '/api/servers/\.\.' || true)"
if [[ "${PATH_RULE_OK}" == true && "${NGINX_SELF_CALLS}" == "0" ]]; then
    pass "1.2.6 every unsafe path is rejected locally, none reach the registry"
else
    fail "1.2.6 path rule check failed (see above)"
fi

# ---------------------------------------------------------------------------
# Test 1.2.7: tool names.
# ---------------------------------------------------------------------------
log "Test 1.2.7: tool names"
CONTROL_CHAR_TEXT="$(call "${ADMIN_TOKEN}" invoke_mcp_tool "$(printf '{"server_path": "/currenttime", "tool_name": "bad\\u0007name", "arguments": {}}')" | jq -r '.result.content[0].text // empty')"
LONG_NAME="$(printf 'x%.0s' {1..129})"
LONG_NAME_TEXT="$(call "${ADMIN_TOKEN}" invoke_mcp_tool "{\"server_path\": \"/currenttime\", \"tool_name\": \"${LONG_NAME}\", \"arguments\": {}}" | jq -r '.result.content[0].text // empty')"
if [[ -n "${CONTROL_CHAR_TEXT}" && -n "${LONG_NAME_TEXT}" ]]; then
    pass "1.2.7 control-character and over-length tool names are rejected locally"
else
    fail "1.2.7 expected both invalid tool names to be rejected locally"
fi

# ---------------------------------------------------------------------------
# Test 5.2: request body inspection.
# ---------------------------------------------------------------------------
log "Test 5.2: request body inspection"
BODY_DIRECTIVE_COUNT="$(docker compose exec -T registry sh -c 'grep -c "client_body_buffer_size 256k" /etc/nginx/conf.d/*.conf 2>/dev/null | awk -F: "{s+=\$2} END{print s}"' || echo 0)"
LUA_CAPTURE_COUNT="$(docker compose exec -T registry sh -c 'grep -c "capture_body.lua" /etc/nginx/conf.d/*.conf 2>/dev/null | awk -F: "{s+=\$2} END{print s}"' || echo 0)"
if [[ "${BODY_DIRECTIVE_COUNT}" == "${LUA_CAPTURE_COUNT}" && "${BODY_DIRECTIVE_COUNT}" -gt 0 ]]; then
    pass "5.2 client_body_buffer_size present on every capture_body.lua location (${BODY_DIRECTIVE_COUNT})"
else
    fail "5.2 directive count (${BODY_DIRECTIVE_COUNT}) does not match capture_body.lua count (${LUA_CAPTURE_COUNT})"
fi

direct_call() { # direct_call <route_path> <tool> <bytes> -> prints the HTTP status code
    local hdr
    hdr="$(mktemp)"
    local common=(-H "X-Authorization: Bearer ${ADMIN_TOKEN}" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream")
    curl -sS -D "${hdr}" -o /dev/null -X POST "${REGISTRY_URL}$1/mcp" "${common[@]}" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
    local sid
    sid="$(grep -i '^mcp-session-id:' "${hdr}" | tr -d '\r' | awk '{print $2}')"
    local sess=()
    [[ -n "${sid}" ]] && sess=(-H "Mcp-Session-Id: ${sid}")
    curl -sS -o /dev/null -X POST "${REGISTRY_URL}$1/mcp" "${common[@]}" "${sess[@]}" \
        -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    python3 -c "import json,sys; print(json.dumps({'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':sys.argv[1],'arguments':{'tz_name':'x'*int(sys.argv[2])}}}))" "$2" "$3" >"/tmp/direct-body-${RUN_ID}.json"
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${REGISTRY_URL}$1/mcp" "${common[@]}" "${sess[@]}" --data-binary "@/tmp/direct-body-${RUN_ID}.json")"
    rm -f "${hdr}" "/tmp/direct-body-${RUN_ID}.json"
    echo "${code}"
}

BODY_SIZE_OK=true
for bytes_and_expect in "9000:200" "204800:200" "307200:413"; do
    BYTES="${bytes_and_expect%%:*}"
    EXPECT="${bytes_and_expect##*:}"
    CODE="$(direct_call /currenttime current_time_by_timezone "${BYTES}")"
    if [[ "${CODE}" != "${EXPECT}" ]]; then
        BODY_SIZE_OK=false
        echo "  ${BYTES} bytes: expected ${EXPECT}, got ${CODE}"
    fi
done
if [[ "${BODY_SIZE_OK}" == true ]]; then
    pass "5.2 body-size thresholds: 9 KB and 200 KiB succeed, 300 KiB returns 413"
else
    fail "5.2 body-size thresholds: see details above"
fi

echo
echo "================================================================"
echo "Smoke test summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
echo "================================================================"

if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi
exit 0
