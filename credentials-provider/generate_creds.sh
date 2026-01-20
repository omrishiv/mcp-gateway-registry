#!/bin/bash
#
# Ingress Token Generator Script
#
# This script generates ingress authentication tokens using the configured
# identity provider (Keycloak or Entra ID based on AUTH_PROVIDER).
#
# Usage:
#   ./generate_creds.sh              # Generate ingress token
#   ./generate_creds.sh --verbose    # Enable verbose logging
#   ./generate_creds.sh --force      # Force new token generation
#   ./generate_creds.sh --help       # Show this help

set -e  # Exit on error

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env file if it exists
if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

# Also load main project .env file to get AUTH_PROVIDER
if [ -f "$(dirname "$SCRIPT_DIR")/.env" ]; then
    source "$(dirname "$SCRIPT_DIR")/.env"
fi

# Default values (empty - require explicit configuration)
VERBOSE=false
FORCE=false
IDENTITIES_FILE=""
AUTH_PROVIDER_ARG=""
KEYCLOAK_URL_ARG=""
KEYCLOAK_REALM_ARG=""
ENTRA_TENANT_ID_ARG=""
ENTRA_CLIENT_ID_ARG=""
ENTRA_CLIENT_SECRET_ARG=""
ENTRA_LOGIN_BASE_URL_ARG=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

show_help() {
    cat << EOF
Ingress Token Generator Script

This script generates ingress authentication tokens for the MCP Gateway.
It automatically uses the configured AUTH_PROVIDER (keycloak or entra).

USAGE:
    ./generate_creds.sh [OPTIONS]

OPTIONS:
    --auth-provider, -a PROVIDER       Auth provider: 'keycloak' or 'entra' (required if AUTH_PROVIDER env not set)
    --keycloak-url, -k URL             Keycloak server URL (required for keycloak if KEYCLOAK_EXTERNAL_URL env not set)
    --keycloak-realm, -r REALM         Keycloak realm name (default: mcp-gateway, or KEYCLOAK_REALM env)
    --entra-tenant-id TENANT_ID        Entra tenant ID (required for entra if ENTRA_TENANT_ID env not set)
    --entra-client-id CLIENT_ID        Entra client ID (required for entra if ENTRA_CLIENT_ID env not set)
    --entra-client-secret SECRET       Entra client secret (required for entra if ENTRA_CLIENT_SECRET env not set)
    --entra-login-url URL              Entra login base URL (default: https://login.microsoftonline.com)
    --identities-file, -i FILE         Custom path to identities JSON file (for entra)
    --force, -f                        Force new token generation, ignore existing tokens
    --verbose, -v                      Enable verbose debug logging
    --help, -h                         Show this help message

EXAMPLES:
    # Keycloak with explicit URL
    ./generate_creds.sh -a keycloak -k https://kc.example.com

    # Keycloak using environment variables
    export KEYCLOAK_EXTERNAL_URL=https://kc.example.com
    ./generate_creds.sh -a keycloak

    # Entra ID with explicit parameters
    ./generate_creds.sh -a entra --entra-tenant-id "tenant-id" --entra-client-id "client-id" --entra-client-secret "secret"

    # Entra ID using identities file
    ./generate_creds.sh -a entra -i /path/to/identities.json

ENVIRONMENT VARIABLES:
    General:
        AUTH_PROVIDER                  # IdP selection: 'keycloak' or 'entra'

    For Keycloak (AUTH_PROVIDER=keycloak):
        KEYCLOAK_EXTERNAL_URL          # Keycloak server URL (external/public URL)
        KEYCLOAK_REALM                 # Keycloak realm name (default: mcp-gateway)

    For Entra ID (AUTH_PROVIDER=entra):
        ENTRA_TENANT_ID                # Azure AD tenant ID
        ENTRA_CLIENT_ID                # App registration client ID
        ENTRA_CLIENT_SECRET            # App registration client secret
        ENTRA_LOGIN_BASE_URL           # Login base URL (default: https://login.microsoftonline.com)

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --auth-provider|-a)
            AUTH_PROVIDER_ARG="$2"
            shift 2
            ;;
        --keycloak-url|-k)
            KEYCLOAK_URL_ARG="$2"
            shift 2
            ;;
        --keycloak-realm|-r)
            KEYCLOAK_REALM_ARG="$2"
            shift 2
            ;;
        --entra-tenant-id)
            ENTRA_TENANT_ID_ARG="$2"
            shift 2
            ;;
        --entra-client-id)
            ENTRA_CLIENT_ID_ARG="$2"
            shift 2
            ;;
        --entra-client-secret)
            ENTRA_CLIENT_SECRET_ARG="$2"
            shift 2
            ;;
        --entra-login-url)
            ENTRA_LOGIN_BASE_URL_ARG="$2"
            shift 2
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --identities-file|-i)
            IDENTITIES_FILE="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Function to run Keycloak token generation
run_keycloak_auth() {
    log_info "Running Keycloak M2M token generation..."

    # Determine Keycloak URL (CLI arg > env var)
    local keycloak_url=""
    if [ -n "$KEYCLOAK_URL_ARG" ]; then
        keycloak_url="$KEYCLOAK_URL_ARG"
    elif [ -n "$KEYCLOAK_EXTERNAL_URL" ]; then
        keycloak_url="$KEYCLOAK_EXTERNAL_URL"
    fi

    # Determine Keycloak realm (CLI arg > env var > default)
    local keycloak_realm=""
    if [ -n "$KEYCLOAK_REALM_ARG" ]; then
        keycloak_realm="$KEYCLOAK_REALM_ARG"
    elif [ -n "$KEYCLOAK_REALM" ]; then
        keycloak_realm="$KEYCLOAK_REALM"
    else
        keycloak_realm="mcp-gateway"
    fi

    # Validate required parameters
    if [ -z "$keycloak_url" ]; then
        log_error "Keycloak URL is required. Provide via --keycloak-url or KEYCLOAK_EXTERNAL_URL environment variable."
        return 1
    fi

    log_info "Keycloak URL: $keycloak_url"
    log_info "Keycloak Realm: $keycloak_realm"

    local cmd="uv run '$SCRIPT_DIR/keycloak/generate_tokens.py' --all-agents"
    cmd="$cmd --keycloak-url '$keycloak_url'"
    cmd="$cmd --realm '$keycloak_realm'"

    if [ "$VERBOSE" = true ]; then
        cmd="$cmd --verbose"
    fi

    log_debug "Executing: $cmd"

    if eval "$cmd"; then
        log_info "Keycloak token generation completed successfully"
        return 0
    else
        log_error "Keycloak token generation failed"
        return 1
    fi
}

# Function to run Entra ID token generation
run_entra_auth() {
    log_info "Running Entra ID token generation..."

    # Export Entra environment variables (CLI args override env vars)
    if [ -n "$ENTRA_TENANT_ID_ARG" ]; then
        export ENTRA_TENANT_ID="$ENTRA_TENANT_ID_ARG"
    fi
    if [ -n "$ENTRA_CLIENT_ID_ARG" ]; then
        export ENTRA_CLIENT_ID="$ENTRA_CLIENT_ID_ARG"
    fi
    if [ -n "$ENTRA_CLIENT_SECRET_ARG" ]; then
        export ENTRA_CLIENT_SECRET="$ENTRA_CLIENT_SECRET_ARG"
    fi
    if [ -n "$ENTRA_LOGIN_BASE_URL_ARG" ]; then
        export ENTRA_LOGIN_BASE_URL="$ENTRA_LOGIN_BASE_URL_ARG"
    fi

    local cmd="uv run '$SCRIPT_DIR/entra/generate_tokens.py' --all-agents"

    if [ -n "$IDENTITIES_FILE" ]; then
        cmd="$cmd --identities-file '$IDENTITIES_FILE'"
    fi

    if [ "$VERBOSE" = true ]; then
        cmd="$cmd --verbose"
    fi

    log_debug "Executing: $cmd"

    if eval "$cmd"; then
        log_info "Entra ID token generation completed successfully"
        return 0
    else
        log_error "Entra ID token generation failed"
        return 1
    fi
}

# Main execution
main() {
    # CLI argument takes precedence over environment variable
    local auth_provider
    if [ -n "$AUTH_PROVIDER_ARG" ]; then
        auth_provider="$AUTH_PROVIDER_ARG"
    elif [ -n "$AUTH_PROVIDER" ]; then
        auth_provider="$AUTH_PROVIDER"
    else
        log_error "Auth provider is required. Provide via --auth-provider or AUTH_PROVIDER environment variable."
        log_error "Valid values: 'keycloak' or 'entra'"
        exit 1
    fi

    # Validate auth provider value
    if [ "$auth_provider" != "keycloak" ] && [ "$auth_provider" != "entra" ]; then
        log_error "Invalid auth provider: $auth_provider (must be 'keycloak' or 'entra')"
        exit 1
    fi

    log_info "Starting Ingress Token Generator"
    log_info "AUTH_PROVIDER: $auth_provider"

    local success=false

    if [ "$auth_provider" = "entra" ]; then
        if run_entra_auth; then
            success=true
        fi
    else
        if run_keycloak_auth; then
            success=true
        fi
    fi

    # Summary
    echo ""
    log_info "Summary:"
    if [ "$success" = true ]; then
        log_info "  Token generation: SUCCESS"
    else
        log_info "  Token generation: FAILED"
    fi

    log_info "Check ./.oauth-tokens/ for generated token files"

    if [ "$success" = false ]; then
        exit 1
    fi
}

# Run main function
main "$@"
