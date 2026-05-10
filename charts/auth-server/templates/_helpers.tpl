{{/*
Reserved env var names for the auth-server chart.

Users must not supply these via .Values.extraEnv. The list is the union of:
  - the superset of names the chart may render into `env:` (including
    every conditional branch), and
  - every key the chart sources via `envFrom` from stack-level or
    per-chart secrets/configmaps.

Sections (in order below):
  1. env: block — IdP secrets via valueFrom (conditional)
  2. auth-server-app-log-config configmap
  3. auth-server per-chart secret
  4. keycloak-client-secret (runtime-created by keycloak-configure Job)
  5. mongo-credentials secret
  6. shared-secret (stack-level)

Over-rejection is preferred to under-rejection: a user attempting to
inject one of these via extraEnv gets a clear template-render error.
*/}}
{{- define "auth-server.reservedEnvNames" -}}
- ENTRA_CLIENT_SECRET
- OKTA_CLIENT_SECRET
- OKTA_M2M_CLIENT_SECRET
- OKTA_API_TOKEN
- AUTH0_CLIENT_SECRET
- AUTH0_M2M_CLIENT_SECRET
- AUTH0_MANAGEMENT_API_TOKEN
- APP_LOG_BACKUP_COUNT
- APP_LOG_CENTRALIZED_ENABLED
- APP_LOG_CENTRALIZED_TTL_DAYS
- APP_LOG_EXCLUDED_LOGGERS
- APP_LOG_LEVEL
- APP_LOG_MAX_BYTES
- APP_LOG_MONGODB_BUFFER_SIZE
- APP_LOG_MONGODB_FLUSH_INTERVAL_SECONDS
- AUTH_PROVIDER
- AUTH_SERVER_EXTERNAL_URL
- AWS_REGION
- COGNITO_CLIENT_ID
- COGNITO_CLIENT_SECRET
- COGNITO_DOMAIN
- COGNITO_ENABLED
- COGNITO_USER_POOL_ID
- ENTRA_CLIENT_ID
- ENTRA_ENABLED
- ENTRA_LOGIN_BASE_URL
- ENTRA_TENANT_ID
- FEDERATION_ENCRYPTION_KEY
- FEDERATION_STATIC_TOKEN
- FEDERATION_STATIC_TOKEN_AUTH_ENABLED
- JWT_AUDIENCE
- JWT_ISSUER
- KEYCLOAK_ENABLED
- KEYCLOAK_EXTERNAL_URL
- KEYCLOAK_REALM
- KEYCLOAK_URL
- MAX_TOKENS_PER_USER_PER_HOUR
- OAUTH_STORE_TOKENS_IN_SESSION
- OKTA_AUTH_SERVER_ID
- OKTA_CLIENT_ID
- OKTA_DOMAIN
- OKTA_ENABLED
- REGISTRY_API_TOKEN
- REGISTRY_ID
- REGISTRY_ROOT_PATH
- REGISTRY_STATIC_TOKEN_AUTH_ENABLED
- REGISTRY_URL
- ROOT_PATH
- SECRET_KEY
- SESSION_COOKIE_DOMAIN
- SESSION_COOKIE_SECURE
- KEYCLOAK_CLIENT_ID
- KEYCLOAK_CLIENT_SECRET
- KEYCLOAK_M2M_CLIENT_ID
- KEYCLOAK_M2M_CLIENT_SECRET
- DOCUMENTDB_DATABASE
- DOCUMENTDB_HOST
- DOCUMENTDB_NAMESPACE
- DOCUMENTDB_PASSWORD
- DOCUMENTDB_PORT
- DOCUMENTDB_REPLICA_SET
- DOCUMENTDB_USERNAME
- DOCUMENTDB_USE_TLS
- MONGODB_CONNECTION_STRING
- STORAGE_BACKEND
- ASOR_ACCESS_TOKEN
- FEDERATION_CLIENT_ID
- FEDERATION_CLIENT_SECRET
- FEDERATION_TOKEN_ENDPOINT
- WORKDAY_TOKEN_URL
{{- end -}}

{{/*
Validate .Values.extraEnv for the auth-server chart.

Fails helm template render if any entry:
  - is missing the required `name` field,
  - shares a name with another entry in extraEnv (would silently shadow
    under Kubernetes merge rules), or
  - collides with a chart-reserved name.

Call as: {{- include "auth-server.validateExtraEnv" . -}}
*/}}
{{- define "auth-server.validateExtraEnv" -}}
{{- $reserved := fromYamlArray (include "auth-server.reservedEnvNames" .) -}}
{{- $seen := dict -}}
{{- range $i, $e := .Values.extraEnv -}}
  {{- if not $e.name -}}
    {{- fail (printf "auth-server.extraEnv[%d]: missing required 'name' field" $i) -}}
  {{- end -}}
  {{- if has $e.name $reserved -}}
    {{- fail (printf "auth-server.extraEnv[%d]: %q is a reserved variable managed by the chart (via env: or envFrom from the chart's secrets/configmaps). Remove it from extraEnv. If a values.yaml field controls it (e.g. app.jwtIssuer for JWT_ISSUER), set that instead; otherwise the value is managed by the chart's internal secrets and must not be overridden via extraEnv." $i $e.name) -}}
  {{- end -}}
  {{- if hasKey $seen $e.name -}}
    {{- fail (printf "auth-server.extraEnv[%d]: duplicate name %q (first seen at index %v)" $i $e.name (index $seen $e.name)) -}}
  {{- end -}}
  {{- $_ := set $seen $e.name $i -}}
{{- end -}}
{{- end -}}
