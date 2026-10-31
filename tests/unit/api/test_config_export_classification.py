"""Property tests for configuration export secret classification.

Pins the confidentiality property of ``GET /api/config/export``: a secret held
in the registry Settings reaches an export only when an admin passes both
``include_sensitive=true`` and ``confirm_sensitive_export=true``. Three parts
hold that up: every Settings field is explicitly classified as sensitive or
not, so a new field cannot reach an export unreviewed; a masked export never
carries credentials embedded as URL userinfo, whatever the field is named; and
the sensitive export fails closed on every flag combination other than the
double opt-in.
"""

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from registry.api.config_routes import (
    _EXPORT_FUNCTIONS,
    CONFIG_GROUPS,
    ExportFormat,
    _is_sensitive_field,
    _iter_group_fields,
    _rate_limit_cache,
)
from registry.auth.dependencies import enhanced_auth
from registry.core.config import Settings, settings

SECRET_SENTINEL: str = "SECRETVALUE"
SENSITIVE_SENTINEL: str = "SENTINEL-SENSITIVE-SECRET-KEY-0123456789"
SENSITIVE_PROBE_FIELD: str = "secret_key"
URL_FIELD_SUFFIXES: tuple[str, ...] = ("_url", "_uri", "_endpoint")
EXPORT_FORMATS: tuple[ExportFormat, ...] = tuple(ExportFormat)
FLAG_VALUES: tuple[str | None, ...] = (None, "true", "false", "maybe")

# URL forms that carry a credential in the userinfo component. The last two put
# the secret in the username slot, the usual shape for a token in a git or
# proxy URL.
USERINFO_URLS: tuple[str, ...] = (
    f"https://user:{SECRET_SENTINEL}@host.example/",
    f"https://:{SECRET_SENTINEL}@host.example/path",
    f"https://{SECRET_SENTINEL}@host.example/",
    f"http://{SECRET_SENTINEL}:x-oauth-basic@host.example:8443/api",
)

# Every registry Settings field that is NOT classified sensitive by the export
# classifier (the explicit is_sensitive flag in CONFIG_GROUPS, or a name match in
# _is_sensitive_field). When you add a Settings field, the classification test
# below fails until you decide: if the field can ever hold a secret, credential,
# private key or a URL with embedded credentials, mark it sensitive in
# CONFIG_GROUPS (or give it a name _is_sensitive_field matches); otherwise add it
# here. Remove names from this set when you delete the field.
NON_SENSITIVE_SETTINGS_FIELDS: frozenset[str] = frozenset(
    {
        "a2a_reverse_proxy_enabled",
        "agent_security_add_pending_tag",
        "agent_security_analyzers",
        "agent_security_block_unsafe_agents",
        "agent_security_scan_enabled",
        "agent_security_scan_on_registration",
        "agent_security_scan_timeout",
        "allow_caller_supplied_asset_id",
        "allowed_idp_groups",
        "ans_api_endpoint",
        "ans_api_timeout_seconds",
        "ans_integration_enabled",
        "ans_sync_interval_hours",
        "ans_verification_cache_ttl_seconds",
        "app_log_backup_count",
        "app_log_centralized_enabled",
        "app_log_centralized_ttl_days",
        "app_log_console_format",
        "app_log_dir",
        "app_log_excluded_loggers",
        "app_log_file_format",
        "app_log_level",
        "app_log_max_bytes",
        "app_log_mongodb_buffer_size",
        "app_log_mongodb_flush_interval_seconds",
        "ard_catalog_default_namespace",
        "ard_catalog_enabled",
        "ard_catalog_max_entries_per_type",
        "ard_publisher_domain",
        "ard_registry_enabled",
        "audit_log_dir",
        "audit_log_enabled",
        "audit_log_health_checks",
        "audit_log_local_retention_hours",
        "audit_log_mongodb_enabled",
        "audit_log_mongodb_ttl_days",
        "audit_log_require_durable",
        "audit_log_rotation_hours",
        "audit_log_rotation_max_mb",
        "audit_log_static_assets",
        "auth_provider",
        "auth_server_external_url",
        "auth_server_url",
        "batch_job_retention_days",
        "batch_max_concurrent_jobs_per_user",
        "batch_max_operations_per_job",
        "batch_max_request_bytes",
        "batch_worker_enabled",
        "batch_worker_lease_heartbeat_seconds",
        "batch_worker_lease_ttl_seconds",
        "batch_worker_poll_interval_seconds",
        "bind_host",
        "cimd_cache_ttl",
        "cimd_client_name",
        "cimd_contacts",
        "cimd_logo_uri",
        "cimd_publisher_enabled",
        "cimd_redirect_uris",
        "cimd_scope",
        "coding_assistants",
        "container_app_dir",
        "container_log_dir",
        "container_registry_dir",
        "cors_allowed_origins",
        "custom_entity_types_enabled",
        "custom_type_cache_ttl_seconds",
        "dedup_max_suggestions",
        "dedup_registration_hint_enabled",
        "dedup_score_threshold",
        "deployment_mode",
        "disable_ai_registry_tools_server",
        "documentdb_database",
        "documentdb_direct_connection",
        "documentdb_host",
        "documentdb_namespace",
        "documentdb_port",
        "documentdb_read_preference",
        "documentdb_replica_set",
        "documentdb_tls_ca_file",
        "documentdb_use_iam",
        "documentdb_use_tls",
        "egress_auth_enabled",
        "egress_consent_use_elicitation",
        "egress_forward_proxy_ca_bundle",
        "egress_forward_proxy_enabled",
        "egress_http_pool_connect_retries",
        "egress_http_pool_keepalive_expiry_seconds",
        "egress_http_pool_max_connections",
        "egress_http_pool_max_keepalive",
        "egress_oauth_callback_base_url",
        "egress_oauth_trusted_idp_hosts",
        "egress_obo_allowed_audiences",
        "egress_refresh_worker_interval_seconds",
        "egress_registry_internal_url",
        "egress_state_ttl_seconds",
        "embeddings_api_base",
        "embeddings_auth_mode",
        "embeddings_aws_region",
        "embeddings_encode_concurrency",
        "embeddings_extra_header_1",
        "embeddings_extra_header_2",
        "embeddings_extra_header_3",
        "embeddings_extra_header_4",
        "embeddings_extra_header_5",
        "embeddings_idp_allow_insecure",
        "embeddings_idp_client_id",
        "embeddings_idp_scope",
        "embeddings_idp_timeout_seconds",
        "embeddings_max_retries",
        "embeddings_model_dimensions",
        "embeddings_model_name",
        "embeddings_provider",
        "embeddings_request_timeout_seconds",
        "embeddings_response_format",
        "embeddings_retry_max_input_chars",
        "enable_wellknown_discovery",
        "entra_application_id_uri",
        "entra_enabled",
        "entra_group_admin_id",
        "entra_login_base_url",
        "entra_scope_format",
        "entra_tenant_id",
        "gateway_canonical_namespace_enabled",
        "gateway_egress_selfcheck_enabled",
        "gateway_generic_acquire_timeout_seconds",
        "gateway_generic_client_max_body_size",
        "gateway_generic_max_concurrency",
        "gateway_generic_proxy_enabled",
        "gateway_generic_require_bearer_for_writes",
        "gateway_generic_stream_max_bytes",
        "gateway_generic_stream_max_concurrency",
        "gateway_generic_stream_max_duration_seconds",
        "gateway_generic_stream_read_timeout_seconds",
        "gateway_generic_tls_verify",
        "gateway_proxy_allow_private_targets",
        "gateway_proxy_prefix",
        "generic_proxy_max_body_bytes",
        "github_api_base_url",
        "github_app_id",
        "github_app_installation_id",
        "github_extra_hosts",
        "health_check_interval_seconds",
        "health_check_timeout_seconds",
        "ide_connect_scope",
        "ide_oauth_callback_port",
        "ide_oauth_client_id",
        "idp_group_filter_prefix",
        "idp_user_group_fallback_enabled_providers",
        "internal_deployment_type",
        "internal_only_deployment",
        "keycloak_enabled",
        "keycloak_external_url",
        "keycloak_realm",
        "keycloak_url",
        "m2m_direct_registration_enabled",
        "max_custom_records_per_type",
        "max_custom_types",
        "max_websocket_connections",
        "mcp_advertised_scopes",
        "mcp_cloud_provider",
        "mcp_https_required",
        "mcp_proxy_max_body_bytes",
        "mcp_proxy_timeout",
        "mcp_resource_documentation_url",
        "mcp_tools_list_filter_enabled",
        "metrics_legacy_http_post",
        "mongodb_connection_string",
        "nginx_config_validation_required",
        "okta_auth_server_id",
        "okta_domain",
        "okta_enabled",
        "openbao_addr",
        "openbao_auth_method",
        "openbao_auth_mount",
        "openbao_kv_mount",
        "openbao_namespace",
        "openbao_role",
        "otel_exporter_otlp_metrics_temporality_preference",
        "otel_metric_export_interval_ms",
        "otel_otlp_endpoint",
        "otel_otlp_export_interval_ms",
        "rate_limit_agent_floor_per_min",
        "rate_limit_backend",
        "rate_limit_backend_timeout_ms",
        "rate_limit_definitions_cache_ttl_seconds",
        "rate_limit_fail_open",
        "rate_limit_quarantine_fail_closed",
        "rate_limit_user_floor_per_min",
        "rate_limiting_enabled",
        "registration_enforced_status",
        "registration_gate_auth_header_name",
        "registration_gate_auth_type",
        "registration_gate_enabled",
        "registration_gate_max_retries",
        "registration_gate_oauth2_client_id",
        "registration_gate_oauth2_scope",
        "registration_gate_timeout_seconds",
        "registration_gate_url",
        "registration_webhook_auth_header",
        "registration_webhook_timeout_seconds",
        "registration_webhook_url",
        "registry_contact_email",
        "registry_contact_url",
        "registry_description",
        "registry_id",
        "registry_mode",
        "registry_name",
        "registry_organization_name",
        "registry_url",
        "rum_allowed_hosts",
        "search_fusion_method",
        "search_log_query_text",
        "secret_store_backend",
        "secrets_manager_path_prefix",
        "security_add_pending_tag",
        "security_allow_unsafe_servers",
        "security_analyzers",
        "security_block_on_scan_failure",
        "security_block_unsafe_servers",
        "security_scan_enabled",
        "security_scan_on_registration",
        "security_scan_timeout",
        "session_cookie_domain",
        "session_cookie_name",
        "session_cookie_secure",
        "session_max_age_seconds",
        "show_agents_tab",
        "show_servers_tab",
        "show_skills_tab",
        "show_virtual_servers_tab",
        "skill_security_add_pending_tag",
        "skill_security_analyzers",
        "skill_security_block_unsafe_skills",
        "skill_security_scan_enabled",
        "skill_security_scan_on_registration",
        "skill_security_scan_timeout",
        "ssrf_allowed_cidrs",
        "ssrf_allowed_hosts",
        "storage_backend",
        "telemetry_debug",
        "telemetry_enabled",
        "telemetry_endpoint",
        "telemetry_heartbeat_interval_minutes",
        "telemetry_imds_probe_disabled",
        "telemetry_opt_out",
        "tool_filter_audit_log_level",
        "trusted_external_hosts",
        "ui_title",
        "update_check_enabled",
        "update_check_interval_hours",
        "vector_search_ef_search",
        "vector_search_overrequest",
        "websocket_broadcast_interval_ms",
        "websocket_cache_ttl_seconds",
        "websocket_max_batch_size",
        "websocket_send_timeout_seconds",
        "wellknown_cache_ttl",
    }
)


def _explicit_sensitive_flags() -> dict[str, bool]:
    """Collect the explicit ``is_sensitive`` flag for every exported field.

    Returns:
        Mapping of field name to True when any CONFIG_GROUPS tuple for it is
        flagged sensitive.
    """
    flags: dict[str, bool] = {}
    for group_def in CONFIG_GROUPS.values():
        for field_name, _display, is_sensitive, _subgroup in _iter_group_fields(group_def):
            flags[field_name] = flags.get(field_name, False) or bool(is_sensitive)
    return flags


def _is_classified_sensitive(
    field_name: str,
    flags: dict[str, bool],
) -> bool:
    """Return True when the export classifier treats ``field_name`` as sensitive.

    Args:
        field_name: Settings attribute name.
        flags: Output of ``_explicit_sensitive_flags``.

    Returns:
        True if the field is flagged sensitive or matches a sensitive name pattern.
    """
    return flags.get(field_name, False) or _is_sensitive_field(field_name)


def _url_valued_export_fields() -> tuple[str, ...]:
    """Return exported, non-sensitive Settings fields whose name marks a URL.

    Returns:
        Sorted field names ending in a URL suffix.

    Raises:
        RuntimeError: If no such field exists, so the value check cannot pass
            vacuously.
    """
    flags = _explicit_sensitive_flags()
    fields = sorted(
        name
        for name in flags
        if name in Settings.model_fields
        and not _is_classified_sensitive(name, flags)
        and name.endswith(URL_FIELD_SUFFIXES)
    )
    if not fields:
        raise RuntimeError("no URL-valued exported settings found; the value check is vacuous")
    return tuple(fields)


@contextmanager
def _export_client(
    is_admin: bool,
) -> Iterator[TestClient]:
    """Yield a TestClient for the registry app with a fixed caller and settings.

    The export reads a Settings copy whose ``secret_key`` holds a known sentinel,
    the audit sink is replaced with an AsyncMock (no datastore), and the
    per-user export throttle is cleared so every request is evaluated.

    Args:
        is_admin: Whether the authenticated caller is an administrator.

    Yields:
        TestClient bound to the registry app.
    """
    from registry.main import app

    caller: dict[str, Any] = {
        "username": "admin" if is_admin else "alice",
        "is_admin": is_admin,
        "auth_method": "session",
        "groups": ["mcp-registry-admin"] if is_admin else ["users"],
        "scopes": [],
    }
    overridden = settings.model_copy(update={SENSITIVE_PROBE_FIELD: SENSITIVE_SENTINEL})
    with ExitStack() as stack:
        stack.enter_context(patch("registry.api.config_routes.settings", overridden))
        audit_logger = getattr(app.state, "audit_logger", None)
        if audit_logger is not None:
            stack.enter_context(patch.object(audit_logger, "log_event", AsyncMock()))
        app.dependency_overrides[enhanced_auth] = lambda: caller
        stack.callback(app.dependency_overrides.pop, enhanced_auth, None)
        _rate_limit_cache.clear()
        stack.callback(_rate_limit_cache.clear)
        yield TestClient(app)


def _query(
    export_format: ExportFormat,
    include_sensitive: str | None,
    confirm_sensitive_export: str | None,
) -> dict[str, str]:
    """Build the export query string, omitting flags that are None.

    Args:
        export_format: Export format to request.
        include_sensitive: Raw ``include_sensitive`` value, or None to omit it.
        confirm_sensitive_export: Raw ``confirm_sensitive_export`` value, or None.

    Returns:
        Query parameter mapping.
    """
    params = {"format": export_format.value}
    if include_sensitive is not None:
        params["include_sensitive"] = include_sensitive
    if confirm_sensitive_export is not None:
        params["confirm_sensitive_export"] = confirm_sensitive_export
    return params


@pytest.mark.unit
def test_every_settings_field_is_classified() -> None:
    """Property: every Settings field is classified sensitive or listed as non-sensitive.

    The explicit non-sensitive set must equal the Settings fields minus the
    classified-sensitive ones, so a new field fails CI until someone classifies
    it and a stale or contradictory entry fails too.
    """
    flags = _explicit_sensitive_flags()
    all_fields = frozenset(Settings.model_fields)
    sensitive = frozenset(name for name in all_fields if _is_classified_sensitive(name, flags))

    unclassified = all_fields - sensitive - NON_SENSITIVE_SETTINGS_FIELDS
    stale = NON_SENSITIVE_SETTINGS_FIELDS - all_fields
    contradictory = NON_SENSITIVE_SETTINGS_FIELDS & sensitive

    assert not unclassified, (
        "Settings fields with no sensitivity classification; mark them sensitive in "
        f"CONFIG_GROUPS or add them to NON_SENSITIVE_SETTINGS_FIELDS: {sorted(unclassified)}"
    )
    assert not stale, (
        f"NON_SENSITIVE_SETTINGS_FIELDS names fields that do not exist: {sorted(stale)}"
    )
    assert not contradictory, (
        f"NON_SENSITIVE_SETTINGS_FIELDS lists fields now classified sensitive: {sorted(contradictory)}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("userinfo_url", USERINFO_URLS)
@pytest.mark.parametrize("export_format", EXPORT_FORMATS, ids=lambda f: f.value)
def test_masked_export_never_contains_url_userinfo(
    export_format: ExportFormat,
    userinfo_url: str,
) -> None:
    """Property: a masked export carries no credential from a URL's userinfo.

    Every exported, non-sensitive URL-named setting is set to a URL whose
    userinfo holds a secret; with ``include_sensitive=False`` the secret must
    not appear anywhere in the export, in every format.
    """
    url_fields = _url_valued_export_fields()
    overridden = settings.model_copy(update=dict.fromkeys(url_fields, userinfo_url))
    with patch("registry.api.config_routes.settings", overridden):
        output = _EXPORT_FUNCTIONS[export_format](False)

    leaking = [line.strip() for line in output.splitlines() if SECRET_SENTINEL in line]
    assert not leaking, (
        f"{export_format.value} export leaks URL userinfo in {len(leaking)} line(s): {leaking[:3]}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("confirm_sensitive_export", FLAG_VALUES, ids=str)
@pytest.mark.parametrize("include_sensitive", FLAG_VALUES, ids=str)
@pytest.mark.parametrize("export_format", EXPORT_FORMATS, ids=lambda f: f.value)
def test_sensitive_export_requires_acknowledgement(
    export_format: ExportFormat,
    include_sensitive: str | None,
    confirm_sensitive_export: str | None,
) -> None:
    """Property: an admin export contains a secret only under the double opt-in.

    Over every combination of absent, true, false and malformed flag values, the
    secret appears in the response if and only if both ``include_sensitive`` and
    ``confirm_sensitive_export`` are ``true``, and ``include_sensitive=true``
    without the acknowledgement is refused rather than downgraded.
    """
    with _export_client(is_admin=True) as client:
        response = client.get(
            "/api/config/export",
            params=_query(export_format, include_sensitive, confirm_sensitive_export),
        )

    double_opt_in = include_sensitive == "true" and confirm_sensitive_export == "true"
    secret_exported = SENSITIVE_SENTINEL in response.text
    assert secret_exported is double_opt_in, (
        f"secret exported={secret_exported} with include_sensitive={include_sensitive!r} "
        f"confirm_sensitive_export={confirm_sensitive_export!r} (status {response.status_code})"
    )
    if double_opt_in:
        assert response.status_code == 200
    if include_sensitive == "true" and confirm_sensitive_export != "true":
        assert response.status_code >= 400, (
            f"unacknowledged sensitive export was not refused: status {response.status_code}"
        )


@pytest.mark.unit
@pytest.mark.parametrize("export_format", EXPORT_FORMATS, ids=lambda f: f.value)
def test_sensitive_export_denied_to_non_admin(
    export_format: ExportFormat,
) -> None:
    """Property: a non-admin caller never receives a secret, even with both flags set."""
    with _export_client(is_admin=False) as client:
        response = client.get(
            "/api/config/export",
            params=_query(export_format, "true", "true"),
        )

    assert response.status_code == 403
    assert SENSITIVE_SENTINEL not in response.text
