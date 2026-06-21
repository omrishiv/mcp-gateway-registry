"""Unit tests for the OAuth AS-facade core (registry/egress_auth/as_facade.py).

Covers the pure logic: discovery documents (RFC 9728/8414), DCR loopback
enforcement (RFC 7591/8252), the single-use PKCE-bound authorization code, and
the server egress-config helpers. The route layer (session capture, provider
leg, auth-server mint delegation) is exercised separately.
"""

from datetime import UTC, datetime

import pytest

from registry.egress_auth import as_facade
from registry.egress_auth.oauth_engine import generate_pkce_verifier, pkce_challenge_s256

REGISTRY_URL = "https://gw.example.com"


def _now() -> datetime:
    return datetime(2026, 6, 19, 12, 0, 0, tzinfo=UTC)


@pytest.mark.unit
class TestDiscoveryDocuments:
    def test_metadata_url_and_resource_field_are_distinct(self):
        # RFC 9728: the resource_metadata URL LOCATES the PRM document; the
        # `resource` field INSIDE identifies the MCP server the client accesses.
        # They are DIFFERENT values -- the client validates `resource` against
        # the server URL it is talking to (.../github), so equating them with the
        # metadata-document URL breaks discovery (the live failure that motivated
        # this split).
        url = as_facade.build_resource_metadata_url(REGISTRY_URL, "github")
        doc = as_facade.build_protected_resource_metadata(REGISTRY_URL, "github")
        assert url == f"{REGISTRY_URL}/.well-known/oauth-protected-resource/github"
        assert doc["resource"] == f"{REGISTRY_URL}/github"
        assert doc["resource"] != url

    def test_resource_metadata_url_normalizes_leading_slash(self):
        with_slash = as_facade.build_resource_metadata_url(REGISTRY_URL, "/github")
        without = as_facade.build_resource_metadata_url(REGISTRY_URL, "github")
        assert with_slash == without

    def test_prm_points_at_gateway_egress_as_not_idp(self):
        doc = as_facade.build_protected_resource_metadata(
            REGISTRY_URL, "github", scopes_supported=["repo"]
        )
        # The authorization server is the gateway's OWN egress facade -- this is
        # what makes the IDE drive the third-party consent through us.
        assert doc["authorization_servers"] == [f"{REGISTRY_URL}/oauth2/egress"]
        assert doc["scopes_supported"] == ["repo"]

    def test_as_metadata_advertises_facade_endpoints_and_s256(self):
        doc = as_facade.build_authorization_server_metadata(REGISTRY_URL)
        assert doc["issuer"] == f"{REGISTRY_URL}/oauth2/egress"
        assert doc["authorization_endpoint"] == f"{REGISTRY_URL}/oauth2/egress/authorize"
        assert doc["token_endpoint"] == f"{REGISTRY_URL}/oauth2/egress/token"
        assert doc["registration_endpoint"] == f"{REGISTRY_URL}/oauth2/egress/register"
        assert doc["code_challenge_methods_supported"] == ["S256"]
        # Public client: no client authentication at the token endpoint.
        assert doc["token_endpoint_auth_methods_supported"] == ["none"]
        assert doc["grant_types_supported"] == ["authorization_code"]

    def test_trailing_slash_on_registry_url_is_normalized(self):
        doc = as_facade.build_authorization_server_metadata(REGISTRY_URL + "/")
        assert doc["issuer"] == f"{REGISTRY_URL}/oauth2/egress"

    def test_is_facade_issuer_path_matches_both_routing_modes(self):
        # Subdomain mode: client appends the bare issuer suffix.
        assert as_facade.is_facade_issuer_path("oauth2/egress")
        assert as_facade.is_facade_issuer_path("/oauth2/egress")
        # Path mode: the issuer carries the ROOT_PATH prefix (e.g. /registry),
        # so the client appends it after the well-known segment.
        assert as_facade.is_facade_issuer_path("registry/oauth2/egress")
        assert as_facade.is_facade_issuer_path("/registry/oauth2/egress")
        # An arbitrary deeper prefix still resolves (suffix match is the anchor).
        assert as_facade.is_facade_issuer_path("a/b/oauth2/egress")

    def test_is_facade_issuer_path_rejects_foreign_suffix(self):
        assert as_facade.is_facade_issuer_path("oauth2/ingress") is None
        assert as_facade.is_facade_issuer_path("some/other/issuer") is None
        assert as_facade.is_facade_issuer_path("") is None
        # Must end in the full suffix, not merely contain the last segment.
        assert as_facade.is_facade_issuer_path("egress") is None


@pytest.mark.unit
class TestDynamicClientRegistration:
    def test_loopback_ipv4_redirect_accepted(self):
        info = as_facade.register_client({"redirect_uris": ["http://127.0.0.1:53217/callback"]})
        assert info["client_id"].startswith("egress-")
        assert info["token_endpoint_auth_method"] == "none"
        assert info["redirect_uris"] == ["http://127.0.0.1:53217/callback"]

    def test_localhost_redirect_accepted(self):
        info = as_facade.register_client({"redirect_uris": ["http://localhost:8080/cb"]})
        assert info["client_id"]

    def test_private_use_scheme_redirect_accepted(self):
        # RFC 8252 §7.1 private-use scheme (no network host).
        info = as_facade.register_client({"redirect_uris": ["com.example.app:/callback"]})
        assert info["client_id"]

    def test_non_loopback_redirect_rejected(self):
        with pytest.raises(as_facade.RegistrationError):
            as_facade.register_client({"redirect_uris": ["https://evil.example.com/cb"]})

    def test_missing_redirect_uris_rejected(self):
        with pytest.raises(as_facade.RegistrationError):
            as_facade.register_client({})

    def test_empty_redirect_uris_rejected(self):
        with pytest.raises(as_facade.RegistrationError):
            as_facade.register_client({"redirect_uris": []})

    def test_one_bad_uri_in_list_rejects_whole_request(self):
        with pytest.raises(as_facade.RegistrationError):
            as_facade.register_client(
                {"redirect_uris": ["http://127.0.0.1:5000/cb", "https://evil.com/cb"]}
            )

    def test_issued_client_ids_are_unique(self):
        a = as_facade.register_client({"redirect_uris": ["http://127.0.0.1:1/cb"]})
        b = as_facade.register_client({"redirect_uris": ["http://127.0.0.1:1/cb"]})
        assert a["client_id"] != b["client_id"]


def _ctx(
    challenge: str, redirect_uri: str = "http://127.0.0.1:5000/cb"
) -> as_facade.ClientAuthzContext:
    return as_facade.ClientAuthzContext(
        client_id="egress-abc",
        redirect_uri=redirect_uri,
        client_state="client-state-xyz",
        code_challenge=challenge,
        code_challenge_method="S256",
        server_path="/github",
        resource=f"{REGISTRY_URL}/.well-known/oauth-protected-resource/github",
    )


def _identity() -> as_facade.CapturedIdentity:
    return as_facade.CapturedIdentity(
        user_id="alice",
        auth_method="oauth2",
        groups=["mcp-registry-user"],
        scopes=["openid", "email"],
        provider="github",
        server_path="/github",
    )


@pytest.mark.unit
class TestPendingSerialization:
    """Round-trip of leg-1 context + identity through the repo-stored JSON blob."""

    def test_pending_roundtrip(self):
        ctx = _ctx(pkce_challenge_s256(generate_pkce_verifier()))
        blob = as_facade.serialize_pending(ctx, _identity())
        ctx2, ident2 = as_facade.deserialize_pending(blob)
        assert ctx2 == ctx
        assert ident2 == _identity()

    def test_correlation_and_code_values_are_distinct_and_urlsafe(self):
        a, b = as_facade.new_correlation_id(), as_facade.new_correlation_id()
        c = as_facade.new_auth_code()
        assert a != b and a != c
        assert "/" not in c and "+" not in c  # url-safe token


@pytest.mark.unit
class TestAuthCodeRecord:
    """The auth-code record's serialization + pure verification (TTL + single-use
    are the repo's responsibility; these tests cover PKCE/redirect/client_id)."""

    def _record_and_verifier(self):
        verifier = generate_pkce_verifier()
        ctx = _ctx(pkce_challenge_s256(verifier))
        record = as_facade.build_auth_code_record(ctx, _identity())
        return record, verifier

    def test_roundtrip_serialization(self):
        record, _ = self._record_and_verifier()
        blob = as_facade.serialize_auth_code_record(record)
        record2 = as_facade.deserialize_auth_code_record(blob)
        assert record2 == record

    def test_verify_happy_path_returns_identity(self):
        record, verifier = self._record_and_verifier()
        ident = as_facade.verify_auth_code_record(record, verifier, "http://127.0.0.1:5000/cb")
        assert ident.user_id == "alice"
        assert ident.scopes == ["openid", "email"]

    def test_wrong_pkce_verifier_rejected(self):
        record, _ = self._record_and_verifier()
        with pytest.raises(as_facade.AuthCodeError):
            as_facade.verify_auth_code_record(
                record, generate_pkce_verifier(), "http://127.0.0.1:5000/cb"
            )

    def test_redirect_uri_mismatch_rejected(self):
        record, verifier = self._record_and_verifier()
        with pytest.raises(as_facade.AuthCodeError):
            as_facade.verify_auth_code_record(record, verifier, "http://127.0.0.1:9999/other")

    def test_client_id_binding_enforced_when_supplied(self):
        record, verifier = self._record_and_verifier()  # ctx client_id == "egress-abc"
        with pytest.raises(as_facade.AuthCodeError):
            as_facade.verify_auth_code_record(
                record, verifier, "http://127.0.0.1:5000/cb", client_id="egress-OTHER"
            )

    def test_client_id_binding_passes_for_matching_client(self):
        record, verifier = self._record_and_verifier()
        ident = as_facade.verify_auth_code_record(
            record, verifier, "http://127.0.0.1:5000/cb", client_id="egress-abc"
        )
        assert ident.user_id == "alice"

    def test_client_id_omitted_skips_binding(self):
        record, verifier = self._record_and_verifier()
        ident = as_facade.verify_auth_code_record(
            record, verifier, "http://127.0.0.1:5000/cb", client_id=None
        )
        assert ident.user_id == "alice"


@pytest.mark.unit
class TestServerConfigHelpers:
    def _server(self, **over) -> dict:
        base = {
            "egress_auth_mode": "oauth_user",
            "egress_oauth": {"provider": "github", "client_id": "Iv1.x"},
        }
        base.update(over)
        return base

    def test_egress_configured_true_for_valid_github(self):
        assert as_facade.is_server_egress_configured(self._server()) is True

    def test_none_server_not_configured(self):
        assert as_facade.is_server_egress_configured(None) is False

    def test_mode_none_not_configured(self):
        assert as_facade.is_server_egress_configured(self._server(egress_auth_mode="none")) is False

    def test_missing_egress_oauth_not_configured(self):
        assert as_facade.is_server_egress_configured(self._server(egress_oauth=None)) is False

    def test_unresolvable_provider_not_configured(self):
        bad = self._server(egress_oauth={"provider": "does-not-exist"})
        assert as_facade.is_server_egress_configured(bad) is False

    def test_advertised_scopes_pulled_from_config(self):
        srv = self._server(
            egress_oauth={"provider": "github", "client_id": "x", "scopes": ["repo", "read:org"]}
        )
        assert as_facade.server_advertised_scopes(srv) == ["repo", "read:org"]

    def test_advertised_scopes_empty_when_unset(self):
        assert as_facade.server_advertised_scopes({}) == []
