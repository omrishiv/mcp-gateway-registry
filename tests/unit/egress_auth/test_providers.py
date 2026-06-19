"""Provider registry + resolver tests."""

import pytest

from registry.egress_auth.providers import (
    PROVIDER_REGISTRY,
    list_provider_names,
    resolve_provider,
)
from registry.egress_auth.schemas import TokenEndpointAuthStyle


@pytest.mark.unit
class TestProviderRegistry:
    @pytest.mark.parametrize("name", ["github", "google", "atlassian", "microsoft", "slack"])
    def test_builtin_present_and_wellformed(self, name):
        cfg = PROVIDER_REGISTRY[name]
        assert cfg.name == name
        assert cfg.authorize_url.startswith("https://")
        assert cfg.token_url.startswith("https://")

    def test_list_includes_custom(self):
        names = list_provider_names()
        assert "custom" in names
        assert "github" in names

    def test_github_has_form_parser(self):
        assert PROVIDER_REGISTRY["github"].token_response_parser == "github_form"

    def test_slack_has_nested_parser(self):
        assert PROVIDER_REGISTRY["slack"].token_response_parser == "slack_nested"

    def test_google_offline_params(self):
        params = PROVIDER_REGISTRY["google"].extra_authorize_params
        assert params.get("access_type") == "offline"
        assert params.get("prompt") == "consent"


@pytest.mark.unit
class TestResolveProvider:
    def test_resolve_builtin(self):
        cfg = resolve_provider({"provider": "github"})
        assert cfg.name == "github" and cfg.is_builtin

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown egress provider"):
            resolve_provider({"provider": "bogus"})

    def test_missing_provider_raises(self):
        with pytest.raises(ValueError, match="provider is required"):
            resolve_provider({})

    def test_custom_requires_urls(self):
        with pytest.raises(ValueError, match="custom_authorize_url and custom_token_url"):
            resolve_provider({"provider": "custom"})

    def test_custom_assembled(self):
        cfg = resolve_provider(
            {
                "provider": "custom",
                "custom_authorize_url": "https://idp.example/authorize",
                "custom_token_url": "https://idp.example/token",
                "custom_scope_separator": ",",
                "custom_token_auth_style": "basic_header",
            }
        )
        assert cfg.name == "custom" and not cfg.is_builtin
        assert cfg.authorize_url == "https://idp.example/authorize"
        assert cfg.scope_separator == ","
        assert cfg.token_endpoint_auth_style == TokenEndpointAuthStyle.BASIC_HEADER
        assert cfg.use_pkce is True
