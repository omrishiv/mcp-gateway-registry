"""Validation tests for the egress credential vault config (Phase 1).

Covers _validate_secret_store_backend (@field_validator) and the cross-field
_validate_egress_auth_config checks run in Settings.__init__:
- SECRET_STORE_BACKEND allowlist + normalization.
- L0: egress_auth_enabled=true requires a Mongo-family storage_backend.
- dev-fernet refused when ENVIRONMENT=production.
- callback base URL required when the feature is enabled.
"""

import pytest

from registry.core.config import ALLOWED_SECRET_STORES, Settings


def _valid_egress_kwargs(**overrides):
    base = {
        "egress_auth_enabled": True,
        "storage_backend": "mongodb-ce",
        "egress_oauth_callback_base_url": "https://gw.example",
        "secret_store_backend": "openbao",
    }
    base.update(overrides)
    return base


@pytest.mark.unit
@pytest.mark.core
class TestSecretStoreBackendAllowlist:
    @pytest.mark.parametrize("value", sorted(ALLOWED_SECRET_STORES))
    def test_every_allowlist_value_accepted(self, monkeypatch, value):
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        s = Settings(secret_store_backend=value)  # egress off -> no cross-field checks
        assert s.secret_store_backend == value

    @pytest.mark.parametrize("bad", ["vault", "aws", "fernet", "secretsmanager", "openbao "])
    def test_unknown_value_rejected(self, bad):
        # note: "openbao " (trailing space) normalizes to "openbao" and is OK;
        # exclude it from the bad set
        if bad.strip().lower() in ALLOWED_SECRET_STORES:
            s = Settings(secret_store_backend=bad)
            assert s.secret_store_backend == bad.strip().lower()
            return
        with pytest.raises(Exception) as exc:
            Settings(secret_store_backend=bad)
        assert "SECRET_STORE_BACKEND" in str(exc.value)

    def test_empty_coerces_to_dev_fernet(self):
        assert Settings(secret_store_backend="").secret_store_backend == "dev-fernet"


@pytest.mark.unit
@pytest.mark.core
class TestEgressCrossFieldValidation:
    def test_disabled_skips_all_checks(self, monkeypatch):
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        # egress off + file backend + dev-fernet + no callback url: all fine
        s = Settings(egress_auth_enabled=False, storage_backend="file")
        assert s.egress_auth_enabled is False

    def test_l0_file_backend_rejected_when_enabled(self, monkeypatch):
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        with pytest.raises(ValueError, match="Mongo-family STORAGE_BACKEND"):
            Settings(**_valid_egress_kwargs(storage_backend="file"))

    @pytest.mark.parametrize("backend", ["documentdb", "mongodb-ce", "mongodb", "mongodb-atlas"])
    def test_mongo_family_backends_accepted_when_enabled(self, monkeypatch, backend):
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        s = Settings(**_valid_egress_kwargs(storage_backend=backend))
        assert s.storage_backend == backend

    def test_callback_url_required_when_enabled(self, monkeypatch):
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        with pytest.raises(ValueError, match="EGRESS_OAUTH_CALLBACK_BASE_URL"):
            Settings(**_valid_egress_kwargs(egress_oauth_callback_base_url=""))

    def test_dev_fernet_refused_in_production(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        with pytest.raises(ValueError, match="dev-fernet is refused"):
            Settings(**_valid_egress_kwargs(secret_store_backend="dev-fernet"))

    def test_dev_fernet_allowed_outside_production(self, monkeypatch):
        monkeypatch.delenv("ENVIRONMENT", raising=False)
        s = Settings(**_valid_egress_kwargs(secret_store_backend="dev-fernet"))
        assert s.secret_store_backend == "dev-fernet"

    def test_secrets_manager_allowed_in_production(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        s = Settings(**_valid_egress_kwargs(secret_store_backend="secrets-manager"))
        assert s.secret_store_backend == "secrets-manager"
