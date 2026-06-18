"""Unit tests for RegistryMetricsMiddleware.extract_user_info.

After the registry header-forgery fix, the metrics user label is read from the
VERIFIED auth context (request.state.user_context), never from the forgeable
inbound X-User/X-Username headers.
"""

from types import SimpleNamespace

from registry.metrics.middleware import RegistryMetricsMiddleware
from registry.metrics.utils import hash_user_id


def _middleware() -> RegistryMetricsMiddleware:
    # BaseHTTPMiddleware needs an app arg; a no-op placeholder is fine here.
    return RegistryMetricsMiddleware(app=lambda *a, **k: None)


def _request(*, user_context=None, headers=None):
    state = SimpleNamespace()
    if user_context is not None:
        state.user_context = user_context
    return SimpleNamespace(state=state, headers=headers or {})


class TestExtractUserInfo:
    def test_reads_verified_context_username(self) -> None:
        mw = _middleware()
        req = _request(user_context={"username": "alice"})
        assert mw.extract_user_info(req) == hash_user_id("alice")

    def test_ignores_forgeable_headers(self) -> None:
        # X-User header is present and forged, but no verified context → anonymous.
        mw = _middleware()
        req = _request(user_context=None, headers={"X-User": "attacker"})
        assert mw.extract_user_info(req) == hash_user_id("anonymous")

    def test_anonymous_when_no_context(self) -> None:
        mw = _middleware()
        req = _request()
        assert mw.extract_user_info(req) == hash_user_id("anonymous")

    def test_anonymous_when_context_has_no_username(self) -> None:
        mw = _middleware()
        req = _request(user_context={"is_admin": False})
        assert mw.extract_user_info(req) == hash_user_id("anonymous")
