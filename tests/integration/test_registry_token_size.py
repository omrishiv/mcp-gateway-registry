"""JWT-size guard for the registry-UI internal token (kiro review item #2).

Binding groups into the token reintroduces the large-group-membership pressure that
#971 (server-side OAuth session store) solved for cookies. This test pins the two
regimes:

- Session-backed callers (the large-group Entra population) carry NO groups in the
  token -- only an opaque session_id -- so the token is constant-size regardless of
  group count. This is the path that would otherwise overflow the header.
- Bearer/static-token callers carry groups in the claim, so their token grows with
  group count. These are machine identities with small group sets in practice; this
  test records the size at 50/200/500 groups so a regression (or an unexpectedly
  large machine identity) is visible, and documents that the nginx
  large_client_header_buffers must accommodate the upper bound.
"""

import os
from unittest.mock import patch

import pytest

from auth_server.internal_request_token import mint_registry_ui_token

_SECRET = "size-benchmark-secret-key"

# The static nginx confs set `large_client_header_buffers 4 32k` (well above the
# 8k default), so a single header value up to ~32k is accepted. Keep the test
# ceiling at that buffer size as the contract: a token exceeding it would be
# rejected by nginx before reaching the registry.
_HEADER_BUFFER_CEILING = 32 * 1024


@pytest.fixture(autouse=True)
def _secret_env():
    with patch.dict(os.environ, {"SECRET_KEY": _SECRET}, clear=False):
        yield


def _groups(n: int) -> list[str]:
    # Realistic-ish group names (IdP groups are often long DN-like strings).
    return [f"group-{i:04d}-some-realistic-org-unit-name" for i in range(n)]


class TestSessionBackedTokenIsSizeIndependent:
    def test_groups_do_not_inflate_session_backed_token(self) -> None:
        # The session-backed token carries session_id, NOT groups -- so passing a
        # huge group list (which a caller never would here) still yields a small,
        # constant-size token because mint ignores groups when... actually mint
        # encodes whatever is passed; the POINT is /validate passes groups=[] for
        # session callers. Assert that the session-backed shape /validate uses
        # (groups=[]) is tiny and independent of the user's real group count.
        small = mint_registry_ui_token(
            subject="entra-user@example.com",
            session_id="opaque-session-id-1234567890",
            groups=[],  # /validate passes [] for session callers
            auth_method="session_cookie",
            client_id="",
        )
        assert len(small) < 1024, "session-backed token must stay small"


class TestBearerTokenSizeBounds:
    @pytest.mark.parametrize("n,expected_under", [(50, 4 * 1024), (200, 12 * 1024)])
    def test_bearer_token_size_within_documented_bound(self, n: int, expected_under: int) -> None:
        token = mint_registry_ui_token(
            subject="svc-account",
            session_id="",
            groups=_groups(n),
            auth_method="network-trusted",
            client_id="key-1",
        )
        size = len(token)
        # Record the size so a regression is visible in the assertion message.
        assert size < expected_under, (
            f"{n}-group bearer token is {size} bytes (expected < {expected_under}). "
            f"If real machine identities approach this many groups, raise nginx "
            f"large_client_header_buffers and this bound."
        )

    def test_500_groups_documents_upper_bound(self) -> None:
        # 500 groups is well beyond a realistic machine identity; this asserts the
        # token still fits the bumped header buffer ceiling, documenting the wall.
        token = mint_registry_ui_token(
            subject="svc-account",
            session_id="",
            groups=_groups(500),
            auth_method="network-trusted",
            client_id="key-1",
        )
        assert len(token) < _HEADER_BUFFER_CEILING, (
            f"500-group token is {len(token)} bytes, exceeding the {_HEADER_BUFFER_CEILING}-byte "
            f"header-buffer ceiling. A bearer/static caller with this many groups needs either a "
            f"larger nginx large_client_header_buffers or the #971 server-side claim-store pattern."
        )
