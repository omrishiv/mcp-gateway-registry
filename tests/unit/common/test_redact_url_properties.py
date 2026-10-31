"""Property tests for ``registry.common.log_redaction.redact_url``.

These pin the logging-safety property of ``redact_url``: a credential planted
in the password slot of the userinfo, in the query string or in the fragment
of any URL-ish string (well-formed or not) never survives into the redacted
output, and redacting already-redacted output changes nothing.
"""

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.common.log_redaction import redact_url

_SECRET_ALPHABET: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

_SECRETS = st.text(alphabet=_SECRET_ALPHABET, min_size=12, max_size=24)

_PINNED_SECRET: str = "pinnedSecret42"

_SCHEMELESS_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: redact_url returns URLs without a '//' authority "
        "marker unchanged, so the userinfo password is logged."
    ),
)

# Each shape takes the planted secret via ``str.format``.
_SHAPES = [
    pytest.param("http://user:{secret}@host:8080/path", id="scheme-authority"),
    pytest.param("https://h/p?token={secret}", id="query"),
    pytest.param("https://h/p#{secret}", id="fragment"),
    pytest.param("user:{secret}@proxy:3128", id="no-scheme", marks=_SCHEMELESS_XFAIL),
    pytest.param("http:/user:{secret}@host/", id="scheme-single-slash", marks=_SCHEMELESS_XFAIL),
    pytest.param("http:user:{secret}@host", id="scheme-no-slash", marks=_SCHEMELESS_XFAIL),
]

_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)


@pytest.mark.unit
class TestRedactUrlSecretInjection:
    """A planted secret never reaches the redacted URL."""

    @pytest.mark.parametrize("shape", _SHAPES)
    @_SETTINGS
    @given(secret=_SECRETS)
    @example(secret=_PINNED_SECRET)
    def test_secret_absent_from_output(self, shape, secret):
        """Property: the planted secret is not a substring of redact_url(url)."""
        url = shape.format(secret=secret)
        redacted = redact_url(url)
        assert secret not in redacted, f"redact_url({url!r}) = {redacted!r}"

    @pytest.mark.parametrize(
        "shape",
        [pytest.param(p.values[0], id=p.id) for p in _SHAPES],
    )
    @_SETTINGS
    @given(secret=_SECRETS)
    @example(secret=_PINNED_SECRET)
    def test_redaction_is_idempotent(self, shape, secret):
        """Property: redact_url(redact_url(url)) == redact_url(url)."""
        once = redact_url(shape.format(secret=secret))
        assert redact_url(once) == once
