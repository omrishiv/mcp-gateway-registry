"""Property tests for the forward-proxy NO_PROXY startup check against urllib.

The registry refuses to start with the forward proxy enabled unless NO_PROXY
excludes the cloud credential endpoints, because botocore sends its IMDS and
container-credential requests through ``urllib.request`` proxy settings. These
tests pin the security property of that check: whenever the guard accepts a
NO_PROXY configuration, urllib (what botocore actually consults) bypasses the
proxy for every credential endpoint, so credential traffic never reaches it.
"""

import os
import urllib.request
from unittest.mock import patch

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.exceptions import UrlValidationError
from registry.utils import url_guard
from registry.utils.url_guard import (
    _PROXY_REQUIRED_NO_PROXY_IPS,
    _no_proxy_matches,
    _parse_no_proxy,
)

PROPERTY_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_PROXY_URL: str = "http://corp-proxy.internal:3128"
_ALL_CREDENTIAL_ENDPOINTS: str = ",".join(_PROXY_REQUIRED_NO_PROXY_IPS)

# Entry vocabulary: the endpoints themselves, their ip:port forms, CIDRs and
# numeric suffixes that cover them, unrelated hosts, and the wildcard.
_ENTRY_ATOMS: tuple[str, ...] = (
    *_PROXY_REQUIRED_NO_PROXY_IPS,
    *(f"{ip}:80" for ip in _PROXY_REQUIRED_NO_PROXY_IPS),
    *(f"{ip}:443" for ip in _PROXY_REQUIRED_NO_PROXY_IPS),
    "169.254.169.254.",
    "169.254.0.0/16",
    "169.254.170.0/24",
    "254.169.254",
    "254.170.2",
    "254.170.23",
    "169.254",
    "70.23",
    "10.0.0.1",
    "127.0.0.1",
    "localhost",
    "keycloak",
    "Svc.Cluster.Local",
    "foo",
    "*",
    "*.example.com",
)

_PROXY_ENV_KEYS: tuple[str, ...] = (
    "EGRESS_FORWARD_PROXY_ENABLED",
    "EGRESS_FORWARD_PROXY_CA_BUNDLE",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUEST_METHOD",
)

_STRING_CHECK_REASON: str = (
    "Known defect: the NO_PROXY startup check accepts a '*' entry inside a list "
    "and ip:port entries, neither of which urllib treats as excluding the bare "
    "credential endpoint address botocore requests."
)
_ENV_CHECK_REASON: str = (
    "Known defect: the startup check reads NO_PROXY with upper case winning and "
    "empty values skipped, while urllib lets a lower-case no_proxy (even an empty "
    "one) override it, and it accepts NO_PROXY entries urllib does not honour."
)


def _reset_caches() -> None:
    """Clear the cached forward-proxy configuration and TLS context."""
    url_guard._forward_proxy_config.cache_clear()
    url_guard._forward_proxy_ssl_context.cache_clear()


@pytest.fixture(autouse=True)
def _clear_proxy_caches():
    """The proxy configuration is lru_cached per process."""
    _reset_caches()
    yield
    _reset_caches()


@st.composite
def _no_proxy_entry(draw: st.DrawFn) -> str:
    """Draw one NO_PROXY entry with optional leading dots, padding and case.

    Args:
        draw: Hypothesis draw function.

    Returns:
        A single entry, possibly padded with spaces.
    """
    entry = draw(st.sampled_from(_ENTRY_ATOMS))
    entry = "." * draw(st.integers(min_value=0, max_value=2)) + entry
    if draw(st.booleans()):
        entry = entry.upper()
    left = " " * draw(st.integers(min_value=0, max_value=2))
    right = " " * draw(st.integers(min_value=0, max_value=2))
    return left + entry + right


_NO_PROXY_VALUES = st.lists(_no_proxy_entry(), min_size=0, max_size=6).map(",".join)


def _urllib_bypasses(
    ip: str,
    no_proxy: str,
) -> bool:
    """Return whether urllib bypasses the proxy for ``ip`` under ``no_proxy``.

    botocore calls ``urllib.request.proxy_bypass`` on the URL netloc, which for
    the credential endpoints is the bare address with no port, and on Linux
    that is ``proxy_bypass_environment``.

    Args:
        ip: Credential endpoint address.
        no_proxy: Raw NO_PROXY value.

    Returns:
        True when urllib would connect directly.
    """
    return urllib.request.proxy_bypass_environment(ip, {"no": no_proxy})


@pytest.mark.unit
class TestNoProxyMatcherAgainstUrllib:
    """The guard's NO_PROXY matcher never claims an exclusion urllib ignores."""

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason=_STRING_CHECK_REASON)
    @PROPERTY_SETTINGS
    @given(no_proxy=_NO_PROXY_VALUES)
    @example(no_proxy="*,foo")
    @example(no_proxy="169.254.169.254:80")
    def test_guard_exclusion_implies_urllib_bypass(self, no_proxy):
        """Property: _no_proxy_matches(parse(s), ip, 80) implies urllib bypasses ip."""
        patterns = _parse_no_proxy(no_proxy)
        for ip in _PROXY_REQUIRED_NO_PROXY_IPS:
            if _no_proxy_matches(patterns, ip, 80):
                assert _urllib_bypasses(ip, no_proxy), (
                    f"NO_PROXY={no_proxy!r}: guard excludes {ip}, urllib proxies it"
                )

    @PROPERTY_SETTINGS
    @given(no_proxy=_NO_PROXY_VALUES)
    @example(no_proxy="*")
    @example(no_proxy=" .169.254.169.254 ")
    def test_urllib_bypass_implies_guard_exclusion(self, no_proxy):
        """Property: whenever urllib bypasses an endpoint, the guard also excludes
        it, so the startup check never refuses a configuration that is safe."""
        patterns = _parse_no_proxy(no_proxy)
        for ip in _PROXY_REQUIRED_NO_PROXY_IPS:
            if _urllib_bypasses(ip, no_proxy):
                assert _no_proxy_matches(patterns, ip, 80), (
                    f"NO_PROXY={no_proxy!r}: urllib bypasses {ip}, guard does not"
                )


_ENV_VALUE = st.none() | st.just("") | _NO_PROXY_VALUES


@st.composite
def _proxy_environments(draw: st.DrawFn) -> dict[str, str]:
    """Draw a forward-proxy environment with both NO_PROXY spellings.

    Args:
        draw: Hypothesis draw function.

    Returns:
        Environment variables to apply, with absent keys omitted.
    """
    env = {"EGRESS_FORWARD_PROXY_ENABLED": "true"}
    for proxy_key in draw(
        st.sampled_from((("HTTP_PROXY",), ("http_proxy",), ("HTTP_PROXY", "HTTPS_PROXY")))
    ):
        env[proxy_key] = _PROXY_URL
    for no_proxy_key in ("NO_PROXY", "no_proxy"):
        value = draw(_ENV_VALUE)
        if value is not None:
            env[no_proxy_key] = value
    return env


def _credential_endpoints_proxied_by_urllib() -> list[str]:
    """Return the credential endpoints urllib would send to the proxy.

    Reads the current process environment the way botocore does: the proxy map
    from ``getproxies_environment`` and the bypass decision from
    ``proxy_bypass_environment`` on the bare endpoint address.

    Returns:
        Endpoint addresses that would be proxied over plain HTTP.
    """
    proxies = urllib.request.getproxies_environment()
    if not proxies.get("http"):
        return []
    return [
        ip
        for ip in _PROXY_REQUIRED_NO_PROXY_IPS
        if not urllib.request.proxy_bypass_environment(ip, proxies)
    ]


def _startup_accepts(
    env: dict[str, str],
) -> tuple[bool, list[str]]:
    """Run the real startup check under ``env`` and ask urllib the same question.

    Args:
        env: Proxy-related environment variables to apply.

    Returns:
        Whether startup succeeded, and the endpoints urllib would proxy.
    """
    with patch.dict(os.environ):
        for key in _PROXY_ENV_KEYS:
            os.environ.pop(key, None)
        os.environ.update(env)
        _reset_caches()
        try:
            url_guard.validate_forward_proxy_config()
            accepted = True
        except UrlValidationError:
            accepted = False
        proxied = _credential_endpoints_proxied_by_urllib()
    _reset_caches()
    return accepted, proxied


@pytest.mark.unit
class TestStartupCheckAgainstUrllib:
    """validate_forward_proxy_config only starts when urllib would bypass the proxy."""

    @pytest.mark.xfail(strict=True, raises=AssertionError, reason=_ENV_CHECK_REASON)
    @PROPERTY_SETTINGS
    @given(env=_proxy_environments())
    @example(
        env={
            "EGRESS_FORWARD_PROXY_ENABLED": "true",
            "HTTP_PROXY": _PROXY_URL,
            "NO_PROXY": _ALL_CREDENTIAL_ENDPOINTS,
            "no_proxy": "localhost",
        }
    )
    @example(
        env={
            "EGRESS_FORWARD_PROXY_ENABLED": "true",
            "HTTP_PROXY": _PROXY_URL,
            "NO_PROXY": _ALL_CREDENTIAL_ENDPOINTS,
            "no_proxy": "",
        }
    )
    @example(
        env={"EGRESS_FORWARD_PROXY_ENABLED": "true", "HTTP_PROXY": _PROXY_URL, "NO_PROXY": "*,foo"}
    )
    def test_accepted_startup_means_urllib_bypasses_credentials(self, env):
        """Property: if startup succeeds with the proxy enabled, urllib bypasses
        the proxy for every credential endpoint under the same environment."""
        accepted, proxied = _startup_accepts(env)
        if accepted:
            assert not proxied, f"startup accepted {env!r} but urllib proxies {proxied}"

    @pytest.mark.parametrize(
        "no_proxy",
        [
            _ALL_CREDENTIAL_ENDPOINTS,
            "*",
            f"localhost, .{_PROXY_REQUIRED_NO_PROXY_IPS[0]} ,{','.join(_PROXY_REQUIRED_NO_PROXY_IPS[1:])}",
            "169.254",
        ],
    )
    def test_single_spelling_environments_agree(self, no_proxy):
        """Property: with only upper-case NO_PROXY set, startup accepts exactly
        when urllib bypasses every credential endpoint."""
        env = {"EGRESS_FORWARD_PROXY_ENABLED": "true", "HTTP_PROXY": _PROXY_URL}
        env["NO_PROXY"] = no_proxy
        accepted, proxied = _startup_accepts(env)
        assert accepted == (not proxied), (accepted, proxied)
