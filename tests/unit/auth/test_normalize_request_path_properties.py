"""``normalize_request_path`` must produce a stable normal form.

The auth server compares the raw ``X-Original-URL`` path with the location
nginx selected by running it through ``normalize_request_path``. The property
pinned here: the function returns an absolute path with no empty, ``.`` or
``..`` segment, and on input without ``%`` (where decoding is the identity) a
second application changes nothing, so the comparison never depends on how
many times a caller normalized the path.
"""

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.auth.resource_binding import normalize_request_path

_DOT_SEGMENTS: frozenset[str] = frozenset({".", ".."})
_PERCENT_FREE_TOKENS: tuple[str, ...] = ("/", ".", "..", ";", "?", "#", "a", "b", "//")
_PERCENT_TOKENS: tuple[str, ...] = ("%2e", "%2E", "%2f", "%2F", "%25", "%3f", "%23", "%")
_PINNED_PATHS: tuple[str, ...] = (
    "",
    "/",
    "//a//b/",
    "/a/../../b",
    "a/./b/",
    "/a?b/../c",
    "/a#b/../c",
    "/a;b/..",
    "/a/.%2e/b",
    "/a%2f..%2fb",
    "/%252e%252e/a",
)


def _path_from_tokens(
    tokens: list[str],
) -> str:
    """Join generated tokens into one candidate request path.

    Args:
        tokens: Path fragments drawn from a token alphabet.

    Returns:
        The concatenated path, which may or may not start with ``/``.
    """
    return "".join(tokens)


def _percent_free_paths() -> st.SearchStrategy[str]:
    """Generate request paths that contain no ``%`` character.

    Returns:
        A strategy mixing the routing-relevant token alphabet with arbitrary
        text that has every ``%`` removed.
    """
    token_paths = st.lists(st.sampled_from(_PERCENT_FREE_TOKENS), max_size=12).map(
        _path_from_tokens
    )
    free_text = st.text(max_size=24).map(lambda text: text.replace("%", ""))
    return st.one_of(token_paths, free_text)


def _any_paths() -> st.SearchStrategy[str]:
    """Generate request paths that may contain percent escapes.

    Returns:
        A strategy over the routing token alphabet, percent tokens and
        arbitrary percent triplets.
    """
    triplet = st.builds(
        lambda high, low: f"%{high}{low}",
        st.sampled_from("0123456789abcdefABCDEF"),
        st.sampled_from("0123456789abcdefABCDEF"),
    )
    token = st.one_of(
        st.sampled_from(_PERCENT_FREE_TOKENS),
        st.sampled_from(_PERCENT_TOKENS),
        triplet,
    )
    return st.lists(token, max_size=12).map(_path_from_tokens)


def _normal_form_violation(
    normalized: str,
) -> str | None:
    """Describe how ``normalized`` departs from the documented normal form.

    Args:
        normalized: A ``normalize_request_path`` result.

    Returns:
        A human readable reason, or None when the value is in normal form.
    """
    if not normalized.startswith("/"):
        return "does not start with '/'"
    if "//" in normalized:
        return "contains an empty segment"
    segments = normalized.split("/")[1:]
    if any(segment in _DOT_SEGMENTS for segment in segments):
        return "contains a '.' or '..' segment"
    return None


@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(path=_percent_free_paths())
@example(path="//a//b/")
@example(path="/a/../../b")
@example(path="/a?b/../c")
def test_normalize_request_path_is_idempotent_without_percent(
    path: str,
) -> None:
    """Property: for input without '%', normalizing twice equals normalizing once."""
    once = normalize_request_path(path)
    twice = normalize_request_path(once)
    assert twice == once, f"{path!r} -> {once!r} -> {twice!r}"


@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(path=_any_paths())
@example(path="/a/.%2e/b")
@example(path="/a%2f..%2f..%2fb")
def test_normalize_request_path_output_is_normal_form(
    path: str,
) -> None:
    """Property: every result is absolute with no empty, '.' or '..' segment."""
    normalized = normalize_request_path(path)
    violation = _normal_form_violation(normalized)
    assert violation is None, f"{path!r} -> {normalized!r} {violation}"


@pytest.mark.parametrize("path", _PINNED_PATHS)
def test_pinned_paths_are_normal_form(
    path: str,
) -> None:
    """Property: hand-picked encoded, dotted and doubled-slash paths reach normal form."""
    assert _normal_form_violation(normalize_request_path(path)) is None
