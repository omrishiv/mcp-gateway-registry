"""Server registration paths must already be in normal form.

A server path is interpolated into nginx ``location`` blocks and compared
against the normalized request path when binding authorization to a resource.
The property pinned here: every path accepted by ``validate_server_path`` and
by the ``ServerInfo`` path pattern is its own normal form, so no segment is
``.`` or ``..`` and ``normalize_request_path`` leaves it unchanged apart from a
trailing slash.
"""

import itertools
from collections.abc import Callable

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.auth.resource_binding import normalize_request_path
from registry.core.schemas import _SERVER_PATH_RE
from registry.exceptions import UrlValidationError
from registry.utils.url_guard import validate_server_path

_DOT_SEGMENTS: frozenset[str] = frozenset({".", ".."})
_ENUMERATED_SEGMENTS: tuple[str, ...] = (".", "..", "a", "b-c")
_MAX_ENUMERATED_SEGMENTS: int = 3
_PINNED_TRAVERSAL_PATHS: tuple[str, ...] = ("/peer/../github", "/../x")
_PLAIN_PATHS: tuple[str, ...] = (
    "/github",
    "/a/b-c",
    "/peer/github",
    "/peer/github/",
    "/my.server",
    "/.hidden",
    "/.../x",
    "/a_b/c-d.e",
    "/v1.2/tools",
)


def _accepted_by_url_guard(
    path: str,
) -> bool:
    """Return True if ``validate_server_path`` accepts ``path``."""
    try:
        validate_server_path(path)
    except UrlValidationError:
        return False
    return True


def _accepted_by_schema_pattern(
    path: str,
) -> bool:
    """Return True if the ``ServerInfo`` path pattern accepts ``path``."""
    return _SERVER_PATH_RE.fullmatch(path) is not None


def _enumerated_paths() -> list[str]:
    """Build every path of one to three segments drawn from the enumerated set.

    Returns:
        The enumerated paths followed by the pinned traversal paths.
    """
    paths = [
        "/" + "/".join(segments)
        for count in range(1, _MAX_ENUMERATED_SEGMENTS + 1)
        for segments in itertools.product(_ENUMERATED_SEGMENTS, repeat=count)
    ]
    return paths + list(_PINNED_TRAVERSAL_PATHS)


def _normal_form_violation(
    path: str,
) -> str | None:
    """Describe how ``path`` departs from normal form, or return None.

    Args:
        path: An absolute server path with no empty interior segments.

    Returns:
        A short description of the violation, or None if ``path`` is normal.
    """
    dot_segments = [segment for segment in path.split("/") if segment in _DOT_SEGMENTS]
    if dot_segments:
        return f"dot segments {dot_segments!r}"
    expected = path.rstrip("/") or "/"
    normalized = normalize_request_path(path)
    if normalized != expected:
        return f"normalizes to {normalized!r}, expected {expected!r}"
    return None


def _path_strategy() -> st.SearchStrategy[str]:
    """Generate absolute paths over the allowed charset with non-empty segments.

    Returns:
        A strategy of paths such as ``/a.b/../c-d/``.
    """
    segment = st.one_of(
        st.sampled_from(sorted(_DOT_SEGMENTS)),
        st.from_regex(r"[A-Za-z0-9._\-]{1,8}", fullmatch=True),
    )
    return st.builds(
        lambda segments, trailing: "/" + "/".join(segments) + ("/" if trailing else ""),
        st.lists(segment, min_size=1, max_size=5),
        st.booleans(),
    )


_VALIDATORS = [
    pytest.param(_accepted_by_url_guard, id="validate_server_path"),
    pytest.param(_accepted_by_schema_pattern, id="server_path_re"),
]


@pytest.mark.parametrize("accepts", _VALIDATORS)
def test_enumerated_accepted_paths_are_normal_form(
    accepts: Callable[[str], bool],
) -> None:
    """Property: every accepted path of 1 to 3 enumerated segments is in normal form."""
    violations = {
        path: violation
        for path in _enumerated_paths()
        if accepts(path) and (violation := _normal_form_violation(path)) is not None
    }

    assert violations == {}, f"accepted non-normal server paths: {violations!r}"


@pytest.mark.parametrize("accepts", _VALIDATORS)
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(path=_path_strategy())
@example(path="/peer/../github")
@example(path="/../x")
def test_generated_accepted_paths_are_normal_form(
    accepts: Callable[[str], bool],
    path: str,
) -> None:
    """Property: every accepted path over the allowed charset is in normal form."""
    if accepts(path):
        violation = _normal_form_violation(path)
        assert violation is None, f"accepted non-normal server path {path!r}: {violation}"


@pytest.mark.parametrize("accepts", _VALIDATORS)
@pytest.mark.parametrize("path", _PLAIN_PATHS)
def test_plain_paths_are_accepted_and_normal_form(
    accepts: Callable[[str], bool],
    path: str,
) -> None:
    """Property: plain registration paths stay accepted and are already normal form."""
    assert accepts(path), f"plain server path {path!r} must be accepted"
    assert _normal_form_violation(path) is None
