"""Byline links rendered by scripts/render-doc-html.py carry only safe schemes.

The byline is built from metadata fetched from GitHub, so every markdown link in
it is untrusted. The property pinned here: after a browser applies its URL
preprocessing (trim C0 controls and spaces, drop tabs and newlines, lowercase
the scheme), every ``href`` in the rendered HTML is http, https, mailto or
scheme-less. The module is loaded by path because the filename uses hyphens.
"""

import importlib.util
import re
from html.parser import HTMLParser
from pathlib import Path
from types import ModuleType

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

_SCRIPT: Path = Path(__file__).resolve().parents[2] / "scripts" / "render-doc-html.py"
_SAFE_SCHEMES: frozenset[str] = frozenset({"http", "https", "mailto"})
_EMPHASIS_MARKERS: str = "*_"
_MAX_INSERTIONS: int = 4
_SCRIPT_URL: str = "javascript:alert`1`"
_HTTPS_URL: str = "https://example.com/a_b"
_SAFE_URL_SEEDS: tuple[str, ...] = (
    _HTTPS_URL,
    "http://example.com/x_y*z",
    "mailto:dev_team@example.com",
    "docs/design_notes.md",
    "#section_two",
    "../README.md",
)
_SCHEME_RE: re.Pattern[str] = re.compile(r"^([a-z][a-z0-9+.\-]*):")
_C0_OR_SPACE: str = "".join(chr(code) for code in range(0x21))
_TAB_OR_NEWLINE_RE: re.Pattern[str] = re.compile(r"[\t\n\r]")


def _load_module() -> ModuleType:
    """Load scripts/render-doc-html.py as a module.

    Returns:
        The executed script module.
    """
    spec = importlib.util.spec_from_file_location("render_doc_html", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_RENDER = _load_module()


class _HrefCollector(HTMLParser):
    """Collect every ``href`` attribute value, with character references decoded."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """Record the ``href`` attributes of one start tag."""
        self.hrefs.extend(value or "" for name, value in attrs if name == "href")


def _hrefs(
    rendered: str,
) -> list[str]:
    """Return every href in ``rendered`` HTML.

    Args:
        rendered: HTML produced by the byline renderer.

    Returns:
        The decoded href values in document order.
    """
    collector = _HrefCollector()
    collector.feed(rendered)
    collector.close()
    return collector.hrefs


def _browser_scheme(
    href: str,
) -> str | None:
    """Return the scheme a browser would parse from ``href``, or None if relative.

    Args:
        href: A decoded href attribute value.

    Returns:
        The lowercase scheme, or None when the URL has no scheme.
    """
    cleaned = _TAB_OR_NEWLINE_RE.sub("", href.strip(_C0_OR_SPACE)).lower()
    match = _SCHEME_RE.match(cleaned)
    return match.group(1) if match else None


def _unsafe_hrefs(
    url: str,
) -> list[str]:
    """Render ``[x](url)`` as a byline and return hrefs with a disallowed scheme.

    Args:
        url: The link target placed in the markdown link.

    Returns:
        Every rendered href whose browser-parsed scheme is not allowed.
    """
    rendered = _RENDER._inline_markdown_to_html(f"[x]({url})")
    return [
        href
        for href in _hrefs(rendered)
        if (scheme := _browser_scheme(href)) is not None and scheme not in _SAFE_SCHEMES
    ]


def _with_markers(
    base: str,
) -> st.SearchStrategy[str]:
    """Generate ``base`` with emphasis markers inserted at arbitrary positions.

    Args:
        base: The URL to perturb.

    Returns:
        A strategy of ``base`` with up to four ``*`` or ``_`` characters inserted.
    """

    def _insert(
        insertions: list[tuple[int, str]],
    ) -> str:
        chars = list(base)
        for position, marker in sorted(insertions, reverse=True):
            chars.insert(position, marker)
        return "".join(chars)

    insertion = st.tuples(
        st.integers(min_value=0, max_value=len(base)),
        st.sampled_from(_EMPHASIS_MARKERS),
    )
    return st.lists(insertion, max_size=_MAX_INSERTIONS).map(_insert)


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: the byline renderer checks the href scheme before it strips "
        "emphasis markers, so java_script: becomes a live javascript: href."
    ),
)
@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(url=st.one_of(_with_markers(_SCRIPT_URL), _with_markers(_HTTPS_URL)))
@example(url="java_script:alert`1`")
def test_marker_perturbed_link_hrefs_have_safe_scheme(
    url: str,
) -> None:
    """Property: no rendered href has a scheme outside http, https, mailto or none."""
    unsafe = _unsafe_hrefs(url)

    assert unsafe == [], f"link target {url!r} rendered unsafe hrefs {unsafe!r}"


@settings(max_examples=200, derandomize=True, database=None, report_multiple_bugs=False)
@given(url=st.sampled_from(_SAFE_URL_SEEDS).flatmap(_with_markers))
def test_marker_perturbed_safe_link_hrefs_stay_safe(
    url: str,
) -> None:
    """Property: perturbing an http, https, mailto or relative link keeps every href safe."""
    unsafe = _unsafe_hrefs(url)

    assert unsafe == [], f"link target {url!r} rendered unsafe hrefs {unsafe!r}"
