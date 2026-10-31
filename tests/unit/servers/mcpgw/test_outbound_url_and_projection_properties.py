"""Property tests for mcpgw outbound URLs and response projection.

mcpgw turns tool arguments into registry URLs and turns registry responses into
model-facing output. These tests pin four security properties: a skill name the
tool accepts always lands in exactly one path segment of the registry URL; a
resource path reaches the registry as exactly the query value the caller gave;
the registry derives a resource URL that keeps the skill's origin, stays under
the skill's directory and names exactly the manifest file; and registrant
metadata and raw registry fields never reach the model unless the caller asked.
"""

import asyncio
import copy
import posixpath
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import (
    MagicMock,
    patch,
)
from urllib.parse import (
    parse_qs,
    urlsplit,
)

import httpx
import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st
from starlette.datastructures import Headers

from registry.utils.url_utils import derive_resource_url

# The mcpgw server depends on `fastmcp` which is not installed in the main
# project venv. Stub it out before importing the server module.
# FastMCP.tool() is a decorator, so make it a passthrough to keep the original
# async functions callable.
if "fastmcp" not in sys.modules:
    _fastmcp_stub = types.ModuleType("fastmcp")
    _fastmcp_stub.Context = type("Context", (), {})
    _mock_mcp = MagicMock()
    _mock_mcp.tool.return_value = lambda fn: fn  # decorator is a no-op
    _fastmcp_stub.FastMCP = MagicMock(return_value=_mock_mcp)
    sys.modules["fastmcp"] = _fastmcp_stub

# Add servers/mcpgw to sys.path so that `from models import ...` works
_mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
if _mcpgw_path not in sys.path:
    sys.path.insert(0, _mcpgw_path)

# Import (not re-import) the server module: popping it from sys.modules here
# would break sibling test modules that already hold a reference to the
# previously imported module object, since patch() targets would then resolve
# to a different module than the tools under test came from.

from servers.mcpgw import server as mcpgw_server  # noqa: E402
from servers.mcpgw.server import (  # noqa: E402
    _SKILL_NAME_PATTERN,
    MAX_WITHHELD_ITEMS,
    _dedupe_candidates,
    _without_unrequested_agent_card_metadata,
    _without_unrequested_metadata,
    get_skill_content,
    intelligent_tool_finder,
    search_registry,
)

# Captured before any test patches httpx.AsyncClient (the patch target is the
# shared httpx module attribute, so the fake factory needs the real class).
_REAL_ASYNC_CLIENT = httpx.AsyncClient

REGISTRY_BASE: str = "http://registry.test"
REGISTRY_HOST: str = "registry.test"
CALLER_TOKEN: str = "caller-token"
VALID_SKILL_NAME: str = "pr-review"

# The intended skill-name grammar, written independently of the production
# pattern: lower-case ASCII words joined by single hyphens.
_REFERENCE_SKILL_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_SKILL_NAME_CHARS: frozenset[str] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
_ASCII_SUFFIXES: tuple[str, ...] = tuple(chr(code) for code in range(128))

RECEIPT_ITEM_KEYS: frozenset[str] = frozenset(
    {"asset_type", "service_path", "name", "similarity_score"}
)

SKILL_MD_BASES: tuple[str, ...] = (
    "https://raw.githubusercontent.com/o/r/main/skills/demo/SKILL.md",
    "https://skills.example.com/team/demo/SKILL.md",
    "https://skills.example.com/team/demo/README.md",
)

# Characters a git file name may carry that are meaningful inside a URL.
_FILE_NAME_ALPHABET: str = "ab1.-_ ?#%2eEfF~@:;=&+"

PROPERTY_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_RESOURCE_URL_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: derive_resource_url interpolates the manifest path into the "
        "URL without percent-encoding, so '?', '#' and '%' in a file name change "
        "which URL the registry fetches with the skill's credential."
    ),
)


def _build_ctx() -> SimpleNamespace:
    """Build a FastMCP-like context carrying the caller's bearer token.

    Returns:
        A context object whose request headers are case-insensitive.
    """
    request = SimpleNamespace(headers=Headers(headers={"Authorization": f"Bearer {CALLER_TOKEN}"}))
    return SimpleNamespace(request_context=SimpleNamespace(request=request))


def _client_factory(
    handler,
):
    """Return an httpx.AsyncClient replacement that routes to `handler`.

    Args:
        handler: Callable taking an httpx.Request and returning an httpx.Response.

    Returns:
        A factory with the AsyncClient call signature that builds a real client
        on top of an in-memory transport.
    """

    def _factory(*args, **kwargs):
        return _REAL_ASYNC_CLIENT(
            transport=httpx.MockTransport(handler),
            timeout=kwargs.get("timeout"),
        )

    return _factory


def _run_tool(
    coro_factory,
    handler,
) -> dict[str, Any]:
    """Run one mcpgw tool in passthrough mode against an in-memory registry.

    Args:
        coro_factory: Zero-argument callable returning the tool coroutine.
        handler: MockTransport handler standing in for the registry.

    Returns:
        The tool's result dict.
    """
    with (
        patch.object(mcpgw_server, "REGISTRY_URL", REGISTRY_BASE),
        patch.object(mcpgw_server, "REGISTRY_API_TOKEN", ""),
        patch.object(mcpgw_server, "_m2m_manager", None),
        patch.object(mcpgw_server, "REGISTRY_EXTERNAL_URL", ""),
        patch.object(mcpgw_server.httpx, "AsyncClient", _client_factory(handler)),
    ):
        return asyncio.run(coro_factory())


def _capture_skill_requests(
    skill_name: str,
    resource_path: str | None,
) -> tuple[dict[str, Any], list[httpx.Request]]:
    """Call get_skill_content and record every request it sends the registry.

    Args:
        skill_name: The skill_name argument.
        resource_path: The resource_path argument.

    Returns:
        The tool result and the list of outbound requests.
    """
    seen: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"content": "# skill", "url": "https://skills.example"})

    result = _run_tool(
        lambda: get_skill_content(
            skill_name=skill_name,
            resource_path=resource_path,
            ctx=_build_ctx(),
        ),
        _handler,
    )
    return result, seen


# ---------------------------------------------------------------------------
# Outbound URL construction
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "suffix", _ASCII_SUFFIXES, ids=[f"0x{ord(c):02x}" for c in _ASCII_SUFFIXES]
)
def test_skill_name_pattern_rejects_unsafe_single_character_suffix(
    suffix: str,
) -> None:
    """Property: a valid name plus one ASCII character matches only for [a-z0-9]."""
    accepted = _SKILL_NAME_PATTERN.match(VALID_SKILL_NAME + suffix) is not None
    assert accepted is (suffix in _SKILL_NAME_CHARS), (
        f"pattern accepted={accepted} for suffix {suffix!r}"
    )


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(
    skill_name=st.one_of(
        st.text(max_size=24),
        st.from_regex(r"\A[a-z0-9]+(-[a-z0-9]+)*\Z", fullmatch=True),
        st.from_regex(r"\A\s*[a-z0-9]+(-[a-z0-9]+)*[\s/%.?#]*\Z", fullmatch=True),
    )
)
@example(skill_name="pr-review\n")
@example(skill_name="pr-review/../admin")
@example(skill_name="pr-review%2f..")
@example(skill_name="pr-review?x=1")
def test_skill_content_url_names_exactly_one_segment(
    skill_name: str,
) -> None:
    """Property: the tool either refuses or requests /api/skills/<name>/content.

    The name in the URL is the stripped argument and matches the intended
    grammar, so no argument can reach another registry route.
    """
    result, seen = _capture_skill_requests(skill_name, None)
    stripped = skill_name.strip()

    if not _REFERENCE_SKILL_NAME.fullmatch(stripped):
        assert seen == [], f"{skill_name!r} is not a skill name yet reached {seen[0].url}"
        assert result["status"] == "failed"
        return

    assert len(seen) == 1, f"expected one registry call for {skill_name!r}, got {len(seen)}"
    url = seen[0].url
    expected_path = f"/api/skills/{stripped}/content"
    assert url.host == REGISTRY_HOST
    assert url.path == expected_path
    assert url.raw_path == expected_path.encode("ascii")


_RESOURCE_PATHS = st.one_of(
    st.none(),
    st.text(max_size=24),
    st.text(alphabet="ab/. ?#&=+%;,\x00\r\n\u00e9\u2028", max_size=24),
)


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(resource_path=_RESOURCE_PATHS)
@example(resource_path="refs/a b+c%2F&resource=x#frag;y")
@example(resource_path="references/architecture.md")
@example(resource_path="")
def test_resource_query_value_reaches_registry_exactly(
    resource_path: str | None,
) -> None:
    """Property: the registry's parsed `resource` value equals the input, or nothing is sent.

    httpx's query encoding must not change, split or add to the value the
    registry matches against the manifest.
    """
    result, seen = _capture_skill_requests(VALID_SKILL_NAME, resource_path)

    if not seen:
        assert resource_path, "an absent resource_path must still fetch SKILL.md"
        assert result["status"] == "failed"
        return

    assert len(seen) == 1
    query = parse_qs(seen[0].url.query.decode("ascii"), keep_blank_values=True)
    expected = {"resource": [resource_path]} if resource_path else {}
    assert query == expected, f"resource_path {resource_path!r} reached the registry as {query!r}"


@st.composite
def _manifest_path(draw: st.DrawFn) -> str:
    """Draw a relative manifest path whose segments are valid git file names."""
    segments = draw(
        st.lists(
            st.text(alphabet=_FILE_NAME_ALPHABET, min_size=1, max_size=8).filter(
                lambda segment: segment not in (".", "..")
            ),
            min_size=1,
            max_size=3,
        )
    )
    return "/".join(segments)


def _base_directory(
    skill_md_url: str,
) -> str:
    """Return the URL path of the directory holding the skill's markdown file.

    Args:
        skill_md_url: The skill's SKILL.md (or other markdown) URL.

    Returns:
        The directory path, ending with "/".
    """
    return urlsplit(skill_md_url).path.rsplit("/", 1)[0] + "/"


def _parse_derived(
    derived: str,
) -> httpx.URL | None:
    """Parse a derived resource URL the way the fetch client would.

    Args:
        derived: URL returned by derive_resource_url.

    Returns:
        The parsed URL, or None when the client would refuse it (fail closed).
    """
    try:
        return httpx.URL(derived)
    except httpx.InvalidURL:
        return None


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(base=st.sampled_from(SKILL_MD_BASES), resource=_manifest_path())
@example(base=SKILL_MD_BASES[0], resource="references/a?b.md")
@example(base=SKILL_MD_BASES[0], resource="%2e%2e/secret.md")
def test_derived_resource_url_keeps_skill_origin(
    base: str,
    resource: str,
) -> None:
    """Property: the derived resource URL has the scheme, host and port of SKILL.md."""
    parsed = _parse_derived(derive_resource_url(base, resource))
    if parsed is None:
        return
    expected = httpx.URL(base)
    assert (parsed.scheme, parsed.host, parsed.port) == (
        expected.scheme,
        expected.host,
        expected.port,
    )


@pytest.mark.unit
@_RESOURCE_URL_XFAIL
@PROPERTY_SETTINGS
@given(base=st.sampled_from(SKILL_MD_BASES), resource=_manifest_path())
@example(base=SKILL_MD_BASES[0], resource="%2e%2e/secret.md")
def test_derived_resource_url_stays_under_skill_directory(
    base: str,
    resource: str,
) -> None:
    """Property: after percent-decoding and dot-segment removal, the path is under the skill dir."""
    parsed = _parse_derived(derive_resource_url(base, resource))
    if parsed is None:
        return
    resolved = posixpath.normpath(parsed.path)
    base_dir = _base_directory(base)
    assert resolved.startswith(base_dir), (
        f"manifest path {resource!r} resolves to {resolved!r}, outside {base_dir!r}"
    )


@pytest.mark.unit
@_RESOURCE_URL_XFAIL
@PROPERTY_SETTINGS
@given(base=st.sampled_from(SKILL_MD_BASES), resource=_manifest_path())
@example(base=SKILL_MD_BASES[0], resource="references/a?b.md")
def test_derived_resource_url_names_exactly_the_manifest_file(
    base: str,
    resource: str,
) -> None:
    """Property: the fetched URL names exactly <skill dir>/<manifest path>, with no query or fragment."""
    parsed = _parse_derived(derive_resource_url(base, resource))
    if parsed is None:
        return
    expected_path = _base_directory(base) + resource
    assert (parsed.path, parsed.query, parsed.fragment) == (expected_path, b"", ""), (
        f"manifest path {resource!r} fetched path={parsed.path!r} "
        f"query={parsed.query!r} fragment={parsed.fragment!r}"
    )


# ---------------------------------------------------------------------------
# Response projection
# ---------------------------------------------------------------------------

_JSON_VALUES = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=5)),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=5), children, max_size=3),
    ),
    max_leaves=8,
)

# metadata_fields values that name no key: absent, empty, or only separators
# and whitespace (including Unicode whitespace that str.strip removes).
_UNREQUESTED_FIELDS = st.one_of(
    st.none(),
    st.lists(st.sampled_from(("", " ", "\t", "\n", "\u00a0", "\u3000")), max_size=4).map(",".join),
)


@st.composite
def _record(draw: st.DrawFn) -> dict[str, Any]:
    """Draw a registry record that may carry metadata at the top and in its agent card."""
    record = draw(
        st.dictionaries(
            st.sampled_from(("path", "name", "description", "tags", "url")),
            _JSON_VALUES,
            max_size=4,
        )
    )
    if draw(st.booleans()):
        record["metadata"] = draw(_JSON_VALUES)
    if draw(st.booleans()):
        card = draw(st.dictionaries(st.sampled_from(("name", "skills", "url")), _JSON_VALUES))
        if draw(st.booleans()):
            card["metadata"] = draw(_JSON_VALUES)
        record["agent_card"] = card
    return record


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(record=_record(), metadata_fields=_UNREQUESTED_FIELDS)
def test_listing_projection_drops_unrequested_metadata(
    record: dict[str, Any],
    metadata_fields: str | None,
) -> None:
    """Property: with no key requested, top-level metadata is gone, the rest kept, input intact."""
    before = copy.deepcopy(record)
    projected = _without_unrequested_metadata(record, metadata_fields)

    assert record == before, "projection mutated its input"
    assert "metadata" not in projected
    assert projected == {k: v for k, v in before.items() if k != "metadata"}


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(record=_record(), metadata_fields=_UNREQUESTED_FIELDS)
def test_agent_card_projection_drops_unrequested_metadata(
    record: dict[str, Any],
    metadata_fields: str | None,
) -> None:
    """Property: with no key requested, agent_card.metadata is gone, the rest kept, input intact."""
    before = copy.deepcopy(record)
    projected = _without_unrequested_agent_card_metadata(record, metadata_fields)

    assert record == before, "projection mutated its input"
    assert {k: v for k, v in projected.items() if k != "agent_card"} == {
        k: v for k, v in before.items() if k != "agent_card"
    }
    card = projected.get("agent_card")
    if isinstance(card, dict):
        assert "metadata" not in card
        assert card == {k: v for k, v in before["agent_card"].items() if k != "metadata"}


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(record=_record(), metadata_fields=_UNREQUESTED_FIELDS)
def test_combined_projection_leaves_no_metadata(
    record: dict[str, Any],
    metadata_fields: str | None,
) -> None:
    """Property: both projections together leave metadata at neither level."""
    projected = _without_unrequested_agent_card_metadata(
        _without_unrequested_metadata(record, metadata_fields),
        metadata_fields,
    )
    assert "metadata" not in projected
    card = projected.get("agent_card")
    assert not (isinstance(card, dict) and "metadata" in card)


_SCORES = st.one_of(st.none(), st.floats(min_value=-1, max_value=1, allow_nan=False))

_CANDIDATES = st.lists(
    st.fixed_dictionaries(
        {
            "asset_type": st.sampled_from(("tool", "agent")),
            "service_path": st.sampled_from(("/a", "/b")),
            "name": st.sampled_from(("x", "y", "z")),
            "similarity_score": _SCORES,
        },
        optional={"extra": st.text(max_size=3)},
    ),
    max_size=10,
)


def _candidate_key(
    candidate: dict[str, Any],
) -> tuple[str, str, str]:
    """Return the identity of a discovery candidate.

    Args:
        candidate: One discovery candidate.

    Returns:
        The (asset_type, service_path, name) triple.
    """
    return (
        candidate.get("asset_type", ""),
        candidate.get("service_path", ""),
        candidate.get("name", ""),
    )


def _score(
    candidate: dict[str, Any],
) -> float:
    """Return a candidate's score, with None ranked as 0 as the receipt documents.

    Args:
        candidate: One discovery candidate.

    Returns:
        The numeric score.
    """
    return candidate.get("similarity_score") or 0


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(candidates=_CANDIDATES)
def test_dedupe_candidates_is_an_ordered_best_score_projection(
    candidates: list[dict[str, Any]],
) -> None:
    """Property: dedupe is idempotent, first-seen ordered, and keeps a top-scoring input."""
    deduped = _dedupe_candidates(candidates)

    first_seen: list[tuple[str, str, str]] = []
    for candidate in candidates:
        if _candidate_key(candidate) not in first_seen:
            first_seen.append(_candidate_key(candidate))

    assert [_candidate_key(c) for c in deduped] == first_seen
    assert _dedupe_candidates(deduped) == deduped
    for kept in deduped:
        group = [c for c in candidates if _candidate_key(c) == _candidate_key(kept)]
        assert any(kept is c for c in group), "dedupe returned a candidate it was not given"
        assert _score(kept) == max(_score(c) for c in group)


# Raw registry fields that must never be copied into a discovery receipt.
_RAW_EXTRAS = st.dictionaries(
    st.sampled_from(("description", "metadata", "inputSchema", "registered_by", "token")),
    st.text(max_size=4),
    max_size=3,
)
_HIT_NAMES = st.sampled_from(("x", "y", "z"))
_HIT_PATHS = st.sampled_from(("/a", "/b"))
_HIT_SCORES = st.one_of(st.none(), st.floats(min_value=0.01, max_value=1, allow_nan=False))


@st.composite
def _matching_tool(draw: st.DrawFn) -> dict[str, Any]:
    """Draw one matching_tools entry of a server hit."""
    return {
        **draw(_RAW_EXTRAS),
        "tool_name": draw(_HIT_NAMES),
        "relevance_score": draw(_HIT_SCORES),
    }


@st.composite
def _search_response(draw: st.DrawFn) -> dict[str, Any]:
    """Draw a semantic-search response with duplicates and raw extra fields."""
    tools = [
        {**tool, "server_path": draw(_HIT_PATHS)}
        for tool in draw(st.lists(_matching_tool(), max_size=4))
    ]
    servers = [
        {
            **draw(_RAW_EXTRAS),
            "path": draw(_HIT_PATHS),
            "server_name": "s",
            "matching_tools": draw(st.lists(_matching_tool(), max_size=3)),
        }
        for _ in range(draw(st.integers(min_value=0, max_value=2)))
    ]
    agents = [
        {
            **draw(_RAW_EXTRAS),
            "path": draw(_HIT_PATHS),
            "agent_name": draw(_HIT_NAMES),
            "relevance_score": draw(_HIT_SCORES),
        }
        for _ in range(draw(st.integers(min_value=0, max_value=2)))
    ]
    skills = [
        {
            **draw(_RAW_EXTRAS),
            "path": draw(_HIT_PATHS),
            "skill_name": draw(_HIT_NAMES),
            "relevance_score": draw(_HIT_SCORES),
        }
        for _ in range(draw(st.integers(min_value=0, max_value=2)))
    ]
    return {"servers": servers, "tools": tools, "agents": agents, "skills": skills}


def _expected_keys(
    response: dict[str, Any],
    tools_only: bool,
) -> set[tuple[str, str, str]]:
    """Return the distinct candidate identities a receipt must account for.

    Args:
        response: The semantic-search response the registry sent.
        tools_only: True for intelligent_tool_finder, which counts only the
            matching_tools of server hits.

    Returns:
        The set of (asset_type, service_path, name) triples.
    """
    keys = {
        ("tool", server["path"], tool["tool_name"])
        for server in response["servers"]
        for tool in server["matching_tools"]
    }
    if tools_only:
        return keys
    keys |= {("tool", tool["server_path"], tool["tool_name"]) for tool in response["tools"]}
    keys |= {("agent", agent["path"], agent["agent_name"]) for agent in response["agents"]}
    keys |= {("skill", skill["path"], skill["skill_name"]) for skill in response["skills"]}
    return keys


def _assert_receipt_is_compact(
    receipt: dict[str, Any],
    expected: set[tuple[str, str, str]],
) -> None:
    """Assert a receipt carries only the four item keys and accounts for every candidate.

    Args:
        receipt: The discovery_receipt from a tool result.
        expected: Distinct candidate identities the registry response holds.
    """
    exposed = receipt["exposed_results"]
    withheld = receipt["withheld"]
    listed = exposed + withheld["top_withheld"]

    for item in listed:
        assert set(item) == RECEIPT_ITEM_KEYS, f"receipt item carries {sorted(item)}"

    listed_keys = [_candidate_key(item) for item in listed]
    assert len(listed_keys) == len(set(listed_keys)), f"duplicate receipt items {listed_keys}"
    assert set(listed_keys) <= expected
    assert len(exposed) + withheld["candidate_result_count"] == len(expected)
    if withheld["candidate_result_count"] <= MAX_WITHHELD_ITEMS:
        assert set(listed_keys) == expected


def _search_handler(
    response: dict[str, Any],
):
    """Return a registry handler answering semantic search with `response`.

    Args:
        response: The JSON body to return.

    Returns:
        A MockTransport handler.
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response)

    return _handler


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(response=_search_response(), max_results=st.integers(min_value=1, max_value=12))
def test_search_registry_receipt_items_have_exactly_four_keys(
    response: dict[str, Any],
    max_results: int,
) -> None:
    """Property: search_registry receipt items carry only the four receipt keys.

    Exposed plus withheld candidates are the deduplicated candidate set, with
    no item listed twice.
    """
    result = _run_tool(
        lambda: search_registry(
            query="q",
            max_results=max_results,
            include_discovery_receipt=True,
            ctx=_build_ctx(),
        ),
        _search_handler(response),
    )
    assert result["status"] == "success", result
    _assert_receipt_is_compact(result["discovery_receipt"], _expected_keys(response, False))


@pytest.mark.unit
@PROPERTY_SETTINGS
@given(response=_search_response(), top_n=st.integers(min_value=1, max_value=12))
def test_tool_finder_receipt_items_have_exactly_four_keys(
    response: dict[str, Any],
    top_n: int,
) -> None:
    """Property: intelligent_tool_finder receipt items carry only the four receipt keys.

    Exposed plus withheld candidates are the deduplicated candidate set, with
    no item listed twice.
    """
    result = _run_tool(
        lambda: intelligent_tool_finder(
            query="q",
            top_n=top_n,
            include_discovery_receipt=True,
            ctx=_build_ctx(),
        ),
        _search_handler(response),
    )
    assert result["status"] == "success", result
    _assert_receipt_is_compact(result["discovery_receipt"], _expected_keys(response, True))
