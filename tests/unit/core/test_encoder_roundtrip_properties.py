"""Round-trip and injectivity properties for the nginx location-name encoders.

Each registration gets its own internal nginx location whose name is derived
from the server path (and, for inactive versions, the version label). If two
distinct registrations could encode to the same name, one would silently route
to the other's backend. These tests pin that ``_encode_path_for_location`` is
uniquely decodable (a reference decoder inverts it) over the restricted output
alphabet, that the version-id composition feeding it stays injective, and that
the ``:`` version separator cannot appear in a registered server path.
"""

import asyncio
import re
from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
)

import pytest
from hypothesis import (
    assume,
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.core.nginx_service import NginxConfigService
from registry.exceptions import UrlValidationError
from registry.services.server_service import ServerService
from registry.utils.path_utils import (
    VERSION_ID_SEPARATOR,
    make_version_id,
)

_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

_OUTPUT_RE = re.compile(r"[A-Za-z0-9_.\-]*")

_ASCII_KEPT: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
)

_LOWER_HEX: frozenset[str] = frozenset("0123456789abcdef")

_VIRTUAL_BACKEND_PREFIX: str = "/_vs_backend"

# Characters that sit on every branch of the encoder: the slash, the two
# characters reserved by the encoding itself, the version separator, a
# percent sign, a multi-byte character and a control character.
_TRICKY_ALPHABET: str = "/._-:%aZ09\u00e9\u20ac\x00 "

_ANY_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)))

_PATHS = st.one_of(
    st.text(alphabet=_TRICKY_ALPHABET),
    _ANY_TEXT,
)

_COLON_FREE_TEXT = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        blacklist_characters=VERSION_ID_SEPARATOR,
    ),
)

_COLON_FREE_PATHS = st.one_of(
    st.text(alphabet=_TRICKY_ALPHABET.replace(VERSION_ID_SEPARATOR, ""), min_size=1),
    _COLON_FREE_TEXT.filter(bool),
)

_VERSIONS = st.one_of(
    st.none(),
    st.text(alphabet=_TRICKY_ALPHABET),
    _ANY_TEXT,
)

# Paths that carry the version separator; each one passes every other
# registration check, so only a separator check can reject it.
_COLON_PATHS = [
    pytest.param("/github:v2", id="version-id-shape"),
    pytest.param("/a:b", id="inner-colon"),
    pytest.param("/:x", id="leading-colon"),
    pytest.param("/x:", id="trailing-colon"),
]

_COLON_XFAIL = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "Known defect: only the Pydantic path regex bans ':', so the service-level "
        "registration path persists a server path shaped like a version document id."
    ),
)


def _decode_location_suffix(
    encoded: str,
) -> str:
    """Invert ``_encode_path_for_location``, rejecting any non-canonical input.

    Args:
        encoded: A location-name suffix produced by the encoder.

    Returns:
        The server path the suffix encodes.

    Raises:
        ValueError: If ``encoded`` is not a canonical encoding of any string.
    """
    out = bytearray()
    index = 0
    while index < len(encoded):
        char = encoded[index]
        if char == "_":
            out += b"/"
            index += 1
        elif char == ".":
            pair = encoded[index + 1 : index + 3]
            if len(pair) != 2 or not set(pair) <= _LOWER_HEX:
                raise ValueError(f"bad escape at {index} in {encoded!r}")
            out.append(int(pair, 16))
            index += 3
        elif char in _ASCII_KEPT:
            out += char.encode("ascii")
            index += 1
        else:
            raise ValueError(f"character {char!r} outside the encoder alphabet")
    return out.decode("utf-8")


def _backend_key(
    path: str,
    version: str | None,
) -> tuple[str, str | None]:
    """Collapse the version inputs that ``_virtual_backend_location`` treats alike.

    Args:
        path: Registered server path.
        version: Version label, or ``None`` for the active document.

    Returns:
        ``(path, version)`` with the empty label folded into ``None``.
    """
    return (path, version or None)


def _register_and_capture_create(
    path: str,
) -> MagicMock:
    """Run ``ServerService.register_server`` for ``path`` against a mock repo.

    The repository reports no existing server, so a path that passes
    validation reaches ``repo.create``. A rejection may surface as an
    exception or as a ``success: False`` result; both are swallowed here and
    the caller inspects ``repo.create`` instead.

    Args:
        path: The server path to register.

    Returns:
        The mock repository, for inspecting ``create`` calls.
    """
    repo = MagicMock()
    repo.get = AsyncMock(return_value=None)
    repo.find_by_id = AsyncMock(return_value=None)
    repo.create = AsyncMock(return_value=True)
    repo.get_state = AsyncMock(return_value=False)
    search = MagicMock()
    search.index_server = AsyncMock(return_value=None)
    with (
        patch("registry.services.server_service.get_server_repository", return_value=repo),
        patch("registry.repositories.factory.get_search_repository", return_value=search),
    ):
        service = ServerService()
    try:
        asyncio.run(service.register_server({"path": path, "server_name": "colon"}))
    except (UrlValidationError, ValueError):
        pass
    return repo


@pytest.mark.unit
class TestLocationSuffixEncoder:
    """``_encode_path_for_location`` is uniquely decodable over a safe alphabet."""

    @_SETTINGS
    @given(path=_PATHS)
    @example(path="/a-b")
    @example(path="/a.b")
    @example(path="/a_b")
    @example(path="/a.5fb")
    @example(path="")
    @example(path="\u00e9/\u20ac")
    def test_reference_decoder_inverts_encoder(self, path):
        """Property: dec(enc(p)) == p, so distinct paths never share a location."""
        encoded = NginxConfigService._encode_path_for_location(path)
        assert _decode_location_suffix(encoded) == path, f"enc({path!r}) = {encoded!r}"

    @_SETTINGS
    @given(path=_PATHS)
    @example(path='/x"; return 200;')
    @example(path="/a\nb{}$#")
    def test_output_alphabet(self, path):
        """Property: enc(p) uses only [A-Za-z0-9_.-], so it cannot break a directive."""
        encoded = NginxConfigService._encode_path_for_location(path)
        assert _OUTPUT_RE.fullmatch(encoded), f"enc({path!r}) = {encoded!r}"

    @_SETTINGS
    @given(path=_PATHS)
    @example(path="/github")
    @example(path="_github")
    @example(path="")
    def test_leading_underscore_iff_leading_slash(self, path):
        """Property: enc(p) starts with '_' exactly when p starts with '/'."""
        encoded = NginxConfigService._encode_path_for_location(path)
        assert encoded.startswith("_") == path.startswith("/"), f"enc({path!r}) = {encoded!r}"


@pytest.mark.unit
class TestVirtualBackendLocation:
    """Internal backend locations are distinct per (path, version) registration."""

    @_SETTINGS
    @given(
        path_a=_COLON_FREE_PATHS,
        version_a=_VERSIONS,
        path_b=_COLON_FREE_PATHS,
        version_b=_VERSIONS,
    )
    @example(path_a="/github", version_a="v2", path_b="/github", version_b=None)
    @example(path_a="/a", version_a="b:c", path_b="/a", version_b="b")
    @example(path_a="/github", version_a="", path_b="/github", version_b=None)
    def test_backend_location_injective(self, path_a, version_a, path_b, version_b):
        """Property: equal backend locations imply equal (path, version or None)."""
        service = NginxConfigService()
        loc_a = service._virtual_backend_location(path_a, version_a)
        loc_b = service._virtual_backend_location(path_b, version_b)
        same_key = _backend_key(path_a, version_a) == _backend_key(path_b, version_b)
        assert (loc_a == loc_b) == same_key, (
            f"({path_a!r}, {version_a!r}) -> {loc_a!r}; ({path_b!r}, {version_b!r}) -> {loc_b!r}"
        )

    @_SETTINGS
    @given(path=_COLON_FREE_PATHS, version=_VERSIONS)
    def test_backend_location_alphabet(self, path, version):
        """Property: every backend location is the fixed prefix over [A-Za-z0-9_.-]."""
        location = NginxConfigService()._virtual_backend_location(path, version)
        assert location.startswith(_VIRTUAL_BACKEND_PREFIX)
        assert _OUTPUT_RE.fullmatch(location[len(_VIRTUAL_BACKEND_PREFIX) :]), location


@pytest.mark.unit
class TestVersionIdComposition:
    """``make_version_id`` is injective once ':' is banned from both inputs."""

    @_SETTINGS
    @given(
        path_a=_COLON_FREE_PATHS,
        version_a=_COLON_FREE_TEXT,
        path_b=_COLON_FREE_PATHS,
        version_b=_COLON_FREE_TEXT,
    )
    @example(path_a="/a", version_a="bc", path_b="/ab", version_b="c")
    def test_injective_over_colon_free_inputs(self, path_a, version_a, path_b, version_b):
        """Property: make_version_id(p, v) == make_version_id(q, w) iff (p, v) == (q, w)."""
        same_out = make_version_id(path_a, version_a) == make_version_id(path_b, version_b)
        assert same_out == ((path_a, version_a) == (path_b, version_b))

    @_SETTINGS
    @given(path=_COLON_FREE_PATHS, version=_COLON_FREE_TEXT)
    def test_separator_splits_back(self, path, version):
        """Property: the first ':' of a version id splits it into (path, version)."""
        head, sep, tail = make_version_id(path, version).partition(VERSION_ID_SEPARATOR)
        assert (head, sep, tail) == (path, VERSION_ID_SEPARATOR, version)

    @_SETTINGS
    @given(path=_COLON_FREE_PATHS, version=_COLON_FREE_TEXT, other=_COLON_FREE_PATHS)
    def test_version_id_never_equals_a_colon_free_path(self, path, version, other):
        """Property: no version id equals any colon-free (active) server path."""
        assume(other)
        assert make_version_id(path, version) != other


@pytest.mark.unit
class TestServerPathRejectsVersionSeparator:
    """A server path can never carry the ':' that delimits version ids."""

    @pytest.mark.parametrize(
        "path",
        [pytest.param(p.values[0], id=p.id, marks=_COLON_XFAIL) for p in _COLON_PATHS],
    )
    def test_register_server_never_persists_colon_path(self, path):
        """Property: ServerService.register_server never creates a path containing ':'."""
        repo = _register_and_capture_create(path)
        assert not repo.create.await_args_list, f"register_server persisted {path!r}"
