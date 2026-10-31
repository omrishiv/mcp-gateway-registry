"""Injectivity of the L1 cache keys built by ``docker/lua/virtual_router.lua``.

The virtual router keeps per-user and per-session state in one shared nginx
dict (``virtual_server_map``). If two different (user, session, backend,
version, server, generation) inputs could build the same key, one caller would
read another caller's backend session, tool list or session-validity verdict.
This module ports each key builder to Python, quotes the Lua it was ported from
and fails if that Lua changes, then proves injectivity by decoding: every key
built from a valid input has exactly one decoding, and it is that input. Keys
from different builders never collide either, because each starts with its own
colon-free tag.
"""

import re
from pathlib import Path

import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.core.nginx_service import (
    NginxConfigService,
    _virtual_config_generation,
)
from registry.schemas.virtual_server_models import VirtualServerConfig

_LUA_SOURCE: Path = Path(__file__).resolve().parents[3] / "docker" / "lua" / "virtual_router.lua"

_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
)

# The exact Lua lines each builder below was ported from. If any block stops
# appearing verbatim, the port is stale and must be redone.
_LUA_MAPPING_KEY: tuple[str, ...] = (
    '    local cache_key = "mapping:" .. (ngx.var.vs_config_generation or "") .. ":" .. server_id',
)

_LUA_BSESS_GET_KEY: tuple[str, ...] = (
    '    local version = type(backend_version) == "string" and backend_version or ""',
    '    local session_key = client_session_id .. ":" .. backend_location',
    '        .. (version ~= "" and (":" .. #version .. ":" .. version) or "")',
    "    local owner = _auth_user_id()",
    "    if not owner then",
    "        return nil, false",
    "    end",
    '    local owner_key = ":" .. #owner .. ":" .. owner',
    '    local cache_key = "bsess:" .. session_key .. owner_key',
    '    local stateless_key = "bsess_stateless:" .. session_key .. owner_key',
)

_LUA_BSESS_INVALIDATE_KEY: tuple[str, ...] = (
    '    local version = type(backend_version) == "string" and backend_version or ""',
    '    local session_key = client_session_id .. ":" .. backend_location',
    '        .. (version ~= "" and (":" .. #version .. ":" .. version) or "")',
    "    local owner = _auth_user_id()",
    "    if not owner then",
    "        return",
    "    end",
    '    local owner_key = ":" .. #owner .. ":" .. owner',
    '    session_cache:delete("bsess:" .. session_key .. owner_key)',
    '    session_cache:delete("bsess_stateless:" .. session_key .. owner_key)',
)

_LUA_TOOLS_ENRICHED_KEY: tuple[str, ...] = (
    '    local enriched_cache_key = "tools_enriched:" .. (ngx.var.vs_config_generation or "") .. ":"',
    '        .. (server_id or "unknown") .. ":" .. #user_id .. ":" .. user_id',
)

_LUA_LOOKUP_KEY: tuple[str, ...] = (
    "    local user_id = _auth_user_id()",
    "    if not user_id then",
    "        return nil",
    "    end",
    '    return result_key .. "_lookup:" .. (ngx.var.vs_config_generation or "") .. ":"',
    '        .. (server_id or "unknown") .. ":" .. #user_id .. ":" .. user_id',
)

_LUA_CSESS_VALID_KEY: tuple[str, ...] = (
    '    local cache_key = "csess_valid:" .. user_id .. ":"',
    '        .. (virtual_server_path or "") .. ":" .. client_session_id',
)

# Lines that fix the input domains the decoders rely on: the session-id
# allowlist and the virtual-server path passed to the csess_valid builder.
_LUA_SESSION_ID_ALLOWLIST: tuple[str, ...] = (
    '    if not client_session_id or not string.match(client_session_id, "^vs%-[0-9a-f]+$") then',
)

_LUA_CSESS_VALID_CALL: tuple[str, ...] = (
    "    local session_ok, session_err = _validate_client_session(client_session_id, auth_user,",
    '        "/virtual/" .. server_id)',
)

_LUA_PINNED_BLOCKS = [
    pytest.param(_LUA_MAPPING_KEY, id="mapping"),
    pytest.param(_LUA_BSESS_GET_KEY, id="bsess-get"),
    pytest.param(_LUA_BSESS_INVALIDATE_KEY, id="bsess-invalidate"),
    pytest.param(_LUA_TOOLS_ENRICHED_KEY, id="tools-enriched"),
    pytest.param(_LUA_LOOKUP_KEY, id="lookup"),
    pytest.param(_LUA_CSESS_VALID_KEY, id="csess-valid"),
    pytest.param(_LUA_SESSION_ID_ALLOWLIST, id="session-id-allowlist"),
    pytest.param(_LUA_CSESS_VALID_CALL, id="csess-valid-call"),
]

# Every access to the shared dict, in source order. A new key builder shows up
# here first; port it before updating this list.
_LUA_SHARED_DICT_CALLS: tuple[str, ...] = (
    "local cached = session_cache:get(cache_key)",
    "session_cache:set(cache_key, content, MAPPING_CACHE_TTL)",
    "local session_id = session_cache:get(cache_key)",
    "if session_cache:get(stateless_key) == STATELESS_CACHE_VALUE then",
    "session_cache:set(stateless_key, STATELESS_CACHE_VALUE, SESSION_CACHE_TTL)",
    "session_cache:set(cache_key, data.backend_session_id, SESSION_CACHE_TTL)",
    "session_cache:set(cache_key, session_id, SESSION_CACHE_TTL)",
    "session_cache:set(stateless_key, STATELESS_CACHE_VALUE, SESSION_CACHE_TTL)",
    'session_cache:delete("bsess:" .. session_key .. owner_key)',
    'session_cache:delete("bsess_stateless:" .. session_key .. owner_key)',
    "local cached_enriched = not has_egress_backend and session_cache:get(enriched_cache_key)",
    "session_cache:set(enriched_cache_key, encoded, ENRICHED_CACHE_TTL)",
    "session_cache:set(cache_key, encoded, ENRICHED_CACHE_TTL)",
    "local cached = cache_key and session_cache:get(cache_key)",
    "local cached = session_cache:get(cache_key)",
    'session_cache:set(cache_key, "1", SESSION_CACHE_TTL)',
)

_TAGS: dict[str, bytes] = {
    "mapping": b"mapping",
    "bsess": b"bsess",
    "bsess_stateless": b"bsess_stateless",
    "tools_enriched": b"tools_enriched",
    "resources_lookup": b"resources_lookup",
    "prompts_lookup": b"prompts_lookup",
    "csess_valid": b"csess_valid",
}

_RESULT_KEYS: tuple[bytes, ...] = (b"resources", b"prompts")

_SESSION_ID_RE = re.compile(rb"vs-[0-9a-f]+")

_DIGITS_RE = re.compile(rb"0|[1-9][0-9]*")

_ANY_BYTES = st.binary(max_size=24)

_OWNERS = st.one_of(
    st.binary(min_size=1, max_size=24),
    st.text(alphabet=":0123456789ab", min_size=1, max_size=12).map(str.encode),
)

_VERSIONS = st.one_of(
    st.none(),
    _ANY_BYTES,
    st.text(alphabet=":0123456789ab", max_size=12).map(str.encode),
)

# Generation, server id and virtual path never contain ':' (pinned below).
_COLON_FREE = st.binary(max_size=24).map(lambda raw: raw.replace(b":", b""))

_GENERATIONS = st.one_of(
    st.none(),
    st.text(alphabet="0123456789abcdef", min_size=16, max_size=16).map(str.encode),
    _COLON_FREE,
)

_SERVER_IDS = st.from_regex(r"[a-z0-9]{1,8}(-[a-z0-9]{1,8}){0,2}", fullmatch=True).map(str.encode)

_SESSION_IDS = st.from_regex(r"vs-[0-9a-f]{1,32}", fullmatch=True).map(str.encode)

_BACKEND_LOCATIONS = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    max_size=16,
).map(lambda path: ("/_vs_backend" + NginxConfigService._encode_path_for_location(path)).encode())


def _lua_len(
    value: bytes,
) -> bytes:
    """Render Lua's ``#value`` as concatenated by ``..``.

    Args:
        value: A Lua string (a byte string).

    Returns:
        The byte length in decimal ASCII.
    """
    return str(len(value)).encode("ascii")


def _mapping_key(
    generation: bytes | None,
    server_id: bytes,
) -> bytes:
    """Port of the ``mapping:`` builder (see ``_LUA_MAPPING_KEY``).

    Args:
        generation: ``$vs_config_generation``, or ``None`` when unset.
        server_id: ``$virtual_server_id``.

    Returns:
        The cache key.
    """
    return b"mapping:" + (generation or b"") + b":" + server_id


def _bsess_keys(
    client_session_id: bytes,
    backend_location: bytes,
    version: bytes | None,
    owner: bytes,
) -> tuple[bytes, bytes]:
    """Port of the ``bsess:`` and ``bsess_stateless:`` builders.

    Ported from ``_LUA_BSESS_GET_KEY``; ``_LUA_BSESS_INVALIDATE_KEY`` builds
    the same two keys. ``None`` stands for a non-string ``backend_version``.

    Args:
        client_session_id: The allowlisted ``Mcp-Session-Id``.
        backend_location: The mapped internal backend location.
        version: The pinned backend version, or ``None``.
        owner: The authenticated user id (never empty).

    Returns:
        ``(cache_key, stateless_key)``.
    """
    version = version if version is not None else b""
    session_key = (
        client_session_id
        + b":"
        + backend_location
        + ((b":" + _lua_len(version) + b":" + version) if version != b"" else b"")
    )
    owner_key = b":" + _lua_len(owner) + b":" + owner
    return (b"bsess:" + session_key + owner_key, b"bsess_stateless:" + session_key + owner_key)


def _tools_enriched_key(
    generation: bytes | None,
    server_id: bytes,
    user_id: bytes,
) -> bytes:
    """Port of the ``tools_enriched:`` builder (see ``_LUA_TOOLS_ENRICHED_KEY``).

    Args:
        generation: ``$vs_config_generation``, or ``None`` when unset.
        server_id: ``$virtual_server_id`` (never nil past ``route()``).
        user_id: The authenticated user id (never empty).

    Returns:
        The cache key.
    """
    return (
        b"tools_enriched:"
        + (generation or b"")
        + b":"
        + server_id
        + b":"
        + _lua_len(user_id)
        + b":"
        + user_id
    )


def _lookup_key(
    result_key: bytes,
    generation: bytes | None,
    server_id: bytes,
    user_id: bytes,
) -> bytes:
    """Port of ``_lookup_cache_key`` (see ``_LUA_LOOKUP_KEY``).

    Args:
        result_key: ``resources`` or ``prompts``.
        generation: ``$vs_config_generation``, or ``None`` when unset.
        server_id: ``$virtual_server_id`` (never nil past ``route()``).
        user_id: The authenticated user id (never empty).

    Returns:
        The cache key.
    """
    return (
        result_key
        + b"_lookup:"
        + (generation or b"")
        + b":"
        + server_id
        + b":"
        + _lua_len(user_id)
        + b":"
        + user_id
    )


def _csess_valid_key(
    user_id: bytes,
    virtual_server_path: bytes,
    client_session_id: bytes,
) -> bytes:
    """Port of the ``csess_valid:`` builder (see ``_LUA_CSESS_VALID_KEY``).

    Args:
        user_id: The authenticated user id (never empty).
        virtual_server_path: ``"/virtual/" .. server_id`` from ``route()``.
        client_session_id: The allowlisted ``Mcp-Session-Id``.

    Returns:
        The cache key.
    """
    return b"csess_valid:" + user_id + b":" + virtual_server_path + b":" + client_session_id


def _strip_tag(
    key: bytes,
    tag: bytes,
) -> bytes | None:
    """Return ``key`` without its ``tag:`` prefix, or ``None`` if absent.

    Args:
        key: A cache key.
        tag: The expected builder tag, without the colon.

    Returns:
        The remainder after ``tag:``, or ``None``.
    """
    prefix = tag + b":"
    return key[len(prefix) :] if key.startswith(prefix) else None


def _split_length_prefixed(
    rest: bytes,
) -> tuple[bytes, bytes] | None:
    """Read one ``N:value`` field of exactly N bytes from the front of ``rest``.

    Args:
        rest: Bytes starting with a decimal length and a colon.

    Returns:
        ``(value, remainder)``, or ``None`` if ``rest`` does not start with a
        canonical length field followed by that many bytes.
    """
    digits, sep, tail = rest.partition(b":")
    if not sep or not _DIGITS_RE.fullmatch(digits):
        return None
    length = int(digits)
    if len(tail) < length:
        return None
    return tail[:length], tail[length:]


def _decode_owner_tail(
    rest: bytes,
) -> bytes | None:
    """Decode a trailing ``:N:owner`` segment that must consume all of ``rest``.

    Args:
        rest: Bytes expected to be ``:N:owner``.

    Returns:
        The owner, or ``None`` if ``rest`` is not exactly one such segment.
    """
    if not rest.startswith(b":"):
        return None
    parsed = _split_length_prefixed(rest[1:])
    if parsed is None or parsed[1] != b"" or parsed[0] == b"":
        return None
    return parsed[0]


def _decode_bsess(
    key: bytes,
    tag: bytes,
) -> list[tuple[bytes, bytes, bytes, bytes]]:
    """List every (session, location, version, owner) that builds ``key``.

    Uses only the domain facts the Lua relies on: the session id matches the
    route allowlist, the backend location is colon-free, a version segment is
    present only for a non-empty version, and the owner is non-empty.

    Args:
        key: A ``bsess:`` or ``bsess_stateless:`` key.
        tag: Which of the two tags to expect.

    Returns:
        All decodings; injectivity means there is exactly one.
    """
    rest = _strip_tag(key, tag)
    if rest is None:
        return []
    session_id, sep, rest = rest.partition(b":")
    if not sep or not _SESSION_ID_RE.fullmatch(session_id):
        return []
    location, sep, rest = rest.partition(b":")
    if not sep:
        return []
    rest = b":" + rest
    decodings: list[tuple[bytes, bytes, bytes, bytes]] = []
    owner = _decode_owner_tail(rest)
    if owner is not None:
        decodings.append((session_id, location, b"", owner))
    versioned = _split_length_prefixed(rest[1:])
    if versioned is not None and versioned[0] != b"":
        owner = _decode_owner_tail(versioned[1])
        if owner is not None:
            decodings.append((session_id, location, versioned[0], owner))
    return decodings


def _decode_generation_server_user(
    rest: bytes,
) -> list[tuple[bytes, bytes, bytes]]:
    """List every (generation, server_id, user_id) that builds ``rest``.

    Args:
        rest: A ``tools_enriched`` or lookup key with its tag removed.

    Returns:
        All decodings; injectivity means there is exactly one.
    """
    generation, sep, rest = rest.partition(b":")
    if not sep:
        return []
    server_id, sep, rest = rest.partition(b":")
    if not sep:
        return []
    user_id = _decode_owner_tail(b":" + rest)
    return [] if user_id is None else [(generation, server_id, user_id)]


def _decode_csess_valid(
    key: bytes,
) -> list[tuple[bytes, bytes, bytes]]:
    """List every (user_id, virtual_server_path, session_id) that builds ``key``.

    The user id may contain ':', but the path and session id cannot, so the
    last two colons are the field separators.

    Args:
        key: A ``csess_valid:`` key.

    Returns:
        All decodings; injectivity means there is exactly one.
    """
    rest = _strip_tag(key, b"csess_valid")
    if rest is None:
        return []
    parts = rest.rsplit(b":", 2)
    if len(parts) != 3 or not parts[0] or not _SESSION_ID_RE.fullmatch(parts[2]):
        return []
    return [(parts[0], parts[1], parts[2])]


def _lua_lines() -> list[str]:
    """Read the virtual router source as a list of lines.

    Returns:
        The lines of ``docker/lua/virtual_router.lua`` without newlines.
    """
    return _LUA_SOURCE.read_text(encoding="utf-8").splitlines()


def _contains_block(
    lines: list[str],
    block: tuple[str, ...],
) -> bool:
    """Report whether ``block`` appears as consecutive lines of ``lines``.

    Args:
        lines: The source lines.
        block: The exact lines to find.

    Returns:
        True if the block occurs verbatim and contiguously.
    """
    width = len(block)
    return any(tuple(lines[i : i + width]) == block for i in range(len(lines) - width + 1))


@pytest.mark.unit
class TestLuaSourcePinned:
    """The Python ports match the Lua they were ported from."""

    @pytest.mark.parametrize("block", _LUA_PINNED_BLOCKS)
    def test_ported_lines_unchanged(self, block):
        """Property: each ported Lua block still appears verbatim in virtual_router.lua."""
        assert _contains_block(_lua_lines(), block), "\n".join(block)

    def test_shared_dict_accesses_unchanged(self):
        """Property: the shared dict is touched only by the ported key builders."""
        calls = tuple(line.strip() for line in _lua_lines() if "session_cache:" in line)
        assert calls == _LUA_SHARED_DICT_CALLS


@pytest.mark.unit
class TestLuaKeyDomains:
    """The colon-free inputs the decoders rely on are colon-free at their source."""

    @_SETTINGS
    @given(blocks=st.text())
    def test_config_generation_is_hex(self, blocks):
        """Property: $vs_config_generation is 16 lowercase hex characters."""
        assert re.fullmatch(r"[0-9a-f]{16}", _virtual_config_generation(blocks))

    @pytest.mark.parametrize("path", ["/virtual/a:b", "/virtual/a:", "/virtual/:a"])
    def test_virtual_server_path_rejects_colon(self, path):
        """Property: a virtual server path (and so its server id) never contains ':'."""
        try:
            VirtualServerConfig.validate_path(path)
        except ValueError:
            return
        raise AssertionError(f"virtual server path {path!r} accepted")


@pytest.mark.unit
class TestLuaKeyInjectivity:
    """Each key decodes to exactly the input that built it."""

    @_SETTINGS
    @given(generation=_GENERATIONS, server_id=_SERVER_IDS)
    def test_mapping_key_decodes_uniquely(self, generation, server_id):
        """Property: mapping keys decode to exactly (generation or '', server_id)."""
        rest = _strip_tag(_mapping_key(generation, server_id), b"mapping")
        assert rest is not None
        assert rest.split(b":") == [generation or b"", server_id]

    @_SETTINGS
    @given(
        session_id=_SESSION_IDS,
        location=_BACKEND_LOCATIONS,
        version=_VERSIONS,
        owner=_OWNERS,
    )
    @example(session_id=b"vs-1", location=b"/_vs_backend_a", version=b"3:abc", owner=b"x")
    @example(session_id=b"vs-1", location=b"/_vs_backend_a", version=None, owner=b"1:a:1:b")
    @example(session_id=b"vs-1", location=b"/_vs_backend_a", version=b"", owner=b"5:v:1:a")
    def test_bsess_keys_decode_uniquely(self, session_id, location, version, owner):
        """Property: both bsess keys have one decoding, the input (None version = '')."""
        expected = (session_id, location, version or b"", owner)
        cache_key, stateless_key = _bsess_keys(session_id, location, version, owner)
        assert _decode_bsess(cache_key, b"bsess") == [expected], cache_key
        assert _decode_bsess(stateless_key, b"bsess_stateless") == [expected], stateless_key

    @_SETTINGS
    @given(generation=_GENERATIONS, server_id=_SERVER_IDS, user_id=_OWNERS)
    @example(generation=None, server_id=b"a", user_id=b"1:b")
    def test_tools_enriched_key_decodes_uniquely(self, generation, server_id, user_id):
        """Property: tools_enriched keys decode to exactly (generation, server_id, user)."""
        rest = _strip_tag(_tools_enriched_key(generation, server_id, user_id), b"tools_enriched")
        assert rest is not None
        assert _decode_generation_server_user(rest) == [(generation or b"", server_id, user_id)]

    @pytest.mark.parametrize("result_key", _RESULT_KEYS)
    @_SETTINGS
    @given(generation=_GENERATIONS, server_id=_SERVER_IDS, user_id=_OWNERS)
    def test_lookup_key_decodes_uniquely(self, result_key, generation, server_id, user_id):
        """Property: lookup keys decode to exactly (generation, server_id, user)."""
        key = _lookup_key(result_key, generation, server_id, user_id)
        rest = _strip_tag(key, result_key + b"_lookup")
        assert rest is not None
        assert _decode_generation_server_user(rest) == [(generation or b"", server_id, user_id)]

    @_SETTINGS
    @given(user_id=_OWNERS, server_id=_SERVER_IDS, session_id=_SESSION_IDS)
    @example(user_id=b"alice:/virtual/a", server_id=b"b", session_id=b"vs-1")
    def test_csess_valid_key_decodes_uniquely(self, user_id, server_id, session_id):
        """Property: csess_valid keys decode to exactly (user, '/virtual/'+id, session)."""
        path = b"/virtual/" + server_id
        key = _csess_valid_key(user_id, path, session_id)
        assert _decode_csess_valid(key) == [(user_id, path, session_id)], key


@pytest.mark.unit
class TestLuaKeyNamespaces:
    """Keys from different builders never collide in the shared dict."""

    @_SETTINGS
    @given(
        generation=_GENERATIONS,
        server_id=_SERVER_IDS,
        session_id=_SESSION_IDS,
        location=_BACKEND_LOCATIONS,
        version=_VERSIONS,
        user_id=_OWNERS,
    )
    def test_each_builder_owns_its_tag(
        self, generation, server_id, session_id, location, version, user_id
    ):
        """Property: the bytes before a key's first ':' name exactly one builder."""
        cache_key, stateless_key = _bsess_keys(session_id, location, version, user_id)
        built = {
            "mapping": _mapping_key(generation, server_id),
            "bsess": cache_key,
            "bsess_stateless": stateless_key,
            "tools_enriched": _tools_enriched_key(generation, server_id, user_id),
            "resources_lookup": _lookup_key(b"resources", generation, server_id, user_id),
            "prompts_lookup": _lookup_key(b"prompts", generation, server_id, user_id),
            "csess_valid": _csess_valid_key(user_id, b"/virtual/" + server_id, session_id),
        }
        assert len(set(_TAGS.values())) == len(_TAGS)
        for name, key in built.items():
            assert key.split(b":", 1)[0] == _TAGS[name], (name, key)
