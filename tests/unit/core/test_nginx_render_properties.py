"""Property tests: registry values cannot change the nginx directive tree.

``NginxConfigService._render_config_impl`` fills the production templates with
generated location blocks and then substitutes ``{{PLACEHOLDER}}`` markers. The
security property pinned here is that a value a registrant controls (an MCP
server version label, a virtual server name, an A2A agent name or description)
can only ever change the one argument or comment that carries it: the crossplane
parse of the render equals the parse with a safe value except inside that
carrier, the carrier still renders the injected text (or the entity is dropped),
and no template placeholder survives. A registry value that expands into live
directives, or that stops ``nginx -t`` from loading the gateway config, breaks
the property. The docker test checks the same samples against ``nginx -t``.
"""

import functools
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest
from hypothesis import (
    assume,
    example,
    given,
    settings,
)
from hypothesis import strategies as st

from registry.schemas.agent_models import AgentCard
from registry.schemas.virtual_server_models import (
    ToolMapping,
    VirtualServerConfig,
)
from tests.unit.core.nginx_render_harness import (
    HEALTHY,
    HTTP_ONLY_TEMPLATE,
    TEMPLATES,
    RegistrySnapshot,
    flatten_tree,
    parse_config,
    render_config,
)

PLACEHOLDER_PATTERN: re.Pattern[str] = re.compile(r"\{\{[A-Z_]+\}\}")
PLACEHOLDERS: tuple[str, ...] = tuple(
    sorted(
        {
            match
            for template in TEMPLATES
            for match in PLACEHOLDER_PATTERN.findall(template.read_text(encoding="utf-8"))
        }
    )
)

VERSION_LABEL: str = "version_label"
VIRTUAL_SERVER_NAME: str = "virtual_server_name"
AGENT_NAME: str = "agent_name"
AGENT_DESCRIPTION: str = "agent_description"
CARRIERS: tuple[str, ...] = (VERSION_LABEL, VIRTUAL_SERVER_NAME, AGENT_NAME, AGENT_DESCRIPTION)

# Rendered into the carrier for the baseline tree; appears nowhere else.
SENTINEL: str = "zzcarriersentinelzz"
SAFE_VALUES: dict[str, str] = {
    VERSION_LABEL: "v2.0.0",
    VIRTUAL_SERVER_NAME: "Dev Tools",
    AGENT_NAME: "Flight Agent",
    AGENT_DESCRIPTION: "Books flights",
}

SERVER_PATH: str = "/srv"
SERVER_VERSION_PATH: str = "/srv:v2"
VIRTUAL_SERVER_PATH: str = "/virtual/dev"
AGENT_PATH: str = "/flight-agent"
GENERATION_DIRECTIVE_VARIABLE: str = "$vs_config_generation"

PROPERTY_SETTINGS = settings(
    max_examples=200,
    derandomize=True,
    database=None,
    report_multiple_bugs=False,
    deadline=None,
)

NGINX_IMAGE: str = "nginx:1.27"
DOCKER_TIMEOUT_SECONDS: int = 180

# nginx -t in docker.

# Minimal http/server skeleton for the generated blocks. nginx:1.27 has no lua
# module, so the production templates (lua_shared_dict, set_by_lua_block, ...)
# cannot load there; the skeleton declares only what the generated location
# blocks reference. Placeholders other than the three block markers do not need
# to appear: their replace runs over the whole document either way.
_SKELETON_TEMPLATE: str = """events {}
http {
    limit_req_zone $binary_remote_addr zone=mcp_gateway_edge:1m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=mcp_gateway_register:1m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=mcp_gateway_conn:1m;
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        location = /validate {
            internal;
            proxy_pass http://auth-server:8888/validate;
        }
{{NAMED_LOCATIONS}}
{{LOCATION_BLOCKS}}
{{VIRTUAL_SERVER_BLOCKS}}
{{AGENT_LOCATION_BLOCKS}}
    }
}
"""
_NAMED_LOCATION_PATTERN: re.Pattern[str] = re.compile(r"@[a-z_]+")
_LUA_FILE_DIRECTIVE: re.Pattern[str] = re.compile(r"\b[a-z_]+_by_lua_file\b")
_LUA_BLOCK_DIRECTIVE: re.Pattern[str] = re.compile(r"\b[a-z_]+_by_lua_block\s*\{[^{}]*\}")
_DOCKER_HOSTS: tuple[str, ...] = (
    "auth-server",
    "srv.example.com",
    "srv2.example.com",
    "agent.example.com",
    "skill.example.com",
)
_NGINX_T_SCRIPT: str = (
    'for f in /samples/*.conf; do if nginx -t -q -c "$f" 2>/tmp/err; '
    'then echo "OK $(basename "$f")"; '
    'else echo "FAIL $(basename "$f") $(tr "\\n" " " </tmp/err)"; fi; done'
)
_DOCKER_CARRIERS: tuple[str, ...] = (VERSION_LABEL, VIRTUAL_SERVER_NAME, AGENT_NAME)
_BASELINE_SAMPLE: str = "baseline"


def _build_registry(
    carrier: str,
    value: str,
    omit_carrier: bool = False,
) -> RegistrySnapshot:
    """Build the fixed test registry with ``value`` in one carrier field.

    The registry holds one MCP server with a linked second version, one virtual
    server mapping a tool of that server, one A2A agent and one proxied skill,
    so every generated block type is present in each render.

    Args:
        carrier: Which field receives ``value`` (one of ``CARRIERS``).
        value: Text to place in that field.
        omit_carrier: Drop the entity that owns the carrier (the version, the
            virtual server or the agent) instead of setting the field.

    Returns:
        The registry snapshot to render.
    """
    values = {**SAFE_VALUES, carrier: value}
    active = {
        "path": SERVER_PATH,
        "server_name": "srv",
        "proxy_pass_url": "http://srv.example.com:8000/mcp",
        "version": "v1.0.0",
        "other_version_ids": [SERVER_VERSION_PATH],
        "is_enabled": True,
        "supported_transports": ["streamable-http"],
        "tool_list": [{"name": "search", "description": "Search"}],
    }
    version = {
        "path": SERVER_VERSION_PATH,
        "active_version_id": SERVER_PATH,
        "version": values[VERSION_LABEL],
        "proxy_pass_url": "http://srv2.example.com:8000/mcp",
        "is_enabled": True,
    }
    if omit_carrier and carrier == VERSION_LABEL:
        active["other_version_ids"] = []
    virtual_servers = []
    if not (omit_carrier and carrier == VIRTUAL_SERVER_NAME):
        virtual_servers.append(
            VirtualServerConfig(
                path=VIRTUAL_SERVER_PATH,
                server_name=values[VIRTUAL_SERVER_NAME],
                tool_mappings=[ToolMapping(tool_name="search", backend_server_path=SERVER_PATH)],
                is_enabled=True,
            )
        )
    agents = {}
    if not (omit_carrier and carrier in (AGENT_NAME, AGENT_DESCRIPTION)):
        agents[AGENT_PATH] = AgentCard(
            name=values[AGENT_NAME],
            description=values[AGENT_DESCRIPTION],
            url="http://agent.example.com:9000",
            version="1.0",
            path=AGENT_PATH,
            supported_protocol="a2a",
            health_status=HEALTHY,
        )
    return RegistrySnapshot(
        server_docs={SERVER_PATH: active, SERVER_VERSION_PATH: version},
        enabled_servers={SERVER_PATH: active},
        health={SERVER_PATH: HEALTHY},
        virtual_servers=virtual_servers,
        agents=agents,
        generic_resources=[
            {
                "entity_type": "skill",
                "path": "/skills/demo",
                "target_url": "https://skill.example.com/x",
            }
        ],
    )


def _normalized_rows(
    tree: list[dict[str, Any]],
) -> tuple[tuple[tuple[int, ...], str, tuple[str, ...]], ...]:
    """Flatten ``tree`` and mask the virtual config generation hash.

    The generation is a digest of the virtual blocks, so it legitimately
    changes with a virtual server name; masking it keeps the comparison about
    structure and carrier text.

    Args:
        tree: crossplane ``parsed`` list.

    Returns:
        Flattened rows with the generation value replaced by a constant.
    """
    rows = []
    for position, name, args in flatten_tree(tree):
        if name == "set" and args and args[0] == GENERATION_DIRECTIVE_VARIABLE:
            args = (args[0], "<generation>")
        rows.append((position, name, args))
    return tuple(rows)


def _render_rows(
    template: Path,
    registry: RegistrySnapshot,
) -> tuple[str, tuple | None, str | None]:
    """Render and parse a registry.

    Args:
        template: nginx template file.
        registry: Registry contents.

    Returns:
        ``(text, rows, error)``: the rendered text, its normalized rows (None if
        crossplane rejected it) and crossplane's error message.
    """
    text = render_config(template, registry)
    tree, error = parse_config(text)
    rows = _normalized_rows(tree) if tree is not None else None
    return text, rows, error


@functools.cache
def _baseline_rows(
    template: Path,
    carrier: str,
) -> tuple:
    """Rows of the render with ``SENTINEL`` in the carrier (cached).

    Args:
        template: nginx template file.
        carrier: Carrier field.

    Returns:
        Normalized rows.
    """
    _, rows, error = _render_rows(template, _build_registry(carrier, SENTINEL))
    if rows is None:
        raise RuntimeError(f"baseline render of {template.name} does not parse: {error}")
    return rows


def _without_sentinel(
    tree: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return ``tree`` without every directive or comment that carries ``SENTINEL``.

    Models a render that refused the carrier value and dropped the directive
    holding it (with its block), for example a skipped version route.

    Args:
        tree: crossplane ``parsed`` list.

    Returns:
        A pruned copy of ``tree``.
    """
    kept = []
    for directive in tree:
        texts = [*directive.get("args", ()), directive.get("comment", "")]
        if any(SENTINEL in text for text in texts):
            continue
        if "block" in directive:
            directive = {**directive, "block": _without_sentinel(directive["block"])}
        kept.append(directive)
    return kept


@functools.cache
def _dropped_carrier_rows(
    template: Path,
    carrier: str,
) -> tuple:
    """Rows of the sentinel render with the carrier directives removed (cached).

    Args:
        template: nginx template file.
        carrier: Carrier field.

    Returns:
        Normalized rows.
    """
    text = render_config(template, _build_registry(carrier, SENTINEL))
    tree, error = parse_config(text)
    if tree is None:
        raise RuntimeError(f"baseline render of {template.name} does not parse: {error}")
    return _normalized_rows(_without_sentinel(tree))


@functools.cache
def _omitted_rows(
    template: Path,
    carrier: str,
) -> tuple:
    """Rows of the render without the entity that owns the carrier (cached).

    Args:
        template: nginx template file.
        carrier: Carrier field.

    Returns:
        Normalized rows.
    """
    _, rows, error = _render_rows(template, _build_registry(carrier, "", omit_carrier=True))
    if rows is None:
        raise RuntimeError(f"omitted render of {template.name} does not parse: {error}")
    return rows


def _alphanumerics(
    text: str,
) -> str:
    """Return the alphanumeric characters of ``text`` in order.

    A sanitizer may drop or escape punctuation, whitespace and control
    characters, but it must never drop or invent letters or digits.

    Args:
        text: Any string.

    Returns:
        ``text`` with every non-alphanumeric character removed.
    """
    return "".join(char for char in text if char.isalnum())


def _substitution_violations(
    injected: tuple,
    baseline: tuple,
    value: str,
) -> list[str]:
    """Compare an injected render against the sentinel baseline.

    The trees must hold the same directives at the same positions with the
    same argument counts. Every argument that differs must be a baseline
    argument containing ``SENTINEL`` whose surrounding text is unchanged, and
    whose replacement keeps exactly the alphanumerics of ``value``.

    Args:
        injected: Normalized rows of the injected render.
        baseline: Normalized rows of the sentinel render.
        value: The injected carrier value.

    Returns:
        Human-readable violations; empty when the property holds.
    """
    if len(injected) != len(baseline):
        return [f"directive count changed from {len(baseline)} to {len(injected)}"]
    violations = []
    for (position, name, args), (base_position, base_name, base_args) in zip(
        injected, baseline, strict=True
    ):
        if (position, name, len(args)) != (base_position, base_name, len(base_args)):
            return [f"directive tree diverges at {base_name} {base_args!r} -> {name} {args!r}"]
        for arg, base_arg in zip(args, base_args, strict=True):
            if arg == base_arg:
                continue
            if SENTINEL not in base_arg:
                violations.append(f"non-carrier argument changed: {base_arg!r} -> {arg!r}")
                continue
            prefix, _, suffix = base_arg.partition(SENTINEL)
            inner_end = len(arg) - len(suffix)
            if not (arg.startswith(prefix) and arg.endswith(suffix) and inner_end >= len(prefix)):
                violations.append(f"carrier context changed: {base_arg!r} -> {arg!r}")
                continue
            rendered = arg[len(prefix) : inner_end]
            if _alphanumerics(rendered) != _alphanumerics(value):
                violations.append(f"carrier renders {rendered!r} for injected value {value!r}")
    return violations


def _injection_violations(
    template: Path,
    carrier: str,
    value: str,
) -> list[str]:
    """Return every way rendering ``value`` in ``carrier`` breaks the property.

    The property holds when no template placeholder (other than one the value
    itself carries) survives, crossplane parses the render, and the tree either
    matches the sentinel baseline except for faithful carrier text, matches the
    baseline with the carrier directives dropped (the value was refused), or
    matches the render without the carrier's entity (the entity was rejected).

    Args:
        template: nginx template file.
        carrier: Carrier field.
        value: Injected text.

    Returns:
        Violations; empty when the property holds.
    """
    text, rows, error = _render_rows(template, _build_registry(carrier, value))
    violations = [
        f"template placeholder {placeholder} survives the render"
        for placeholder in PLACEHOLDERS
        if placeholder in text and placeholder not in value
    ]
    if rows is None:
        return [*violations, f"crossplane rejects the render: {error}"]
    substitution = _substitution_violations(rows, _baseline_rows(template, carrier), value)
    rejected = (_dropped_carrier_rows(template, carrier), _omitted_rows(template, carrier))
    if substitution and rows not in rejected:
        violations.extend(substitution)
    return violations


def _carrier_params(
    carriers: tuple[str, ...] = CARRIERS,
) -> list:
    """Build ``(carrier, placeholder)`` params.

    Args:
        carriers: Carriers to enumerate.

    Returns:
        ``pytest.param`` list.
    """
    return [
        pytest.param(carrier, placeholder, id=f"{carrier}-{placeholder.strip('{}')}")
        for carrier in carriers
        for placeholder in PLACEHOLDERS
    ]


def _arbitrary_text() -> st.SearchStrategy[str]:
    """Arbitrary text, biased toward nginx syntax and placeholder fragments."""
    nginx_syntax = st.sampled_from(
        ['"', "'", ";", "{", "}", "{{", "}}", "$", "\\", "#", "\n", "\r", " ", "\t", "\x00"]
    )
    return st.lists(st.one_of(st.text(max_size=8), nginx_syntax), max_size=8).map("".join)


def _valid_for_carrier(
    carrier: str,
    value: str,
) -> bool:
    """Return True if registration models accept ``value`` for ``carrier``."""
    if carrier == VIRTUAL_SERVER_NAME:
        return bool(value.strip()) and len(value) <= 128
    return True


@pytest.mark.unit
@pytest.mark.parametrize("template", TEMPLATES, ids=lambda path: path.name)
def test_baseline_render_parses_without_placeholders(
    template: Path,
) -> None:
    """Property: the safe render parses, has no {{...}} and holds every carrier.

    Guards the harness: if a fake stops serving an entity the carrier would
    silently vanish and every injection test would pass vacuously.
    """
    text, rows, error = _render_rows(
        template, _build_registry(VERSION_LABEL, SAFE_VALUES[VERSION_LABEL])
    )

    assert rows is not None, error
    assert "{{" not in text
    for carrier in (VERSION_LABEL, VIRTUAL_SERVER_NAME, AGENT_NAME):
        baseline_text = render_config(template, _build_registry(carrier, SENTINEL))
        assert SENTINEL in baseline_text, f"{carrier} is not rendered by the harness"


@pytest.mark.unit
@pytest.mark.parametrize("template", TEMPLATES, ids=lambda path: path.name)
@pytest.mark.parametrize(
    ("carrier", "placeholder"),
    _carrier_params(),
)
def test_placeholder_in_registry_value_is_not_expanded(
    template: Path,
    carrier: str,
    placeholder: str,
) -> None:
    """Property: a {{PLACEHOLDER}} in a registry value only changes its carrier.

    Exhaustive over every placeholder in both templates and every carrier: the
    crossplane tree equals the sentinel tree except for the carrier text, which
    keeps the placeholder's letters, or the carrier's entity is dropped.
    """
    violations = _injection_violations(template, carrier, placeholder)

    assert violations == [], f"{carrier}={placeholder!r} in {template.name}: {violations}"


@pytest.mark.unit
@pytest.mark.parametrize("carrier", CARRIERS)
@PROPERTY_SETTINGS
@given(template=st.sampled_from(TEMPLATES), data=st.data())
def test_arbitrary_registry_text_only_changes_its_carrier(
    carrier: str,
    template: Path,
    data: st.DataObject,
) -> None:
    """Property: placeholder-free text in a registry value only changes its carrier.

    Hypothesis over text biased toward nginx syntax (quotes, braces, ``;``,
    ``$``, ``#``, newlines, NUL): sanitizers keep the tree identical to the
    sentinel render except for faithful carrier text.
    """
    value = data.draw(
        _arbitrary_text().filter(
            lambda text: (
                _valid_for_carrier(carrier, text) and not PLACEHOLDER_PATTERN.search(text)
            )
        ),
        label="value",
    )

    violations = _injection_violations(template, carrier, value)

    assert violations == [], f"{carrier}={value!r} in {template.name}: {violations}"


@pytest.mark.unit
@pytest.mark.parametrize("carrier", CARRIERS)
@PROPERTY_SETTINGS
@given(
    template=st.sampled_from(TEMPLATES),
    before=_arbitrary_text(),
    placeholder=st.sampled_from(PLACEHOLDERS),
    after=_arbitrary_text(),
)
@example(
    template=HTTP_ONLY_TEMPLATE,
    before="x",
    placeholder="{{AGENT_LOCATION_BLOCKS}}",
    after="",
)
@example(
    template=HTTP_ONLY_TEMPLATE,
    before="v",
    placeholder="{{ROOT_PATH}}",
    after="2",
)
def test_embedded_placeholder_only_changes_its_carrier(
    carrier: str,
    template: Path,
    before: str,
    placeholder: str,
    after: str,
) -> None:
    """Property: text with an embedded {{PLACEHOLDER}} only changes its carrier.

    Hypothesis over ``before + placeholder + after``. Pinned examples:
    ``x{{AGENT_LOCATION_BLOCKS}}`` (must not expand agent blocks into a version
    label or a virtual server name comment) and ``v{{ROOT_PATH}}2`` (must not
    render as ``v/gw2`` in a label or name).
    """
    value = before + placeholder + after
    assume(_valid_for_carrier(carrier, value))

    violations = _injection_violations(template, carrier, value)

    assert violations == [], f"{carrier}={value!r} in {template.name}: {violations}"


def _docker_unavailable_reason() -> str | None:
    """Return why the docker nginx test cannot run, or None if it can."""
    if shutil.which("docker") is None:
        return "docker CLI not found"
    probe = subprocess.run(  # nosec B603 B607 - fixed argv
        ["docker", "info"], capture_output=True, text=True, timeout=30, check=False
    )
    if probe.returncode != 0:
        return f"docker daemon unavailable: {probe.stderr.strip()[:200]}"
    image = subprocess.run(  # nosec B603 B607 - fixed argv
        ["docker", "image", "inspect", NGINX_IMAGE],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if image.returncode != 0:
        return f"docker image {NGINX_IMAGE} is not present locally (tests never pull)"
    return None


def _sample_name(
    carrier: str,
    placeholder: str,
) -> str:
    """Return the sample file stem for one injection."""
    return f"{carrier}-{placeholder.strip('{}')}"


def _nginx_t_sample(
    skeleton: Path,
    carrier: str,
    value: str,
) -> str:
    """Render the skeleton for one injection and make it loadable by nginx:1.27.

    Lua directives are replaced by ``add_header`` stubs of the same arity (file
    form) or removed (block form), so stock nginx can check the rest. Every
    named location the generated blocks reference is declared.

    Args:
        skeleton: Skeleton template path.
        carrier: Carrier field.
        value: Injected text.

    Returns:
        nginx config text.
    """
    text = render_config(skeleton, _build_registry(carrier, value))
    text = _LUA_BLOCK_DIRECTIVE.sub("", text)
    text = _LUA_FILE_DIRECTIVE.sub("add_header X-Lua-Stub", text)
    named = sorted(set(_NAMED_LOCATION_PATTERN.findall(text)))
    declarations = "\n".join(f"        location {name} {{ return 500; }}" for name in named)
    return text.replace("{{NAMED_LOCATIONS}}", declarations)


@pytest.fixture(scope="module")
def nginx_t_verdicts(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, str]:
    """Run ``nginx -t`` in docker over every injection sample, once per module.

    Returns:
        Map of sample stem to ``"OK"`` or the nginx error text.
    """
    reason = _docker_unavailable_reason()
    if reason is not None:
        pytest.skip(reason)
    work = tmp_path_factory.mktemp("nginx_t")
    skeleton = work / "skeleton.conf"
    skeleton.write_text(_SKELETON_TEMPLATE, encoding="utf-8")
    samples = work / "samples"
    samples.mkdir()
    (samples / f"{_BASELINE_SAMPLE}.conf").write_text(
        _nginx_t_sample(skeleton, VERSION_LABEL, SAFE_VALUES[VERSION_LABEL]), encoding="utf-8"
    )
    for carrier in _DOCKER_CARRIERS:
        for placeholder in PLACEHOLDERS:
            sample = _nginx_t_sample(skeleton, carrier, placeholder)
            (samples / f"{_sample_name(carrier, placeholder)}.conf").write_text(
                sample, encoding="utf-8"
            )
    container = f"nginx-render-props-{uuid.uuid4().hex[:12]}"
    command = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--name",
        container,
        *[f"--add-host={host}:127.0.0.1" for host in _DOCKER_HOSTS],
        "-v",
        f"{samples}:/samples:ro",
        NGINX_IMAGE,
        "sh",
        "-c",
        _NGINX_T_SCRIPT,
    ]
    try:
        result = subprocess.run(  # nosec B603 - argv built from constants and tmp paths
            command,
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
            check=False,
        )
    finally:
        subprocess.run(  # nosec B603 B607 - fixed argv
            ["docker", "rm", "-f", container], capture_output=True, timeout=30, check=False
        )
    verdicts: dict[str, str] = {}
    for line in result.stdout.splitlines():
        status, _, rest = line.partition(" ")
        name, _, message = rest.partition(" ")
        verdicts[name.removesuffix(".conf")] = "OK" if status == "OK" else message
    if _BASELINE_SAMPLE not in verdicts:
        raise RuntimeError(f"docker nginx -t produced no verdicts: {result.stderr[-2000:]}")
    return verdicts


@pytest.mark.integration
def test_nginx_t_accepts_baseline_render(
    nginx_t_verdicts: dict[str, str],
) -> None:
    """Property: stock nginx accepts the safe render of the generated blocks.

    Guards the skeleton: if this fails, every other docker verdict is noise.
    """
    assert nginx_t_verdicts[_BASELINE_SAMPLE] == "OK"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("carrier", "placeholder"),
    _carrier_params(carriers=_DOCKER_CARRIERS),
)
def test_nginx_t_accepts_placeholder_injection(
    nginx_t_verdicts: dict[str, str],
    carrier: str,
    placeholder: str,
) -> None:
    """Property: no {{PLACEHOLDER}} in a registry value makes nginx -t reject the config.

    A registrant-controlled value that breaks ``nginx -t`` blocks every reload
    for the whole gateway.
    """
    verdict = nginx_t_verdicts[_sample_name(carrier, placeholder)]

    assert verdict == "OK", f"nginx -t rejects {carrier}={placeholder!r}: {verdict}"
