"""The auth-server receives the registry's SSRF policy on every deploy surface.

The auth-server MCP proxy hop dials registered backends through the same
``url_guard`` profile the registry uses to register and health-check them, and
that profile reads ``SSRF_ALLOWED_HOSTS``, ``SSRF_ALLOWED_CIDRS`` and
``GATEWAY_PROXY_ALLOW_PRIVATE_TARGETS``. If the auth-server container saw a
different value than the registry container, the data plane would refuse a
backend the control plane admitted, or dial one it refused. These tests pin
that every surface gives both containers each variable from one source: the
same Compose interpolation, the same rendered Helm value, the same Terraform
expression, and the same CDK expression. No network is used; the Helm checks
render offline and are skipped when ``helm`` is not on PATH.
"""

import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHARTS_ROOT = REPO_ROOT / "charts"
STACK_CHART = "mcp-gateway-registry-stack"
HELM_TIMEOUT_SECONDS = 180

POLICY_VARIABLES: tuple[str, ...] = (
    "SSRF_ALLOWED_HOSTS",
    "SSRF_ALLOWED_CIDRS",
    "GATEWAY_PROXY_ALLOW_PRIVATE_TARGETS",
)

# Compose file to the files it is layered on (``docker compose -f base -f overlay``).
COMPOSE_FILES: dict[str, tuple[str, ...]] = {
    "docker-compose.yml": (),
    "docker-compose.podman.yml": (),
    "docker-compose.prebuilt.yml": (),
    "docker-compose.dhi.yml": ("docker-compose.yml",),
}
COMPOSE_REGISTRY = "registry"
COMPOSE_AUTH = "auth-server"

# Policy env name to the values key both charts use, and a sentinel no default uses.
HELM_KEYS: dict[str, str] = {
    "SSRF_ALLOWED_HOSTS": "ssrfAllowedHosts",
    "SSRF_ALLOWED_CIDRS": "ssrfAllowedCidrs",
    "GATEWAY_PROXY_ALLOW_PRIVATE_TARGETS": "gatewayProxyAllowPrivateTargets",
}
HELM_SENTINELS: dict[str, object] = {
    "ssrfAllowedHosts": "ssrf-parity-sentinel.invalid",
    "ssrfAllowedCidrs": "198.18.0.0/15",
    "gatewayProxyAllowPrivateTargets": True,
}
HELM_BASE_SET_VALUES: tuple[str, ...] = (
    "global.authProvider.type=keycloak",
    "global.secretKey=test-only-secret-key",
    "keycloak.adminPassword=test-only-admin-password",
)
HELM_DEPLOYMENTS = {"registry": "registry", "auth-server": "auth-server"}

TF_MODULE_DIR = REPO_ROOT / "terraform" / "aws-ecs" / "modules" / "mcp-gateway"
TF_ROOT_DIR = REPO_ROOT / "terraform" / "aws-ecs"
TF_REGISTRY_MODULE = "ecs_service_registry"
TF_AUTH_MODULE = "ecs_service_auth"

CDK_STACK_FILE = REPO_ROOT / "infra" / "lib" / "registry" / "registry-service-stack.ts"

_BRACKET_PAIRS = {"{": "}", "[": "]", "(": ")"}
_HEREDOC_RE = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\n")


def _skip_non_code(text: str, j: int, hcl: bool) -> int | None:
    """Return the end of a string, comment or heredoc starting at ``j``, if any.

    Args:
        text: Source text.
        j: Index to inspect.
        hcl: True for HCL, False for TypeScript.

    Returns:
        Index just past the non-code span, or None when ``j`` is code.
    """
    char = text[j]
    if hcl and text.startswith("<<", j):
        heredoc = _HEREDOC_RE.match(text, j)
        if heredoc:
            terminator = re.compile(r"^\s*" + heredoc.group(1) + r"\s*$", re.M)
            return terminator.search(text, heredoc.end()).end()
    if char == '"' or (not hcl and char in "'`"):
        k = j + 1
        while text[k] != char:
            k += 2 if text[k] == "\\" else 1
        return k + 1
    if (hcl and char == "#") or text.startswith("//", j):
        end = text.find("\n", j)
        return len(text) if end == -1 else end
    if text.startswith("/*", j):
        return text.index("*/", j) + 2
    return None


def _match_bracket(text: str, start: int, hcl: bool) -> int:
    """Return the index of the bracket that closes the one at ``start``.

    Args:
        text: Source text.
        start: Index of an opening ``{``, ``[`` or ``(``.
        hcl: True for HCL, False for TypeScript.

    Returns:
        Index of the matching closing bracket.

    Raises:
        ValueError: If the brackets do not balance.
    """
    expected: list[str] = []
    j = start
    while j < len(text):
        skipped = _skip_non_code(text, j, hcl)
        if skipped is not None:
            j = skipped
            continue
        char = text[j]
        if char in _BRACKET_PAIRS:
            expected.append(_BRACKET_PAIRS[char])
        elif char in ")]}":
            if not expected or expected.pop() != char:
                raise ValueError(f"unbalanced {char!r} at offset {j}")
            if not expected:
                return j
        j += 1
    raise ValueError(f"unterminated bracket at offset {start}")


def _body(text: str, opener: re.Pattern[str], hcl: bool) -> str:
    """Return the bracketed body that follows the single match of ``opener``.

    Args:
        text: Source text.
        opener: Pattern ending at the opening bracket.
        hcl: True for HCL, False for TypeScript.

    Returns:
        The text between the brackets, exclusive.
    """
    matches = list(opener.finditer(text))
    assert len(matches) == 1, f"expected exactly one {opener.pattern!r}, found {len(matches)}"
    open_idx = matches[0].end() - 1
    return text[open_idx + 1 : _match_bracket(text, open_idx, hcl)]


# ---------------------------------------------------------------------------
# Docker Compose
# ---------------------------------------------------------------------------


def _compose_env(service: dict) -> dict[str, str]:
    """Return a Compose service's ``environment`` as a name-to-raw-value map.

    Args:
        service: One entry of the ``services`` mapping.

    Returns:
        The uninterpolated value per variable name.
    """
    environment = service.get("environment") or {}
    if isinstance(environment, dict):
        return {str(k): "" if v is None else str(v) for k, v in environment.items()}
    env: dict[str, str] = {}
    for entry in environment:
        name, _, value = str(entry).partition("=")
        env[name] = value
    return env


def _effective_compose_env(compose_file: str, service: str) -> dict[str, str]:
    """Return a service's environment after layering the file on its bases.

    Args:
        compose_file: Compose file name at the repo root.
        service: Service name.

    Returns:
        The merged environment, later files winning per variable.
    """
    env: dict[str, str] = {}
    for name in (*COMPOSE_FILES[compose_file], compose_file):
        services = yaml.safe_load((REPO_ROOT / name).read_text()).get("services") or {}
        if service in services:
            env.update(_compose_env(services[service]))
    return env


@pytest.mark.unit
@pytest.mark.parametrize("variable", POLICY_VARIABLES)
@pytest.mark.parametrize("compose_file", sorted(COMPOSE_FILES))
def test_compose_auth_server_gets_registry_policy_source(compose_file: str, variable: str) -> None:
    """Property: the auth-server interpolates each policy variable exactly as the registry does."""
    registry = _effective_compose_env(compose_file, COMPOSE_REGISTRY)
    auth = _effective_compose_env(compose_file, COMPOSE_AUTH)
    assert variable in registry, f"{compose_file}: registry does not receive {variable}"
    assert "${" + variable in registry[variable], (
        f"{compose_file}: registry {variable} is not read from the environment: {registry[variable]!r}"
    )
    assert auth.get(variable) == registry[variable], (
        f"{compose_file}: auth-server {variable}={auth.get(variable)!r}, "
        f"registry {variable}={registry[variable]!r}"
    )


# ---------------------------------------------------------------------------
# Helm
# ---------------------------------------------------------------------------


def _stack_copy_with_local_subcharts(workdir: Path) -> Path:
    """Copy the umbrella chart, swapping vendored ``file://`` subcharts for sources.

    Args:
        workdir: Empty temporary directory.

    Returns:
        Path of the copied umbrella chart.
    """
    stack = workdir / STACK_CHART
    shutil.copytree(CHARTS_ROOT / STACK_CHART, stack)
    chart_file = stack / "Chart.yaml"
    chart = yaml.safe_load(chart_file.read_text())
    kept = []
    for dependency in chart.get("dependencies", []):
        archive = stack / "charts" / f"{dependency['name']}-{dependency['version']}.tgz"
        if dependency["repository"].startswith("file://"):
            archive.unlink(missing_ok=True)
            shutil.copytree(
                CHARTS_ROOT / dependency["name"],
                stack / "charts" / dependency["name"],
                ignore=shutil.ignore_patterns("tests"),
            )
        elif not archive.exists():
            continue
        kept.append(dependency)
    chart["dependencies"] = kept
    chart_file.write_text(yaml.safe_dump(chart, sort_keys=False))
    (stack / "Chart.lock").unlink(missing_ok=True)
    return stack


@pytest.fixture(scope="module")
def stack_chart() -> Iterator[tuple[str, Path]]:
    """Yield the helm binary and an offline-renderable copy of the umbrella chart."""
    helm = shutil.which("helm")
    if helm is None:
        pytest.skip("helm is not on PATH")
    with tempfile.TemporaryDirectory() as workdir:
        yield helm, _stack_copy_with_local_subcharts(Path(workdir))


def _render(stack_chart: tuple[str, Path], overrides: dict) -> subprocess.CompletedProcess[str]:
    """Run ``helm template`` on the stack copy with a values override file.

    Args:
        stack_chart: The helm binary and the stack copy.
        overrides: Values merged over the stack defaults.

    Returns:
        The completed helm process.
    """
    helm, stack = stack_chart
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        yaml.safe_dump(overrides, handle)
        values_file = handle.name
    try:
        return subprocess.run(
            [
                helm,
                "template",
                "test",
                str(stack),
                "-f",
                values_file,
                *(arg for value in HELM_BASE_SET_VALUES for arg in ("--set", value)),
            ],
            capture_output=True,
            text=True,
            timeout=HELM_TIMEOUT_SECONDS,
            check=False,
        )
    finally:
        Path(values_file).unlink(missing_ok=True)


def _rendered_policy_env(stdout: str) -> dict[str, dict[str, str | None]]:
    """Return each Deployment's main-container value of every policy variable.

    Args:
        stdout: ``helm template`` output.

    Returns:
        Map of chart to ``{variable: value}``; a missing variable maps to None.
    """
    found: dict[str, dict[str, str | None]] = {}
    for document in yaml.safe_load_all(stdout):
        if not isinstance(document, dict) or document.get("kind") != "Deployment":
            continue
        name = document["metadata"]["name"]
        chart = next((c for c, d in HELM_DEPLOYMENTS.items() if d == name), None)
        if chart is None:
            continue
        env = {
            entry["name"]: entry.get("value")
            for entry in document["spec"]["template"]["spec"]["containers"][0].get("env") or []
        }
        found[chart] = {variable: env.get(variable) for variable in POLICY_VARIABLES}
    assert set(found) == set(HELM_DEPLOYMENTS), f"rendered Deployments: {sorted(found)}"
    return found


def _app_overrides(values: dict) -> dict:
    """Build an override setting the same ``app`` values on both subcharts.

    Args:
        values: ``app`` keys to set.

    Returns:
        A values override for the umbrella chart.
    """
    return {"registry": {"app": dict(values)}, "auth-server": {"app": dict(values)}}


@pytest.mark.unit
def test_helm_auth_server_renders_operator_policy(stack_chart: tuple[str, Path]) -> None:
    """Property: the policy an operator configures reaches the auth-server exactly as the registry."""
    result = _render(stack_chart, _app_overrides(HELM_SENTINELS))
    assert result.returncode == 0, result.stderr[:4000]
    rendered = _rendered_policy_env(result.stdout)
    for variable, key in HELM_KEYS.items():
        expected = (
            str(HELM_SENTINELS[key]).lower() if key.startswith("gateway") else HELM_SENTINELS[key]
        )
        assert rendered["registry"][variable] == expected, (
            f"registry {variable}: {rendered['registry']}"
        )
        assert rendered["auth-server"][variable] == expected, (
            f"auth-server {variable}={rendered['auth-server'][variable]!r}, registry has {expected!r}"
        )


@pytest.mark.unit
def test_helm_default_render_gives_both_the_same_policy(stack_chart: tuple[str, Path]) -> None:
    """Property: with the shipped stack values both containers render the same policy."""
    result = _render(stack_chart, {})
    assert result.returncode == 0, result.stderr[:4000]
    rendered = _rendered_policy_env(result.stdout)
    for variable in POLICY_VARIABLES:
        assert rendered["auth-server"][variable] is not None, f"auth-server lacks {variable}"
        assert rendered["auth-server"][variable] == rendered["registry"][variable], (
            f"{variable}: auth-server={rendered['auth-server'][variable]!r}, "
            f"registry={rendered['registry'][variable]!r}"
        )


@pytest.mark.unit
@pytest.mark.parametrize("variable", POLICY_VARIABLES)
def test_helm_registry_only_override_never_deploys_drift(
    stack_chart: tuple[str, Path], variable: str
) -> None:
    """Property: changing only the registry's policy never renders a diverging auth-server.

    The render either fails closed naming the value, or carries the same value
    into the auth-server.
    """
    key = HELM_KEYS[variable]
    result = _render(stack_chart, {"registry": {"app": {key: HELM_SENTINELS[key]}}})
    if result.returncode != 0:
        assert key in result.stderr, f"render failed for another reason:\n{result.stderr[:4000]}"
        return
    rendered = _rendered_policy_env(result.stdout)
    assert rendered["auth-server"][variable] == rendered["registry"][variable], (
        f"drift rendered: auth-server {variable}={rendered['auth-server'][variable]!r}, "
        f"registry {variable}={rendered['registry'][variable]!r}"
    )


def _mapping_child(node: yaml.Node, key: str) -> yaml.Node | None:
    """Return the value node under ``key`` in a YAML mapping node.

    Args:
        node: A composed mapping node.
        key: Scalar key to find.

    Returns:
        The value node, or None when the key is absent.
    """
    if not isinstance(node, yaml.MappingNode):
        return None
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
            return value_node
    return None


@pytest.mark.unit
@pytest.mark.parametrize("key", sorted(HELM_KEYS.values()))
def test_stack_values_declare_each_policy_value_once(key: str) -> None:
    """Property: the shipped stack values feed both subcharts from one declaration."""
    root = yaml.compose(
        (CHARTS_ROOT / STACK_CHART / "values.yaml").read_text(), Loader=yaml.SafeLoader
    )
    registry = _mapping_child(_mapping_child(root, "registry"), "app")
    auth = _mapping_child(_mapping_child(root, "auth-server"), "app")
    registry_value = _mapping_child(registry, key)
    auth_value = _mapping_child(auth, key)
    assert registry_value is not None, f"registry.app.{key} is not declared in the stack values"
    assert auth_value is registry_value, (
        f"auth-server.app.{key} is not an alias of registry.app.{key} in the stack values"
    )


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------


def _tf_module_env(module: str) -> dict[str, list[str]]:
    """Return every ``{ name = "...", value = ... }`` env entry of an ECS service module.

    Args:
        module: Module block name in ``ecs-services.tf``.

    Returns:
        Map of env name to the value expressions written for it.
    """
    text = (TF_MODULE_DIR / "ecs-services.tf").read_text()
    body = _body(text, re.compile(r'^module\s+"' + module + r'"\s*\{', re.M), True)
    entries: dict[str, list[str]] = {}
    for match in re.finditer(r'\bname\s*=\s*"([A-Z][A-Z0-9_]*)"\s*\n\s*value\s*=\s*([^\n]+)', body):
        entries.setdefault(match.group(1), []).append(match.group(2).strip())
    return entries


@pytest.mark.unit
@pytest.mark.parametrize("variable", POLICY_VARIABLES)
def test_terraform_auth_server_gets_registry_policy_source(variable: str) -> None:
    """Property: the auth-server task sets each policy variable from the registry's expression."""
    registry = _tf_module_env(TF_REGISTRY_MODULE).get(variable, [])
    auth = _tf_module_env(TF_AUTH_MODULE).get(variable, [])
    assert len(registry) == 1, f"registry task sets {variable} {len(registry)} times: {registry}"
    assert "var." in registry[0], f"registry {variable} is not variable-driven: {registry[0]}"
    assert auth == registry, f"auth-server {variable} expressions {auth}, registry {registry}"


def _tf_reserved_extra_env_names(path: Path, variable_name: str) -> set[str]:
    """Return the string literals inside a variable block's ``validation`` blocks.

    Args:
        path: Terraform file declaring the variable.
        variable_name: Variable name.

    Returns:
        Every quoted literal in the block's validations.
    """
    body = _body(
        path.read_text(), re.compile(r'^variable\s+"' + variable_name + r'"\s*\{', re.M), True
    )
    names: set[str] = set()
    for validation in re.finditer(r"^\s*validation\s*\{", body, re.M):
        open_idx = validation.end() - 1
        block = body[open_idx : _match_bracket(body, open_idx, True)]
        names.update(re.findall(r'"([A-Z][A-Z0-9_]*)"', block))
    return names


@pytest.mark.unit
@pytest.mark.parametrize("variable", POLICY_VARIABLES)
@pytest.mark.parametrize("extra_env", ["registry_extra_env", "auth_server_extra_env"])
@pytest.mark.parametrize("tf_dir", [TF_ROOT_DIR, TF_MODULE_DIR], ids=["root", "module"])
def test_terraform_extra_env_cannot_override_policy(
    tf_dir: Path, extra_env: str, variable: str
) -> None:
    """Property: neither service's extra env list can replace a policy variable on one side only."""
    reserved = _tf_reserved_extra_env_names(tf_dir / "variables.tf", extra_env)
    assert variable in reserved, (
        f"{tf_dir.name}/variables.tf {extra_env} does not reject {variable}"
    )


# ---------------------------------------------------------------------------
# CDK
# ---------------------------------------------------------------------------


def _top_level_members(body: str) -> list[str]:
    """Split a TypeScript object-literal body at its top-level commas.

    Args:
        body: Text between the literal's braces.

    Returns:
        Each member's source with whole-line ``//`` comments removed.
    """
    members: list[str] = []
    depth = 0
    start = 0
    j = 0
    while j < len(body):
        skipped = _skip_non_code(body, j, False)
        if skipped is not None:
            j = skipped
            continue
        if body[j] in _BRACKET_PAIRS:
            depth += 1
        elif body[j] in ")]}":
            depth -= 1
        elif body[j] == "," and depth == 0:
            members.append(body[start:j])
            start = j + 1
        j += 1
    members.append(body[start:])
    cleaned = (
        "\n".join(line for line in member.splitlines() if not line.strip().startswith("//")).strip()
        for member in members
    )
    return [member for member in cleaned if member]


def _cdk_effective_env(text: str, identifier: str) -> dict[str, str]:
    """Resolve a CDK env object literal to a name-to-expression map.

    A spread of another env literal is resolved recursively. A names spread
    under a condition maps each of its names to the whole spread expression.

    Args:
        text: Source of the stack file.
        identifier: Name of the ``const <identifier>: Record<string, string> = {`` literal.

    Returns:
        The effective name-to-expression map, later members winning.
    """
    body = _body(
        text,
        re.compile(r"\bconst\s+" + identifier + r"\s*:\s*Record<string,\s*string>\s*=\s*\{"),
        False,
    )
    env: dict[str, str] = {}
    for member in _top_level_members(body):
        if member.startswith("..."):
            spread = member[3:].strip()
            if re.fullmatch(r"[A-Za-z_]\w*", spread):
                env.update(_cdk_effective_env(text, spread))
            else:
                for name in re.findall(r"\b([A-Z][A-Z0-9_]*)\s*:", spread):
                    env[name] = spread
            continue
        pair = re.fullmatch(r"([A-Z][A-Z0-9_]*)\s*:\s*(.+)", member, re.S)
        if pair:
            env[pair.group(1)] = " ".join(pair.group(2).split())
    return env


@pytest.mark.unit
@pytest.mark.parametrize("variable", POLICY_VARIABLES)
def test_cdk_auth_server_gets_registry_policy_source(variable: str) -> None:
    """Property: the CDK auth-server env sets each policy variable exactly as the registry env."""
    text = CDK_STACK_FILE.read_text()
    registry = _cdk_effective_env(text, "registryEnv")
    auth = _cdk_effective_env(text, "authEnv")
    assert auth.get(variable) == registry.get(variable), (
        f"CDK {variable}: authEnv={auth.get(variable)!r}, registryEnv={registry.get(variable)!r}"
    )
