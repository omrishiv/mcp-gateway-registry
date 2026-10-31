"""Every env name a Helm chart sets on its container is reserved against extraEnv.

Pins the no-silent-shadowing property of the ``mcpgw``, ``auth-server`` and
``registry`` charts: each chart's ``reserved-env-names.txt`` is what its
``validateExtraEnv`` helper (and the Docker and Terraform extra-env validators)
rejects, so every name the chart itself sets, directly under ``env:`` in
``templates/deployment.yaml`` or through ``envFrom`` from a chart-rendered
ConfigMap or Secret, must be listed there. Otherwise a user ``extraEnv`` entry
of that name renders without error and, because Kubernetes lets ``env:`` win
over ``envFrom``, replaces the chart-managed value. Names come from a static
scan of the templates, which covers every conditional branch, plus an offline
``helm template`` of the umbrella chart when ``helm`` is on PATH.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHARTS_ROOT = REPO_ROOT / "charts"
STACK_CHART = "mcp-gateway-registry-stack"
HELM_TIMEOUT_SECONDS = 120

# Chart directory name to the metadata.name of its Deployment.
CHART_DEPLOYMENTS: dict[str, str] = {
    "mcpgw": "mcpgw-server",
    "auth-server": "auth-server",
    "registry": "registry",
}

# Values for the offline umbrella render: the CI reserved-list-sync profile plus
# the optional envFrom sources (egress config maps) and the five templated
# EMBEDDINGS_EXTRA_HEADER_<n> entries. No extraEnv or extraEnvFrom is set, so
# every rendered name is chart-managed.
RENDER_SET_VALUES: tuple[str, ...] = (
    "global.authProvider.type=keycloak",
    "global.secretKey=test-only-secret-key",
    "keycloak.adminPassword=test-only-admin-password",
    "registry.awsRegistry.federationEnabled=true",
    "global.ingress.tls=false",
    "global.ingress.routingMode=host",
    "registry.egressAuth.enabled=true",
    "auth-server.egressAuth.enabled=true",
    "registry.embeddings.extraHeaders={X-A: a,X-B: b,X-C: c,X-D: d,X-E: e}",
)

# Reserved names no template renders. The list is documented as a superset
# ("over-rejection is preferred to under-rejection"), so these are deliberate,
# each for the reason given; a stale entry not listed here fails the
# differential test below.
RESERVED_WITHOUT_RENDER: dict[tuple[str, str], str] = {
    ("mcpgw", "OIDC_ENABLED"): (
        "reserved so extraEnv cannot half-enable the OAuth proxy (see the comment on "
        "mcpgw.reservedEnvNames in _helpers.tpl)"
    ),
    ("registry", "REGISTRY_API_TOKEN"): (
        "the static admin API token; reserving it stops extraEnv from minting an admin credential"
    ),
    ("registry", "EGRESS_CREDENTIAL_ENCRYPTION_REQUIRE_ENCRYPTED"): (
        "egress vault encryption enforcement; reserving it stops extraEnv from relaxing it"
    ),
}


def _reserved_names(chart: str) -> dict[str, int]:
    """Return the names in a chart's reserved list with their line numbers.

    Args:
        chart: Chart directory name.

    Returns:
        Map of reserved name to 1-based line, skipping blanks and ``#`` comments.
    """
    path = CHARTS_ROOT / chart / "reserved-env-names.txt"
    names: dict[str, int] = {}
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        name = raw.strip()
        if name and not name.startswith("#"):
            names.setdefault(name, number)
    return names


def _is_env_name(value: str) -> bool:
    """Return True if ``value`` is a literal environment variable name."""
    return value.replace("_", "A").isalnum() and not value[0].isdigit()


def _static_env_names(chart: str) -> dict[str, str]:
    """Scan ``templates/deployment.yaml`` for every literal ``env:`` entry name.

    Every conditional branch is included, because the scan reads the template
    rather than one rendering of it. Names built by template expressions are
    left to the rendered scan.

    Args:
        chart: Chart directory name.

    Returns:
        Map of env name to ``file:line`` of its first ``- name:`` entry.
    """
    rel_path = f"charts/{chart}/templates/deployment.yaml"
    names: dict[str, str] = {}
    env_indent: int | None = None
    item_indent: int | None = None
    for number, line in enumerate((REPO_ROOT / rel_path).read_text().splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("{{", "#")):
            continue
        indent = len(line) - len(line.lstrip())
        if env_indent is not None and indent <= env_indent:
            env_indent = None
        if stripped == "env:":
            env_indent, item_indent = indent, None
            continue
        if env_indent is None or not stripped.startswith("- name:"):
            continue
        if item_indent is None:
            item_indent = indent
        value = stripped.removeprefix("- name:").strip().strip("\"'")
        if indent == item_indent and _is_env_name(value):
            names.setdefault(value, f"{rel_path}:{number}")
    return names


def _static_data_keys(rel_path: str) -> dict[str, str]:
    """Scan a ConfigMap or Secret template for every literal top-level data key.

    Args:
        rel_path: Repo-relative template path.

    Returns:
        Map of key to ``file:line``, across every conditional branch.
    """
    keys: dict[str, str] = {}
    for number, line in enumerate((REPO_ROOT / rel_path).read_text().splitlines(), start=1):
        if not line.startswith("  ") or line.startswith("   "):
            continue
        key, sep, _ = line.strip().partition(":")
        if sep and _is_env_name(key) and key.isupper():
            keys.setdefault(key, f"{rel_path}:{number}")
    return keys


def _stack_copy_with_local_subcharts(workdir: Path) -> Path:
    """Copy the umbrella chart, swapping vendored ``file://`` subcharts for sources.

    The vendored ``charts/*.tgz`` of local subcharts can lag the working tree,
    so each is replaced by a copy of ``charts/<name>``. Remote dependencies
    whose archive is absent are dropped, since fetching them needs network.

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


def _render_stack() -> list[tuple[str, dict]] | None:
    """Render the umbrella chart offline, or return None when helm is absent.

    Returns:
        ``(source template, document)`` pairs, the source mapped to a repo path.

    Raises:
        RuntimeError: If helm is installed but the render fails.
    """
    helm = shutil.which("helm")
    if helm is None:
        return None
    with tempfile.TemporaryDirectory() as workdir:
        stack = _stack_copy_with_local_subcharts(Path(workdir))
        result = subprocess.run(
            [
                helm,
                "template",
                "test",
                str(stack),
                *(arg for value in RENDER_SET_VALUES for arg in ("--set", value)),
            ],
            capture_output=True,
            text=True,
            timeout=HELM_TIMEOUT_SECONDS,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"helm template failed:\n{result.stderr[:4000]}")
    documents: list[tuple[str, dict]] = []
    for chunk in result.stdout.split("\n---"):
        document = yaml.safe_load(chunk)
        if not isinstance(document, dict):
            continue
        source = ""
        for line in chunk.splitlines():
            if line.startswith("# Source: "):
                source = _repo_template_path(line.removeprefix("# Source: ").strip())
                break
        documents.append((source, document))
    return documents


def _repo_template_path(rendered_source: str) -> str:
    """Map a helm ``# Source:`` path to the repo path of that template.

    Args:
        rendered_source: e.g. ``mcp-gateway-registry-stack/charts/registry/templates/secret.yaml``.

    Returns:
        e.g. ``charts/registry/templates/secret.yaml``.
    """
    inner = rendered_source.split("/", 1)[1]
    if inner.startswith("charts/"):
        return inner
    return f"charts/{STACK_CHART}/{inner}"


def _rendered_env_names(documents: list[tuple[str, dict]]) -> dict[str, dict[str, str]]:
    """Collect env names and envFrom keys each chart's Deployment receives.

    For every envFrom ConfigMap or Secret the render produced, both its
    rendered keys and a static scan of its source template (every branch)
    count.

    Args:
        documents: Rendered ``(source, document)`` pairs.

    Returns:
        Map of chart to ``{name: origin}``.
    """
    sources: dict[tuple[str, str], tuple[str, set[str]]] = {}
    for source, document in documents:
        if document.get("kind") in ("ConfigMap", "Secret"):
            keys = set(document.get("data") or {}) | set(document.get("stringData") or {})
            sources[(document["kind"], document["metadata"]["name"])] = (source, keys)
    by_deployment = {deployment: chart for chart, deployment in CHART_DEPLOYMENTS.items()}
    names: dict[str, dict[str, str]] = {chart: {} for chart in CHART_DEPLOYMENTS}
    for source, document in documents:
        chart = by_deployment.get(document.get("metadata", {}).get("name", ""))
        if document.get("kind") != "Deployment" or chart is None:
            continue
        pod = document["spec"]["template"]["spec"]
        for container in [*pod.get("initContainers", []), *pod["containers"]]:
            for entry in container.get("env") or []:
                names[chart].setdefault(entry["name"], f"rendered {source}")
            for env_from in container.get("envFrom") or []:
                if "configMapRef" in env_from:
                    ref = ("ConfigMap", env_from["configMapRef"]["name"])
                else:
                    ref = ("Secret", env_from["secretRef"]["name"])
                assert ref in sources, f"{chart}: envFrom {ref} was not rendered"
                template, keys = sources[ref]
                if (REPO_ROOT / template).is_file():
                    for key, origin in _static_data_keys(template).items():
                        names[chart].setdefault(key, origin)
                for key in keys:
                    names[chart].setdefault(key, f"rendered {template}")
    return names


def _chart_env_names() -> tuple[dict[str, dict[str, str]], bool]:
    """Return every chart-managed env name per chart, and whether helm rendered.

    Returns:
        ``({chart: {name: origin}}, rendered)``.
    """
    names = {chart: _static_env_names(chart) for chart in CHART_DEPLOYMENTS}
    documents = _render_stack()
    if documents is None:
        return names, False
    for chart, rendered in _rendered_env_names(documents).items():
        for name, origin in rendered.items():
            names[chart].setdefault(name, origin)
    return names, True


_ENV_NAMES, _RENDERED = _chart_env_names()


def _forward_params() -> list:
    """Build one param per (chart, chart-managed env name)."""
    params = []
    for chart, names in _ENV_NAMES.items():
        for name in sorted(names):
            params.append(pytest.param(chart, name, id=f"{chart}:{name}"))
    return params


def _reverse_params() -> list:
    """Build one param per (chart, reserved name)."""
    return [
        pytest.param(chart, name, id=f"{chart}:{name}")
        for chart in CHART_DEPLOYMENTS
        for name in sorted(_reserved_names(chart))
    ]


@pytest.mark.unit
@pytest.mark.parametrize(("chart", "name"), _forward_params())
def test_chart_managed_env_name_is_reserved(chart: str, name: str) -> None:
    """Property: every env name the chart sets is in its reserved-env-names.txt."""
    assert name in _reserved_names(chart), (
        f"{_ENV_NAMES[chart][name]} sets {name}, which is missing from "
        f"charts/{chart}/reserved-env-names.txt, so extraEnv can shadow it"
    )


@pytest.mark.unit
@pytest.mark.parametrize(("chart", "name"), _reverse_params())
def test_reserved_env_name_is_chart_managed(chart: str, name: str) -> None:
    """Property: a reserved name is set by the chart or is a documented over-reservation."""
    if not _RENDERED:
        pytest.skip("helm is not on PATH; envFrom keys need a render")
    line = _reserved_names(chart)[name]
    assert name in _ENV_NAMES[chart] or (chart, name) in RESERVED_WITHOUT_RENDER, (
        f"charts/{chart}/reserved-env-names.txt:{line} reserves {name}, which no "
        "template sets and which is not a documented over-reservation"
    )


@pytest.mark.unit
def test_reserved_without_render_names_chart_entries() -> None:
    """Property: every over-reservation entry is still reserved and still never rendered."""
    if not _RENDERED:
        pytest.skip("helm is not on PATH; envFrom keys need a render")
    stale = [
        key
        for key in RESERVED_WITHOUT_RENDER
        if key[1] not in _reserved_names(key[0]) or key[1] in _ENV_NAMES[key[0]]
    ]
    assert not stale, f"entries that no longer match the charts: {stale}"
