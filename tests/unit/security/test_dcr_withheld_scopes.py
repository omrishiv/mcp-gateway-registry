"""Static property tests for the scopes withheld from self-registered clients.

Pins the Dynamic Client Registration boundary: a client that registers itself
with Keycloak, through either the ``anonymous`` or the ``authenticated``
client-registration subtype, must never be able to request a client scope
that confers gateway privilege. A scope is privileged when its seed document
grants ``server: "*"`` or its ``ui_permissions`` make the holder an admin
under ``registry.auth.dependencies._user_is_admin``. Each deployment surface
that writes the Keycloak "Allowed Client Scopes" policy is modelled from its
own source (the withheld list, the jq filter that builds the allowlist and the
subtypes the policy is written for), and the surfaces are compared with each
other so that a realm withholds the same scopes whichever surface set it up.
"""

import functools
import itertools
import json
import re
import shutil
import subprocess
import textwrap
from dataclasses import (
    dataclass,
    field,
)
from pathlib import Path
from typing import Any

import pytest
import yaml

from registry.auth.dependencies import _user_is_admin

REPO_ROOT: Path = Path(__file__).resolve().parents[3]

# The two Keycloak client-registration policy subtypes. Keycloak applies the
# "authenticated" policies when the registration request carries an initial
# access or registration token and the "anonymous" policies otherwise.
SUBTYPES: tuple[str, ...] = ("anonymous", "authenticated")

# Every surface that provisions the Keycloak realm. Each one either writes the
# DCR "Allowed Client Scopes" policy itself or delegates to another surface.
SURFACE_PATHS: dict[str, str] = {
    "init-keycloak": "keycloak/setup/init-keycloak.sh",
    "upgrade-realm-for-dcr": "keycloak/setup/upgrade-realm-for-dcr.sh",
    "helm-keycloak-configure": "charts/keycloak-configure/templates/configmap.yaml",
    "terraform-aws-ecs": "terraform/aws-ecs/scripts/init-keycloak.sh",
}
HELM_SURFACE: str = "helm-keycloak-configure"
HELM_CHART_DIR: str = "charts/keycloak-configure"
HELM_SCRIPT_KEY: str = "script.sh"
HELM_RENDER_TIMEOUT_SECONDS: int = 60
JQ_TIMEOUT_SECONDS: int = 30

# Seed scope documents loaded into the scopes collection at install time.
SEED_GLOB: str = "scripts/*.json"

# The shell function that writes the allowlist, and the call that runs it.
ALLOWLIST_FUNCTION: str = "configure_dcr_allowed_scopes"
ALLOWLIST_INVOCATION_RE = re.compile(rf'^[ \t]*{ALLOWLIST_FUNCTION}[ \t]+"\$TOKEN"', re.M)
POLICY_NAME: str = '"Allowed Client Scopes"'

# Admin API endpoints that make a scope a realm default or optional scope.
# "allow-default-scopes" admits every such scope, so a surface that uses one
# is outside what this model covers and must be modelled before it is trusted.
REALM_DEFAULT_ENDPOINTS: tuple[str, ...] = (
    "default-default-client-scopes",
    "default-optional-client-scopes",
)

# Realm default and optional OIDC client scopes that Keycloak creates in a new
# realm. "allow-default-scopes" admits them, and the built-in policy of a
# subtype that no surface reconfigures admits only them.
KEYCLOAK_REALM_DEFAULT_SCOPES: frozenset[str] = frozenset(
    {
        "acr",
        "address",
        "basic",
        "email",
        "microprofile-jwt",
        "offline_access",
        "organization",
        "phone",
        "profile",
        "roles",
        "web-origins",
    }
)

# The OIDC scope every client requests. It is not a Keycloak client scope, so
# it is requestable only when a surface appends it to the allowlist.
OPENID_SCOPE: str = "openid"

# Realm scope names no surface declares: one plain name and one that follows
# the "/" naming convention, so the comparison covers both filter rules.
PROBE_SCOPES: tuple[str, ...] = ("probe-plain-scope", "probe/slash-scope")

_ARRAY_RE = re.compile(r"^[ \t]*(?P<name>[A-Z][A-Z0-9_]*)=\((?P<body>[^)]*)\)", re.M)
_JSON_LIST_RE = re.compile(r"^[ \t]*(?P<name>[A-Z][A-Z0-9_]*)='(?P<body>\[[^']*\])'", re.M)
_ARRAY_EXPANSION_RE = re.compile(r"\$\{(?P<name>[A-Z][A-Z0-9_]*)\[@\]\}")
_PRIVILEGED_ARG_RE = re.compile(r'--argjson\s+privileged\s+"\$(?P<var>\w+)"')
_JQ_PROGRAM_RE = re.compile(r"'(?P<program>[^']*)'")
_POLICY_CALL_RE = re.compile(
    r'^[ \t]*(?P<func>_\w+)[ \t]+"\$token"[ \t]+"(?P<subtype>\w+)"'
    r'[ \t]+"\$components"[ \t]+"\$all_scope_names"',
    re.M,
)
_DIRECT_SUBTYPE_RE = re.compile(r'--arg\s+subType\s+"(?P<subtype>\w+)"')
_ALLOW_DEFAULT_RE = re.compile(r'"allow-default-scopes":\s*\[\s*"true"\s*\]')
_ALLOWED_SCOPES_ARG_RE = re.compile(r'--argjson\s+allowedScopes\s+"\$all_scope_names"')
_DELEGATION_RE = re.compile(
    r'DCR_SCRIPT="\$\(cd "\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)/(?P<rel>[^"]+)"'
    r'[^)]*&& pwd\)/(?P<name>[^"]+)"'
)
_DELEGATION_CALL_RE = re.compile(r'\bbash[ \t]+"\$DCR_SCRIPT"')
_JQ_SOURCES: frozenset[str] = frozenset({".[].name", "$realm[]"})


@dataclass(frozen=True)
class _Script:
    """Shell text of one surface plus the mapping back to its source file."""

    rel_path: str
    text: str
    line_offset: int = 0

    def ref(
        self,
        pos: int,
    ) -> str:
        """Return ``file:line`` in the source file for an offset in ``text``.

        Args:
            pos: Character offset into ``text``.

        Returns:
            Repo-relative path and 1-based line number.
        """
        return f"{self.rel_path}:{self.text.count(chr(10), 0, pos) + 1 + self.line_offset}"


@dataclass(frozen=True)
class _Allowlist:
    """The allowlist a surface computes from the names of the realm's scopes."""

    withheld: tuple[str, ...]
    withheld_ref: str
    uses_withheld: bool
    excluded_substrings: tuple[str, ...]
    appended: frozenset[str]
    filter_ref: str
    program: str
    source_clause: str

    def admits(
        self,
        realm_scopes: frozenset[str],
    ) -> frozenset[str]:
        """Return the allowlist the jq filter builds for a realm.

        Args:
            realm_scopes: Names of every client scope in the realm.

        Returns:
            Names written to ``allowed-client-scopes``.
        """
        excluded = frozenset(self.withheld) if self.uses_withheld else frozenset()
        kept = {
            name
            for name in realm_scopes
            if name not in excluded and not any(s in name for s in self.excluded_substrings)
        }
        return frozenset(kept) | self.appended


@dataclass(frozen=True)
class _Surface:
    """What one deployment surface does to the DCR Allowed Client Scopes policy."""

    surface_id: str
    rel_path: str
    allowlist: _Allowlist | None
    policies: dict[str, bool] = field(default_factory=dict)
    policy_refs: dict[str, str] = field(default_factory=dict)
    delegated_to: str | None = None

    def allowed(
        self,
        subtype: str,
        realm_scopes: frozenset[str],
    ) -> frozenset[str]:
        """Return the scopes a self-registered client of ``subtype`` may request.

        Args:
            subtype: Client-registration subtype.
            realm_scopes: Names of every client scope in the realm.

        Returns:
            Requestable scope names.
        """
        if subtype not in self.policies:
            return KEYCLOAK_REALM_DEFAULT_SCOPES
        assert self.allowlist is not None
        allowed = self.allowlist.admits(realm_scopes)
        if self.policies[subtype]:
            allowed |= KEYCLOAK_REALM_DEFAULT_SCOPES
        return allowed

    def withheld(
        self,
        subtype: str,
        realm_scopes: frozenset[str],
    ) -> frozenset[str]:
        """Return the requestable names a self-registered client is refused.

        Args:
            subtype: Client-registration subtype.
            realm_scopes: Names of every client scope in the realm.

        Returns:
            Realm scope names plus ``openid`` that the policy does not admit.
        """
        return (realm_scopes | {OPENID_SCOPE}) - self.allowed(subtype, realm_scopes)

    def describe(
        self,
        subtype: str,
    ) -> str:
        """Describe the policy this surface leaves in place for ``subtype``.

        Args:
            subtype: Client-registration subtype.

        Returns:
            Human-readable summary with source references.
        """
        via = f" (delegates to {self.delegated_to})" if self.delegated_to else ""
        if subtype not in self.policies:
            return (
                f"{self.rel_path}{via} never writes the {subtype} policy, so Keycloak's "
                f"built-in policy admits only realm default scopes"
            )
        allowlist = self.allowlist
        assert allowlist is not None
        withheld = list(allowlist.withheld) if allowlist.uses_withheld else []
        return (
            f"{subtype} policy written at {self.policy_refs[subtype]}{via}; it admits every "
            f"realm scope not on the withheld list {withheld} ({allowlist.withheld_ref}) and "
            f"not containing {list(allowlist.excluded_substrings)} (filter at "
            f"{allowlist.filter_ref}), plus {sorted(allowlist.appended)}"
            f"{', plus realm defaults' if self.policies[subtype] else ''}"
        )


def _read(
    rel_path: str,
) -> str:
    """Read a repo file as text.

    Args:
        rel_path: Repo-relative path.

    Returns:
        File contents.
    """
    return (REPO_ROOT / rel_path).read_text()


def _helm_script_from_template() -> tuple[str, int]:
    """Extract the Helm setup script from the raw configmap template.

    Returns:
        The dedented script and the template line just before its first line.
    """
    lines = _read(SURFACE_PATHS[HELM_SURFACE]).splitlines(keepends=True)
    header = next(i for i, line in enumerate(lines) if line.strip() == f"{HELM_SCRIPT_KEY}: |")
    return textwrap.dedent("".join(lines[header + 1 :])), header + 1


def _helm_rendered_script() -> str | None:
    """Render the keycloak-configure chart and return the setup script.

    Returns:
        The rendered ``script.sh``, or None when helm is unavailable or fails.
    """
    helm = shutil.which("helm")
    if helm is None:
        return None
    try:
        result = subprocess.run(
            [helm, "template", "keycloak-configure", str(REPO_ROOT / HELM_CHART_DIR)],
            capture_output=True,
            text=True,
            timeout=HELM_RENDER_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    for doc in yaml.safe_load_all(result.stdout):
        if isinstance(doc, dict) and doc.get("kind") == "ConfigMap":
            script = (doc.get("data") or {}).get(HELM_SCRIPT_KEY)
            if script:
                return script
    return None


@functools.cache
def _script(
    surface_id: str,
) -> _Script:
    """Load the shell text a surface runs.

    The Helm surface is rendered with ``helm template`` when helm is on PATH and
    falls back to the raw template block otherwise. Line numbers always refer to
    the template, because the script block carries no template directives.

    Args:
        surface_id: Key of ``SURFACE_PATHS``.

    Returns:
        The script and its mapping back to the source file.
    """
    rel_path = SURFACE_PATHS[surface_id]
    if surface_id != HELM_SURFACE:
        return _Script(rel_path=rel_path, text=_read(rel_path))
    raw, offset = _helm_script_from_template()
    rendered = _helm_rendered_script()
    return _Script(rel_path=rel_path, text=rendered or raw, line_offset=offset)


def _function_body(
    script: _Script,
    name: str,
) -> tuple[str, int] | None:
    """Return the body of a shell function and its offset in the script.

    Args:
        script: Surface script.
        name: Function name.

    Returns:
        Body text and start offset, or None when the function is not defined.
    """
    opener = re.search(rf"^(?P<indent>[ \t]*){re.escape(name)}\(\)\s*\{{[ \t]*$", script.text, re.M)
    if opener is None:
        return None
    closer = re.compile(rf"^{opener.group('indent')}\}}[ \t]*$", re.M).search(
        script.text, opener.end()
    )
    if closer is None:
        raise ValueError(f"{script.ref(opener.start())}: function {name} is never closed")
    return script.text[opener.end() : closer.start()], opener.end()


def _top_level_lists(
    script: _Script,
) -> dict[str, tuple[tuple[str, ...], str]]:
    """Parse the upper-case bash arrays and JSON list strings a script defines.

    Args:
        script: Surface script.

    Returns:
        Map of variable name to its items and ``file:line`` of the definition.
    """
    found: list[tuple[int, str, str, bool]] = [
        (m.start(), m.group("name"), m.group("body"), False)
        for m in _ARRAY_RE.finditer(script.text)
    ]
    found += [
        (m.start(), m.group("name"), m.group("body"), True)
        for m in _JSON_LIST_RE.finditer(script.text)
    ]
    lists: dict[str, tuple[tuple[str, ...], str]] = {}
    for pos, name, body, is_json in sorted(found):
        if is_json:
            items = tuple(json.loads(body))
        else:
            if re.sub(r'"[^"]*"', "", body).strip():
                raise ValueError(f"{script.ref(pos)}: unquoted item in bash array {name}")
            items = ()
            for item in re.findall(r'"([^"]*)"', body):
                expansion = _ARRAY_EXPANSION_RE.fullmatch(item)
                if expansion is not None:
                    items += lists[expansion.group("name")][0]
                elif "$" in item:
                    raise ValueError(f"{script.ref(pos)}: unmodelled expansion {item!r}")
                else:
                    items += (item,)
        lists[name] = (items, script.ref(pos))
    return lists


def _split_top(
    text: str,
    sep: str,
) -> list[str]:
    """Split jq text on ``sep`` outside brackets and string literals.

    Args:
        text: Whitespace-free jq text.
        sep: One-character separator.

    Returns:
        The top-level pieces.
    """
    pieces: list[str] = []
    depth = 0
    in_string = False
    start = 0
    i = 0
    while i < len(text):
        char = text[i]
        if in_string:
            if char == "\\":
                i += 1
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == sep and depth == 0:
            pieces.append(text[start:i])
            start = i + 1
        i += 1
    pieces.append(text[start:])
    return pieces


def _parse_jq_program(
    program: str,
) -> tuple[str, bool, tuple[str, ...], frozenset[str]]:
    """Interpret the jq filter that builds the DCR allowlist.

    Only the clause shapes the surfaces use are understood; any other clause
    raises, so a reshaped filter is reported instead of being misread.

    Args:
        program: The jq program text.

    Returns:
        The source clause, whether the withheld list is applied, the substrings
        that exclude a name, and the names appended to the result.
    """
    compact = re.sub(r"\s+", "", program)
    collect, *tail = _split_top(compact, "+")
    if not (collect.startswith("[") and collect.endswith("]")):
        raise ValueError(f"unmodelled jq allowlist program: {program!r}")
    clauses = _split_top(collect[1:-1], "|")
    source = clauses[0]
    if source not in _JQ_SOURCES:
        raise ValueError(f"unmodelled jq source {source!r} in {program!r}")
    binding = "."
    uses_withheld = False
    substrings: list[str] = []
    for clause in clauses[1:]:
        bound = re.fullmatch(r"\.as\$(\w+)", clause)
        member = re.fullmatch(r"select\(\(\$privileged\|index\((\$\w+|\.)\)\)==null\)", clause)
        contains = re.fullmatch(r'select\(contains\(("(?:[^"\\]|\\.)*")\)\|not\)', clause)
        if bound is not None:
            binding = f"${bound.group(1)}"
        elif member is not None and member.group(1) == binding:
            uses_withheld = True
        elif contains is not None:
            substrings.append(json.loads(contains.group(1)))
        else:
            raise ValueError(f"unmodelled jq clause {clause!r} in {program!r}")
    appended: set[str] = set()
    for piece in tail:
        literal, *rest = _split_top(piece, "|")
        appended.update(json.loads(literal))
        if any(step != "unique" for step in rest):
            raise ValueError(f"unmodelled jq step after the allowlist: {piece!r}")
    return source, uses_withheld, tuple(substrings), frozenset(appended)


def _parse_allowlist(
    script: _Script,
    body: str,
    body_pos: int,
) -> _Allowlist:
    """Model the allowlist built inside ``configure_dcr_allowed_scopes``.

    Args:
        script: Surface script.
        body: Body of the allowlist function.
        body_pos: Offset of the body in the script.

    Returns:
        The allowlist model.
    """
    assignment = re.search(r"all_scope_names=\$\(", body)
    if assignment is None:
        raise ValueError(f"{script.ref(body_pos)}: no all_scope_names assignment")
    program_text = body[assignment.end() :]
    program_pos = body_pos + assignment.end()
    helper = re.match(r"\s*(?P<func>_\w+)\s", program_text)
    if helper is not None:
        helper_body = _function_body(script, helper.group("func"))
        if helper_body is None:
            raise ValueError(f"{script.ref(program_pos)}: {helper.group('func')} undefined")
        program_text, program_pos = helper_body
    privileged_arg = _PRIVILEGED_ARG_RE.search(program_text)
    if privileged_arg is None:
        raise ValueError(f"{script.ref(program_pos)}: allowlist filter takes no withheld list")
    program = _JQ_PROGRAM_RE.search(program_text, privileged_arg.end())
    if program is None:
        raise ValueError(f"{script.ref(program_pos)}: no jq program after the withheld list")
    lists = _top_level_lists(script)
    var = privileged_arg.group("var")
    if var not in lists:
        built = re.search(
            rf"\b{var}=\$\(printf '%s\\n' \"\$\{{(?P<array>[A-Z][A-Z0-9_]*)\[@\]\}}\"",
            body + program_text,
        )
        if built is None or built.group("array") not in lists:
            raise ValueError(f"{script.ref(program_pos)}: cannot resolve ${var}")
        var = built.group("array")
    withheld, withheld_ref = lists[var]
    source, uses_withheld, substrings, appended = _parse_jq_program(program.group("program"))
    return _Allowlist(
        withheld=withheld,
        withheld_ref=withheld_ref,
        uses_withheld=uses_withheld,
        excluded_substrings=substrings,
        appended=appended,
        filter_ref=script.ref(program_pos + privileged_arg.start()),
        program=program.group("program"),
        source_clause=source,
    )


def _parse_policies(
    script: _Script,
    body: str,
    body_pos: int,
) -> tuple[dict[str, bool], dict[str, str]]:
    """Find the subtypes whose policy receives the allowlist.

    Args:
        script: Surface script.
        body: Body of the allowlist function.
        body_pos: Offset of the body in the script.

    Returns:
        Map of subtype to its ``allow-default-scopes`` flag, and map of subtype
        to the ``file:line`` that writes its policy.
    """
    policies: dict[str, bool] = {}
    refs: dict[str, str] = {}
    calls = list(_POLICY_CALL_RE.finditer(body))
    for call in calls:
        writer = _function_body(script, call.group("func"))
        if writer is None or not _ALLOWED_SCOPES_ARG_RE.search(writer[0]):
            raise ValueError(f"{script.ref(body_pos + call.start())}: unmodelled policy writer")
        policies[call.group("subtype")] = bool(_ALLOW_DEFAULT_RE.search(writer[0]))
        refs[call.group("subtype")] = script.ref(body_pos + call.start())
    if not calls and _ALLOWED_SCOPES_ARG_RE.search(body):
        for direct in _DIRECT_SUBTYPE_RE.finditer(body):
            policies[direct.group("subtype")] = bool(_ALLOW_DEFAULT_RE.search(body))
            refs[direct.group("subtype")] = script.ref(body_pos + direct.start())
    unknown = set(policies) - set(SUBTYPES)
    if unknown:
        raise ValueError(f"{script.rel_path}: unknown client-registration subtypes {unknown}")
    return policies, refs


@functools.cache
def _surface(
    surface_id: str,
) -> _Surface:
    """Model what a surface leaves in the realm's Allowed Client Scopes policies.

    Args:
        surface_id: Key of ``SURFACE_PATHS``.

    Returns:
        The surface model.
    """
    script = _script(surface_id)
    for endpoint in REALM_DEFAULT_ENDPOINTS:
        if endpoint in script.text:
            raise ValueError(f"{script.ref(script.text.index(endpoint))}: unmodelled {endpoint}")
    function = _function_body(script, ALLOWLIST_FUNCTION)
    if function is None:
        delegation = _DELEGATION_RE.search(script.text)
        if delegation is not None and _DELEGATION_CALL_RE.search(script.text):
            target = (
                (REPO_ROOT / SURFACE_PATHS[surface_id]).parent
                / delegation.group("rel")
                / delegation.group("name")
            ).resolve()
            target_rel = target.relative_to(REPO_ROOT).as_posix()
            delegate_id = next(k for k, v in SURFACE_PATHS.items() if v == target_rel)
            delegate = _surface(delegate_id)
            return _Surface(
                surface_id=surface_id,
                rel_path=script.ref(delegation.start()),
                allowlist=delegate.allowlist,
                policies=delegate.policies,
                policy_refs=delegate.policy_refs,
                delegated_to=delegate.rel_path,
            )
        if POLICY_NAME in script.text:
            raise ValueError(f"{script.rel_path}: unmodelled Allowed Client Scopes write")
        return _Surface(surface_id=surface_id, rel_path=script.rel_path, allowlist=None)
    body, body_pos = function
    if not ALLOWLIST_INVOCATION_RE.search(script.text):
        return _Surface(surface_id=surface_id, rel_path=script.rel_path, allowlist=None)
    policies, refs = _parse_policies(script, body, body_pos)
    return _Surface(
        surface_id=surface_id,
        rel_path=script.rel_path,
        allowlist=_parse_allowlist(script, body, body_pos),
        policies=policies,
        policy_refs=refs,
    )


def _server_rules(
    server_access: list[Any],
) -> list[dict[str, Any]]:
    """Flatten a seed document's ``server_access`` into its rules.

    Args:
        server_access: The ``server_access`` list of a seed scope document.

    Returns:
        Every rule, including those nested under ``access_rules``.
    """
    rules: list[dict[str, Any]] = []
    for entry in server_access:
        if isinstance(entry, dict):
            rules.extend(entry.get("access_rules", [entry]) if "access_rules" in entry else [entry])
    return rules


def _privileged_seed_scopes() -> list[tuple[str, str, str]]:
    """List the seed scopes that confer gateway privilege.

    Returns:
        Tuples of scope name, seed file and the reason it is privileged.
    """
    privileged: list[tuple[str, str, str]] = []
    for path in sorted(REPO_ROOT.glob(SEED_GLOB)):
        doc = json.loads(path.read_text())
        if not isinstance(doc, dict) or "_id" not in doc:
            continue
        if "server_access" not in doc and "ui_permissions" not in doc:
            continue
        reasons = []
        if any(rule.get("server") == "*" for rule in _server_rules(doc.get("server_access") or [])):
            reasons.append('server_access grants server "*"')
        if _user_is_admin(doc.get("ui_permissions") or {}):
            reasons.append("ui_permissions confer admin")
        if reasons:
            rel = path.relative_to(REPO_ROOT).as_posix()
            privileged.append((doc["_id"], rel, " and ".join(reasons)))
    return privileged


def _differential_realm() -> frozenset[str]:
    """Build a realm holding every scope name any surface or seed knows of.

    Returns:
        Keycloak defaults, every declared withheld name, every seed scope and
        the probe names.
    """
    names = set(KEYCLOAK_REALM_DEFAULT_SCOPES) | set(PROBE_SCOPES)
    for path in REPO_ROOT.glob(SEED_GLOB):
        doc = json.loads(path.read_text())
        if isinstance(doc, dict) and "_id" in doc:
            names.add(doc["_id"])
    for surface_id in SURFACE_PATHS:
        allowlist = _surface(surface_id).allowlist
        if allowlist is not None:
            names.update(allowlist.withheld)
    return frozenset(names)


PRIVILEGED_SEED_SCOPES: list[tuple[str, str, str]] = _privileged_seed_scopes()


def _privileged_params() -> list[Any]:
    """Build one case per (surface, subtype, privileged scope)."""
    params = []
    for surface_id, subtype, (scope, seed, why) in itertools.product(
        SURFACE_PATHS, SUBTYPES, PRIVILEGED_SEED_SCOPES
    ):
        params.append(
            pytest.param(
                surface_id, subtype, scope, seed, why, id=f"{surface_id}-{subtype}-{scope}"
            )
        )
    return params


def _differential_params() -> list[Any]:
    """Build one case per (subtype, pair of surfaces)."""
    params = []
    for subtype in SUBTYPES:
        for first, second in itertools.combinations(SURFACE_PATHS, 2):
            params.append(pytest.param(subtype, first, second, id=f"{subtype}-{first}-vs-{second}"))
    return params


@pytest.mark.unit
@pytest.mark.parametrize(("surface_id", "subtype", "scope", "seed", "why"), _privileged_params())
def test_privileged_scope_withheld(
    surface_id: str,
    subtype: str,
    scope: str,
    seed: str,
    why: str,
) -> None:
    """Property: no self-registered client of any subtype may request a privileged scope.

    The realm is assumed to define the scope, since another surface or tool may
    have created it, so withholding it must not depend on its absence.
    """
    surface = _surface(surface_id)
    realm = KEYCLOAK_REALM_DEFAULT_SCOPES | {scope}
    assert scope not in surface.allowed(subtype, realm), (
        f"{scope!r} ({why}, {seed}) is requestable by a self-registered {subtype} "
        f"client on {surface_id}: {surface.describe(subtype)}"
    )


@pytest.mark.unit
@pytest.mark.parametrize(("subtype", "first", "second"), _differential_params())
def test_surfaces_withhold_the_same_scopes(
    subtype: str,
    first: str,
    second: str,
) -> None:
    """Property: every surface withholds the same requestable scopes for a subtype.

    Both surfaces are evaluated against one realm that holds every scope name
    any surface or seed file knows of, plus ``openid``.
    """
    realm = _differential_realm()
    first_surface = _surface(first)
    second_surface = _surface(second)
    first_withheld = first_surface.withheld(subtype, realm)
    second_withheld = second_surface.withheld(subtype, realm)
    assert first_withheld == second_withheld, (
        f"{subtype}: {first} withholds {sorted(first_withheld - second_withheld)} that "
        f"{second} admits, and {second} withholds {sorted(second_withheld - first_withheld)} "
        f"that {first} admits. {first}: {first_surface.describe(subtype)}. "
        f"{second}: {second_surface.describe(subtype)}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("surface_id", list(SURFACE_PATHS))
def test_allowlist_model_matches_jq(
    surface_id: str,
) -> None:
    """Property: the static reading of each jq allowlist filter matches jq itself.

    Runs the surface's own jq program on the differential realm and compares
    the result with the model the other tests rely on.
    """
    jq = shutil.which("jq")
    if jq is None:
        pytest.skip("jq is not on PATH")
    allowlist = _surface(surface_id).allowlist
    if allowlist is None:
        pytest.skip(f"{surface_id} writes no allowlist")
    realm = _differential_realm()
    args = [jq, "-c", "--argjson", "privileged", json.dumps(list(allowlist.withheld))]
    stdin = None
    if allowlist.source_clause == "$realm[]":
        args += ["-n", "--argjson", "realm", json.dumps(sorted(realm)), allowlist.program]
    else:
        args.append(allowlist.program)
        stdin = json.dumps([{"name": name} for name in sorted(realm)])
    result = subprocess.run(
        args,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=JQ_TIMEOUT_SECONDS,
        check=True,
    )
    from_jq = frozenset(json.loads(result.stdout))
    modelled = allowlist.admits(realm)
    assert from_jq == modelled, (
        f"{allowlist.filter_ref}: jq admits {sorted(from_jq - modelled)} beyond the model "
        f"and the model admits {sorted(modelled - from_jq)} beyond jq"
    )
