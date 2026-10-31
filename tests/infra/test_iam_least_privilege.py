"""Least-privilege checks over every IAM policy statement in the deploy code.

Pins the least-privilege property of the AWS deployments: no Allow statement in
the Terraform stack (``terraform/aws-ecs``) or the CDK app (``infra/``) grants
an ``Action`` of ``*`` or ``<service>:*``, no Allow statement grants an
unbounded ``Resource`` unless every action in it is one AWS only accepts on
``Resource: "*"``, and each role that exists in both stacks is granted the same
set of actions by both, so neither deployment path silently holds privileges
the other was reviewed without. The policies are read with a small
bracket-balancing scanner over HCL and TypeScript, so no Terraform or CDK
toolchain is needed.
"""

import re
from dataclasses import (
    dataclass,
    field,
)
from functools import cached_property
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TERRAFORM_ROOT = REPO_ROOT / "terraform" / "aws-ecs"
CDK_ROOTS = (REPO_ROOT / "infra" / "bin", REPO_ROOT / "infra" / "lib")

_BRACKET_PAIRS = {"{": "}", "[": "]", "(": ")"}
_HEREDOC_RE = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\n")
_MEMBER_KEY_RE = re.compile(r"\s*([\"']?)([A-Za-z_][A-Za-z0-9_]*)\1\s*(=|:)(?![=:])")
_TF_TOP_BLOCK_RE = re.compile(r'^(resource|data|module)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{', re.M)
_TF_JSONENCODE_RE = re.compile(r"(\w+)\s*=\s*jsonencode\s*\(")
_TF_EFFECT_KEY_RE = re.compile(r"\bEffect\s*=")
_CDK_STATEMENT_RE = re.compile(r"new\s+iam\.PolicyStatement\s*\(")
_CDK_SDK_CALLS_RE = re.compile(r"AwsCustomResourcePolicy\.fromSdkCalls\s*\(")
_CDK_CUSTOM_RESOURCE_RE = re.compile(r"new\s+cr\.AwsCustomResource\s*\(")
_CDK_SDK_ACTION_RE = re.compile(r"service:\s*'(\w+)'\s*,\s*action:\s*'(\w+)'")
_CDK_RESOURCE_POLICY_RE = re.compile(r"([\w.]+)\.addToResourcePolicy\(\s*$")
_ACCOUNT_ROOT_PRINCIPAL_RE = re.compile(
    r"^arn:(aws|\$\{[^}]+\}):iam::\$\{[^}]*account_id[^}]*\}:root$"
)

# Terraform functions that combine lists. Literals inside them are still list
# elements of the attribute; literals inside any other call are arguments.
_LIST_FUNCTIONS = frozenset(
    {"concat", "flatten", "compact", "distinct", "tolist", "toset", "coalescelist"}
)

# Actions that have no IAM resource type in the AWS Service Authorization
# Reference, so AWS only accepts them on Resource "*". A statement whose actions
# are all in this set may use Resource "*". Add an action here only after
# checking the reference; anything that accepts an ARN must be scoped to one.
ACTIONS_ONLY_ALLOWED_ON_ANY_RESOURCE: frozenset[str] = frozenset(
    {
        # ECR registry login token; no repository resource.
        "ecr:GetAuthorizationToken",
        # Identity lookup; needs no permission and has no resource type.
        "sts:GetCallerIdentity",
        # Session Manager data channels used by ECS Exec; no resource types.
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
        # Password generator used by rotation Lambdas; no resource type.
        "secretsmanager:GetRandomPassword",
        # AgentCore registry listing; no resource type.
        "bedrock-agentcore:ListRegistries",
        # EC2 describe calls; no resource-level permissions.
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeManagedPrefixLists",
    }
)

# Allow statements that grant a wildcard Resource for actions that accept a
# resource ARN. Each id is file:line of the statement.
KNOWN_UNBOUNDED_RESOURCE_STATEMENTS: tuple[tuple[str, str], ...] = (
    (
        "terraform/aws-ecs/codebuild.tf:326",
        "the CodeBuild role may create and write to any CloudWatch log group",
    ),
    (
        "terraform/aws-ecs/keycloak-ecs.tf:201",
        "the Keycloak task execution role may call kms:Decrypt with any key",
    ),
    (
        "terraform/aws-ecs/modules/mcp-gateway/iam.tf:131",
        "the ECS Exec task execution policy writes to every log group in every account",
    ),
    (
        "terraform/aws-ecs/secret-rotation.tf:101",
        "the rotation Lambda may create, delete and re-address any network interface",
    ),
    (
        "infra/lib/registry/constructs/keycloak-service.ts:239",
        "the Keycloak task execution role may call kms:Decrypt with any key",
    ),
    (
        "infra/lib/registry/registry-ops-stack.ts:247",
        "the rotation Lambda may create, delete and re-address any network interface",
    ),
)

# Allow statements that grant "*" or "<service>:*" as an action. None today.
KNOWN_WILDCARD_ACTION_STATEMENTS: tuple[tuple[str, str], ...] = ()

# The terraform-aws-modules/ecs service module (v6, modules/service/main.tf)
# builds part of each role itself, outside this repository. Its task execution
# policy is the AmazonECSTaskExecutionRolePolicy action set ("Pulled from
# AmazonECSTaskExecutionRolePolicy" in the module source), and
# enable_execute_command adds the ssmmessages channel actions to the task role.
_ECS_MODULE_TASK_EXEC_BUILTIN = frozenset({"managed:service-role/AmazonECSTaskExecutionRolePolicy"})
_ECS_MODULE_EXECUTE_COMMAND_BUILTIN = frozenset(
    {
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
    }
)

_CDK = "infra/lib/registry"
_CDK_REGISTRY_ECS = f"{_CDK}/constructs/registry-ecs-service.ts"
_CDK_MCP_SERVER = f"{_CDK}/constructs/mcp-server-service.ts"
_CDK_KEYCLOAK = f"{_CDK}/constructs/keycloak-service.ts"
_CDK_OBSERVABILITY = f"{_CDK}/constructs/observability-pipeline.ts"
_CDK_SECRETS_ACCESS = (f"{_CDK}/constructs/registry-secrets.ts", None, "this.accessStatements")


@dataclass(frozen=True)
class _RolePair:
    """One role that both stacks create, with where each stack grants to it.

    Terraform sources are ``("role", "aws_iam_role.<name>")``,
    ``("ecs_task_exec", "<module>")`` or ``("ecs_tasks", "<module>")``. CDK
    sources are ``(file, function or None, identifier)``: every
    ``PolicyStatement`` and AWS managed policy attached through that
    identifier inside that function (or file) counts.
    """

    name: str
    terraform: tuple[tuple[str, str], ...]
    cdk: tuple[tuple[str, str | None, str], ...]
    divergence: str | None = None


def _ecs_service_pair(
    name: str,
    module: str,
    cdk_role_file: str,
    task_extra: tuple[tuple[str, str | None, str], ...] = (),
    exec_extra: tuple[tuple[str, str | None, str], ...] = (),
    task_divergence: str | None = None,
    exec_divergence: str | None = None,
) -> tuple[_RolePair, _RolePair]:
    """Build the task and task-execution role pairs for one ECS service.

    Args:
        name: Service name used in the parametrize id.
        module: Terraform module block name of the service.
        cdk_role_file: CDK construct file that creates both roles.
        task_extra: CDK sources passed in for the task role.
        exec_extra: CDK sources passed in for the execution role.
        task_divergence: Known defect reason for the task role, if any.
        exec_divergence: Known defect reason for the execution role, if any.

    Returns:
        The task role pair and the task execution role pair.
    """
    return (
        _RolePair(
            f"{name}-task",
            (("ecs_tasks", module),),
            ((cdk_role_file, None, "taskRole"), *task_extra),
            task_divergence,
        ),
        _RolePair(
            f"{name}-task-execution",
            (("ecs_task_exec", module),),
            ((cdk_role_file, None, "taskExecRole"), *exec_extra),
            exec_divergence,
        ),
    )


_EXEC_LOG_DESCRIBE = (
    "Terraform also grants logs:DescribeLogGroups and logs:DescribeLogStreams "
    "to the task execution role."
)
_TASK_SECRETS = "Terraform also grants every platform secret plus KMS decrypt to the task role"

# Roles mapped by purpose. The CDK extra sources mirror the props passed in
# registry-service-stack.ts (additionalExecRoleStatements and friends). Not
# mapped: the Terraform ECS cluster-level task execution role (ecs.tf), which
# has no CDK counterpart.
ROLE_PAIRS: tuple[_RolePair, ...] = (
    _RolePair(
        "keycloak-task-execution",
        (("role", "aws_iam_role.keycloak_task_exec_role"),),
        ((_CDK_KEYCLOAK, None, "taskExecRole"),),
    ),
    _RolePair(
        "keycloak-task",
        (("role", "aws_iam_role.keycloak_task_role"),),
        ((_CDK_KEYCLOAK, None, "taskRole"),),
    ),
    _RolePair(
        "codebuild",
        (("role", "aws_iam_role.codebuild"),),
        ((f"{_CDK}/constructs/codebuild-pipeline.ts", None, "role"),),
    ),
    _RolePair(
        "secret-rotation-lambda",
        (("role", "aws_iam_role.rotation_lambda"),),
        ((f"{_CDK}/registry-ops-stack.ts", None, "role"),),
        "Terraform also grants rds:DescribeDBInstances to the rotation Lambda role.",
    ),
    _RolePair(
        "keycloak-rds-proxy",
        (("role", "aws_iam_role.rds_proxy_role"),),
        ((f"{_CDK}/constructs/keycloak-database.ts", None, "proxyRole"),),
        "CDK also grants kms:Decrypt to the RDS proxy role.",
    ),
    *_ecs_service_pair(
        "registry",
        "ecs_service_registry",
        _CDK_REGISTRY_ECS,
        task_extra=((f"{_CDK}/registry-service-stack.ts", None, "agentCoreStatements"),),
        exec_extra=(_CDK_SECRETS_ACCESS,),
        task_divergence=(f"{_TASK_SECRETS}, the egress vault, Cognito read and AMP remote write."),
        exec_divergence=_EXEC_LOG_DESCRIBE,
    ),
    *_ecs_service_pair(
        "auth-server",
        "ecs_service_auth",
        _CDK_REGISTRY_ECS,
        exec_extra=(_CDK_SECRETS_ACCESS,),
        task_divergence=f"{_TASK_SECRETS} and AMP remote write.",
        exec_divergence=_EXEC_LOG_DESCRIBE,
    ),
    *_ecs_service_pair(
        "mcpgw",
        "ecs_service_mcpgw",
        _CDK_MCP_SERVER,
        exec_extra=(_CDK_SECRETS_ACCESS,),
        task_divergence=f"{_TASK_SECRETS} and AMP remote write.",
        exec_divergence=_EXEC_LOG_DESCRIBE,
    ),
    *_ecs_service_pair(
        "currenttime",
        "ecs_service_currenttime",
        _CDK_MCP_SERVER,
        exec_divergence=_EXEC_LOG_DESCRIBE,
    ),
    *_ecs_service_pair(
        "realserverfaketools",
        "ecs_service_realserverfaketools",
        _CDK_MCP_SERVER,
        exec_divergence=_EXEC_LOG_DESCRIBE,
    ),
    *_ecs_service_pair(
        "flight-booking-agent",
        "ecs_service_flight_booking_agent",
        _CDK_MCP_SERVER,
        exec_divergence=_EXEC_LOG_DESCRIBE,
    ),
    *_ecs_service_pair(
        "travel-assistant-agent",
        "ecs_service_travel_assistant_agent",
        _CDK_MCP_SERVER,
        exec_divergence=_EXEC_LOG_DESCRIBE,
    ),
    _RolePair(
        "metrics-service-task",
        (("ecs_tasks", "ecs_service_metrics"),),
        (
            (_CDK_OBSERVABILITY, "_createTaskRole", "role"),
            (_CDK_OBSERVABILITY, None, "ampRemoteWritePolicy"),
        ),
        f"{_TASK_SECRETS}.",
    ),
    _RolePair(
        "metrics-service-task-execution",
        (("ecs_task_exec", "ecs_service_metrics"),),
        ((_CDK_OBSERVABILITY, "_createTaskExecRole", "role"), _CDK_SECRETS_ACCESS),
        _EXEC_LOG_DESCRIBE,
    ),
    _RolePair(
        "grafana-task",
        (("ecs_tasks", "ecs_service_grafana"),),
        (
            (_CDK_OBSERVABILITY, "_createTaskRole", "role"),
            (_CDK_OBSERVABILITY, None, "ampQueryPolicy"),
        ),
    ),
    _RolePair(
        "grafana-task-execution",
        (("ecs_task_exec", "ecs_service_grafana"),),
        ((_CDK_OBSERVABILITY, "_createTaskExecRole", "role"), _CDK_SECRETS_ACCESS),
        _EXEC_LOG_DESCRIBE,
    ),
)


@dataclass(frozen=True)
class _Statement:
    """One IAM policy statement as written in the source.

    ``resources`` holds the string literals of the Resource value; computed
    references (``aws_s3_bucket.x.arn``, ``logGroup.logGroupArn``) are not
    literals and so never match a wildcard.
    """

    source: str
    line: int
    owner: str
    kind: str
    effect: str
    actions: tuple[str, ...]
    has_not_action: bool
    resources: tuple[str, ...]
    has_not_resource: bool
    principals: tuple[str, ...]
    offset: int = field(compare=False)

    @property
    def id(self) -> str:
        """Return the ``file:line`` id of the statement."""
        return f"{self.source}:{self.line}"


def _is_string_start(char: str, hcl: bool) -> bool:
    """Return True if ``char`` opens a string literal in the given language.

    Args:
        char: Character to test.
        hcl: True for HCL, False for TypeScript.

    Returns:
        Whether a string literal starts here.
    """
    return char == '"' or (not hcl and char in "'`")


def _skip_string(text: str, start: int, hcl: bool) -> int:
    """Return the index just past the string literal starting at ``start``.

    Args:
        text: Source text.
        start: Index of the opening quote.
        hcl: True for HCL (``"${...}"`` interpolation), False for TypeScript.

    Returns:
        Index of the first character after the closing quote.
    """
    quote = text[start]
    j = start + 1
    while text[j] != quote:
        if text[j] == "\\":
            j += 2
            continue
        interpolates = quote == "`" or (hcl and quote == '"')
        if interpolates and text.startswith("${", j):
            j = _match_bracket(text, j + 1, hcl) + 1
            continue
        j += 1
    return j + 1


def _skip_regex_literal(text: str, start: int) -> int:
    """Return the index just past the TypeScript regex literal at ``start``.

    Args:
        text: Source text.
        start: Index of the opening slash.

    Returns:
        Index of the first character after the flags.
    """
    j = start + 1
    in_class = False
    while True:
        char = text[j]
        if char == "\\":
            j += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            break
        j += 1
    j += 1
    while text[j].isalpha():
        j += 1
    return j


def _previous_code_char(text: str, j: int) -> str:
    """Return the last non-whitespace character before ``j``, or ``""``.

    Args:
        text: Source text.
        j: Index to look back from.

    Returns:
        That character, used to tell a regex literal from division.
    """
    k = j - 1
    while k >= 0 and text[k].isspace():
        k -= 1
    return text[k] if k >= 0 else ""


def _skip_non_code(text: str, j: int, hcl: bool) -> int | None:
    """Return the end of a string, comment, heredoc or regex at ``j``, if any.

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
    if _is_string_start(char, hcl):
        return _skip_string(text, j, hcl)
    if (hcl and char == "#") or text.startswith("//", j):
        end = text.find("\n", j)
        return len(text) if end == -1 else end
    if text.startswith("/*", j):
        return text.index("*/", j) + 2
    if not hcl and char == "/" and _previous_code_char(text, j) in "(,=:[!&|?{};":
        return _skip_regex_literal(text, j)
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


def _code_positions(text: str, start: int, end: int, hcl: bool, wanted: str):
    """Yield code (not string or comment) indexes in ``[start, end)`` holding ``wanted``.

    Args:
        text: Source text.
        start: First index to scan.
        end: Index to stop at.
        hcl: True for HCL, False for TypeScript.
        wanted: Character to look for.

    Yields:
        Each matching index.
    """
    j = start
    while j < end:
        skipped = _skip_non_code(text, j, hcl)
        if skipped is not None:
            j = skipped
            continue
        if text[j] == wanted:
            yield j
        j += 1


def _code_matches(text: str, pattern: re.Pattern[str], hcl: bool) -> list[re.Match[str]]:
    """Return the matches of ``pattern`` that start in code, not in strings or comments.

    Args:
        text: Source text.
        pattern: Compiled regex.
        hcl: True for HCL, False for TypeScript.

    Returns:
        Matches whose start index is code.
    """
    code_starts: set[int] = set()
    j = 0
    while j < len(text):
        skipped = _skip_non_code(text, j, hcl)
        if skipped is not None:
            j = skipped
            continue
        code_starts.add(j)
        j += 1
    return [m for m in pattern.finditer(text) if m.start() in code_starts]


def _members(text: str, open_idx: int, close_idx: int, hcl: bool) -> dict[str, tuple[int, int]]:
    """Split an object or block body into its top-level ``key = value`` members.

    Args:
        text: Source text.
        open_idx: Index of the opening brace.
        close_idx: Index of the closing brace.
        hcl: True for HCL (``=``, newline separated), False for TypeScript.

    Returns:
        Map of member name to the ``(start, end)`` span of its value.
    """
    segments: list[tuple[int, int]] = []
    segment_start = open_idx + 1
    j = segment_start
    while j < close_idx:
        skipped = _skip_non_code(text, j, hcl)
        if skipped is not None:
            j = skipped
            continue
        char = text[j]
        if char in _BRACKET_PAIRS:
            j = _match_bracket(text, j, hcl) + 1
            continue
        if char == "," or (hcl and char == "\n"):
            segments.append((segment_start, j))
            segment_start = j + 1
        j += 1
    segments.append((segment_start, close_idx))
    members: dict[str, tuple[int, int]] = {}
    for seg_start, seg_end in segments:
        p = seg_start
        while p < seg_end:
            if text[p].isspace():
                p += 1
                continue
            skipped = _skip_non_code(text, p, hcl)
            if skipped is None or _is_string_start(text[p], hcl):
                break
            p = skipped
        key = _MEMBER_KEY_RE.match(text, p, seg_end)
        if key:
            members[key.group(2)] = (key.end(), seg_end)
    return members


def _is_comparison_operand(text: str, lo: int, start: int, end: int, hi: int) -> bool:
    """Return True if the literal ``text[start:end]`` is compared with ``==`` or ``!=``.

    Args:
        text: Source text.
        lo: Start of the enclosing value.
        start: Start of the literal.
        end: End of the literal.
        hi: End of the enclosing value.

    Returns:
        Whether the literal is a comparison operand rather than a value.
    """
    before = text[lo:start].rstrip()
    after = text[end:hi].lstrip()
    return before.endswith(("==", "!=")) or after.startswith(("==", "!="))


def _value_literals(text: str, start: int, end: int, hcl: bool) -> tuple[str, ...]:
    """Return the string literals that are elements of a member value.

    Descends into lists, grouping parens and list-combining functions, but not
    into objects or other calls, whose literals are arguments, not elements.

    Args:
        text: Source text.
        start: Start of the value.
        end: End of the value.
        hcl: True for HCL, False for TypeScript.

    Returns:
        The literal contents, raw (interpolations kept as written).
    """
    found: list[str] = []
    j = start
    while j < end:
        char = text[j]
        if _is_string_start(char, hcl):
            literal_end = _skip_string(text, j, hcl)
            if not _is_comparison_operand(text, start, j, literal_end, end):
                found.append(text[j + 1 : literal_end - 1])
            j = literal_end
            continue
        skipped = _skip_non_code(text, j, hcl)
        if skipped is not None:
            j = skipped
            continue
        if char == "{":
            j = _match_bracket(text, j, hcl) + 1
            continue
        if char == "(":
            callee = re.search(r"([A-Za-z_][\w.]*)\s*$", text[start:j])
            if callee and callee.group(1) not in _LIST_FUNCTIONS:
                j = _match_bracket(text, j, hcl) + 1
                continue
        j += 1
    return tuple(found)


def _all_literals(text: str, start: int, end: int, hcl: bool) -> tuple[str, ...]:
    """Return every string literal in ``text[start:end]``, at any depth.

    Args:
        text: Source text.
        start: Start of the span.
        end: End of the span.
        hcl: True for HCL, False for TypeScript.

    Returns:
        The literal contents.
    """
    found: list[str] = []
    j = start
    while j < end:
        if _is_string_start(text[j], hcl):
            literal_end = _skip_string(text, j, hcl)
            found.append(text[j + 1 : literal_end - 1])
            j = literal_end
            continue
        skipped = _skip_non_code(text, j, hcl)
        j = skipped if skipped is not None else j + 1
    return tuple(found)


def _line_of(text: str, offset: int) -> int:
    """Return the 1-based line number of ``offset``."""
    return text.count("\n", 0, offset) + 1


def _terraform_files() -> list[Path]:
    """Return the repo's own ``.tf`` files, excluding ``.terraform`` module caches."""
    return sorted(
        path
        for path in TERRAFORM_ROOT.rglob("*.tf")
        if not any(part.startswith(".") for part in path.relative_to(REPO_ROOT).parts)
    )


def _cdk_files() -> list[Path]:
    """Return the CDK app's TypeScript sources."""
    return sorted(
        path
        for root in CDK_ROOTS
        for path in root.rglob("*.ts")
        if "node_modules" not in path.parts and not path.name.endswith(".d.ts")
    )


@dataclass
class _Block:
    """A top-level Terraform ``resource``, ``data`` or ``module`` block."""

    address: str
    block_type: str
    source: str
    text: str = field(repr=False)
    open_idx: int
    close_idx: int

    @cached_property
    def members(self) -> dict[str, tuple[int, int]]:
        """Return the block's top-level attribute spans."""
        return _members(self.text, self.open_idx, self.close_idx, True)

    def attribute(self, name: str) -> str:
        """Return the raw text of a top-level attribute, or ``""`` if absent."""
        span = self.members.get(name)
        return self.text[span[0] : span[1]] if span else ""


def _terraform_blocks() -> list[_Block]:
    """Parse every top-level block of every repo Terraform file."""
    blocks: list[_Block] = []
    for path in _terraform_files():
        text = path.read_text()
        for match in _code_matches(text, _TF_TOP_BLOCK_RE, True):
            keyword, block_type, name = match.groups()
            if keyword == "module":
                address, kind = f"module.{block_type}", "module"
            elif keyword == "data":
                address, kind = f"data.{block_type}.{name}", block_type
            else:
                address, kind = f"{block_type}.{name}", block_type
            open_idx = match.end() - 1
            blocks.append(
                _Block(
                    address,
                    kind,
                    str(path.relative_to(REPO_ROOT)),
                    text,
                    open_idx,
                    _match_bracket(text, open_idx, True),
                )
            )
    return blocks


def _terraform_statements(blocks: list[_Block]) -> list[_Statement]:
    """Extract every statement object inside a ``jsonencode(...)`` policy.

    Args:
        blocks: Parsed top-level blocks.

    Returns:
        One entry per object with an ``Effect`` key, owned by the enclosing
        block address (or the file, outside any block).
    """
    by_source: dict[str, list[_Block]] = {}
    for block in blocks:
        by_source.setdefault(block.source, []).append(block)
    statements: list[_Statement] = []
    for path in _terraform_files():
        source = str(path.relative_to(REPO_ROOT))
        text = path.read_text()
        for encode in _code_matches(text, _TF_JSONENCODE_RE, True):
            block = next(
                (b for b in by_source.get(source, ()) if b.open_idx < encode.start() < b.close_idx),
                None,
            )
            call_open = encode.end() - 1
            call_close = _match_bracket(text, call_open, True)
            for obj_open in _code_positions(text, call_open, call_close, True, "{"):
                members = _members(text, obj_open, _match_bracket(text, obj_open, True), True)
                if "Effect" not in members:
                    continue

                def _get(key: str, members=members, text=text) -> tuple[str, ...]:
                    span = members.get(key)
                    return _value_literals(text, *span, True) if span else ()

                if block is not None and block.block_type == "aws_kms_key":
                    kind = "kms-key"
                elif encode.group(1) == "assume_role_policy":
                    kind = "trust"
                elif "Principal" in members:
                    kind = "resource"
                else:
                    kind = "identity"
                principal_span = members.get("Principal")
                statements.append(
                    _Statement(
                        source=source,
                        line=_line_of(text, obj_open),
                        owner=block.address if block is not None else source,
                        kind=kind,
                        effect=(_get("Effect") or ("?",))[0],
                        actions=_get("Action"),
                        has_not_action="NotAction" in members,
                        resources=_get("Resource"),
                        has_not_resource="NotResource" in members,
                        principals=(
                            _all_literals(text, *principal_span, True) if principal_span else ()
                        ),
                        offset=obj_open,
                    )
                )
    return statements


def _cdk_statements() -> list[_Statement]:
    """Extract every ``new iam.PolicyStatement`` and SDK-call policy in the CDK app.

    Returns:
        One entry per statement. ``AwsCustomResourcePolicy.fromSdkCalls``
        becomes one statement whose actions are the custom resource's SDK calls.
    """
    statements: list[_Statement] = []
    for path in _cdk_files():
        text = path.read_text()
        source = str(path.relative_to(REPO_ROOT))
        for match in _code_matches(text, _CDK_STATEMENT_RE, False):
            call_open = match.end() - 1
            obj_open = text.index("{", call_open)
            members = _members(text, obj_open, _match_bracket(text, obj_open, False), False)

            def _get(key: str, members=members, text=text) -> tuple[str, ...]:
                span = members.get(key)
                return _value_literals(text, *span, False) if span else ()

            receiver = _CDK_RESOURCE_POLICY_RE.search(text[: match.start()])
            if receiver:
                kind = "kms-key" if "key" in receiver.group(1).lower() else "resource"
            elif "principals" in members:
                kind = "resource"
            else:
                kind = "identity"
            effect_span = members.get("effect")
            denies = effect_span is not None and "DENY" in text[effect_span[0] : effect_span[1]]
            principal_span = members.get("principals")
            statements.append(
                _Statement(
                    source=source,
                    line=_line_of(text, match.start()),
                    owner=source,
                    kind=kind,
                    effect="Deny" if denies else "Allow",
                    actions=_get("actions"),
                    has_not_action="notActions" in members,
                    resources=_get("resources"),
                    has_not_resource="notResources" in members,
                    principals=(
                        _all_literals(text, *principal_span, False) if principal_span else ()
                    ),
                    offset=match.start(),
                )
            )
        custom_resources = [
            (m.end() - 1, _match_bracket(text, m.end() - 1, False))
            for m in _code_matches(text, _CDK_CUSTOM_RESOURCE_RE, False)
        ]
        for match in _code_matches(text, _CDK_SDK_CALLS_RE, False):
            enclosing = next(
                (span for span in custom_resources if span[0] < match.start() < span[1]),
                None,
            )
            assert enclosing is not None, (
                f"{source}:{_line_of(text, match.start())}: fromSdkCalls outside "
                "new cr.AwsCustomResource(...)"
            )
            actions = sorted(
                {
                    f"{service.lower()}:{action[0].upper()}{action[1:]}"
                    for service, action in _CDK_SDK_ACTION_RE.findall(
                        text[enclosing[0] : enclosing[1]]
                    )
                }
            )
            obj_open = text.index("{", match.end() - 1)
            members = _members(text, obj_open, _match_bracket(text, obj_open, False), False)
            span = members.get("resources")
            value = text[span[0] : span[1]] if span else ""
            resources = ("*",) if "ANY_RESOURCE" in value else _value_literals(text, *span, False)
            statements.append(
                _Statement(
                    source=source,
                    line=_line_of(text, match.start()),
                    owner=source,
                    kind="identity",
                    effect="Allow",
                    actions=tuple(actions),
                    has_not_action=False,
                    resources=resources,
                    has_not_resource=False,
                    principals=(),
                    offset=match.start(),
                )
            )
    return statements


_TERRAFORM_BLOCKS = _terraform_blocks()
_TERRAFORM_STATEMENTS = _terraform_statements(_TERRAFORM_BLOCKS)
_CDK_STATEMENTS = _cdk_statements()
_ALLOW_STATEMENTS = [
    statement
    for statement in (*_TERRAFORM_STATEMENTS, *_CDK_STATEMENTS)
    if statement.effect == "Allow"
]


def _is_unbounded_resource(resource: str) -> bool:
    """Return True for ``*`` or an ARN wildcarded in region, account and resource.

    Args:
        resource: A Resource literal.

    Returns:
        Whether it matches every resource of its service in every account,
        e.g. ``arn:aws:logs:*:*:*``.
    """
    if resource == "*":
        return True
    parts = resource.split(":", 5)
    return (
        len(parts) == 6
        and parts[0] == "arn"
        and parts[3] in ("", "*")
        and parts[4] in ("", "*")
        and parts[5] == "*"
    )


def _is_kms_root_delegation(statement: _Statement) -> bool:
    """Return True for the default key-policy statement that delegates to IAM.

    A KMS key policy must grant ``kms:*`` to the owning account root, or the key
    becomes unmanageable; IAM policies then decide who may use it.

    Args:
        statement: Statement to test.

    Returns:
        Whether this is that statement and nothing broader.
    """
    return (
        statement.kind == "kms-key"
        and statement.actions == ("kms:*",)
        and bool(statement.principals)
        and all(_ACCOUNT_ROOT_PRINCIPAL_RE.match(p) for p in statement.principals)
    )


def _params(
    statements: list[_Statement],
    known: tuple[tuple[str, str], ...],
) -> list:
    """Build one param per statement, xfailing the ids listed in ``known``.

    Args:
        statements: Statements to parametrize over.
        known: ``(id, reason)`` pairs of known violations.

    Returns:
        List of ``pytest.param`` objects with ``file:line`` ids.
    """
    reasons = dict(known)
    params = []
    for statement in statements:
        marks = ()
        if statement.id in reasons:
            marks = pytest.mark.xfail(
                strict=True,
                raises=AssertionError,
                reason=f"Known defect: {reasons[statement.id]}.",
            )
        params.append(pytest.param(statement, id=statement.id, marks=marks))
    return params


@pytest.mark.unit
@pytest.mark.parametrize("statement", _params(_ALLOW_STATEMENTS, KNOWN_WILDCARD_ACTION_STATEMENTS))
def test_allow_statement_grants_no_wildcard_action(statement: _Statement) -> None:
    """Property: no Allow statement grants ``*``, ``<service>:*`` or NotAction."""
    if _is_kms_root_delegation(statement):
        return
    wildcards = [a for a in statement.actions if a == "*" or a.endswith(":*")]
    assert not wildcards and not statement.has_not_action, (
        f"{statement.id} ({statement.owner}) grants wildcard actions {wildcards}"
        f"{' via NotAction' if statement.has_not_action else ''}"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "statement",
    _params(
        [s for s in _ALLOW_STATEMENTS if s.kind not in ("kms-key", "trust")],
        KNOWN_UNBOUNDED_RESOURCE_STATEMENTS,
    ),
)
def test_allow_statement_on_any_resource_needs_it(statement: _Statement) -> None:
    """Property: an unbounded Resource only carries actions AWS allows on nothing else.

    KMS key policies are exempt because their ``Resource: "*"`` means the key
    itself, and trust policies carry no Resource.
    """
    unbounded = [r for r in statement.resources if _is_unbounded_resource(r)]
    scopable = sorted(set(statement.actions) - ACTIONS_ONLY_ALLOWED_ON_ANY_RESOURCE)
    assert not statement.has_not_resource, f"{statement.id} uses NotResource"
    assert not unbounded or not scopable, (
        f"{statement.id} ({statement.owner}) grants {scopable} on {unbounded}; "
        "these actions accept a resource ARN"
    )


@pytest.mark.unit
@pytest.mark.parametrize("tree", ["terraform", "cdk"])
def test_policy_scanner_sees_every_statement(tree: str) -> None:
    """Property: every IAM statement in the source is one the scanner extracted.

    The least-privilege tests are only as complete as the scanner, so a policy
    form it does not read (a heredoc or ``.json`` policy, an
    ``aws_iam_policy_document`` data source, ``PolicyStatement.fromJson``)
    must fail here rather than pass unchecked.
    """
    unsupported: list[str] = []
    if tree == "terraform":
        expected = 0
        for path in _terraform_files():
            text = path.read_text()
            expected += len(_code_matches(text, _TF_EFFECT_KEY_RE, True))
            for heredoc in _HEREDOC_RE.finditer(text):
                terminator = re.compile(r"^\s*" + heredoc.group(1) + r"\s*$", re.M)
                body_end = terminator.search(text, heredoc.end()).start()
                if '"Statement"' in text[heredoc.end() : body_end]:
                    unsupported.append(f"{path}:{_line_of(text, heredoc.start())} heredoc policy")
        unsupported += [
            f"{b.source} {b.address}"
            for b in _TERRAFORM_BLOCKS
            if b.block_type == "aws_iam_policy_document"
        ]
        unsupported += [
            str(p.relative_to(REPO_ROOT))
            for p in TERRAFORM_ROOT.rglob("*.json")
            if not any(part.startswith(".") for part in p.relative_to(REPO_ROOT).parts)
            and '"Statement"' in p.read_text()
        ]
        extracted = len(_TERRAFORM_STATEMENTS)
    else:
        expected = 0
        for path in _cdk_files():
            text = path.read_text()
            expected += len(_code_matches(text, _CDK_STATEMENT_RE, False))
            expected += len(_code_matches(text, _CDK_SDK_CALLS_RE, False))
            unsupported += [
                f"{path.relative_to(REPO_ROOT)}:{_line_of(text, m.start())} {m.group(0)}"
                for m in re.finditer(r"Policy(Statement|Document)\.fromJson|grant[A-Z]\w*\(", text)
            ]
        extracted = len(_CDK_STATEMENTS)
    assert not unsupported, f"policy forms the scanner does not read: {unsupported}"
    assert extracted == expected, (
        f"{tree}: scanner extracted {extracted} statements, source has {expected}"
    )


@pytest.mark.unit
def test_known_violation_ids_name_existing_statements() -> None:
    """Property: every known-violation id still names a statement in the source.

    Ids are ``file:line``, so an edit above a statement moves it; this keeps a
    stale id from silently dropping its xfail.
    """
    ids = {s.id for s in _ALLOW_STATEMENTS}
    stale = [
        known_id
        for known_id, _ in (*KNOWN_UNBOUNDED_RESOURCE_STATEMENTS, *KNOWN_WILDCARD_ACTION_STATEMENTS)
        if known_id not in ids
    ]
    assert not stale, f"known-violation ids with no statement at that line: {stale}"


def _terraform_policy_actions(owner: str) -> set[str]:
    """Return the Allow actions of every non-trust statement owned by ``owner``."""
    return {
        action
        for s in _TERRAFORM_STATEMENTS
        if s.owner == owner and s.effect == "Allow" and s.kind != "trust"
        for action in s.actions
    }


def _terraform_policy_refs(expression: str) -> set[str]:
    """Return actions of AWS managed and repo policies referenced in an expression.

    Args:
        expression: Raw HCL expression, e.g. a ``policy_arn`` or a policy map.

    Returns:
        Actions, with AWS managed policies as ``managed:<path>``.
    """
    actions: set[str] = set()
    for managed in re.finditer(r'"arn:aws:iam::aws:policy/([^"]+)"', expression):
        actions.add(f"managed:{managed.group(1)}")
    for policy in re.finditer(r"\baws_iam_policy\.(\w+)", expression):
        actions |= _terraform_policy_actions(f"aws_iam_policy.{policy.group(1)}")
    return actions


def _terraform_role_actions(kind: str, ref: str) -> set[str]:
    """Return every action Terraform grants to one role.

    Args:
        kind: ``role``, ``ecs_task_exec`` or ``ecs_tasks``.
        ref: Role address or ECS service module name.

    Returns:
        The union of actions across all conditional branches.
    """
    if kind == "role":
        actions = _terraform_policy_actions(ref)
        role_ref = re.compile(re.escape(ref) + r"\b")
        for block in _TERRAFORM_BLOCKS:
            if not role_ref.search(block.attribute("role")):
                continue
            if block.block_type == "aws_iam_role_policy":
                actions |= _terraform_policy_actions(block.address)
            elif block.block_type == "aws_iam_role_policy_attachment":
                actions |= _terraform_policy_refs(block.attribute("policy_arn"))
        return actions
    module = next(b for b in _TERRAFORM_BLOCKS if b.address == f"module.{ref}")
    if kind == "ecs_task_exec":
        actions = _terraform_policy_refs(module.attribute("task_exec_iam_role_policies"))
        if module.attribute("create_task_exec_policy").strip() != "false":
            actions |= _ECS_MODULE_TASK_EXEC_BUILTIN
        return actions
    actions = _terraform_policy_refs(module.attribute("tasks_iam_role_policies"))
    if module.attribute("enable_execute_command").strip() == "true":
        actions |= _ECS_MODULE_EXECUTE_COMMAND_BUILTIN
    return actions


def _cdk_scope(text: str, function: str | None) -> tuple[int, int]:
    """Return the span of ``function``'s body, or the whole file when None.

    Args:
        text: TypeScript source.
        function: Top-level function name, or None.

    Returns:
        ``(start, end)`` offsets.
    """
    if function is None:
        return 0, len(text)
    header = re.search(r"\bfunction\s+" + re.escape(function) + r"\s*\(", text)
    assert header, f"function {function} not found"
    params_close = _match_bracket(text, header.end() - 1, False)
    body_open = text.index("{", params_close)
    return body_open, _match_bracket(text, body_open, False)


def _cdk_role_actions(file: str, function: str | None, identifier: str) -> set[str]:
    """Return the actions CDK attaches through ``identifier``.

    Counts statements and AWS managed policies inside ``identifier = ...``,
    ``identifier.addToPolicy(...)``, ``identifier.addToPrincipalPolicy(...)``,
    ``identifier.addManagedPolicy(...)`` and ``identifier.push(...)``.

    Args:
        file: Repo-relative TypeScript path.
        function: Function to restrict the search to, or None for the file.
        identifier: Variable or property name, e.g. ``taskExecRole``.

    Returns:
        Actions, with AWS managed policies as ``managed:<name>``.
    """
    text = (REPO_ROOT / file).read_text()
    scope_start, scope_end = _cdk_scope(text, function)
    name = r"(?<![\w.$])" + re.escape(identifier)
    spans: list[tuple[int, int]] = []
    attach = re.compile(
        name + r"\s*\.\s*(addToPolicy|addToPrincipalPolicy|addManagedPolicy|push)\s*\("
    )
    assign = re.compile(name + r"(?:\s*:\s*[\w.\[\]<>]+)?\s*=\s*(?:new\s+[\w.]+\s*)?(?=[\[{(])")
    for pattern in (attach, assign):
        for match in pattern.finditer(text, scope_start, scope_end):
            spans.append((match.end() - 1, _match_bracket(text, match.end() - 1, False)))
    assert spans, f"{file}: nothing attached through {identifier}"
    actions: set[str] = set()
    for start, end in spans:
        for statement in _CDK_STATEMENTS:
            if statement.source == file and start < statement.offset < end:
                if statement.effect == "Allow":
                    actions |= set(statement.actions)
        for managed in re.finditer(
            r"fromAwsManagedPolicyName\(\s*['\"]([^'\"]+)['\"]", text[start:end]
        ):
            actions.add(f"managed:{managed.group(1)}")
    return actions


def _role_params() -> list:
    """Build one param per mapped role, xfailing the known divergences."""
    params = []
    for pair in ROLE_PAIRS:
        marks = ()
        if pair.divergence:
            marks = pytest.mark.xfail(
                strict=True,
                raises=AssertionError,
                reason=f"Known defect: {pair.divergence}",
            )
        params.append(pytest.param(pair, id=pair.name, marks=marks))
    return params


@pytest.mark.unit
@pytest.mark.parametrize("pair", _role_params())
def test_terraform_and_cdk_grant_a_role_the_same_actions(pair: _RolePair) -> None:
    """Property: a role both stacks create holds the same action set in both.

    Each side is the union over every conditional branch, so the comparison is
    between the most each deployment path can ever grant.
    """
    terraform = set().union(*(_terraform_role_actions(k, r) for k, r in pair.terraform))
    cdk = set().union(*(_cdk_role_actions(*source) for source in pair.cdk))
    terraform_lower = {a.lower() for a in terraform}
    cdk_lower = {a.lower() for a in cdk}
    only_terraform = sorted(a for a in terraform if a.lower() not in cdk_lower)
    only_cdk = sorted(a for a in cdk if a.lower() not in terraform_lower)
    assert terraform, f"{pair.name}: no Terraform actions found for {pair.terraform}"
    assert cdk, f"{pair.name}: no CDK actions found for {pair.cdk}"
    assert not only_terraform and not only_cdk, (
        f"{pair.name}: Terraform only {only_terraform}; CDK only {only_cdk}"
    )
