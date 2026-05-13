"""Validation helpers for local-runtime registration.

This module enforces server-side checks on LocalRuntime payloads at registration
time. The checks are SOFT accidental-leak guards — they catch obvious mistakes
(pasting a real secret value, forgetting to pin a Docker digest), not
adversarial submitters.
"""

import logging
import math
import re
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)


# Known prefix patterns for popular secret formats. Hits return immediate flag.
_SECRET_PREFIXES: tuple[str, ...] = (
    "sk-",  # OpenAI / Stripe
    "ghp_",  # GitHub personal token
    "gho_",  # GitHub OAuth
    "ghu_",  # GitHub user-to-server
    "ghs_",  # GitHub server-to-server
    "ghr_",  # GitHub refresh
    "AKIA",  # AWS access key
    "ASIA",  # AWS temporary access key
    "xoxb-",  # Slack bot
    "xoxp-",  # Slack user
    "xoxa-",  # Slack workspace
    "AIza",  # Google API key
)

# Threshold for high-entropy long strings. ~4.0 bits/char is roughly random
# alphanumeric. Tuned to flag base64/hex secrets without false-positiving on
# normal config values like URLs.
_ENTROPY_THRESHOLD: float = 4.0
_MIN_ENTROPY_LENGTH: int = 32


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


_PLACEHOLDER_RE = re.compile(r"\$\{[^}]+\}")


def _value_looks_like_secret(value: str) -> bool:
    """Return True if `value` looks like a literal credential.

    Strings that contain any ${VAR} placeholder are exempt — they're treated
    as templates that will be expanded at connect time. This covers both the
    bare `${VAR}` case and embedded use like `https://${HOST}/api`.
    """
    if not value:
        return False
    # Any ${VAR} placeholder anywhere in the string → treat as a template.
    if _PLACEHOLDER_RE.search(value):
        return False
    # Known prefixes for popular secret formats.
    if any(value.startswith(p) for p in _SECRET_PREFIXES):
        return True
    # Long high-entropy strings.
    if len(value) >= _MIN_ENTROPY_LENGTH and _shannon_entropy(value) > _ENTROPY_THRESHOLD:
        return True
    return False


def find_leaked_secrets(env: dict[str, str], args: list[str]) -> dict[str, list[str]]:
    """Scan env values and args for literal-looking secrets.

    Args:
        env: Environment variable dict (key -> value).
        args: Argv-style argument list.

    Returns:
        Dict with two keys:
        - "env_keys": list of env keys whose values look like secrets
        - "arg_indices": list of arg indices whose values look like secrets

        Empty lists when no leaks detected.
    """
    leaked_env_keys: list[str] = []
    leaked_arg_indices: list[str] = []

    for key, value in env.items():
        if _value_looks_like_secret(value):
            leaked_env_keys.append(key)

    for idx, arg in enumerate(args):
        if _value_looks_like_secret(arg):
            leaked_arg_indices.append(str(idx))

    return {"env_keys": leaked_env_keys, "arg_indices": leaked_arg_indices}


def add_unpinned_warning_tag(
    local_runtime: dict[str, Any],
    tags: list[str],
) -> list[str]:
    """Add 'unpinned-version' tag if the runtime lacks a version/digest pin.

    Returns the (possibly extended) tag list. Idempotent — tag is added at most
    once even if called multiple times.
    """
    rt_type = local_runtime.get("type")
    needs_pin = False

    if rt_type == "docker":
        needs_pin = not local_runtime.get("image_digest")
    elif rt_type in ("npx", "uvx"):
        needs_pin = not local_runtime.get("version")

    if needs_pin and "unpinned-version" not in tags:
        return [*tags, "unpinned-version"]
    return tags


# ----- Shared register/edit helpers -----------------------------
#
# Both POST /register and POST /edit must perform the same deployment-shape
# validation and local-runtime parsing. The helpers below centralize that
# logic so the two endpoints can't drift. They raise HTTPException directly —
# FastAPI propagates it from any call depth, so the route doesn't need an
# extra layer of translation.


def validate_deployment_shape(
    *,
    is_local: bool,
    proxy_pass_url: str | None,
    local_runtime: str | None,
) -> None:
    """Reject malformed deployment payloads with 400 errors.

    `is_local` is the pre-resolved bool (route handles default-vs-explicit).
    `proxy_pass_url` and `local_runtime` are the raw form-field values.
    """
    # Local imports keep this module independent of FastAPI at module load time
    # (used in tests that don't need the web layer).
    from fastapi import HTTPException, status

    if is_local:
        if not local_runtime:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="deployment='local' requires local_runtime (JSON-encoded launch recipe)",
            )
        if proxy_pass_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="deployment='local' must not set proxy_pass_url",
            )
    else:
        if not proxy_pass_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="proxy_pass_url is required for deployment='remote'",
            )
        if local_runtime:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="local_runtime is only valid for deployment='local'",
            )


def parse_and_validate_local_runtime(local_runtime_json: str) -> Any:
    """Parse a JSON-string `local_runtime` form field into a LocalRuntime,
    then run the secret-leak guard over its env values + args.

    Returns the parsed LocalRuntime instance. Raises HTTPException(400) with a
    structured detail on parse failure or leak detection.
    """
    from fastapi import HTTPException, status

    # Local import: schemas pulls in registry.core.config etc., which we don't
    # want to drag into this module at import time.
    from registry.core.schemas import LocalRuntime

    try:
        local_runtime_obj = LocalRuntime.model_validate_json(local_runtime_json)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid local_runtime: {e}",
        ) from e

    leaks = find_leaked_secrets(local_runtime_obj.env, local_runtime_obj.args)
    if leaks["env_keys"] or leaks["arg_indices"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "literal-looking secret detected in local_runtime",
                "env_keys": leaks["env_keys"],
                "arg_indices": leaks["arg_indices"],
                "hint": (
                    "Use ${VAR} placeholders or move sensitive values into "
                    "required_env so users provide them at connect time."
                ),
            },
        )

    return local_runtime_obj
