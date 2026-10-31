"""Exhaustive single-character suffix sweep over the security validators.

Each validator below guards a value that is later interpolated into nginx
config, a URL, or a storage key. The property pinned here: appending any one
ASCII character to a valid seed is accepted only when that character is a
printable, non-whitespace character, and, for validators that feed nginx
directive positions, not an nginx metacharacter. A ``$``-anchored pattern used
with ``re.match`` breaks this because ``$`` also matches before a trailing
newline.
"""

from collections.abc import Callable

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from registry.api.virtual_server_routes import _normalize_virtual_path
from registry.core.nginx_service import (
    _NGINX_AGENT_PATH_SAFE,
    _NGINX_AGENT_URL_SAFE,
)
from registry.core.schemas import _SERVER_PATH_RE
from registry.schemas.skill_models import (
    SkillCard,
    SkillRegistrationRequest,
)
from registry.schemas.virtual_server_models import VirtualServerConfig
from registry.utils.agent_validator import _validate_agent_url
from registry.utils.url_guard import _NGINX_METACHARACTERS

_ASCII_SUFFIXES: tuple[str, ...] = tuple(chr(code) for code in range(128))

_TRAILING_NEWLINE_REASON: str = (
    "Known defect: the validator uses a $-anchored pattern with re.match, so it "
    "accepts the seed followed by a trailing newline."
)
_AGENT_URL_CONTROL_REASON: str = (
    "Known defect: the agent card URL validator accepts a trailing newline and "
    "other C0 control characters such as NUL."
)


def _is_printable_non_whitespace(
    char: str,
) -> bool:
    """Return True for a printable ASCII character other than space.

    Args:
        char: A single character.

    Returns:
        True if ``char`` is in the range ``!`` to ``~``.
    """
    return "!" <= char <= "~"


def _accepts_agent_path(
    value: str,
) -> bool:
    """Return True if the nginx agent path guard accepts ``value``."""
    return _NGINX_AGENT_PATH_SAFE.match(value) is not None


def _accepts_agent_backend_url(
    value: str,
) -> bool:
    """Return True if the nginx agent backend URL guard accepts ``value``."""
    return _NGINX_AGENT_URL_SAFE.match(value) is not None


def _accepts_virtual_server_model_path(
    value: str,
) -> bool:
    """Return True if ``VirtualServerConfig`` accepts ``value`` as its path."""
    try:
        VirtualServerConfig(path=value, server_name="sweep")
    except ValidationError:
        return False
    return True


def _accepts_virtual_server_route_path(
    value: str,
) -> bool:
    """Return True if the virtual server route path normalizer accepts ``value``."""
    try:
        _normalize_virtual_path(value)
    except HTTPException:
        return False
    return True


def _accepts_agent_card_url(
    value: str,
) -> bool:
    """Return True if the agent card URL validator accepts ``value``."""
    return _validate_agent_url(value)


def _accepts_skill_card_name(
    value: str,
) -> bool:
    """Return True if the ``SkillCard`` name validator accepts ``value``."""
    try:
        SkillCard.validate_name(value)
    except ValueError:
        return False
    return True


def _accepts_skill_registration_name(
    value: str,
) -> bool:
    """Return True if ``SkillRegistrationRequest`` accepts ``value`` as its name."""
    try:
        SkillRegistrationRequest(
            name=value,
            description="sweep",
            skill_md_url="https://example.com/SKILL.md",
        )
    except ValidationError:
        return False
    return True


def _accepts_server_path(
    value: str,
) -> bool:
    """Return True if the ``ServerInfo`` path pattern accepts ``value``."""
    return _SERVER_PATH_RE.fullmatch(value) is not None


@pytest.mark.parametrize(
    ("accepts", "seed", "forbid_nginx_metacharacters"),
    [
        pytest.param(
            _accepts_agent_path,
            "agents/foo",
            True,
            id="nginx_agent_path_safe",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_TRAILING_NEWLINE_REASON
            ),
        ),
        pytest.param(
            _accepts_agent_backend_url,
            "http://agent.example:8080/a2a",
            True,
            id="nginx_agent_url_safe",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_TRAILING_NEWLINE_REASON
            ),
        ),
        pytest.param(
            _accepts_virtual_server_model_path,
            "/virtual/dev-tools",
            True,
            id="virtual_server_model_path",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_TRAILING_NEWLINE_REASON
            ),
        ),
        pytest.param(
            _accepts_virtual_server_route_path,
            "/virtual/dev-tools",
            True,
            id="virtual_server_route_path",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_TRAILING_NEWLINE_REASON
            ),
        ),
        pytest.param(
            _accepts_agent_card_url,
            "https://agent.example.com/a2a",
            False,
            id="agent_card_url",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_AGENT_URL_CONTROL_REASON
            ),
        ),
        pytest.param(
            _accepts_skill_card_name,
            "pdf-tools",
            True,
            id="skill_card_name",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_TRAILING_NEWLINE_REASON
            ),
        ),
        pytest.param(
            _accepts_skill_registration_name,
            "pdf-tools",
            True,
            id="skill_registration_name",
            marks=pytest.mark.xfail(
                strict=True, raises=AssertionError, reason=_TRAILING_NEWLINE_REASON
            ),
        ),
        pytest.param(
            _accepts_server_path,
            "/github",
            True,
            id="server_path_re",
        ),
    ],
)
def test_validator_rejects_unsafe_single_character_suffix(
    accepts: Callable[[str], bool],
    seed: str,
    forbid_nginx_metacharacters: bool,
) -> None:
    """Property: seed + c is accepted only if c is printable, non-whitespace and safe.

    For every ASCII character c, acceptance of ``seed + c`` implies c is in the
    printable non-space range; validators that feed nginx directive positions
    must also reject every nginx metacharacter. In particular no validator may
    accept a trailing ``\\n``, ``\\r`` or ``\\x00``.
    """
    if not accepts(seed):
        pytest.fail(f"seed {seed!r} must be accepted for the sweep to be meaningful")

    unsafe_accepted = [
        char
        for char in _ASCII_SUFFIXES
        if accepts(seed + char)
        and (
            not _is_printable_non_whitespace(char)
            or (forbid_nginx_metacharacters and char in _NGINX_METACHARACTERS)
        )
    ]

    assert unsafe_accepted == [], (
        f"validator accepted {seed!r} followed by unsafe suffixes {unsafe_accepted!r}"
    )
