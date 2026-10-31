"""Execution-boundary guard for model-emitted tool calls.

The model's tool calls are untrusted: prompt injection in an inbound A2A message,
a remote agent's reply or a tool result can steer the model into calling any tool
with any argument. A system prompt cannot stop that, so this guard classifies each
tool call at the point of execution and denies a mutating call unless a human
confirmed it.

Design notes (fail closed):
    - A call is read-only only when the agent's classifier says so. Anything else,
      including an unknown tool name, is treated as mutating.
    - A mutating call runs only when a confirmation handler (a channel to a human,
      supplied by the embedding application) approves it. A tool argument the
      model fills in is never a confirmation.
    - An A2A server has no confirmation channel, so by default every mutating call
      is denied. ``AGENT_ALLOW_MUTATING_TOOLS=true`` is an explicit, logged operator
      opt-in that lets mutating calls run without confirmation (trusted demo or
      sandbox only).

This module is intentionally self-contained so it can be copied into any strands
agent without pulling in registry internals.
"""

import logging
import os
from collections.abc import Callable
from typing import Any

from strands.hooks import (
    BeforeToolCallEvent,
    HookProvider,
    HookRegistry,
)

logger = logging.getLogger(__name__)

ALLOW_MUTATING_TOOLS_ENV: str = "AGENT_ALLOW_MUTATING_TOOLS"

# Returns True when the (tool name, tool input) call is provably read-only.
ReadOnlyClassifier = Callable[[str, dict[str, Any]], bool]
# Asks a human to approve a mutating (tool name, tool input) call; True approves.
ConfirmationHandler = Callable[[str, dict[str, Any]], bool]


def _allow_mutating_from_env() -> bool:
    """Return True when the operator opted in to unconfirmed mutating tools."""
    raw = os.getenv(ALLOW_MUTATING_TOOLS_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class MutatingToolGuard(HookProvider):
    """strands hook that denies unconfirmed mutating tool calls."""

    def __init__(
        self,
        is_read_only: ReadOnlyClassifier,
        confirm: ConfirmationHandler | None = None,
        allow_mutating: bool | None = None,
    ) -> None:
        """Initialize the guard.

        Args:
            is_read_only: Classifier for a single tool call. Must return True only
                for calls that cannot change state.
            confirm: Channel to a human that approves or rejects a mutating call.
                None means no channel exists, so mutating calls are denied.
            allow_mutating: Operator opt-in that lets mutating calls run without
                confirmation. None reads ``AGENT_ALLOW_MUTATING_TOOLS``.
        """
        self._is_read_only = is_read_only
        self._confirm = confirm
        self._allow_mutating = (
            _allow_mutating_from_env() if allow_mutating is None else allow_mutating
        )
        if self._allow_mutating:
            logger.warning(
                "MUTATING TOOLS RUN WITHOUT HUMAN CONFIRMATION (%s). A model steered by "
                "prompt injection can book, pay, cancel or write data. Use only in a "
                "trusted demo or sandbox.",
                ALLOW_MUTATING_TOOLS_ENV,
            )

    def register_hooks(
        self,
        registry: HookRegistry,
        **kwargs: Any,
    ) -> None:
        """Register the pre-execution check."""
        registry.add_callback(BeforeToolCallEvent, self._check_tool_call)

    def _check_tool_call(
        self,
        event: BeforeToolCallEvent,
    ) -> None:
        """Cancel a mutating tool call that no human confirmed."""
        tool_name = event.tool_use.get("name", "")
        tool_input = event.tool_use.get("input")
        if not isinstance(tool_input, dict):
            tool_input = {}

        try:
            read_only = self._is_read_only(tool_name, tool_input)
        except Exception:  # noqa: BLE001 - a classifier error must not fall open
            logger.exception("Tool classifier failed for %s; treating it as mutating", tool_name)
            read_only = False
        if read_only:
            return

        if self._allow_mutating:
            logger.warning("Running mutating tool %s without confirmation (opt-in)", tool_name)
            return

        if self._confirm is not None:
            try:
                approved = self._confirm(tool_name, tool_input)
            except Exception:  # noqa: BLE001 - a broken channel must not fall open
                logger.exception("Confirmation handler failed for %s; denying", tool_name)
                approved = False
            if approved is True:
                logger.info("Mutating tool %s approved by a human", tool_name)
                return
            reason = "a human did not approve it"
        else:
            reason = "no human confirmation channel is available"

        logger.warning("Denied mutating tool call %s: %s", tool_name, reason)
        event.cancel_tool = (
            f"Tool '{tool_name}' changes data and was not run because {reason}. "
            "Tell the user the action needs explicit human confirmation outside this "
            "conversation; do not retry it."
        )
