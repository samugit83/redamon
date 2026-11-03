"""Agent in the Loop: an external MCP client answers the agent's model calls.

The pseudo-model ``loop/mcp`` makes every model call of a chat run a *step*
that a driver (Claude Code, Codex, any MCP client) claims and answers over the
inbound MCP server. RedAmon keeps the loop, the tools and every gate.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger("agent_in_the_loop")

LOOP_PREFIX = "loop/"
LOOP_MODEL_ID = "loop/mcp"
LOOP_MODEL_LABEL = "Agent in the Loop"
CONTRACT_VERSION = 1


def is_loop_model(model_id: str | None) -> bool:
    return isinstance(model_id, str) and model_id.strip().startswith(LOOP_PREFIX)


def is_loop_llm(obj: object) -> bool:
    """Whether ``obj`` is the Agent in the Loop adapter.

    A class marker rather than an isinstance check, so callers need not import
    LangChain (several unit tests stub it out of sys.modules). ``is True``,
    because a MagicMock answers any attribute with a truthy mock.
    """
    return getattr(obj, "is_agent_in_the_loop", False) is True


def loop_enabled() -> bool:
    raw = os.environ.get("AGENT_IN_THE_LOOP_ENABLED", "")
    return raw.strip().lower() in ("true", "1", "yes")


@dataclass(frozen=True)
class LoopSettings:
    step_deadline_s: int
    lease_s: int
    wait_max_s: int
    page_chars: int
    answer_max_chars: int
    max_open_steps_per_user: int
    no_driver_grace_s: int
    driver_seen_s: int
    state_ttl_s: int


# (env key, default, min, max). wait_max_s stays under Codex's 60 s default
# tool timeout; page_chars under Claude Code's 50 000-char spill-to-file limit.
_TUNABLES = {
    "step_deadline_s": ("LOOP_STEP_DEADLINE_S", 900, 30, 7200),
    "lease_s": ("LOOP_LEASE_S", 90, 15, 600),
    "wait_max_s": ("LOOP_WAIT_MAX_S", 55, 1, 55),
    "page_chars": ("LOOP_PAGE_CHARS", 40000, 4000, 200000),
    "answer_max_chars": ("LOOP_ANSWER_MAX_CHARS", 262144, 1024, 1048576),
    "max_open_steps_per_user": ("LOOP_MAX_OPEN_STEPS_PER_USER", 16, 1, 256),
    "no_driver_grace_s": ("LOOP_NO_DRIVER_GRACE_S", 300, 60, 3600),
    "driver_seen_s": ("LOOP_DRIVER_SEEN_S", 60, 10, 600),
    "state_ttl_s": ("LOOP_STATE_TTL_S", 3600, 600, 86400),
}


def _bounded_int(key: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("%s is not an integer; using the default %d", key, default)
        return default
    if not lo <= value <= hi:
        logger.warning("%s=%d is outside %d..%d; using the default %d", key, value, lo, hi, default)
        return default
    return value


def confirmation_required(setting: bool) -> bool:
    """Whether a dangerous tool must wait for a person.

    In an Agent in the Loop run the "model" is any process holding a driver
    token, and the human confirmation is the only code-enforced brake on a
    dangerous tool, so it applies whatever REQUIRE_TOOL_CONFIRMATION says.
    Provider-model runs keep the project setting.
    """
    from agent_context import current_log_session_id
    from .broker import get_broker
    if get_broker().scope_for_session(current_log_session_id.get()) is not None:
        return True
    return bool(setting)


def settings() -> LoopSettings:
    """Read the tunables. A bad value logs one warning and uses the default."""
    values = {attr: _bounded_int(*spec) for attr, spec in _TUNABLES.items()}
    # A grace shorter than a lease would fail a step a driver still holds.
    if values["no_driver_grace_s"] < values["lease_s"]:
        logger.warning("LOOP_NO_DRIVER_GRACE_S is below LOOP_LEASE_S; using the lease")
        values["no_driver_grace_s"] = values["lease_s"]
    return LoopSettings(**values)
