"""Delete the route exposure body files a session left in the Kali sandbox.

The route exposure parts keep every response body in a kali file named
`/tmp/rex-...`, delete it in the script that reads it, and sweep what is left
before `transition_phase` or `complete`. Live sessions skipped that sweep (a
rejected lead's two bodies stayed on disk), so the end of a run sweeps in code.

Only the paths this session named in its own tool arguments are removed. A
person's sandbox serves all of their sessions, so a glob would delete another
session's bodies mid-read; tool outputs are not read either, since a printed `glob`
listing can name files that are not this session's.

The sweep never starts a sandbox: one that stopped took its /tmp with it, and a
cold start at the end of a run with no Kali step would reserve memory and show
the person a sandbox starting for nothing.
"""

from __future__ import annotations

import json
import logging
import re
import shlex

logger = logging.getLogger(__name__)

# Concrete names only: a script's `/tmp/rex-*` or a `<id>` placeholder stops the
# match at the first character outside the class, so no wildcard ever reaches rm.
_REX_PATH = re.compile(r"/tmp/rex-[A-Za-z0-9_.\-]+")
_MAX_PATHS = 200


def session_body_paths(execution_trace) -> list[str]:
    """The `/tmp/rex-...` paths in this session's tool arguments, sorted."""
    found: set[str] = set()
    for step in execution_trace or []:
        args = step.get("tool_args") if isinstance(step, dict) else getattr(step, "tool_args", None)
        if not args:
            continue
        found.update(_REX_PATH.findall(json.dumps(args)))
    return sorted(found)[:_MAX_PATHS]


async def sweep_session_bodies(tool_executor, state) -> int:
    """Remove this session's leftover body files; returns how many paths it named.

    Never raises: a failed sweep is logged and the run ends as it would have.
    """
    paths = session_body_paths(state.get("execution_trace"))
    if not paths or tool_executor is None:
        return 0
    command = "rm -rf -- " + " ".join(shlex.quote(p) for p in paths)
    import sandbox_router

    try:
        if not await _sandbox_is_up(sandbox_router):
            return 0
        # No model reads this call's result: it must not use up the chat's restart note.
        with sandbox_router.without_restart_note():
            result = await tool_executor.execute(
                "kali_shell", {"command": command}, state.get("current_phase") or "informational",
                skip_phase_check=True)
        if not (result or {}).get("success"):
            logger.warning("body sweep: kali_shell did not succeed for %d path(s)", len(paths))
    except Exception as exc:  # noqa: BLE001 - a sweep must never break the run's end
        logger.warning("body sweep failed for %d path(s): %s", len(paths), type(exc).__name__)
    return len(paths)


async def _sandbox_is_up(sandbox_router) -> bool:
    """Whether the run's person has a sandbox to sweep, asked without starting one: the
    run's own handle, else a running instance in the gateway's list."""
    if sandbox_router.current_handle() is not None:
        return True
    person = sandbox_router.sandbox_user()
    return bool(person) and await sandbox_router.is_running(person)
