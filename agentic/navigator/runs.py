"""The agent's live AI Navigator runs (plan §8.11): run_id -> task, person, project.

Most stops arrive as a client disconnect (the webapp aborts its fetch); /navigator/stop and
/navigator/stop-all cancel by id or all at once, and /emergency-stop-all calls stop_all too.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional

from navigator.limits import AGENT_MAX_NAVIGATOR_RUNS


@dataclass
class Run:
    run_id: str
    task: asyncio.Task
    user_id: str
    project_id: str
    started_at: float


_RUNS: dict[str, Run] = {}


def count() -> int:
    return len(_RUNS)


def at_capacity() -> bool:
    return len(_RUNS) >= AGENT_MAX_NAVIGATOR_RUNS


def register(run_id: str, task: asyncio.Task, user_id: str, project_id: str) -> Optional[Run]:
    if run_id in _RUNS:
        return None
    run = Run(run_id, task, user_id, project_id, time.time())
    _RUNS[run_id] = run
    return run


def unregister(run_id: str) -> None:
    _RUNS.pop(run_id, None)


def stop(run_id: str) -> bool:
    run = _RUNS.pop(run_id, None)
    if run is None:
        return False
    run.task.cancel()
    return True


def stop_all() -> int:
    n = 0
    for run_id in list(_RUNS):
        if stop(run_id):
            n += 1
    return n


def clear_for_tests() -> None:
    _RUNS.clear()
