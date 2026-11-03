"""
Background job runner for long-running tool calls.

JobRegistry holds asyncio Tasks keyed by job_id (uuid4 hex). Each job's stdout
is tee'd to /workspace/<projectId>/jobs/<job_id>.log and metadata sits beside
it as <job_id>.meta.json.

Lifecycle:
    - spawn(): creates meta + log, kicks off asyncio.create_task(_run).
    - _run(): calls a caller-supplied `runner(tool_name, args, append_log)`
      coroutine which executes the tool and appends to the log. On completion
      flips status, writes final meta, emits a job_update WS event.
    - On agent process restart: in-memory state is gone, so recover_on_boot()
      flips any "running" meta on disk to "interrupted".

The 5 fs_*-shaped tools (job_spawn / status / wait / cancel / list) live in
tools.py's in-process dispatch and route directly to this module.
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace"))


def _governed_max_jobs() -> Optional[int]:
    """Concurrent-background-job ceiling byte-budgeted to available RAM, or None to
    not cap (governor disabled / unavailable). Each job is a real subprocess
    (~measured envelope), so this uses the byte-budget model (not ratio) — safe on
    small hosts. Generous base (MAX_BACKGROUND_JOBS, default 16). Fail-open."""
    try:
        from graph_db import resource_governor as rg
    except Exception:
        try:
            import resource_governor as rg
        except Exception:
            return None
    try:
        if not rg.governor_enabled():
            return None
        base = int(os.environ.get("MAX_BACKGROUND_JOBS", "16") or "16")
        env = rg.envelope("background_job_envelope_bytes")
        frac = rg._env_float("AGENT_MEM_BUDGET_FRACTION", 0.5)
        return rg.scaled_cap(base, env, frac, 1)
    except Exception:
        return None


@dataclass
class JobHandle:
    job_id: str
    project_id: str
    tool_name: str
    args: dict
    label: Optional[str]
    status: str  # running|done|failed|cancelled|interrupted
    started_at: str
    ended_at: Optional[str] = None
    exit_code: Optional[int] = None
    output_path: str = ""
    error: Optional[str] = None
    # Set by long in-process jobs through report_progress(); meta files written
    # before this field existed simply lack it.
    progress: Optional[dict] = None
    # False for workspace upload/import jobs: they run in-process and are capped
    # by WORKSPACE_IMPORT_MAX_JOBS instead of taking a governed subprocess slot.
    counts_toward_cap: bool = True
    task: Optional[asyncio.Task] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        # Build dict explicitly: asdict() deep-copies every field, which
        # blows up on the live asyncio.Task before we can pop it.
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "task"}


# Runner callable contract:
#   async def runner(tool_name: str, args: dict, append_log: Callable[[str], Awaitable[None]]) -> dict
# Must return {"success": bool, "output": str|None, "error": str|None}.
RunnerFn = Callable[[str, dict, Callable[[str], Awaitable[None]]], Awaitable[dict]]

# (registry, handle) of the job whose runner is executing in this task, so a
# runner can report progress without a change to the runner contract above.
_current_job: contextvars.ContextVar = contextvars.ContextVar("current_job", default=None)
_PROGRESS_META_INTERVAL_SEC = 1.0


def current_job_id() -> Optional[str]:
    """The id of the job whose runner is executing in this task, or None."""
    current = _current_job.get()
    return current[1].job_id if current else None


async def report_progress(progress: dict, *, now: Callable[[], float] = time.monotonic) -> None:
    """Record the running job's progress. Meta and the job_update event are
    throttled to one per second; the final meta write always carries the last
    value. Outside a job this does nothing."""
    current = _current_job.get()
    if current is None:
        return
    registry, handle = current
    handle.progress = dict(progress)
    t = now()
    last = registry._progress_written.get(handle.job_id)
    if last is not None and t - last < _PROGRESS_META_INTERVAL_SEC:
        return
    registry._progress_written[handle.job_id] = t
    registry._write_meta(handle)
    await registry._notify({
        "type": "job_update",
        "project_id": handle.project_id,
        "job_id": handle.job_id,
        "status": "running",
        "progress": handle.progress,
    })


class JobRegistry:
    def __init__(self):
        self._jobs: dict[str, JobHandle] = {}
        self._lock = asyncio.Lock()
        self._ws_emit: Optional[Callable[[dict], Awaitable[None]]] = None
        self._progress_written: dict[str, float] = {}

    def set_ws_emitter(self, fn: Optional[Callable[[dict], Awaitable[None]]]) -> None:
        """Register a coroutine to receive job_update events for the drawer."""
        self._ws_emit = fn

    # ---- path helpers ------------------------------------------------------

    def _jobs_dir(self, project_id: str) -> Path:
        d = WORKSPACE_ROOT / project_id / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _meta_path(self, project_id: str, job_id: str) -> Path:
        return self._jobs_dir(project_id) / f"{job_id}.meta.json"

    def _log_path(self, project_id: str, job_id: str) -> Path:
        return self._jobs_dir(project_id) / f"{job_id}.log"

    def _write_meta(self, handle: JobHandle) -> None:
        try:
            self._meta_path(handle.project_id, handle.job_id).write_text(
                json.dumps(handle.to_dict(), indent=2, default=str)
            )
        except Exception as e:
            logger.error(f"write_meta failed for {handle.job_id}: {e}")

    async def _notify(self, evt: dict) -> None:
        if not self._ws_emit:
            return
        try:
            await self._ws_emit(evt)
        except Exception as e:
            logger.warning(f"job_update emit failed: {e}")

    # ---- public API --------------------------------------------------------

    async def spawn(
        self,
        project_id: str,
        tool_name: str,
        args: dict,
        runner: RunnerFn,
        label: Optional[str] = None,
        counts_toward_cap: bool = True,
    ) -> dict:
        """Kick off a background tool execution. Returns synchronously."""
        if not project_id:
            return {"error": "project_id required"}
        # Memory governor (Part 3): cap concurrent background jobs to available RAM
        # (none existed before). Generous base, scaled down under pressure; the
        # agent container mem_limit is the hard backstop. Fail-open.
        cap = _governed_max_jobs() if counts_toward_cap else None
        workspace_cap = None
        if not counts_toward_cap:
            from workspace_import import limits as _ws_limits
            workspace_cap = _ws_limits.max_jobs()
        job_id = uuid.uuid4().hex
        started = datetime.now(timezone.utc).isoformat()
        log_path = self._log_path(project_id, job_id)

        handle = JobHandle(
            job_id=job_id,
            project_id=project_id,
            tool_name=tool_name,
            args=args or {},
            label=label,
            status="running",
            started_at=started,
            output_path=str(log_path),
            counts_toward_cap=counts_toward_cap,
        )
        # Count-and-insert atomically under the lock so two concurrent spawns
        # can't both pass the cap and over-admit.
        async with self._lock:
            if cap is not None:
                active = sum(1 for h in self._jobs.values()
                             if h.status == "running" and h.counts_toward_cap)
                if active >= cap:
                    return {"error": f"Too many background jobs running ({active}/{cap}); "
                                     f"memory-limited, retry shortly.", "limitType": "ram"}
            if workspace_cap is not None:
                active = sum(1 for h in self._jobs.values()
                             if h.status == "running" and not h.counts_toward_cap)
                if active >= workspace_cap:
                    return {"error": f"Too many workspace uploads and imports running "
                                     f"({active}/{workspace_cap}); retry shortly.",
                            "limitType": "workspace"}
            self._jobs[job_id] = handle
        log_path.touch()   # only after admission, so a rejected job leaves no file
        self._write_meta(handle)

        async def append_log(chunk: str) -> None:
            if chunk is None:
                return
            try:
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(chunk)
                    if not chunk.endswith("\n"):
                        f.write("\n")
            except Exception as e:
                logger.error(f"job {job_id} log append failed: {e}")

        async def _run():
            _current_job.set((self, handle))
            try:
                result = await runner(tool_name, args or {}, append_log)
                if isinstance(result, dict) and result.get("success"):
                    handle.status = "done"
                    handle.exit_code = 0
                else:
                    handle.status = "failed"
                    handle.exit_code = 1
                    if isinstance(result, dict) and result.get("error"):
                        handle.error = str(result["error"])
                final = (result or {}).get("output") if isinstance(result, dict) else result
                if final:
                    txt = final if isinstance(final, str) else str(final)
                    await append_log("\n--- final ---\n")
                    await append_log(txt)
            except asyncio.CancelledError:
                handle.status = "cancelled"
                raise
            except Exception as e:
                handle.status = "failed"
                handle.error = str(e)
                logger.exception(f"job {job_id} crashed")
            finally:
                handle.ended_at = datetime.now(timezone.utc).isoformat()
                handle.task = None
                self._progress_written.pop(job_id, None)
                self._write_meta(handle)
                await self._notify({
                    "type": "job_update",
                    "project_id": project_id,
                    "job_id": job_id,
                    "status": handle.status,
                })

        handle.task = asyncio.create_task(_run())
        await self._notify({
            "type": "job_update",
            "project_id": project_id,
            "job_id": job_id,
            "status": "running",
        })
        return {"job_id": job_id, "output_path": str(log_path), "status": "running"}

    def status(self, project_id: str, job_id: str) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id:
            mp = self._meta_path(project_id, job_id)
            if mp.exists():
                try:
                    data = json.loads(mp.read_text())
                    data["size_bytes"] = self._log_size(project_id, job_id)
                    data["tail"] = self._log_tail(project_id, job_id, 40)
                    return data
                except Exception as e:
                    return {"error": f"meta unreadable: {e}"}
            return {"error": f"unknown job {job_id}"}
        d = h.to_dict()
        d["size_bytes"] = self._log_size(project_id, job_id)
        d["tail"] = self._log_tail(project_id, job_id, 40)
        return d

    async def wait(self, project_id: str, job_id: str, timeout_sec: float = 30.0) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id or h.task is None:
            return self.status(project_id, job_id)
        try:
            await asyncio.wait_for(asyncio.shield(h.task), timeout=timeout_sec)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        return self.status(project_id, job_id)

    async def cancel(self, project_id: str, job_id: str) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id:
            return {"error": f"unknown job {job_id}"}
        if h.task and not h.task.done():
            h.task.cancel()
            try:
                await h.task
            except (asyncio.CancelledError, Exception):
                pass
            if h.status == "running":
                # Cancelled before its first step, so _run never ran to record it.
                h.status = "cancelled"
                h.ended_at = datetime.now(timezone.utc).isoformat()
                h.task = None
                self._write_meta(h)
                await self._notify({"type": "job_update", "project_id": project_id,
                                    "job_id": job_id, "status": "cancelled"})
        return self.status(project_id, job_id)

    def list(self, project_id: str, active: Optional[bool] = None) -> list[dict]:
        rows = [h.to_dict() for h in self._jobs.values() if h.project_id == project_id]
        # Augment from disk so jobs survived across restarts are visible too.
        jobs_dir = WORKSPACE_ROOT / project_id / "jobs"
        if jobs_dir.exists():
            in_mem = {r["job_id"] for r in rows}
            for mp in jobs_dir.glob("*.meta.json"):
                jid = mp.name[:-len(".meta.json")]
                if jid in in_mem:
                    continue
                try:
                    rows.append(json.loads(mp.read_text()))
                except Exception:
                    pass
        if active is True:
            rows = [r for r in rows if r.get("status") == "running"]
        elif active is False:
            rows = [r for r in rows if r.get("status") != "running"]
        rows.sort(key=lambda r: r.get("started_at", ""), reverse=True)
        # Augment with on-disk size/tail snapshot
        for r in rows:
            jid = r.get("job_id")
            if jid:
                r["size_bytes"] = self._log_size(project_id, jid)
        return rows

    # ---- internals ---------------------------------------------------------

    def _log_size(self, project_id: str, job_id: str) -> int:
        try:
            return self._log_path(project_id, job_id).stat().st_size
        except Exception:
            return 0

    def _log_tail(self, project_id: str, job_id: str, n_lines: int) -> str:
        try:
            with self._log_path(project_id, job_id).open("r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            return "".join(lines[-n_lines:])
        except Exception:
            return ""

    def recover_on_boot(self) -> None:
        """Flip any meta files still marked 'running' to 'interrupted'."""
        if not WORKSPACE_ROOT.exists():
            return
        try:
            for project_dir in WORKSPACE_ROOT.iterdir():
                jobs_dir = project_dir / "jobs"
                if not jobs_dir.is_dir():
                    continue
                for mp in jobs_dir.glob("*.meta.json"):
                    try:
                        data = json.loads(mp.read_text())
                        if data.get("status") == "running":
                            data["status"] = "interrupted"
                            data["ended_at"] = datetime.now(timezone.utc).isoformat()
                            mp.write_text(json.dumps(data, indent=2, default=str))
                    except Exception as e:
                        logger.warning(f"recover_on_boot: bad meta {mp}: {e}")
        except Exception as e:
            logger.warning(f"recover_on_boot scan failed: {e}")


# Module-level singleton
_registry: Optional[JobRegistry] = None


def get_registry() -> JobRegistry:
    global _registry
    if _registry is None:
        _registry = JobRegistry()
    return _registry


JOB_TOOL_NAMES = frozenset({
    "job_spawn", "job_status", "job_wait", "job_cancel", "job_list",
})
