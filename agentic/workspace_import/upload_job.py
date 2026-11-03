"""The commit job of an upload session: extract (folders and archives), then
place the result into the destination folder.

It runs in-process as a `workspace_upload` job that takes no governed
background-job slot (the agent's job_spawn and MCP kali exec need those), on
the import pool for the heavy work. Failures are codes; exception text never
reaches the job's meta, its log or the server log.
"""
from __future__ import annotations

import asyncio
import logging
import posixpath
import threading

import job_runner
from workspace_import import busy, executor, place, project_check, staging, upload_sessions
from workspace_import.errors import ImportFailure, map_os_error
from workspace_import.extract import safe_extract, single_top_dir
from workspace_import import limits
from workspace_import.redact import safe_traceback

logger = logging.getLogger(__name__)

JOB_TOOL = "workspace_upload"
MAX_LOGGED_SKIPS = 200
_PROGRESS_TICK_SEC = 0.25
_CANCEL_GRACE_SEC = 30.0


def _safe(name: str) -> str:
    from prompts.base import _prompt_safe_name
    return _prompt_safe_name(name)


class _Progress:
    """Extraction progress written by the pool thread, reported by the job's task."""

    def __init__(self, base: dict):
        self.state = dict(base)
        self._lock = threading.Lock()
        self.version = 0

    def update(self, **kw) -> None:
        with self._lock:
            self.state.update(kw)
            self.version += 1

    def snapshot(self) -> tuple[int, dict]:
        with self._lock:
            return self.version, dict(self.state)


async def _report_loop(progress: _Progress) -> None:
    seen = -1
    while True:
        version, state = progress.snapshot()
        if version != seen:
            seen = version
            await job_runner.report_progress(state)
        await asyncio.sleep(_PROGRESS_TICK_SEC)


async def _extract(session, out, progress: _Progress, cancel: threading.Event):
    def on_progress(files, nbytes):
        progress.update(phase="extracting", files=files, bytes=nbytes)

    future, queued = executor.start(
        lambda: safe_extract(session.data_path, out, max_bytes=limits.max_bytes(),
                             max_entries=limits.max_entries(), progress=on_progress,
                             cancel_event=cancel, single_name=session.name),
    )
    if queued:
        progress.update(phase="queued")
    try:
        return await asyncio.wrap_future(future)
    except asyncio.CancelledError:
        # A pool thread cannot be killed: tell it to stop, and wait for it, so
        # staging is not deleted under a writer.
        cancel.set()
        try:
            await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)), _CANCEL_GRACE_SEC)
        except BaseException:
            pass
        raise


def _staged_entry(session, out):
    """What gets placed. A folder upload's tar is rooted at <name>/; an archive
    whose output is one folder is that folder; otherwise the whole output
    (a lone gzip's file then sits in a folder named after the archive)."""
    top = single_top_dir(out)
    if top is not None and (session.kind == "archive" or top.name == session.name):
        return top
    return out


async def run_upload_commit(session, append_log) -> dict:
    pid = session.project_id
    job_id = job_runner.current_job_id() or session.upload_id
    target = posixpath.join(session.dest_dir, session.name) if session.on_conflict == "replace" else None
    busy.register(pid, job_id, target=target, dest_dir=session.dest_dir)
    progress = _Progress({"phase": "extracting", "files": 0, "bytes": 0, "totalBytes": session.size})
    reporter = asyncio.ensure_future(_report_loop(progress))
    cancel = threading.Event()
    kind = f"upload-{session.kind}"
    try:
        files, nbytes, skipped = 1, session.size, []
        if session.kind == "file":
            staged = session.data_path
        else:
            out = session.op_dir / "out"
            out.mkdir(mode=0o777)
            report = await _extract(session, out, progress, cancel)
            files, nbytes = report.files, report.bytes
            skipped = report.skipped
            staged = _staged_entry(session, out)

        try:
            exists = await project_check.project_exists(pid)
        except project_check.ProjectCheckFailed:
            raise ImportFailure("settings_unavailable") from None
        if not exists:
            raise ImportFailure("project_deleted")

        progress.update(phase="placing")
        rel = await place.place(pid, staged, session.dest_dir, session.name, session.on_conflict)

        if skipped:
            lines = [f"skipped {_safe(name)} ({reason})" for name, reason in skipped[:MAX_LOGGED_SKIPS]]
            await append_log("\n".join(lines))
        reporter.cancel()
        await job_runner.report_progress({"phase": "done", "path": rel, "files": files, "bytes": nbytes},
                                         now=lambda: float("inf"))
        logger.info(f"[workspace-import] done project={pid} job={job_id} kind={kind} "
                    f"path={_safe(rel)} files={files} bytes={nbytes}")
        return {"success": True,
                "output": f"Saved as {rel}: {files} files, {nbytes} bytes, {len(skipped)} skipped."}
    except asyncio.CancelledError:
        cancel.set()
        raise
    except ImportFailure as e:
        logger.info(f"[workspace-import] project={pid} job={job_id} kind={kind} code={e.code}")
        return {"success": False, "error": e.code}
    except OSError as e:
        failure = map_os_error(e)
        code = failure.code if failure else "internal_error"
        logger.warning(f"[workspace-import] project={pid} job={job_id} kind={kind} code={code} "
                       f"error={type(e).__name__}")
        return {"success": False, "error": code}
    except Exception as e:
        logger.error(f"[workspace-import] project={pid} job={job_id} kind={kind} code=internal_error "
                     f"error={type(e).__name__}\n{safe_traceback(e)}")
        return {"success": False, "error": "internal_error"}
    finally:
        reporter.cancel()
        busy.unregister(job_id)
        session.reservation.release()
        staging.remove_tree(session.op_dir)


async def commit(project_id: str, upload_id: str) -> dict:
    """Start the commit job of a complete session. Answers the session's own
    facts, which the web app writes to its audit row."""
    session = upload_sessions.take_for_commit(project_id, upload_id)
    args = {"destDir": session.dest_dir, "name": session.name, "kind": session.kind,
            "size": session.size, "onConflict": session.on_conflict}

    async def runner(_tool, _args, append_log):
        return await run_upload_commit(session, append_log)

    started = await job_runner.get_registry().spawn(
        project_id, JOB_TOOL, args, runner, label=f"upload {session.name}"[:60], counts_toward_cap=False,
    )
    if not isinstance(started, dict) or "job_id" not in started:
        upload_sessions.restore(session)
        raise ImportFailure("too_many_jobs")
    return {"jobId": started["job_id"], "destDir": session.dest_dir, "name": session.name,
            "kind": session.kind, "size": session.size}
