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
from workspace_import import busy, jobs_common, place, staging, upload_sessions
from workspace_import.errors import ImportFailure, map_os_error
from workspace_import.extract import safe_extract, single_top_dir
from workspace_import.redact import safe_traceback

logger = logging.getLogger(__name__)

JOB_TOOL = "workspace_upload"
MAX_LOGGED_SKIPS = 200


def _safe(name: str) -> str:
    from prompts.base import _prompt_safe_name
    return _prompt_safe_name(name)


async def _extract(session, out, progress, cancel):
    # `safe_extract` is read here, at call time, so tests can patch it.
    return await jobs_common.extract_on_pool(safe_extract, session.data_path, out, progress, cancel,
                                             reservation=session.reservation, base_bytes=session.size,
                                             single_name=session.name)


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
    progress = jobs_common.Progress({"phase": "extracting", "files": 0, "bytes": 0, "totalBytes": session.size})
    reporter = asyncio.ensure_future(jobs_common.report_loop(progress))
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

        await jobs_common.ensure_project_exists(pid)

        progress.update(phase="placing")
        rel = await place.place(pid, staged, session.dest_dir, session.name, session.on_conflict)

        if skipped:
            lines = [f"skipped {_safe(name)} ({reason})" for name, reason in skipped[:MAX_LOGGED_SKIPS]]
            await append_log("\n".join(lines))
        reporter.cancel()
        await jobs_common.report_done({"phase": "done", "path": rel, "files": files, "bytes": nbytes})
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
