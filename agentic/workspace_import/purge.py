"""Delete a deleted project's workspace: its jobs, sessions, staging and folder.

The web app calls this after the project row is gone. It acts only when the web
app answers 404 for the project, so a mistaken call can never wipe a live
project's workspace; any other answer, or none, refuses (fail closed).
"""
from __future__ import annotations

import logging
import shutil
from pathlib import Path

import job_runner
import workspace_fs
from workspace_import import executor, project_check, staging, upload_sessions
from workspace_import.errors import ImportFailure

logger = logging.getLogger(__name__)

_JOB_WAIT_SEC = 30.0


def _remove_root(path: Path) -> bool:
    """Remove a project root or staging folder. A root that is itself a symlink
    is unlinked, never followed; rmtree does not follow links inside."""
    if path.is_symlink():
        path.unlink()
        return True
    if path.is_dir():
        shutil.rmtree(path)
        return True
    if path.exists():
        path.unlink()
        return True
    return False


async def purge_project(project_id: str) -> dict:
    try:
        workspace_fs._validate_project_id(project_id)
    except ValueError:
        raise ImportFailure("invalid_request") from None
    try:
        exists = await project_check.project_exists(project_id)
    except project_check.ProjectCheckFailed:
        raise ImportFailure("settings_unavailable") from None
    if exists:
        raise ImportFailure("project_exists")

    reg = job_runner.get_registry()
    cancelled = 0
    for row in reg.list(project_id, active=True):
        job_id = row.get("job_id")
        if not job_id:
            continue
        await reg.cancel(project_id, job_id)
        await reg.wait(project_id, job_id, _JOB_WAIT_SEC)
        cancelled += 1
    root = workspace_fs.WORKSPACE_ROOT / project_id
    stage = staging.staging_root() / project_id
    had_staging = stage.exists() or stage.is_symlink()
    upload_sessions.forget_project(project_id)
    staging.sweep_project(project_id)

    removed = ["staging"] if had_staging else []
    await executor.run_blocking(_remove_root, stage)
    if await executor.run_blocking(_remove_root, root):
        removed.append("workspace")
    logger.info(f"[workspace-import] purged project={project_id} jobs={cancelled}")
    return {"cancelledJobs": cancelled, "removed": removed}
