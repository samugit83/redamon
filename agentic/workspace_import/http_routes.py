"""HTTP routes for workspace uploads and URL imports.

Every route sits behind the master key (the agent port is published on the
host, so the key is the control) and answers failures as `{error, code}` with a
fixed sentence per code, never exception text.
"""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

import job_runner
import workspace_fs
from llm_guard import require_configured_master_auth
from workspace_import import staging
from workspace_import.errors import error_body, status_for

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/workspace",
    tags=["Workspace"],
    dependencies=[Depends(require_configured_master_auth)],
)

JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
WORKSPACE_JOB_TOOLS = frozenset({"workspace_upload", "workspace_import"})


def fail(code: str, **extra) -> JSONResponse:
    return JSONResponse(content=error_body(code, **extra), status_code=status_for(code))


def valid_project(project_id: str) -> bool:
    try:
        workspace_fs._validate_project_id(project_id)
        return True
    except ValueError:
        return False


@router.get("/jobs/{job_id}")
async def workspace_job_status(job_id: str, projectId: str = Query(...)):
    """One job's status and progress, for the transfers panel's polling."""
    if not JOB_ID_RE.match(job_id) or not valid_project(projectId):
        return fail("not_found")
    status = job_runner.get_registry().status(projectId, job_id)
    # A handle always carries job_id; the registry's "unknown job" and
    # "meta unreadable" answers do not.
    if not isinstance(status, dict) or "job_id" not in status:
        return fail("not_found")
    if status.get("project_id") not in (None, projectId):
        return fail("not_found")
    status.pop("tail", None)
    return status


async def reset_project_imports(project_id: str) -> int:
    """Cancel the project's running uploads and imports, wait for them, then
    clear its staging. The workspace reset calls this before wiping the tree,
    so no job places into a folder that is being emptied."""
    reg = job_runner.get_registry()
    cancelled = 0
    for row in reg.list(project_id, active=True):
        if row.get("tool_name") in WORKSPACE_JOB_TOOLS and row.get("job_id"):
            # cancel() awaits the task; a replace's swap is shielded, so the
            # target is whole when this returns.
            await reg.cancel(project_id, row["job_id"])
            cancelled += 1
    staging.sweep_project(project_id)
    return cancelled
