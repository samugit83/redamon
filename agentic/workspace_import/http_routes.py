"""HTTP routes for workspace uploads and URL imports.

Every route sits behind the master key (the agent port is published on the
host, so the key is the control) and answers failures as `{error, code}` with a
fixed sentence per code, never exception text.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError, StrictInt, StrictStr

import job_runner
import workspace_fs
from llm_guard import require_configured_master_auth
from workspace_import import limits, purge, staging, upload_job, upload_sessions
from workspace_import.errors import ImportFailure, error_body, status_for

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


def failure_response(e: ImportFailure) -> JSONResponse:
    extra = {}
    if e.code == "offset_mismatch" and e.detail.isdigit():
        extra["expectedOffset"] = int(e.detail)
    if e.code == "busy" and e.detail:
        extra["jobId"] = e.detail
    return JSONResponse(content=error_body(e.code, **extra), status_code=e.status)


def unexpected(route: str, e: Exception) -> JSONResponse:
    logger.error(f"[workspace-import] {route} failed: {type(e).__name__}")
    return fail("internal_error")


async def parse_body(request: Request, model: type[BaseModel]):
    """The request's JSON as `model`, or None. Never lets pydantic's error (which
    quotes the rejected input, token fields included) reach a response."""
    try:
        raw = await request.body()
        return model.model_validate(json.loads(raw or b"null"))
    except (ValueError, ValidationError, TypeError):
        return None


class _Body(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CreateSessionBody(_Body):
    projectId: StrictStr
    destDir: StrictStr = "."
    name: StrictStr
    size: StrictInt
    kind: StrictStr
    onConflict: StrictStr = "keep_both"


class ProjectBody(_Body):
    projectId: StrictStr


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
    upload_sessions.forget_project(project_id)
    staging.sweep_project(project_id)
    return cancelled


# ---------------------------------------------------------------------------
# Upload sessions (folders, archives and files over the single-request cap)
# ---------------------------------------------------------------------------

@router.post("/upload-sessions")
async def create_upload_session(request: Request):
    body = await parse_body(request, CreateSessionBody)
    if body is None or not valid_project(body.projectId):
        return fail("invalid_request")
    try:
        created = upload_sessions.create(body.projectId, body.destDir, body.name, body.size,
                                         body.kind, body.onConflict)
    except ImportFailure as e:
        return failure_response(e)
    except Exception as e:
        return unexpected("create upload session", e)
    return JSONResponse(content=created, status_code=201)


async def _read_capped(request: Request, cap: int) -> Optional[bytes]:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > cap:
        return None
    chunks, total = [], 0
    async for part in request.stream():
        total += len(part)
        if total > cap:
            return None
        chunks.append(part)
    return b"".join(chunks)


@router.put("/upload-sessions/{upload_id}/chunk")
async def put_upload_chunk(upload_id: str, request: Request,
                           projectId: str = Query(...), offset: str = Query(...)):
    if not upload_sessions.UPLOAD_ID_RE.match(upload_id) or not valid_project(projectId):
        return fail("session_not_found")
    if not offset.isdigit():
        return fail("invalid_request")
    try:
        upload_sessions.get(projectId, upload_id)
        data = await _read_capped(request, limits.chunk_bytes())
        if data is None:
            return fail("chunk_too_large")
        received = await upload_sessions.write_chunk(projectId, upload_id, int(offset), data)
    except ImportFailure as e:
        return failure_response(e)
    except Exception as e:
        return unexpected("upload chunk", e)
    return {"received": received}


@router.post("/upload-sessions/{upload_id}/commit")
async def commit_upload_session(upload_id: str, request: Request):
    body = await parse_body(request, ProjectBody)
    if body is None or not valid_project(body.projectId):
        return fail("invalid_request")
    if not upload_sessions.UPLOAD_ID_RE.match(upload_id):
        return fail("session_not_found")
    try:
        started = await upload_job.commit(body.projectId, upload_id)
    except ImportFailure as e:
        return failure_response(e)
    except Exception as e:
        return unexpected("commit upload", e)
    return JSONResponse(content=started, status_code=202)


@router.delete("/upload-sessions/{upload_id}")
async def abort_upload_session(upload_id: str, projectId: str = Query(...)):
    if upload_sessions.UPLOAD_ID_RE.match(upload_id) and valid_project(projectId):
        upload_sessions.abort(projectId, upload_id)
    return {"aborted": True}


@router.post("/project-purge")
async def project_purge(request: Request):
    """Called by the web app after it deleted a project (or a user and their
    projects): stop the project's jobs and remove its workspace and staging."""
    body = await parse_body(request, ProjectBody)
    if body is None or not valid_project(body.projectId):
        return fail("invalid_request")
    try:
        return await purge.purge_project(body.projectId)
    except ImportFailure as e:
        return failure_response(e)
    except Exception as e:
        return unexpected("project purge", e)
