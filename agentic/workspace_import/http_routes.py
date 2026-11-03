"""HTTP routes for workspace uploads and URL imports.

Every route sits behind the master key (the agent port is published on the
host, so the key is the control) and answers failures as `{error, code}` with a
fixed sentence per code, never exception text.
"""
from __future__ import annotations

import asyncio
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
from workspace_import import limits, provenance, purge, resolve, runner, staging, upload_job, upload_sessions
from workspace_import.detect import MIRROR_KINDS
from workspace_import.names import sanitize_name
from workspace_import.place import POLICIES
from workspace_import.errors import ImportFailure, error_body, status_for
from workspace_import.fetch import GuardedFetcher

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


class ResolveBody(_Body):
    projectId: StrictStr
    url: StrictStr
    githubToken: Optional[StrictStr] = None
    subpath: Optional[StrictStr] = None


class ImportBody(_Body):
    projectId: StrictStr
    url: StrictStr
    destDir: StrictStr = "."
    name: Optional[StrictStr] = None
    onConflict: StrictStr = "keep_both"
    options: dict = {}
    githubToken: Optional[StrictStr] = None


class ResyncBody(_Body):
    projectId: StrictStr
    path: StrictStr
    githubToken: Optional[StrictStr] = None


IMPORT_OPTION_KEYS = ("subpath",)
RESOLVE_TIMEOUT_SEC = 20.0
# Injectable for tests: builds the fetcher a resolve or an import uses.
fetcher_factory = GuardedFetcher


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


# ---------------------------------------------------------------------------
# URL import
# ---------------------------------------------------------------------------

@router.post("/import-url/resolve")
async def resolve_import_url(request: Request):
    """Preview: what the URL is, how big, and what will not be included."""
    if not limits.url_import_enabled():
        return fail("import_disabled")
    body = await parse_body(request, ResolveBody)
    if body is None or not valid_project(body.projectId):
        return fail("invalid_request")

    async def run():
        async with fetcher_factory(github_token=body.githubToken or "") as fetcher:
            return await resolve.inspect(body.url, fetcher, subpath=body.subpath)

    try:
        inspection = await asyncio.wait_for(run(), RESOLVE_TIMEOUT_SEC)
    except asyncio.TimeoutError:
        return fail("timeout")
    except ImportFailure as e:
        return failure_response(e)
    except Exception as e:
        return unexpected("resolve import url", e)
    return inspection.answer()


def _clean_options(options: dict) -> Optional[dict]:
    """The options this version understands, type-checked; None when invalid."""
    out = {}
    for key, value in (options or {}).items():
        if key not in IMPORT_OPTION_KEYS:
            continue
        if not isinstance(value, str) or len(value) > 1024:
            return None
        if value.strip("/"):
            out[key] = value.strip("/")
    return out


async def start_import(project_id: str, url: str, dest_dir: str, name: Optional[str], on_conflict: str,
                       options: dict, github_token: str, *, resync: bool = False) -> JSONResponse:
    """Shared by a new import and a Re-sync: inspect on the server, then spawn."""
    try:
        dest = workspace_fs.resolve_for_project(project_id, dest_dir)
    except ValueError:
        return fail("invalid_request")
    if not dest.is_dir():
        return fail("destination_missing")

    async def inspect():
        async with fetcher_factory(github_token=github_token) as fetcher:
            return await resolve.inspect(url, fetcher, subpath=options.get("subpath"))

    try:
        insp = await asyncio.wait_for(inspect(), RESOLVE_TIMEOUT_SEC)
        if insp.kind in MIRROR_KINDS:
            raise ImportFailure("kind_not_supported")
        final_name = sanitize_name(name, fallback="") if name else insp.name
        if not final_name:
            return fail("invalid_request")
        spec = runner.ImportSpec(url=url, dest_dir=dest_dir, name=final_name, on_conflict=on_conflict,
                                 options=options, resync=resync)
        started = await runner.start(spec, insp, project_id=project_id, github_token=github_token)
    except asyncio.TimeoutError:
        return fail("timeout")
    except ImportFailure as e:
        return failure_response(e)
    except Exception as e:
        return unexpected("start import", e)
    return JSONResponse(content=started, status_code=202)


@router.post("/import-url")
async def import_url(request: Request):
    """Start a URL import job. The answer's facts come from the server's own
    inspection; the web app audits them."""
    if not limits.url_import_enabled():
        return fail("import_disabled")
    body = await parse_body(request, ImportBody)
    if body is None or not valid_project(body.projectId) or body.onConflict not in POLICIES:
        return fail("invalid_request")
    options = _clean_options(body.options)
    if options is None:
        return fail("invalid_request")
    return await start_import(body.projectId, body.url, body.destDir, body.name, body.onConflict, options,
                              body.githubToken or "")


@router.post("/import-url/resync")
async def resync_import(request: Request):
    """Fetch an imported folder again from its recorded source and replace its
    contents. The folder is a busy target for the whole job."""
    if not limits.url_import_enabled():
        return fail("import_disabled")
    body = await parse_body(request, ResyncBody)
    if body is None or not valid_project(body.projectId):
        return fail("invalid_request")
    try:
        rel = workspace_fs.project_relative(body.projectId, body.path, follow_symlinks=False)
        folder = workspace_fs.resolve_for_project(body.projectId, rel, follow_symlinks=False)
    except ValueError:
        return fail("invalid_request")
    if workspace_fs.is_protected_path(rel):
        return fail("protected_path")
    if folder.is_symlink() or not folder.is_dir():
        return fail("not_imported")
    record = provenance.read(folder, project_id=body.projectId)
    if record is None:
        return fail("not_imported")
    if not record.get("resyncable"):
        return fail("not_resyncable")
    source = record.get("source") or {}
    url = str(source.get("url") or "")
    options = _clean_options(record.get("options") or {})
    if not url or options is None:
        return fail("not_imported")
    parent = rel.rsplit("/", 1)[0] if "/" in rel else "."
    return await start_import(body.projectId, url, parent, folder.name, "replace", options,
                              body.githubToken or "", resync=True)
