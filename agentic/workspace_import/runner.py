"""The URL import job: download (or clone), extract, sign provenance, place.

It runs as a `workspace_import` job that takes no governed background-job
slot. The GitHub token lives only in this job's closure: never in its args,
meta, log, progress, provenance, an error or a response.
"""
from __future__ import annotations

import asyncio
import logging
import posixpath
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import job_runner
from workspace_import import busy, github, jobs_common, place, provenance, staging
from workspace_import.detect import FORGE_KINDS, MIRROR_KINDS, is_html
from workspace_import.errors import ImportFailure, map_os_error
from workspace_import.extract import safe_extract, single_top_dir
from workspace_import.fetch import GuardedFetcher
from workspace_import.limits import max_bytes
from workspace_import.redact import redact_url, safe_traceback

logger = logging.getLogger(__name__)

JOB_TOOL = "workspace_import"
MAX_IMPORTS_PER_PROJECT = 2

# (project, canonical url, destination) -> {"job_id", "done"}: a second
# identical import while one runs is refused with that job's id. The entry is
# claimed before the job is spawned, so a double click cannot start two.
_running: dict[tuple[str, str, str], dict] = {}

# Injectable for tests: builds the fetcher of a job.
fetcher_factory = GuardedFetcher


@dataclass
class ImportSpec:
    url: str
    dest_dir: str
    name: str
    on_conflict: str = "keep_both"
    options: dict = field(default_factory=dict)
    # A Re-sync replaces an existing imported folder; if that folder vanished
    # meanwhile (deleted from the host or kali), nothing is recreated.
    resync: bool = False


def canonical_key(project_id: str, url: str, dest_dir: str) -> tuple[str, str, str]:
    u = urllib.parse.urlsplit(url.strip())
    canon = urllib.parse.urlunsplit((u.scheme.lower(), (u.hostname or "").lower(), u.path.rstrip("/") or "/",
                                     "&".join(sorted(u.query.split("&"))) if u.query else "", ""))
    return project_id, canon, busy.normalize(dest_dir)


def running_job(key) -> Optional[str]:
    entry = _running.get(key)
    return (entry["job_id"] or "pending") if entry else None


def _strip_top(subpath: str = ""):
    """member_filter for a forge/GitHub tarball: drop its single top folder
    (o-r-<sha7>/) and, for a subfolder import, keep only that subtree."""
    prefix = subpath.strip("/") + "/" if subpath else ""

    def keep(name: str) -> Optional[str]:
        parts = name.split("/", 1)
        if len(parts) < 2 or not parts[1]:
            return None
        rest = parts[1]
        if not prefix:
            return rest
        if not rest.startswith(prefix):
            return None
        return rest[len(prefix):] or None
    return keep


def _record(spec: ImportSpec, insp, stats: dict) -> dict:
    source = {"url": redact_url(spec.url), "kind": insp.kind, "host": insp.host}
    if insp.repo is not None:
        source.update(owner=insp.repo.owner, repo=insp.repo.repo, ref=insp.repo.ref, commit=insp.repo.sha,
                      subpath=insp.repo.subpath)
    elif insp.forge is not None:
        source.update(project=insp.forge.project, ref=insp.forge.ref)
    elif insp.kind == "github-gist":
        source.update(gist=insp.parts.get("id"))
    elif insp.kind == "git":
        source.update(repo=insp.parts.get("repo"), commit=insp.parts.get("commit", ""))
    return {
        "source": source,
        "options": dict(spec.options),
        "fetchedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stats": stats,
        # A query is never stored (it can hold a token), so the URL could not be fetched again.
        "resyncable": not urllib.parse.urlsplit(spec.url).query,
    }


async def _download(fetcher, url, dest, reservation, progress, cancel, factor):
    grower = jobs_common.ReservationGrower(reservation, factor)

    def on_progress(nbytes, total):
        progress.update(phase="downloading", bytes=nbytes, totalBytes=total)

    return await fetcher.download(url, dest, max_bytes=max_bytes(), progress=on_progress, on_bytes=grower,
                                  cancel_event=cancel)


async def _fetch_into(fetcher, spec, insp, op, reservation, progress, cancel, github_token: str):
    """Fill `op/out` (a folder import) or return the downloaded file (a file
    import). Returns (staged path, is_folder, stats)."""
    out = op / "out"
    out.mkdir(mode=0o777)
    kind = insp.kind

    if kind == "github-repo" and insp.repo.raw_strategy:
        def on_files(files, nbytes):
            progress.update(phase="downloading", files=files, bytes=nbytes)
        got = await github.fetch_subpath_raw(fetcher, insp.repo, out, max_bytes=max_bytes(),
                                             max_entries=_max_entries(), progress=on_files, cancel_event=cancel)
        return out, True, {"files": got["files"], "bytes": got["bytes"], "skipped": len(got["skipped"])}

    if kind == "github-gist":
        got = await github.fetch_gist(fetcher, insp.parts["id"], out, max_bytes=max_bytes(), cancel_event=cancel)
        return out, True, {"files": got["files"], "bytes": got["bytes"], "skipped": 0}

    if kind == "git":
        from workspace_import import git_clone
        got = await git_clone.clone_into(spec.url, out, reservation=reservation, progress=progress, cancel=cancel)
        insp.parts["commit"] = got.get("commit", "")
        return out, True, {"files": got["files"], "bytes": got["bytes"], "skipped": got.get("skipped", 0)}

    if kind in ("github-repo",) or kind in FORGE_KINDS:
        if kind == "github-repo":
            url = github.tarball_url(insp.repo.owner, insp.repo.repo, insp.repo.sha, with_token=bool(github_token))
            member_filter = _strip_top(insp.repo.subpath)
        else:
            url, member_filter = insp.forge.archive_url, _strip_top()
        tarball = op / "download.tar.gz"
        dl = await _download(fetcher, url, tarball, reservation, progress, cancel, factor=2)
        if is_html(dl.content_type, _head(tarball)):
            raise ImportFailure("unexpected_html")
        report = await jobs_common.extract_on_pool(safe_extract, tarball, out, progress, cancel,
                                                   member_filter=member_filter)
        return out, True, {"files": report.files, "bytes": report.bytes, "skipped": report.skipped_count}

    if kind == "archive":
        data = op / "download"
        dl = await _download(fetcher, spec.url, data, reservation, progress, cancel, factor=2)
        if is_html(dl.content_type, _head(data)):
            raise ImportFailure("unexpected_html")
        report = await jobs_common.extract_on_pool(safe_extract, data, out, progress, cancel,
                                                   single_name=spec.name)
        top = single_top_dir(out)
        return (top or out), True, {"files": report.files, "bytes": report.bytes, "skipped": report.skipped_count}

    # A single file: github-file or file (PDFs included), placed as a file with
    # no provenance (decision Q4).
    url = github.raw_file_url(insp.parts) if kind == "github-file" else spec.url
    data = op / "file"
    dl = await _download(fetcher, url, data, reservation, progress, cancel, factor=1)
    # raw.githubusercontent.com serves every file as text/plain, so only its
    # content type can reveal a login page; a generic link is also sniffed.
    if kind == "github-file":
        if dl.content_type in ("text/html", "application/xhtml+xml"):
            raise ImportFailure("unexpected_html")
    elif is_html(dl.content_type, _head(data)):
        raise ImportFailure("unexpected_html")
    return data, False, {"files": 1, "bytes": dl.bytes, "skipped": 0}


def _target_present(project_id: str, spec: ImportSpec) -> bool:
    import workspace_fs
    try:
        target = workspace_fs.resolve_for_project(project_id, posixpath.join(spec.dest_dir, spec.name),
                                                  follow_symlinks=False)
    except ValueError:
        return False
    return target.is_dir() and not target.is_symlink()


def _max_entries() -> int:
    from workspace_import.limits import max_entries
    return max_entries()


def _head(path, n: int = 512) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


async def run_import(spec: ImportSpec, insp, *, project_id: str, github_token: str, append_log) -> dict:
    """The job's body. `insp` is the server-side inspection the route made."""
    job_id = job_runner.current_job_id() or "unknown"
    key = canonical_key(project_id, spec.url, spec.dest_dir)
    entry = _running.get(key)
    if entry is not None:
        entry["job_id"] = job_id
    target = posixpath.join(spec.dest_dir, spec.name) if spec.on_conflict == "replace" else None
    busy.register(project_id, job_id, target=target, dest_dir=spec.dest_dir)
    progress = jobs_common.Progress({"phase": "resolving"})
    reporter = asyncio.ensure_future(jobs_common.report_loop(progress))
    cancel = threading.Event()
    op = None
    reservation = None
    log_url = redact_url(spec.url)
    try:
        if insp.kind in MIRROR_KINDS:
            raise ImportFailure("kind_not_supported")
        op = staging.new_op_dir(project_id, "imp")
        expected = insp.repo.bytes if insp.repo is not None and not insp.repo.truncated else \
            int(insp.details.get("bytes") or 0)
        factor = 1 if insp.kind in ("github-file", "file") else 2
        reservation = staging.reserve(op.name, expected * factor, project_id=project_id)
        async with fetcher_factory(github_token=github_token) as fetcher:
            staged, is_folder, stats = await _fetch_into(fetcher, spec, insp, op, reservation, progress,
                                                         cancel, github_token)
        if is_folder:
            provenance.write(staged, _record(spec, insp, stats), project_id=project_id)
        await jobs_common.ensure_project_exists(project_id)
        if spec.resync and not _target_present(project_id, spec):
            raise ImportFailure("destination_missing")
        progress.update(phase="placing")
        rel = await place.place(project_id, staged, spec.dest_dir, spec.name, spec.on_conflict)
        reporter.cancel()
        await jobs_common.report_done({"phase": "done", "path": rel, "files": stats["files"], "bytes": stats["bytes"]})
        logger.info(f"[workspace-import] done project={project_id} job={job_id} kind={insp.kind} url={log_url} "
                    f"path={rel} files={stats['files']} bytes={stats['bytes']}")
        return {"success": True, "output": f"Saved as {rel}: {stats['files']} files, {stats['bytes']} bytes."}
    except asyncio.CancelledError:
        cancel.set()
        raise
    except ImportFailure as e:
        logger.info(f"[workspace-import] project={project_id} job={job_id} kind={insp.kind} url={log_url} code={e.code}")
        return {"success": False, "error": e.code}
    except OSError as e:
        failure = map_os_error(e)
        code = failure.code if failure else "internal_error"
        logger.warning(f"[workspace-import] project={project_id} job={job_id} kind={insp.kind} url={log_url} "
                       f"code={code} error={type(e).__name__}")
        return {"success": False, "error": code}
    except Exception as e:
        logger.error(f"[workspace-import] project={project_id} job={job_id} kind={insp.kind} url={log_url} "
                     f"code=internal_error error={type(e).__name__}\n{safe_traceback(e)}")
        return {"success": False, "error": "internal_error"}
    finally:
        reporter.cancel()
        busy.unregister(job_id)
        entry = _running.get(key)
        if entry is not None and entry["job_id"] == job_id:
            entry["done"] = True
            _running.pop(key, None)
        if reservation is not None:
            reservation.release()
        if op is not None:
            staging.remove_tree(op)


def _label(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    return f"import {(u.hostname or '')}{u.path}"[:60]


async def start(spec: ImportSpec, insp, *, project_id: str, github_token: str) -> dict:
    """Spawn the job. Refuses a duplicate of a running import (busy, with its
    job id) and a third concurrent import of the project."""
    key = canonical_key(project_id, spec.url, spec.dest_dir)
    reg = job_runner.get_registry()
    held = _running.get(key)
    if held is not None:
        # A job cancelled before its first step never ran its clean-up.
        if held["job_id"] and reg.status(project_id, held["job_id"]).get("status") != "running":
            _running.pop(key, None)
        else:
            raise ImportFailure("busy", detail=running_job(key))
    active = [r for r in reg.list(project_id, active=True) if r.get("tool_name") == JOB_TOOL]
    if len(active) >= MAX_IMPORTS_PER_PROJECT:
        raise ImportFailure("too_many_imports")
    entry = _running[key] = {"job_id": None, "done": False}
    args = {"url": redact_url(spec.url), "destDir": spec.dest_dir, "name": spec.name,
            "onConflict": spec.on_conflict, "options": dict(spec.options)}

    async def runner(_tool, _args, append_log):
        return await run_import(spec, insp, project_id=project_id, github_token=github_token,
                                append_log=append_log)

    try:
        started = await reg.spawn(project_id, JOB_TOOL, args, runner, label=_label(redact_url(spec.url)),
                                  counts_toward_cap=False)
    except BaseException:
        _running.pop(key, None)
        raise
    if not isinstance(started, dict) or "job_id" not in started:
        _running.pop(key, None)
        raise ImportFailure("too_many_jobs")
    if not entry["done"] and entry["job_id"] is None:
        entry["job_id"] = started["job_id"]
    return {"jobId": started["job_id"], "kind": insp.kind, "destDir": spec.dest_dir, "name": spec.name}
