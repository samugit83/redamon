"""GitHub: repository, subfolder, single file and gist imports."""
from __future__ import annotations

import asyncio
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from workspace_import.errors import ImportFailure
from workspace_import.extract import RESERVED_NAMES, _check_lengths, _normalize
from workspace_import.names import sanitize_name

API = "https://api.github.com"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_REF_PROBES = 4
TREE_MAX_BYTES = 32 * 1024 * 1024
RAW_PARALLEL = 8
# A subfolder this small is fetched file by file; a bigger one (or a truncated
# tree) comes from the commit's tarball with everything else filtered out.
RAW_MAX_FILES = 500
RAW_MAX_BYTES = 100 * 1024 * 1024
_SKIPPED_MODES = {"120000", "160000"}  # symlink, submodule


@dataclass
class RepoInfo:
    owner: str
    repo: str
    default_branch: str
    ref: str
    sha: str
    subpath: str
    private: bool
    size_kb: int
    files: int
    bytes: int
    truncated: bool
    has_submodules: bool
    blobs: list = field(default_factory=list, repr=False)  # (path, size, mode) under subpath

    @property
    def raw_strategy(self) -> bool:
        return bool(self.subpath) and not self.truncated and self.files <= RAW_MAX_FILES \
            and self.bytes <= RAW_MAX_BYTES


def _api_error(status: int, headers) -> ImportFailure:
    if status == 404:
        return ImportFailure("not_found")
    if status == 401:
        return ImportFailure("auth_failed")
    if status in (403, 429) and (headers.get("x-ratelimit-remaining") == "0" or status == 429):
        return ImportFailure("rate_limited")
    if status == 403:
        return ImportFailure("auth_failed")
    return ImportFailure("upstream_status", detail=str(status))


async def _json(fetcher, url, **kw):
    status, obj, headers = await fetcher.get_json(url, **kw)
    if status != 200 or obj is None:
        raise _api_error(status, headers)
    return obj


def _q(value: str) -> str:
    return urllib.parse.quote(value, safe="")


async def _commit_sha(fetcher, owner, repo, ref) -> Optional[str]:
    status, text, _final, headers = await fetcher.get_text(
        f"{API}/repos/{_q(owner)}/{_q(repo)}/commits/{urllib.parse.quote(ref, safe='/')}",
        max_bytes=4096, accept="application/vnd.github.sha")
    if status == 200 and SHA_RE.match(text.strip()):
        return text.strip()
    if status in (404, 422):
        return None
    raise _api_error(status, headers)


async def resolve_repo(fetcher, owner: str, repo: str, rest: str = "") -> RepoInfo:
    meta = await _json(fetcher, f"{API}/repos/{_q(owner)}/{_q(repo)}")
    default = str(meta.get("default_branch") or "main")
    segments = [s for s in (rest or "").split("/") if s]
    ref, sha, subpath = default, None, ""
    if segments:
        # A ref may itself hold slashes (feature/x): try the longest-plausible
        # prefixes, shortest first, at most 4 calls.
        for i in range(1, min(len(segments), MAX_REF_PROBES) + 1):
            candidate = "/".join(segments[:i])
            sha = await _commit_sha(fetcher, owner, repo, candidate)
            if sha:
                ref, subpath = candidate, "/".join(segments[i:])
                break
        if not sha:
            raise ImportFailure("ref_not_found")
    else:
        sha = await _commit_sha(fetcher, owner, repo, default)
        if not sha:
            raise ImportFailure("ref_not_found")

    try:
        tree = await _json(fetcher, f"{API}/repos/{_q(owner)}/{_q(repo)}/git/trees/{sha}?recursive=1",
                           max_bytes=TREE_MAX_BYTES)
        entries, truncated = tree.get("tree") or [], bool(tree.get("truncated"))
    except ImportFailure as e:
        if e.code != "too_large":
            raise
        entries, truncated = [], True
    prefix = subpath.rstrip("/") + "/" if subpath else ""
    if subpath and not truncated and not any(
            e.get("type") == "tree" and e.get("path") == subpath.rstrip("/") for e in entries):
        raise ImportFailure("invalid_subpath")
    blobs, files, nbytes = [], 0, 0
    has_submodules = False
    for e in entries:
        path = str(e.get("path") or "")
        if e.get("type") == "commit" or path == ".gitmodules" or path.endswith("/.gitmodules"):
            has_submodules = True
        if e.get("type") != "blob" or not path.startswith(prefix):
            continue
        files += 1
        nbytes += int(e.get("size") or 0)
        blobs.append((path, int(e.get("size") or 0), str(e.get("mode") or "")))
    return RepoInfo(owner=owner, repo=repo, default_branch=default, ref=ref, sha=sha, subpath=subpath.rstrip("/"),
                    private=bool(meta.get("private")), size_kb=int(meta.get("size") or 0), files=files,
                    bytes=nbytes, truncated=truncated, has_submodules=has_submodules, blobs=blobs)


def tarball_url(owner: str, repo: str, sha: str, *, with_token: bool) -> str:
    # The API endpoint takes the token (a private repository) and redirects to
    # codeload with a short-lived token of its own; codeload direct needs none.
    if with_token:
        return f"{API}/repos/{_q(owner)}/{_q(repo)}/tarball/{sha}"
    return f"https://codeload.github.com/{_q(owner)}/{_q(repo)}/tar.gz/{sha}"


def safe_relative(path: str) -> list[str]:
    """A tree path as safe segments, or unsafe_path for `..`/absolute/NUL."""
    parts = _normalize(path)
    if not parts:
        raise ImportFailure("unsafe_path")
    _check_lengths(parts)
    return parts


async def fetch_subpath_raw(fetcher, info: RepoInfo, dest: Path, *, max_bytes: int, max_entries: int,
                            progress: Optional[Callable[[int, int], None]] = None, cancel_event=None) -> dict:
    """Download every blob under info.subpath, 8 at a time, into `dest`.
    Symlinks and submodules are skipped; the totals are capped."""
    prefix = info.subpath + "/"
    jobs, skipped = [], []
    total_declared = 0
    for path, size, mode in info.blobs:
        rel = path[len(prefix):]
        if mode in _SKIPPED_MODES:
            skipped.append((rel, "link"))
            continue
        parts = safe_relative(rel)
        if any(p in RESERVED_NAMES for p in parts):
            skipped.append((rel, "reserved_name"))
            continue
        total_declared += size
        jobs.append((path, parts))
    if len(jobs) > max_entries:
        raise ImportFailure("too_many_entries")
    if total_declared > max_bytes:
        raise ImportFailure("too_large")

    sem = asyncio.Semaphore(RAW_PARALLEL)
    state = {"files": 0, "bytes": 0}

    async def one(path, parts):
        async with sem:
            if cancel_event is not None and cancel_event.is_set():
                raise ImportFailure("cancelled")
            target = dest.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o777)
            url = (f"https://raw.githubusercontent.com/{_q(info.owner)}/{_q(info.repo)}/{info.sha}/"
                   + "/".join(_q(p) for p in path.split("/")))
            got = await fetcher.download(url, target, max_bytes=max(1, max_bytes - state["bytes"]),
                                         cancel_event=cancel_event)
            state["files"] += 1
            state["bytes"] += got.bytes
            if state["bytes"] > max_bytes:
                raise ImportFailure("too_large")
            if progress is not None:
                progress(state["files"], state["bytes"])

    tasks = [asyncio.ensure_future(one(p, parts)) for p, parts in jobs]
    try:
        await asyncio.gather(*tasks)
    except BaseException:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return {"files": state["files"], "bytes": state["bytes"], "skipped": skipped}


async def gist_files(fetcher, gist_id: str) -> list[tuple[str, str, int]]:
    """(safe name, raw url, size) per file of a public gist."""
    meta = await _json(fetcher, f"{API}/gists/{_q(gist_id)}")
    out = []
    seen = set()
    for name, f in (meta.get("files") or {}).items():
        raw = str((f or {}).get("raw_url") or "")
        if not raw.startswith("https://"):
            continue
        safe = sanitize_name(name, "file")
        if safe in RESERVED_NAMES:
            safe = "_" + safe
        while safe in seen:
            safe = "_" + safe
        seen.add(safe)
        out.append((safe, raw, int((f or {}).get("size") or 0)))
    return out


async def fetch_gist(fetcher, gist_id: str, dest: Path, *, max_bytes: int, cancel_event=None) -> dict:
    files = await gist_files(fetcher, gist_id)
    total = 0
    for name, raw, _size in files:
        got = await fetcher.download(raw, dest / name, max_bytes=max(1, max_bytes - total), cancel_event=cancel_event)
        total += got.bytes
    return {"files": len(files), "bytes": total, "skipped": []}


def raw_file_url(parts: dict) -> str:
    """A /blob/ or raw link as its raw.githubusercontent.com URL."""
    if "path" in parts:
        return (f"https://raw.githubusercontent.com/{_q(parts['owner'])}/{_q(parts['repo'])}/"
                f"{urllib.parse.quote(parts['ref'], safe='/')}/{urllib.parse.quote(parts['path'], safe='/')}")
    return (f"https://raw.githubusercontent.com/{_q(parts['owner'])}/{_q(parts['repo'])}/"
            f"{urllib.parse.quote(parts['rest'], safe='/')}")
