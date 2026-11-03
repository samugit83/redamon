"""GitLab.com, Bitbucket.org and Codeberg.org: default branch and archive URL.

Endpoints as checked by experiment E2 (2026-11-03). No tokens are sent to any
forge in this version, so a private repository there is `not_found`.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from workspace_import.errors import ImportFailure


@dataclass
class ForgeInfo:
    host: str
    project: str
    ref: str
    archive_url: str
    private: bool


def _q(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def metadata_url(kind: str, parts: dict) -> str:
    project = parts["project"]
    if kind == "gitlab-repo":
        return f"https://gitlab.com/api/v4/projects/{_q(project)}"
    owner, repo = project.split("/", 1)
    if kind == "bitbucket-repo":
        return f"https://api.bitbucket.org/2.0/repositories/{_q(owner)}/{_q(repo)}"
    if kind == "codeberg-repo":
        return f"https://codeberg.org/api/v1/repos/{_q(owner)}/{_q(repo)}"
    raise ImportFailure("kind_not_supported")


def archive_url(kind: str, parts: dict, meta: dict, ref: str) -> str:
    project = parts["project"]
    if kind == "gitlab-repo":
        return f"https://gitlab.com/api/v4/projects/{int(meta['id'])}/repository/archive.tar.gz?sha={_q(ref)}"
    owner, repo = project.split("/", 1)
    if kind == "bitbucket-repo":
        return f"https://bitbucket.org/{_q(owner)}/{_q(repo)}/get/{_q(ref)}.tar.gz"
    return f"https://codeberg.org/{_q(owner)}/{_q(repo)}/archive/{_q(ref)}.tar.gz"


def default_branch(kind: str, meta: dict) -> str:
    if kind == "bitbucket-repo":
        return str((meta.get("mainbranch") or {}).get("name") or "")
    return str(meta.get("default_branch") or "")


def is_private(kind: str, meta: dict) -> bool:
    if kind == "bitbucket-repo":
        return bool(meta.get("is_private"))
    if kind == "gitlab-repo":
        return meta.get("visibility") not in (None, "public")
    return bool(meta.get("private"))


async def resolve_forge(fetcher, kind: str, parts: dict) -> ForgeInfo:
    status, meta, _headers = await fetcher.get_json(metadata_url(kind, parts))
    if status in (401, 403, 404):
        raise ImportFailure("not_found")
    if status == 429:
        raise ImportFailure("rate_limited")
    if status != 200 or not isinstance(meta, dict):
        raise ImportFailure("upstream_status", detail=str(status))
    ref = default_branch(kind, meta)
    if not ref or (kind == "gitlab-repo" and "id" not in meta):
        raise ImportFailure("ref_not_found")
    host = urllib.parse.urlsplit(metadata_url(kind, parts)).hostname or ""
    return ForgeInfo(host=host.replace("api.", "", 1) if host.startswith("api.") else host,
                     project=parts["project"], ref=ref,
                     archive_url=archive_url(kind, parts, meta, ref), private=is_private(kind, meta))
