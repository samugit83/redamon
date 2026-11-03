"""Inspect a URL before importing it: what it is, its size, its warnings.

The preview route and the import job both call inspect(); the job never
trusts what the browser was shown.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

from orchestrator_helpers.hard_guardrail import is_hard_blocked
from workspace_import import github
from workspace_import.detect import (
    FORGE_KINDS, MIRROR_KINDS, Classified, classify_probe, classify_url, is_html, suggested_name,
)
from workspace_import.errors import ImportFailure
from workspace_import.forges import resolve_forge
from workspace_import.redact import redact_url

LARGE_DOWNLOAD_BYTES = 500 * 1024 * 1024


@dataclass
class Inspection:
    url: str
    kind: str
    parts: dict
    name: str
    host: str
    details: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    repo: Optional[github.RepoInfo] = None
    forge: Any = None
    probe: Any = None
    # Every kind this version detects can be imported; the field stays for a
    # kind that could only be previewed.
    supported: bool = True

    def answer(self) -> dict:
        return {"kind": self.kind, "url": redact_url(self.url), "suggestedName": self.name, "host": self.host,
                "details": self.details, "warnings": self.warnings, "supported": self.supported}


def url_host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


async def inspect(url: str, fetcher, *, subpath: Optional[str] = None) -> Inspection:
    cls: Classified = classify_url(url)
    kind, parts, host = cls.kind, cls.parts, url_host(url)

    if kind == "github-repo":
        rest = parts.get("rest", "")
        info = await github.resolve_repo(fetcher, parts["owner"], parts["repo"], rest)
        if subpath is not None and subpath.strip("/") != info.subpath:
            # The dialog lets the user change the subfolder of the preview.
            info = await github.resolve_repo(fetcher, parts["owner"], parts["repo"],
                                             "/".join(p for p in (info.ref, subpath.strip("/")) if p))
        warnings = ["history_not_included"]
        if info.truncated:
            warnings.append("tree_truncated")
        if info.bytes > LARGE_DOWNLOAD_BYTES or (info.truncated and info.size_kb * 1024 > LARGE_DOWNLOAD_BYTES):
            warnings.append("large_download")
        if info.has_submodules:
            warnings.append("submodules_not_included")
        return Inspection(url, kind, parts, suggested_name(kind, parts, subpath=info.subpath), host,
                          details={"ref": info.ref, "sha7": info.sha[:7], "files": info.files, "bytes": info.bytes,
                                   "subpath": info.subpath, "private": info.private},
                          warnings=warnings, repo=info)

    if kind == "github-gist":
        files = await github.gist_files(fetcher, parts["id"])
        return Inspection(url, kind, parts, suggested_name(kind, parts), host,
                          details={"files": len(files), "bytes": sum(f[2] for f in files)})

    if kind in FORGE_KINDS:
        info = await resolve_forge(fetcher, kind, parts)
        return Inspection(url, kind, parts, suggested_name(kind, parts), host,
                          details={"ref": info.ref, "private": info.private},
                          warnings=["history_not_included"], forge=info)

    if kind == "git":
        return Inspection(url, kind, parts, suggested_name(kind, parts), host,
                          warnings=["history_not_included", "submodules_not_included"])

    if kind is None or kind in MIRROR_KINDS:
        # A site root is almost surely a site: refuse a protected host without
        # sending it even the classification probe.
        if (urllib.parse.urlsplit(url).path or "/") == "/" and is_hard_blocked(host)[0]:
            raise ImportFailure("hard_blocked")
    target = github.raw_file_url(parts) if kind == "github-file" else url
    probe = await fetcher.probe(target)
    if probe.status == 404:
        raise ImportFailure("not_found")
    if not 200 <= probe.status < 300:
        raise ImportFailure("upstream_status", detail=str(probe.status))
    content_type = (probe.headers.get("content-type") or "").split(";")[0].strip().lower()
    if kind == "archive" and is_html(content_type, probe.head):
        # An archive link that answers a page is a login or error page.
        raise ImportFailure("unexpected_html")
    if kind is None:
        kind = classify_probe(url, probe)
    if kind in MIRROR_KINDS:
        return _mirror_inspection(url, kind, parts, host, probe)
    from workspace_import.fetch import disposition_filename
    disposition = disposition_filename(probe.headers.get("content-disposition"))
    length = probe.headers.get("content-length", "")
    details = {"contentType": content_type}
    if length.isdigit():
        details["bytes"] = int(length)
    warnings = ["large_download"] if length.isdigit() and int(length) > LARGE_DOWNLOAD_BYTES else []
    return Inspection(url, kind, parts, suggested_name(kind, parts, url=url, final_url=probe.final_url,
                                                       disposition=disposition), host,
                      details=details, warnings=warnings, probe=probe)


def _mirror_inspection(url: str, kind: str, parts: dict, host: str, probe) -> Inspection:
    """A website or documentation site: the scope the crawl will keep to and
    the kind's default options. A protected host (at the link or after its
    redirects) is refused here, before any crawl."""
    from workspace_import.mirror import DEFAULTS

    final = probe.final_url or url
    final_host = url_host(final)
    if is_hard_blocked(host)[0] or is_hard_blocked(final_host)[0]:
        raise ImportFailure("hard_blocked")
    path = urllib.parse.urlsplit(final).path or "/"
    details = {"scopeHost": final_host, "scopePath": path[: path.rfind("/") + 1] or "/",
               "defaults": dict(DEFAULTS[kind])}
    return Inspection(url, kind, parts, suggested_name(kind, parts, url=url, final_url=final), host,
                      details=details, probe=probe)
