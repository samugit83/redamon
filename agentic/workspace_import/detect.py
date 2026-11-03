"""What a URL points at: decided from the URL alone where possible, otherwise
from one probe (the first 64 KiB, headers and file signatures)."""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from workspace_import.errors import ImportFailure
from workspace_import.names import sanitize_name

REPO_KINDS = ("github-repo", "gitlab-repo", "bitbucket-repo", "codeberg-repo", "git")
FORGE_KINDS = ("gitlab-repo", "bitbucket-repo", "codeberg-repo")
MIRROR_KINDS = ("docs-site", "website")
ALL_KINDS = REPO_KINDS + ("github-file", "github-gist", "archive", "file") + MIRROR_KINDS

# A forge listed here is imported with a shallow git clone instead of its
# archive endpoint. Experiment E2 (2026-11-03) found all three archive
# endpoints working, so none is.
FORGE_FALLBACK_TO_GIT: frozenset = frozenset()

ARCHIVE_EXTS = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz", ".tar", ".zip", ".gz")
_ARCHIVE_TYPES = {
    "application/zip", "application/x-zip-compressed", "application/gzip", "application/x-gzip",
    "application/x-tar", "application/x-gtar", "application/x-tar-gz", "application/x-bzip2",
    "application/x-xz", "application/x-compressed-tar",
}
_HTML_TYPES = ("text/html", "application/xhtml+xml")
_GITHUB_HOSTS = ("github.com", "www.github.com")
_GIST_ID = re.compile(r"^[0-9a-fA-F]{6,64}$")


@dataclass
class Classified:
    kind: Optional[str]
    parts: dict = field(default_factory=dict)


def archive_ext(name: str) -> str:
    lower = (name or "").lower()
    for ext in ARCHIVE_EXTS:
        if lower.endswith(ext):
            return ext
    return ""


def _segments(path: str) -> list[str]:
    return [urllib.parse.unquote(p) for p in path.split("/") if p]


def _github(parts: list[str]) -> Classified:
    if len(parts) < 2:
        raise ImportFailure("kind_not_supported")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    base = {"owner": owner, "repo": repo}
    if len(parts) == 2:
        return Classified("github-repo", dict(base, rest=""))
    section = parts[2]
    if section == "tree":
        return Classified("github-repo", dict(base, rest="/".join(parts[3:])))
    if section == "blob" and len(parts) >= 5:
        return Classified("github-file", dict(base, rest="/".join(parts[3:])))
    if section == "archive" and archive_ext(parts[-1]):
        return Classified("archive", base)
    if section == "releases" and len(parts) >= 6 and parts[3] == "download":
        return Classified("archive" if archive_ext(parts[-1]) else "file", base)
    # issues, pulls, wiki, actions, a user page...: nothing to import
    raise ImportFailure("kind_not_supported")


def classify_url(url: str) -> Classified:
    """The kind from the URL alone, or kind None when only a probe can tell.
    Refuses non-http(s) schemes, credentials in the URL and a missing host."""
    try:
        u = urllib.parse.urlsplit((url or "").strip())
        host = (u.hostname or "").lower()
    except ValueError:
        raise ImportFailure("invalid_url") from None
    if u.scheme.lower() not in ("http", "https"):
        raise ImportFailure("unsupported_scheme")
    if "@" in u.netloc:
        raise ImportFailure("credentials_in_url")
    if not host:
        raise ImportFailure("invalid_url")
    parts = _segments(u.path)

    if host in _GITHUB_HOSTS:
        return _github(parts)
    if host == "raw.githubusercontent.com":
        if len(parts) < 4:
            raise ImportFailure("kind_not_supported")
        return Classified("github-file", {"owner": parts[0], "repo": parts[1], "ref": parts[2],
                                          "path": "/".join(parts[3:])})
    if host == "gist.github.com":
        gist_id = parts[-1] if parts else ""
        if len(parts) in (1, 2) and _GIST_ID.match(gist_id):
            return Classified("github-gist", {"id": gist_id.lower()})
        raise ImportFailure("kind_not_supported")
    if host in ("gitlab.com", "bitbucket.org", "codeberg.org"):
        kind = {"gitlab.com": "gitlab-repo", "bitbucket.org": "bitbucket-repo", "codeberg.org": "codeberg-repo"}[host]
        # GitLab puts tree/blob after "/-/"; a group can nest (group/sub/project).
        if kind == "gitlab-repo":
            repo_parts = parts[: parts.index("-")] if "-" in parts else parts
        else:
            repo_parts = parts[:2]
        if len(repo_parts) < 2:
            raise ImportFailure("kind_not_supported")
        repo_parts = repo_parts[:-1] + [repo_parts[-1].removesuffix(".git")]
        if kind in FORGE_FALLBACK_TO_GIT:
            return Classified("git", {"repo": repo_parts[-1]})
        return Classified(kind, {"project": "/".join(repo_parts), "owner": repo_parts[0], "repo": repo_parts[-1]})
    last = parts[-1] if parts else ""
    if last.lower().endswith(".git"):
        return Classified("git", {"repo": last[:-4]})
    if archive_ext(last):
        return Classified("archive", {})
    return Classified(None, {})


def _looks_like_html(head: bytes) -> bool:
    start = head.lstrip()[:256].lower()
    return start.startswith(b"<!doctype html") or start.startswith(b"<html") or b"<html" in start[:100]


def is_html(content_type: str, head: bytes) -> bool:
    ct = (content_type or "").split(";")[0].strip().lower()
    return ct in _HTML_TYPES or _looks_like_html(head)


def _magic_archive(head: bytes) -> bool:
    return (head[:4] in (b"PK\x03\x04", b"PK\x05\x06") or head[:2] == b"\x1f\x8b"
            or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00"
            or (len(head) >= 262 and head[257:262] == b"ustar"))


def classify_probe(url: str, probe) -> str:
    """archive | file | docs-site | website, from one probe's headers and head."""
    from workspace_import.fetch import disposition_filename

    disposition = disposition_filename(probe.headers.get("content-disposition"))
    if disposition:
        if archive_ext(disposition):
            return "archive"
        if disposition.lower().endswith(".pdf"):
            return "file"
    ct = (probe.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ct in _ARCHIVE_TYPES:
        return "archive"
    if ct == "application/pdf" or probe.head[:5] == b"%PDF-":
        return "file"
    if _magic_archive(probe.head):
        return "archive"
    if is_html(ct, probe.head):
        from orchestrator_helpers.tradecraft_lookup import detect_type
        text = probe.head.decode("utf-8", "replace")
        tc_type = detect_type(probe.final_url or url, text, probe.status)
        return "docs-site" if tc_type in ("mkdocs-wiki", "sphinx-docs", "gitbook") else "website"
    return "file"


def _last_segment(url: str) -> str:
    try:
        parts = _segments(urllib.parse.urlsplit(url).path)
    except ValueError:
        return ""
    return parts[-1] if parts else ""


def suggested_name(kind: str, parts: dict, *, url: str = "", final_url: str = "", disposition: str = "",
                   subpath: str = "") -> str:
    if kind == "github-repo":
        return sanitize_name(subpath.rstrip("/").split("/")[-1] if subpath else parts.get("repo"), "repository")
    if kind == "github-file":
        return sanitize_name((parts.get("rest") or parts.get("path") or "").split("/")[-1], "file")
    if kind == "github-gist":
        return sanitize_name(f"gist-{parts.get('id', '')[:8]}", "gist")
    if kind in REPO_KINDS:
        return sanitize_name(parts.get("repo"), "repository")
    name = disposition or _last_segment(final_url or url)
    if kind == "archive":
        ext = archive_ext(name)
        return sanitize_name(name[: -len(ext)] if ext else name, "archive")
    if kind in MIRROR_KINDS:
        return mirror_name(final_url or url)
    return sanitize_name(name, "download")


def mirror_name(url: str) -> str:
    """The host, or host-<first path segment> when the site sits under a folder."""
    u = urllib.parse.urlsplit(url)
    host = (u.hostname or "site").lower()
    directory = u.path[: u.path.rfind("/") + 1] if "/" in u.path else "/"
    segs = [s for s in directory.split("/") if s]
    return sanitize_name(f"{host}-{segs[0]}" if segs else host, "site")
