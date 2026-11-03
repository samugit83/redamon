"""Failure codes for workspace uploads and URL imports.

Every expected failure is a code with a fixed sentence. Exception text never
reaches a response, a job's meta or the log: it can carry paths, URLs with
temporary tokens in their query, or an upstream's own words.

Stdlib only: workspace_fs imports busy.py, which imports this module.
"""
from __future__ import annotations

import errno
from typing import Optional

CODES: dict[str, tuple[int, str]] = {
    "invalid_request": (400, "The request is not valid."),
    "internal_error": (500, "Something went wrong on the server. Check the agent log."),
    "not_found": (404, "Not found."),
    "cancelled": (409, "The operation was cancelled."),
    "busy": (409, "A running import is replacing this folder. Retry when it finishes."),
    # Archives
    "unsafe_path": (422, "The archive holds a path that leaves its folder (absolute, '..' or NUL)."),
    "too_deep": (422, "The archive nests folders more than 64 levels deep."),
    "name_too_long": (422, "The archive holds a name longer than 255 bytes, or a path longer than 4096 bytes."),
    "too_many_entries": (413, "The archive holds more entries than the server allows."),
    "too_large": (413, "The content is larger than the server allows."),
    "conflicting_entries": (422, "The archive holds a file and a folder with the same path."),
    "unsupported_archive": (422, "The file is not a zip, tar, tar.gz, tar.bz2, tar.xz or gz archive."),
    "corrupt_archive": (422, "The archive is damaged or truncated."),
    "empty_archive": (422, "The archive holds nothing to extract."),
    # Disk and placement
    "insufficient_storage": (413, "Not enough free disk space on the server for this operation."),
    "protected_path": (403, "That folder is part of the workspace layout and cannot be replaced."),
    "conflict_type": (409, "A file and a folder cannot replace each other."),
    "name_exhausted": (409, "Too many entries with that name already exist in the folder."),
    "exists": (409, "An entry with that name already exists in the folder."),
    "destination_missing": (409, "The destination folder no longer exists."),
    # Upload sessions and jobs
    "too_many_uploads": (429, "This project already has 4 uploads in progress. Wait for one to finish."),
    "session_not_found": (404, "The upload session does not exist (the workspace was reset or the agent restarted)."),
    "offset_mismatch": (409, "The chunk does not continue the upload where it stands."),
    "chunk_overflow": (400, "The chunk goes past the declared size of the upload."),
    "chunk_too_large": (413, "The chunk is larger than the server accepts."),
    "session_incomplete": (409, "The upload is not complete yet."),
    "too_many_jobs": (429, "Too many uploads and imports are running on the server. Retry shortly."),
    "project_deleted": (409, "The project was deleted."),
    "settings_unavailable": (503, "The project could not be checked with the web app. Retry shortly."),
    "project_exists": (409, "The project still exists; its workspace was not purged."),
    # Fetching
    "unsupported_scheme": (400, "Only http and https links can be imported."),
    "credentials_in_url": (400, "The link holds a user name or password. Remove it; private GitHub repositories use the GitHub token in Global Settings."),
    "invalid_url": (400, "The link is not a valid URL."),
    "blocked_address": (403, "The link points at a private, internal or metadata address. Only public internet addresses can be imported."),
    "dns_failed": (422, "The link's host name does not resolve."),
    "timeout": (422, "The source did not answer in time."),
    "network_error": (422, "The source could not be reached."),
    "too_many_redirects": (422, "The link redirects more than 5 times."),
    "upstream_status": (422, "The source answered with an error."),
    # URL import
    "import_disabled": (403, "URL import is turned off on this server."),
    "kind_not_supported": (422, "This page cannot be imported. Link a repository, a folder, a file, a gist, an archive or a website."),
    "rate_limited": (429, "GitHub's hourly rate limit for this server is used up. A GitHub token in Global Settings > API Keys lifts it."),
    "auth_failed": (403, "GitHub refused the token: it may be expired or revoked."),
    "ref_not_found": (404, "The branch, tag or commit in the link does not exist."),
    "invalid_subpath": (404, "The folder in the link does not exist in that branch."),
    "unexpected_html": (422, "The link answered with a web page where a file or an archive was expected (often a login or error page). Nothing was saved."),
    "too_many_imports": (429, "This project already has 2 imports running. Wait for one to finish."),
    "not_imported": (404, "This folder has no valid import record, so it cannot be re-synced."),
    "not_resyncable": (422, "This import cannot be re-synced: its link had a query string, which is not stored."),
    "redirect_refused": (422, "The git server redirected the clone, which is not allowed."),
    "git_failed": (422, "The git clone failed."),
}


class ImportFailure(Exception):
    """An expected failure, carried as a code.

    `detail` is for the server log only (already redacted by the caller); it
    never goes into a response.
    """

    def __init__(self, code: str, *, status: Optional[int] = None, detail: str = ""):
        if code not in CODES:
            raise ValueError(f"unknown workspace import code: {code}")
        super().__init__(code)
        self.code = code
        self.status = status or CODES[code][0]
        self.detail = detail

    def __str__(self) -> str:
        return self.code


def error_body(code: str, **extra) -> dict:
    """The JSON body of a failed request: the fixed sentence plus the code."""
    status_sentence = CODES.get(code) or CODES["internal_error"]
    body = {"error": status_sentence[1], "code": code if code in CODES else "internal_error"}
    body.update(extra)
    return body


def status_for(code: str) -> int:
    return (CODES.get(code) or CODES["internal_error"])[0]


_DISK_FULL_ERRNOS = {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}


def map_os_error(e: BaseException) -> Optional[ImportFailure]:
    """A full disk or quota is the user's to fix, so it gets its own code;
    every other OSError is the caller's internal_error."""
    if isinstance(e, OSError) and e.errno in _DISK_FULL_ERRNOS:
        return ImportFailure("insufficient_storage")
    return None
