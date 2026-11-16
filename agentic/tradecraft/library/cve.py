"""CVE archive lookups, always live (R-307): one CVE's file from the archive at each call.

A port of 1.x's ``_cve_lookup_detailed`` and ``_repo_readme`` onto the web boundary: the
fixed paths ``{year}/{CVE}.md`` and ``{year}/{CVE}/README.md`` through the GitHub contents
API, then the year's listing; a repository whose README names the CVE answers with it. The
GitHub token goes to GitHub hosts only. Patterns per resource arrive with T4.2.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from tradecraft.ingest import fetch
from tradecraft.settings import EffectiveSettings

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_RAW = {"Accept": "application/vnd.github.raw"}


def _api_error(status: int, error: str) -> str:
    return error or f"github_http_{status}"


async def lookup(cve_id: str, meta: dict, settings: EffectiveSettings, *,
                 github_token: Optional[str] = None) -> tuple[str, str, str]:
    """(text, source URL, error code). An error code means GitHub did not answer (a limit, an
    outage): not a "no PoC" answer."""
    if not CVE_ID_RE.match(cve_id or ""):
        return "", "", ""
    owner, repo, branch = meta.get("owner"), meta.get("repo"), meta.get("branch") or "main"
    if not (owner and repo):
        return "", "", ""
    cve = cve_id.upper()
    year = cve.split("-")[1]
    api_error = ""
    for path in (f"{year}/{cve}.md", f"{year}/{cve}/README.md"):
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        resp = await fetch.fetch_raw(url, settings, github_token=github_token, headers=_RAW)
        if resp.status == 200 and resp.body:
            return resp.text, url, ""
        if resp.status not in (200, 404) and not api_error:
            api_error = _api_error(resp.status, resp.error)
    listing = await fetch.fetch_raw(f"https://api.github.com/repos/{owner}/{repo}/contents/{year}", settings,
                                    github_token=github_token)
    if listing.status == 200:
        try:
            items = json.loads(listing.text)
        except ValueError:
            items = []
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict) and cve in str(it.get("name", "")).upper() and it.get("download_url"):
                dl = str(it["download_url"])
                if not fetch.entry_url_ok(dl):
                    continue
                got = await fetch.fetch_raw(dl, settings, github_token=github_token)
                if got.status == 200:
                    return got.text, dl, ""
    elif listing.status != 404 and not api_error:
        api_error = _api_error(listing.status, listing.error)
    return "", "", api_error


async def readme(meta: dict, settings: EffectiveSettings, *, github_token: Optional[str] = None) -> tuple[str, str]:
    """(README text, its page URL) of the repository, or ("", "")."""
    owner, repo = meta.get("owner"), meta.get("repo")
    if not (owner and repo):
        return "", ""
    resp = await fetch.fetch_raw(f"https://api.github.com/repos/{owner}/{repo}/readme", settings,
                                 github_token=github_token, headers=_RAW)
    if resp.status == 200 and resp.body:
        return resp.text, f"https://github.com/{owner}/{repo}#readme"
    return "", ""
