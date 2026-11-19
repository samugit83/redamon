"""CVE archive lookups, always live (R-307): one CVE's file from the archive at each call.

A port of 1.x's ``_cve_lookup_detailed`` and ``_repo_readme`` onto the web boundary, with the
archive's own settings (§6.5, T4.2), which reach a read in the catalog's ``read_settings``:

- ``type.cve.pathPatterns``: the ordered paths a CVE's file may sit at, with ``{year}``,
  ``{cve}`` (``CVE-2023-1234``) and ``{cve_lower}``. The default is 1.x's two fixed paths. Each is
  read as a raw file on the archive's branch, so a pattern finds a CVE in a year folder of any
  size: GitHub lists at most 1,000 entries of a folder (AC-08);
- then the year folder's listing, as 1.x, on the same branch;
- ``type.cve.branch``: the branch to read (else the one ingestion recorded in the map, else
  ``main``);
- ``type.cve.readmeFallback``: off, a repository README that names the CVE is not an answer.

The GitHub token goes to the archive's own repository only (``fetch.repo_token``), a file a listing
names included. A file the person blocked in the archive's Map is never requested (``blocked``),
whichever step names it.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Awaitable, Callable, Optional

from tradecraft.ingest import fetch
from tradecraft.settings import EffectiveSettings, constant

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE | re.ASCII)
# A CVE's file and the README are pages, read live into the agent process every run shares: they
# stop at a page's ceiling, as ingestion's pages do. A year folder's listing is an index answer.
FILE_MAX_BYTES = fetch.PAGE_MAX_BYTES
LISTING_MAX_BYTES = int(constant("sitemapMaxBytes"))
# ``lookup``'s error when the only files that would answer are blocked: not "no PoC", a refusal.
BLOCKED = "page_blocked"
_RAW = {"Accept": "application/vnd.github.raw"}
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
PLACEHOLDERS = ("year", "cve", "cve_lower")


def _api_error(status: int, error: str) -> str:
    return error or f"github_http_{status}"


def repo_url(meta: dict) -> str:
    """The archive's repository page, from its map's owner and repo; "" when the map names none."""
    owner, repo = (meta or {}).get("owner"), (meta or {}).get("repo")
    return f"https://github.com/{owner}/{repo}" if owner and repo else ""


def pattern_path(pattern: str, cve_id: str) -> Optional[str]:
    """The path ``pattern`` names for ``cve_id``, or None for a pattern that is not a relative
    path inside the repository or uses another placeholder. Placeholders are replaced, never
    formatted, so a pattern cannot reach anything but these three values."""
    if not CVE_ID_RE.match(cve_id or ""):
        return None
    cve = cve_id.upper()
    names = _PLACEHOLDER.findall(pattern or "")
    if not names or any(n not in PLACEHOLDERS for n in names) or not ({"cve", "cve_lower"} & set(names)):
        return None
    path = pattern.strip()
    for name, value in (("year", cve.split("-")[1]), ("cve", cve), ("cve_lower", cve.lower())):
        path = path.replace("{" + name + "}", value)
    segments = path.split("/")
    if (path.startswith("/") or "://" in path or "\\" in path or "{" in path or "}" in path
            or any(s in ("", ".", "..") for s in segments)):
        return None
    return path


def branch_of(meta: dict, settings: EffectiveSettings) -> str:
    return settings.str("type.cve.branch").strip() or str(meta.get("branch") or "") or "main"


def _quoted(value: str) -> str:
    return "/".join(urllib.parse.quote(seg, safe="") for seg in value.split("/"))


def raw_url(owner: str, repo: str, branch: str, path: str) -> str:
    """The raw file's URL. The branch is encoded as the path is: the repository's owner names it,
    and a ``#`` or ``?`` in it would cut the URL (entries of one archive would share it)."""
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{_quoted(branch)}/{_quoted(path)}"


async def lookup(cve_id: str, meta: dict, settings: EffectiveSettings, *, github_token: Optional[str] = None,
                 blocked: Optional[Callable[[str], Awaitable[bool]]] = None) -> tuple[str, str, str]:
    """(text, source URL, error code). An error code means GitHub did not answer (a limit, an
    outage), or ``BLOCKED`` that every file found for the CVE is blocked: not a "no PoC" answer.
    ``blocked(url)`` is asked before each file is requested."""
    if not CVE_ID_RE.match(cve_id or ""):
        return "", "", ""
    owner, repo = meta.get("owner"), meta.get("repo")
    if not (owner and repo):
        return "", "", ""
    cve = cve_id.upper()
    year = cve.split("-")[1]
    branch = branch_of(meta, settings)
    api_error = ""
    refused = False
    for pattern in settings.list("type.cve.pathPatterns"):
        path = pattern_path(pattern, cve)
        if path is None:
            continue
        url = raw_url(str(owner), str(repo), branch, path)
        if blocked is not None and await blocked(url):
            refused = True
            continue
        resp = await fetch.fetch_raw(url, settings, github_token=github_token, max_bytes=FILE_MAX_BYTES)
        if resp.status == 200 and resp.body:
            return resp.text, url, ""
        if resp.status not in (200, 404) and not api_error:
            api_error = _api_error(resp.status, resp.error)
    ref = f"?ref={urllib.parse.quote(branch, safe='')}" if settings.str("type.cve.branch").strip() else ""
    listing = await fetch.fetch_raw(f"https://api.github.com/repos/{owner}/{repo}/contents/{year}{ref}", settings,
                                    github_token=github_token, max_bytes=LISTING_MAX_BYTES)
    if listing.status == 200 and not listing.truncated:
        try:
            items = json.loads(listing.text)
        except ValueError:
            items = []
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict) and cve in str(it.get("name", "")).upper() and it.get("download_url"):
                dl = str(it["download_url"])
                if not fetch.entry_url_ok(dl):
                    continue
                # A block is on the archive's own URL for the file, as its entry stores it: GitHub's
                # download_url spells the repository its own way (another case, a new name).
                own = raw_url(str(owner), str(repo), branch, str(it.get("path") or f"{year}/{it['name']}"))
                if blocked is not None and await blocked(own):
                    refused = True
                    continue
                got = await fetch.fetch_raw(dl, settings, max_bytes=FILE_MAX_BYTES,
                                            github_token=fetch.repo_token(dl, github_token, repo_url(meta)))
                if got.status == 200:
                    return got.text, dl, ""
    elif listing.status != 404 and not api_error:
        api_error = _api_error(listing.status, listing.error)
    return "", "", BLOCKED if refused else api_error


async def readme(meta: dict, settings: EffectiveSettings, *, github_token: Optional[str] = None) -> tuple[str, str]:
    """(README text, its page URL) of the repository, or ("", "") also when the archive turns
    the README fallback off."""
    owner, repo = meta.get("owner"), meta.get("repo")
    if not (owner and repo) or not settings.bool("type.cve.readmeFallback"):
        return "", ""
    ref = f"?ref={urllib.parse.quote(branch_of(meta, settings), safe='')}" if settings.str("type.cve.branch").strip() else ""
    resp = await fetch.fetch_raw(f"https://api.github.com/repos/{owner}/{repo}/readme{ref}", settings,
                                 github_token=github_token, headers=_RAW, max_bytes=FILE_MAX_BYTES)
    if resp.status == 200 and resp.body:
        return resp.text, f"https://github.com/{owner}/{repo}#readme"
    return "", ""
