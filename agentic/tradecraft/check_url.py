"""Check URL (§6.3, T4.1): what a URL is, before a resource is saved. No model is called and
nothing is written (AC-09): this module imports neither the page store nor a model builder.

In order: the URL's own problems, the start page (the address guard on every hop, as every
fetch here, through ``net``), the type (a forced type is honoured, a PDF is told by its
content, a thin page is a website as ingestion would crawl it), the type's index through the
same code ingestion uses (a sitemap, including one a ``Sitemap:`` line of robots.txt names; the
GitHub tree with its default branch, first page of branches and tags, top-level folders; the
Sphinx search index; the PDF's page count), whether the page needs the browser, whether
robots.txt allows crawling, the recommended storage mode and an estimated size (the index's
count times the average of at most 3 sampled pages), and, for a CVE archive, the first path
pattern that finds a CVE id the archive's README or first listing names.

The router ends the call at the contract's deadline (``contract.DEADLINES_SEC["check_url"]``)
with ``timeout``. A request's ``type_options`` are read as the spec's ``type.*`` settings.
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from typing import Any, Callable, Optional

from logging_config import get_logger
from orchestrator_helpers.web_sources import split_github_url
from tradecraft import net
from tradecraft.contract import CheckUrlRequest, CheckUrlResult, GithubInfo, IndexInfo, SampleEntry
from tradecraft.ingest import builders, crawl, fetch, robots
from tradecraft.ingest.builders import Candidate
from tradecraft.ingest.detect import WEBSITE, detect
from tradecraft.library import cve
from tradecraft.settings import EffectiveSettings, constant

logger = get_logger(__name__)

MB = 1024 * 1024
SAMPLED_PAGES = 3
# The path patterns a CVE archive is probed with, in this order (§6.5); a lookup reads the
# one proposed exactly the same way (``library.cve``).
CVE_PATTERNS = (
    "{year}/{cve}.md", "{year}/{cve}.json", "{year}/{cve}/README.md",
    "{year}/{cve_lower}.md", "{year}/{cve_lower}.json", "{year}/{cve_lower}/README.md",
)
# CVE ids tried per pattern: enough to get past an id the README names but the archive lacks.
CVE_PROBE_IDS = 3
_CVE_RE = re.compile(r"CVE-(\d{4})-\d{4,7}", re.IGNORECASE)
_YEAR_DIR = re.compile(r"(?:19|20)\d{2}")
# The start page's problems that end a check; a thin page is a website, as ingestion reads it.
_FATAL = ("blocked_private_address", "userinfo_refused", "bad_url", "timeout", "fetch_failed", "homepage_http_error")


async def _thread(fn: Callable[..., Any], *args: Any) -> Any:
    # XML, HTML and PDF parsing runs off the API's event loop, as a job's does on its pool.
    return await asyncio.to_thread(fn, *args)


def _settings(request: CheckUrlRequest) -> EffectiveSettings:
    return EffectiveSettings({**request.settings, **request.type_options})


def _with(settings: EffectiveSettings, values: dict[str, Any]) -> EffectiveSettings:
    return EffectiveSettings({**settings.values, **values})


async def check_url(request: CheckUrlRequest) -> CheckUrlResult:
    url = request.url.strip()
    problem = net.url_problem(url)
    if problem:
        return CheckUrlResult(ok=False, error_code=problem)
    settings = _settings(request)
    token = request.secrets.github_token
    login = request.secrets.credentials is not None and not request.secrets.credentials.is_empty()
    # §5: a resource with a login never uses the browser; Check URL still says when it would need it.
    home = await fetch.smart_fetch(url, settings, github_token=token, allow_browser=not login)
    problem = fetch.homepage_problem(home, settings)
    if problem in _FATAL:
        logger.info(f"[tradecraft] check_url code={problem}")
        return CheckUrlResult(ok=False, error_code=problem, final_url=_url_or_empty(home.final_url))

    if request.forced_type:
        site_type = request.forced_type
    elif home.is_pdf:
        site_type = "pdf"
    elif problem:
        site_type = WEBSITE
    else:
        site_type = detect(url, home.html, home.status, settings)

    robots_txt = await robots.read(url, settings)
    result = CheckUrlResult(
        ok=True,
        final_url=_url_or_empty(home.final_url or url),
        needs_browser=_needs_browser(home, settings),
        robots_allows=robots_txt.allows(url, settings.str("fetching.userAgent")),
    )
    if site_type == "pdf":
        await _pdf(result, url, home, settings)
    elif site_type in ("github-repo", "cve-poc-db"):
        site_type = await _github(result, url, site_type, settings, token, forced=bool(request.forced_type))
    elif site_type == WEBSITE:
        await _website(result, url, robots_txt, settings, token)
    else:
        await _known(result, url, site_type, home, settings, token, allow_browser=not login)
    result.detected_type = site_type
    result.recommended_storage = recommended_storage(site_type, result, settings)
    logger.info(f"[tradecraft] check_url code= type={site_type} entries={result.index.count if result.index else 0}")
    return CheckUrlResult.model_validate(result.model_dump())


def _url_or_empty(url: str) -> str:
    return url if url and len(url) <= 2048 else ""


def _needs_browser(home: fetch.FetchedPage, settings: EffectiveSettings) -> bool:
    """The page came from the browser, or its plain text is under the browser threshold (the
    browser being off, or refused for a login, does not change what the page needs)."""
    if home.is_pdf:
        return False
    if home.tier == 2:
        return True
    return len(home.text or "") < settings.int("fetching.browserBelowChars")


def recommended_storage(site_type: str, result: CheckUrlResult, settings: EffectiveSettings) -> str:
    """§4.5's table: a website, a GitHub repository and a PDF are Stored; a CVE archive Live; a
    wiki, a GitBook or a docs site Stored when it fits the per-resource limits, else Live."""
    if site_type == "cve-poc-db":
        return "live"
    if site_type in ("pdf", "github-repo", WEBSITE):
        return "stored"
    count = result.index.count if result.index else 0
    fits = (0 < count <= settings.int("storage.maxPages") and 0 < result.estimated_bytes
            <= settings.int("storage.maxResourceMb") * MB)
    return "stored" if fits else "live"


def _samples(entries: list[Candidate]) -> list[SampleEntry]:
    out = []
    for e in entries:
        if fetch.entry_url_ok(e.url):
            out.append(SampleEntry(url=e.url, title=(e.title or "")[:500]))
        if len(out) >= int(constant("checkUrlSampleEntries")):
            break
    return out


async def _estimate(count: int, urls: list[str], settings: EffectiveSettings, token: Optional[str]) -> int:
    """``count`` times the average stored size of at most 3 pages, each read once with a plain
    GET and cut at the per-page limit, as storage would cut it."""
    if count <= 0:
        return 0
    cap = settings.int("storage.maxPageKb") * 1024
    sizes = []
    for url in urls[:SAMPLED_PAGES]:
        resp = await fetch.fetch_raw(url, settings, github_token=token, max_bytes=min(cap * 4, fetch.PAGE_MAX_BYTES))
        if not resp.ok:
            continue
        options = fetch.content_options(settings)
        text = (await _thread(fetch.clean_page_args, resp.text, options["body_selector"], options["remove"])
                if "html" in resp.content_type else resp.text)
        sizes.append(min(cap, len(text.encode("utf-8"))))
    return int(count * sum(sizes) / len(sizes)) if sizes else 0


async def _pdf(result: CheckUrlResult, url: str, home: fetch.FetchedPage, settings: EffectiveSettings) -> None:
    sample = _with(settings, {"knownTypes.pdfMaxPages": SAMPLED_PAGES})
    pages, total, _error = await _thread(builders.pdf_pages, home.body, sample)
    result.pdf_pages = total
    mapped = min(total, settings.int("knownTypes.pdfMaxPages"))
    result.index = IndexInfo(kind="pdf", url=_url_or_empty(home.final_url or url), count=mapped)
    canonical = fetch.canonical_url(url)
    result.sample_entries = _samples([Candidate(f"{canonical}#page={p['page']}", p["first_line"] or f"Page {p['page']}", "pdf")
                                      for p in pages])
    sizes = [len((p["text"] or "").encode("utf-8")) for p in pages]
    result.estimated_bytes = int(mapped * sum(sizes) / len(sizes)) if sizes else 0


async def _website(result: CheckUrlResult, url: str, robots_txt: robots.Robots, settings: EffectiveSettings,
                   token: Optional[str]) -> None:
    """The sitemap Auto would take, with the follow rules; without one the crawl finds the
    pages, so there is no index to count."""
    base = fetch.canonical_url(url)
    cache = robots.RobotsCache(settings)
    cache.remember(robots_txt)
    rules = crawl.FollowRules(settings, crawl.start_pages(base, settings), crawl.exclude_patterns(settings))
    found = await crawl.sitemap_entries(base, settings, rules=rules, robots_cache=cache, blocking=_thread)
    entries, source = found.entries, found.source
    if not entries:
        result.index = IndexInfo(kind="none")
        return
    configured = [urllib.parse.urljoin(base, u.strip()) for u in settings.list("type.website.sitemapUrls") if u.strip()]
    named = {"configured": configured[:1], "robots": robots_txt.sitemaps[:1]}.get(source) or [f"{robots.origin_of(base)}/sitemap.xml"]
    named = named[0]
    result.index = IndexInfo(kind="sitemap", url=_url_or_empty(named), count=len(entries))
    result.sample_entries = _samples(entries)
    result.estimated_bytes = await _estimate(len(entries), [e.url for e in entries], settings, token)


async def _known(result: CheckUrlResult, url: str, site_type: str, home: fetch.FetchedPage,
                 settings: EffectiveSettings, token: Optional[str], *, allow_browser: bool) -> None:
    mapped = await builders.build_known(site_type, url, settings, github_token=token, home_html=home.html,
                                        home_final_url=home.final_url, allow_browser=allow_browser, blocking=_thread)
    kind = mapped.index_kind if mapped.entries else "none"
    result.index = IndexInfo(kind=kind, url=_url_or_empty(mapped.index_url) if mapped.entries else "",
                             count=len(mapped.entries))
    result.sample_entries = _samples(mapped.entries)
    result.estimated_bytes = await _estimate(len(mapped.entries), [e.url for e in mapped.entries], settings, token)


# --------------------------------------------------------------------------------------
# GitHub: the repository's metadata, its tree, and a CVE archive's path pattern
# --------------------------------------------------------------------------------------

def _api(owner: str, repo: str, tail: str = "") -> str:
    return f"https://api.github.com/repos/{owner}/{repo}{tail}"


async def _json(url: str, settings: EffectiveSettings, token: Optional[str]) -> Any:
    # A GitHub listing; the same bound as a sitemap, so no answer is read whole whatever its size.
    resp = await fetch.fetch_raw(url, settings, github_token=token, max_bytes=int(constant("sitemapMaxBytes")))
    if resp.status != 200:
        return None
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


def _names(items: Any, *, kind: Optional[str] = None) -> list[str]:
    if not isinstance(items, list):
        return []
    return [str(it["name"])[:200] for it in items
            if isinstance(it, dict) and it.get("name") and (kind is None or it.get("type") == kind)][:500]


async def _github(result: CheckUrlResult, url: str, site_type: str, settings: EffectiveSettings,
                  token: Optional[str], *, forced: bool = False) -> str:
    """Fills the GitHub fields and the index; answers the type ingestion would use (a detected
    CVE archive with no year folder at its root is a plain repository, as ``builders.build_cve``
    says; a forced one stays a CVE archive)."""
    parsed = split_github_url(url)
    if not parsed:
        result.index = IndexInfo(kind="none")
        return site_type
    owner, repo = parsed
    info = await _json(_api(owner, repo), settings, token)
    default_branch = str(info.get("default_branch") or "main") if isinstance(info, dict) else "main"
    short = "cve" if site_type == "cve-poc-db" else "github"
    branch = settings.str(f"type.{short}.branch") or default_branch
    root = await _json(_api(owner, repo, f"/contents?ref={urllib.parse.quote(branch, safe='')}"), settings, token)
    result.github = GithubInfo(
        default_branch=default_branch[:200],
        branches=_names(await _json(_api(owner, repo, "/branches?per_page=100"), settings, token)),
        tags=_names(await _json(_api(owner, repo, "/tags?per_page=100"), settings, token)),
        top_folders=_names(root, kind="dir"),
    )
    if site_type == "cve-poc-db":
        years = [n for n in _names(root, kind="dir") if _YEAR_DIR.fullmatch(n)]
        if isinstance(root, list) and not years and not forced:
            site_type = "github-repo"
        else:
            result.index = IndexInfo(kind="none", url=f"https://github.com/{owner}/{repo}")
            result.cve_pattern = await probe_cve_pattern(owner, repo, branch, root, years, settings, token)
            return site_type
    mapped = await builders.build_github(url, _with(settings, {"type.github.branch": branch}), github_token=token,
                                         blocking=_thread)
    result.index = IndexInfo(kind="github_tree", url=f"https://github.com/{owner}/{repo}", count=len(mapped.entries))
    result.sample_entries = _samples(mapped.entries)
    result.estimated_bytes = await _estimate(len(mapped.entries), [e.url for e in mapped.entries], settings, token)
    return site_type


def _patterns(settings: EffectiveSettings) -> list[str]:
    """The archive's own patterns first (they may name a folder below the root), then the
    candidates, each once."""
    return list(dict.fromkeys([*settings.list("type.cve.pathPatterns"), *CVE_PATTERNS]))


def _year_roots(settings: EffectiveSettings) -> list[str]:
    """Where year folders sit: the root, and the folder before ``{year}`` in the archive's own
    patterns (``http/cves`` in ``http/cves/{year}/{cve}.yaml``)."""
    roots = [""]
    for pattern in settings.list("type.cve.pathPatterns"):
        head = pattern.split("{year}", 1)[0].strip("/")
        if "{year}" in pattern and head and "{" not in head and ".." not in head.split("/") and head not in roots:
            roots.append(head)
    return roots[:3]


async def _cve_ids(owner: str, repo: str, root: Any, years: list[str], settings: EffectiveSettings,
                   token: Optional[str]) -> list[str]:
    """CVE ids the archive itself names: its first year folder's listing (at the root, or under
    the folder its own pattern names), then its README."""
    ids: list[str] = []
    for folder in _year_roots(settings):
        found = years if not folder else [
            n for n in _names(await _json(_api(owner, repo, f"/contents/{urllib.parse.quote(folder)}"), settings, token),
                              kind="dir") if _YEAR_DIR.fullmatch(n)]
        if found:
            path = f"{folder}/{sorted(found)[0]}" if folder else sorted(found)[0]
            listing = await _json(_api(owner, repo, f"/contents/{urllib.parse.quote(path)}"), settings, token)
            ids += [m.group(0).upper() for n in _names(listing) if (m := _CVE_RE.search(n))]
        if ids:
            break
    readme = next((it for it in root if isinstance(it, dict) and str(it.get("name", "")).lower().startswith("readme")
                   and it.get("download_url")), None) if isinstance(root, list) else None
    if readme is not None and fetch.entry_url_ok(str(readme["download_url"])):
        resp = await fetch.fetch_raw(str(readme["download_url"]), settings, github_token=token, max_bytes=512 * 1024)
        if resp.ok:
            ids += [m.group(0).upper() for m in _CVE_RE.finditer(resp.text)]
    return list(dict.fromkeys(ids))


async def probe_cve_pattern(owner: str, repo: str, branch: str, root: Any, years: list[str],
                            settings: EffectiveSettings, token: Optional[str]) -> Optional[str]:
    """The first pattern (the archive's own, then ``CVE_PATTERNS``) under which a CVE id the
    archive names exists, or None."""
    ids = (await _cve_ids(owner, repo, root, years, settings, token))[:CVE_PROBE_IDS]
    for pattern in _patterns(settings):
        for cve_id in ids:
            path = cve.pattern_path(pattern, cve_id)
            if path is None:
                continue
            resp = await fetch.fetch_raw(cve.raw_url(owner, repo, branch, path), settings, github_token=token,
                                         max_bytes=1024)
            if resp.status == 200:
                return pattern
    return None
