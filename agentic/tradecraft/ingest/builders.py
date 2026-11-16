"""One map builder per known site type (port of the 1.x ``_build_sitemap_*`` functions).

A builder answers a ``MapResult``: candidate entries ``{url, title, source, path, extra}``
and the type's metadata (owner, repository and branch of a GitHub repository, the index
URL of a Sphinx site). Every request goes through ``fetch.fetch_raw`` (the GitHub token
only to GitHub hosts) and every cap is a setting whose default is 1.x's value; the wiki's
sitemap, unlimited in 1.x, stops at ``knownTypes.maxMapEntries.wiki`` (20,000).

Parsing (XML, HTML, PDF) is CPU work: the pipeline passes ``blocking``, which runs it on
the job runner's thread pool; called alone, a builder parses inline.
"""

from __future__ import annotations

import io
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from orchestrator_helpers.web_sources import (
    _LANG_RE,
    BeautifulSoup,
    PdfReader,
    document_base_href,
    parse_sitemap_xml,
    prefer_english,
    resolve_link,
    split_github_url,
)
from tradecraft import net
from tradecraft.ingest import fetch, robots
from tradecraft.settings import EffectiveSettings, constant

Blocking = Callable[..., Awaitable[Any]]


async def inline(fn: Callable[..., Any], *args: Any) -> Any:
    return fn(*args)


@dataclass
class Candidate:
    """A map entry before it is stored. ``path`` is what the 1.x ``sitemap`` names it by
    (``legacy_map``); ``extra`` carries what a later stage needs (a PDF page's text)."""

    url: str
    title: str
    source: str
    path: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class MapResult:
    type: str
    entries: list[Candidate] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    index_kind: str = "none"
    index_url: str = ""
    # A job error code when the builder could not read the site's index; `note` says why,
    # for the log line only (never page text, never a URL).
    error: str = ""
    note: str = ""
    truncated: bool = False
    # A CVE repository without year folders is a plain repository (1.x re-types it).
    retype: str = ""


_YEAR_DIR_RE = re.compile(r"(?:19|20)\d{2}")
_WIKI_NAV = ".md-nav__link, nav a"
_GITBOOK_NAV = "aside nav a, nav a, [role='navigation'] a"
_SPHINX_INDEXES = ("/searchindex.json", "/search-index.json", "/searchindex.js")


# --------------------------------------------------------------------------------------
# Shared pieces
# --------------------------------------------------------------------------------------

def _dedupe(entries: list[Candidate], cap: int) -> tuple[list[Candidate], bool]:
    """Distinct by canonical URL, valid URLs only, at most ``cap``; True when cut."""
    seen: set[str] = set()
    out: list[Candidate] = []
    for e in entries:
        if not fetch.entry_url_ok(e.url):
            continue
        key = fetch.canonical_url(e.url) if "#page=" not in e.url else e.url
        if key in seen:
            continue
        seen.add(key)
        e.url = key
        out.append(e)
        if len(out) > cap:
            return out[:cap], True
    return out, False


def title_from_slug(url: str, *, strip_html: bool) -> str:
    slug = urllib.parse.urlsplit(url).path.strip("/").split("/")[-1] or url
    if strip_html:
        slug = slug.removesuffix(".html")
    return re.sub(r"[-_]", " ", slug).title()


def language_filter(urls: list[str], settings: EffectiveSettings) -> list[str]:
    """``auto`` keeps English when the site is mostly per-language copies (1.x
    ``prefer_english``); ``preferred`` does the same for the person's language; ``all`` keeps
    every copy."""
    mode = settings.str("knownTypes.language")
    if mode == "all":
        return urls
    lang = settings.str("knownTypes.preferredLanguage").strip().lower() if mode == "preferred" else ""
    if not lang or lang == "en":
        return prefer_english(urls)
    tagged, keep = 0, []
    for u in urls:
        m = _LANG_RE.match(urllib.parse.urlsplit(u).path or "/")
        if m:
            tagged += 1
            if m.group(1).lower() == lang:
                keep.append(u)
    return keep if keep and tagged > 0.4 * len(urls) else urls


async def sitemap_urls(url: str, settings: EffectiveSettings, *, blocking: Blocking = inline,
                       depth: Optional[int] = None) -> list[str]:
    """The page URLs of a sitemap or sitemap index: at most ``sitemapMaxBytes`` each, two
    levels, ``sitemapMaxChildren`` children of an index (the mirror's limits)."""
    depth = constant("sitemapMaxDepth") if depth is None else depth
    if depth <= 0:
        return []
    max_bytes = int(constant("sitemapMaxBytes"))
    resp = await fetch.fetch_raw(url, settings, max_bytes=max_bytes + 1)
    if not resp.ok or resp.truncated or not resp.body:
        return []
    kind, locs = await blocking(parse_sitemap_xml, resp.text)
    if kind == "index":
        urls: list[str] = []
        for loc in locs[: int(constant("sitemapMaxChildren"))]:
            urls.extend(await sitemap_urls(loc, settings, blocking=blocking, depth=depth - 1))
        return urls
    return list(locs) if kind == "urlset" else []


def _nav_links(html: str, page_url: str, selector: str) -> list[tuple[str, str]]:
    if not html or BeautifulSoup is None:
        return []
    soup = BeautifulSoup(html, "html.parser")
    base_href = document_base_href(soup)
    out = []
    try:
        anchors = soup.select(selector)
    except Exception:  # a menu selector from the person's settings that does not parse
        return []
    for a in anchors:
        path = resolve_link(page_url, a.get("href") or "", base_href)
        title = a.get_text(strip=True)
        if path and title:
            out.append((title, path))
    return out


async def _from_sitemaps(base: str, configured: list[str], settings: EffectiveSettings,
                         blocking: Blocking) -> tuple[list[str], str]:
    """The first sitemap that lists pages: the resource's own URLs (§6.5; they replace
    ``/sitemap.xml`` at the resource's URL, which is read only when none is set), and the ones
    a ``Sitemap:`` line of robots.txt names."""
    named = [urllib.parse.urljoin(base + "/", sm.strip()) for sm in configured if sm.strip()]
    named += (await robots.read(base, settings)).sitemaps[: int(constant("sitemapMaxChildren"))]
    if not configured:
        named.append(f"{base}/sitemap.xml")
    for sm in dict.fromkeys(named):
        urls = await sitemap_urls(sm, settings, blocking=blocking)
        if urls:
            return urls, sm
    return [], ""


# --------------------------------------------------------------------------------------
# MkDocs / mdBook wiki
# --------------------------------------------------------------------------------------

async def build_wiki(url: str, settings: EffectiveSettings, *, home_html: str = "", home_final_url: str = "",
                     blocking: Blocking = inline) -> MapResult:
    """sitemap.xml, else mkdocs.yml's nav, else the links of the rendered menu."""
    base = url.rstrip("/")
    cap = settings.int("knownTypes.maxMapEntries.wiki")
    urls, index_url = await _from_sitemaps(base, settings.list("type.wiki.sitemapUrls"), settings, blocking)
    if urls:
        urls = language_filter(urls, settings)
        entries = [Candidate(u, title_from_slug(u, strip_html=True), "sitemap", u) for u in urls]
        entries, cut = _dedupe(entries, cap)
        return MapResult("mkdocs-wiki", entries, index_kind="sitemap", index_url=index_url, truncated=cut)

    resp = await fetch.fetch_raw(f"{base}/mkdocs.yml", settings)
    if resp.ok and resp.body:
        nav = await blocking(_mkdocs_yml_nav, resp.text)
        if nav:
            entries = [Candidate(_join(base, path), title, "nav", path) for title, path in nav]
            entries, cut = _dedupe(entries, cap)
            return MapResult("mkdocs-wiki", entries, index_kind="nav", index_url=f"{base}/mkdocs.yml", truncated=cut)

    if not home_html:
        page = await fetch.fetch_raw(base, settings)
        home_html, home_final_url = (page.text, page.final_url) if page.ok else ("", "")
    selector = settings.str("type.wiki.menuSelector") or _WIKI_NAV
    links = await blocking(_nav_links, home_html, home_final_url or base, selector)
    menu_cap = min(cap, int(constant("navHarvestMaxEntries")["wiki"]))
    entries, cut = _dedupe([Candidate(p, t, "nav", p) for t, p in links], menu_cap)
    return MapResult("mkdocs-wiki", entries, index_kind="nav" if entries else "none", truncated=cut)


def _mkdocs_yml_nav(text: str) -> list[tuple[str, str]]:
    try:
        import yaml
        data = yaml.safe_load(text)
    except Exception:
        return []
    out: list[tuple[str, str]] = []

    def walk(node: Any, prefix: str = "") -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{prefix} > {k}".strip(" >"))
        elif isinstance(node, list):
            for item in node:
                walk(item, prefix)
        elif isinstance(node, str):
            out.append((prefix or node, node))

    walk((data or {}).get("nav") if isinstance(data, dict) else [])
    return out


def _join(base: str, path: str) -> str:
    """1.x's generic resolution of a relative map path against the resource URL."""
    if path.startswith(("http://", "https://")):
        return path
    encoded = "/".join(urllib.parse.quote(seg, safe="") for seg in path.lstrip("/").split("/"))
    return urllib.parse.urljoin(base.rstrip("/") + "/", encoded)


# --------------------------------------------------------------------------------------
# Sphinx / Docusaurus
# --------------------------------------------------------------------------------------

async def build_docs(url: str, settings: EffectiveSettings, *, blocking: Blocking = inline) -> MapResult:
    base = url.rstrip("/")
    cap = settings.int("knownTypes.maxMapEntries.docs")
    configured = settings.str("type.docs.searchIndexUrl")
    candidates = [urllib.parse.urljoin(base + "/", configured)] if configured else [base + c for c in _SPHINX_INDEXES]
    for idx_url in candidates:
        resp = await fetch.fetch_raw(idx_url, settings)
        if resp.status != 200 or not resp.body:
            continue
        nav = await blocking(_sphinx_index_entries, resp.text, base)
        if nav:
            entries, cut = _dedupe([Candidate(p, t, "searchindex", p) for t, p in nav], cap)
            return MapResult("sphinx-docs", entries, meta={"indexUrl": idx_url}, index_kind="searchindex",
                             index_url=idx_url, truncated=cut)
    return MapResult("sphinx-docs", [], meta={"indexUrl": ""})


def _sphinx_index_entries(text: str, base: str) -> list[tuple[str, str]]:
    m = re.search(r"\{.*\}", text.strip(), re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except Exception:
        return []
    nav: list[tuple[str, str]] = []
    docnames = (data.get("docnames") or data.get("docNames") or []) if isinstance(data, dict) else []
    titles = (data.get("titles") or []) if isinstance(data, dict) else []
    for i, doc in enumerate(docnames):
        title = titles[i] if i < len(titles) else doc
        nav.append((str(title), f"{base}/{doc}.html"))
    if not nav and isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and "title" in entry and ("url" in entry or "path" in entry):
                p = entry.get("url") or entry.get("path")
                nav.append((str(entry["title"]), urllib.parse.urljoin(base + "/", str(p))))
    return nav


# --------------------------------------------------------------------------------------
# GitBook
# --------------------------------------------------------------------------------------

async def build_gitbook(url: str, settings: EffectiveSettings, *, home_html: str = "", home_final_url: str = "",
                        allow_browser: bool = True, blocking: Blocking = inline) -> MapResult:
    """sitemap.xml, else the menu of the page (1.x read it only after a browser render
    succeeded; here the plain page is read first and the browser only when it has none)."""
    base = url.rstrip("/")
    cap = settings.int("knownTypes.maxMapEntries.gitbook")
    urls, index_url = await _from_sitemaps(base, settings.list("type.gitbook.sitemapUrls"), settings, blocking)
    if urls:
        urls = language_filter(urls, settings)
        entries, cut = _dedupe([Candidate(u, title_from_slug(u, strip_html=False), "sitemap", u) for u in urls], cap)
        return MapResult("gitbook", entries, index_kind="sitemap", index_url=index_url, truncated=cut)

    selector = settings.str("type.gitbook.menuSelector") or _GITBOOK_NAV
    menu_cap = min(cap, int(constant("navHarvestMaxEntries")["gitbook"]))
    if not home_html:
        page = await fetch.fetch_raw(base, settings)
        home_html, home_final_url = (page.text, page.final_url) if page.ok else ("", "")
    links = await blocking(_nav_links, home_html, home_final_url or base, selector)
    if not links and allow_browser and settings.bool("fetching.browserEnabled"):
        rendered = await net.get_fetcher().render(base, **fetch.render_options(settings))
        if rendered.html:
            links = await blocking(_nav_links, rendered.html, base, selector)
    entries, cut = _dedupe([Candidate(p, t, "nav", p) for t, p in links], menu_cap)
    return MapResult("gitbook", entries, index_kind="nav" if entries else "none", truncated=cut)


# --------------------------------------------------------------------------------------
# GitHub repository and CVE archive
# --------------------------------------------------------------------------------------

def _api(owner: str, repo: str, tail: str = "") -> str:
    return f"https://api.github.com/repos/{owner}/{repo}{tail}"


def _json_or_none(resp: Any) -> Any:
    try:
        return json.loads(resp.text)
    except (ValueError, TypeError):
        return None


def _status_note(status: int) -> str:
    return {403: "github_rate_limited", 404: "github_not_found"}.get(status, f"github_http_{status}")


def _wanted_path(path: str, file_types: list[str], include: list[str], exclude: list[str]) -> bool:
    lower = path.lower()
    if not any(lower.endswith(ext if ext.startswith(".") else "." + ext) for ext in file_types):
        return False

    def under(folders: list[str]) -> bool:
        return any(path == f.strip("/") or path.startswith(f.strip("/") + "/") for f in folders if f.strip("/"))

    if include and not under(include):
        return False
    return not under(exclude)


def _is_readme(path: str) -> bool:
    return path.rsplit("/", 1)[-1].lower().startswith("readme.")


def folder_entries(paths: list[str]) -> list[str]:
    """§6.5 "One entry per folder": a folder (not the root) with a README becomes one entry, its
    README, standing for every file under it that no deeper README folder claims. Files under
    no such folder stay one entry each. Order: the first file of each group."""
    readme_dirs = {p.rsplit("/", 1)[0] for p in paths if "/" in p and _is_readme(p)}
    out: list[str] = []
    for p in paths:
        parts = p.split("/")[:-1]
        owner = next(("/".join(parts[:i]) for i in range(len(parts), 0, -1) if "/".join(parts[:i]) in readme_dirs), None)
        entry = p if owner is None else next(q for q in paths if q.rsplit("/", 1)[0] == owner and _is_readme(q))
        if entry not in out:
            out.append(entry)
    return out


async def build_github(url: str, settings: EffectiveSettings, *, github_token: Optional[str] = None) -> MapResult:
    """The repository's tree through the GitHub API at ``type.github.branch`` (a branch or a
    tag; the default branch when empty): one entry per text file, or per README folder."""
    parsed = split_github_url(url)
    if not parsed:
        return MapResult("github-repo", error="bad_url", note="github_url_unparsed")
    owner, repo = parsed
    branch = settings.str("type.github.branch")
    meta = {"owner": owner, "repo": repo, "branch": branch or "main"}
    if not branch:
        resp = await fetch.fetch_raw(_api(owner, repo), settings, github_token=github_token)
        if resp.status != 200:
            return MapResult("github-repo", meta=meta, error="fetch_failed",
                             note=resp.error or _status_note(resp.status))
        info = _json_or_none(resp) or {}
        branch = str(info.get("default_branch") or "main") if isinstance(info, dict) else "main"
        meta["branch"] = branch
    tree_url = _api(owner, repo, f"/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1")
    resp = await fetch.fetch_raw(tree_url, settings, github_token=github_token)
    if resp.status != 200:
        return MapResult("github-repo", meta=meta, error="fetch_failed", note=resp.error or _status_note(resp.status))
    data = _json_or_none(resp)
    items = data.get("tree", []) if isinstance(data, dict) else []
    file_types = settings.list("knownTypes.githubFileTypes")
    include, exclude = settings.list("type.github.includeFolders"), settings.list("type.github.excludeFolders")
    paths = [str(item.get("path", "")) for item in items if isinstance(item, dict) and item.get("type") == "blob"]
    paths = [p for p in paths if _wanted_path(p, file_types, include, exclude)]
    by_folder = settings.bool("type.github.folderEntries")
    if by_folder:
        paths = folder_entries(paths)
    entries = []
    for path in paths:
        # A folder's entry is named after the folder; every other entry after its file (1.x).
        name = path.rsplit("/", 1)[0] if by_folder and _is_readme(path) and "/" in path else path.rsplit(".", 1)[0]
        title = " > ".join(seg.replace("_", " ").replace("-", " ") for seg in name.split("/"))
        encoded = "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/"))
        raw = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{encoded}"
        entries.append(Candidate(raw, title, "tree", path))
    entries, cut = _dedupe(entries, settings.int("knownTypes.maxMapEntries.github"))
    result = MapResult("github-repo", entries, meta=meta, index_kind="github_tree", index_url=f"https://github.com/{owner}/{repo}",
                       truncated=cut or bool(isinstance(data, dict) and data.get("truncated")))
    if isinstance(data, dict) and data.get("truncated"):
        result.note = "github_tree_truncated"
    return result


async def build_cve(url: str, settings: EffectiveSettings, *, github_token: Optional[str] = None) -> MapResult:
    """A CVE archive is not listed: lookups probe its year folders. A repository with no year
    folder at its root is a plain repository (only a definite listing decides)."""
    parsed = split_github_url(url)
    if not parsed:
        return MapResult("cve-poc-db", error="bad_url", note="github_url_unparsed")
    owner, repo = parsed
    branch = settings.str("type.cve.branch") or "main"
    if not settings.str("type.cve.branch"):
        resp = await fetch.fetch_raw(_api(owner, repo), settings, github_token=github_token)
        info = _json_or_none(resp) if resp.status == 200 else None
        if isinstance(info, dict) and info.get("default_branch"):
            branch = str(info["default_branch"])
    result = MapResult("cve-poc-db", meta={"owner": owner, "repo": repo, "branch": branch}, index_kind="none",
                       index_url=f"https://github.com/{owner}/{repo}")
    resp = await fetch.fetch_raw(_api(owner, repo, "/contents"), settings, github_token=github_token)
    listing = _json_or_none(resp) if resp.status == 200 else None
    if isinstance(listing, list) and not any(
            isinstance(it, dict) and it.get("type") == "dir" and _YEAR_DIR_RE.fullmatch(str(it.get("name", "")))
            for it in listing):
        result.retype = "github-repo"
    return result


# --------------------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------------------

def _skip_set(text: str) -> set[int]:
    out: set[int] = set()
    for part in (text or "").split(","):
        part = part.strip()
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            out.update(range(min(a, b), min(max(a, b), min(a, b) + 100_000) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def _chapter_starts(reader: Any) -> list[tuple[int, str]]:
    """(first page, title) of each top-level bookmark, in page order; [] when the PDF has none."""
    starts: list[tuple[int, str]] = []
    try:
        outline = reader.outline
    except Exception:
        return []
    for item in outline or []:
        if isinstance(item, list):  # the children of the previous bookmark
            continue
        try:
            page = reader.get_destination_page_number(item) + 1
        except Exception:
            continue
        title = str(getattr(item, "title", "") or "").strip()[:200]
        if page >= 1 and not any(page == p for p, _t in starts):
            starts.append((page, title))
    return sorted(starts)


def pdf_pages(body: bytes, settings: EffectiveSettings) -> tuple[list[dict], int, str]:
    """(pages, total pages, error code) where each page is {page, first_line, text}: the
    pages from ``type.pdf.firstPage`` to ``lastPage`` (0 = the end) without ``skipPages``, at
    most ``knownTypes.pdfMaxPages``. With ``type.pdf.mapBy`` = ``chapters`` and bookmarks, one
    item per top-level bookmark instead: its first page, its title, the text of its pages.
    Blocking: run it through ``blocking``."""
    if PdfReader is None or not body:
        return [], 0, "fetch_failed"
    try:
        reader = PdfReader(io.BytesIO(body))
        total = len(reader.pages)
    except Exception:
        return [], 0, "fetch_failed"
    pages = _pages(reader, total, settings)
    if settings.str("type.pdf.mapBy") == "chapters":
        chapters = _chapters(reader, pages)
        if chapters:
            return chapters, total, ""
    return pages, total, ""


def _chapters(reader: Any, pages: list[dict]) -> list[dict]:
    starts = _chapter_starts(reader)
    if not starts:
        return []
    out: list[dict] = []
    for i, (start, title) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else None
        own = [p for p in pages if p["page"] >= start and (end is None or p["page"] < end)]
        if not own:
            continue
        out.append({"page": own[0]["page"], "first_line": title or own[0]["first_line"],
                    "text": "\n\n".join(p["text"] for p in own if p["text"])})
    # Pages before the first bookmark keep an item of their own, so no page of the range is lost.
    before = [p for p in pages if p["page"] < starts[0][0]]
    if before:
        out.insert(0, {"page": before[0]["page"], "first_line": before[0]["first_line"],
                       "text": "\n\n".join(p["text"] for p in before if p["text"])})
    return out


def _pages(reader: Any, total: int, settings: EffectiveSettings) -> list[dict]:
    first = max(1, settings.int("type.pdf.firstPage"))
    last = settings.int("type.pdf.lastPage") or total
    skip = _skip_set(settings.str("type.pdf.skipPages"))
    limit = settings.int("knownTypes.pdfMaxPages")
    pages: list[dict] = []
    for n in range(first, min(last, total) + 1):
        if n in skip:
            continue
        if len(pages) >= limit:
            break
        try:
            text = reader.pages[n - 1].extract_text() or ""
        except Exception:
            text = ""
        first_line = next((ln.strip()[:80] for ln in text.splitlines() if ln.strip()), "")
        pages.append({"page": n, "first_line": first_line, "text": text})
    return pages


async def build_pdf(url: str, body: bytes, settings: EffectiveSettings, *, blocking: Blocking = inline) -> MapResult:
    pages, total, error = await blocking(pdf_pages, body, settings)
    entries = [Candidate(f"{fetch.canonical_url(url)}#page={p['page']}", p["first_line"] or f"Page {p['page']}", "pdf",
                         str(p["page"]), {"page": p["page"], "text": p["text"], "first_line": p["first_line"]})
               for p in pages]
    result = MapResult("pdf", entries, meta={"totalPages": total}, index_kind="pdf", error=error)
    result.truncated = bool(total) and len(pages) < total and len(pages) >= settings.int("knownTypes.pdfMaxPages")
    return result


# --------------------------------------------------------------------------------------

async def build_known(site_type: str, url: str, settings: EffectiveSettings, *, github_token: Optional[str] = None,
                      home_html: str = "", home_final_url: str = "", allow_browser: bool = True,
                      blocking: Blocking = inline) -> MapResult:
    """The builder of a known type (not ``pdf``, which needs the document, nor the website
    crawl of ``crawl.py``)."""
    if site_type == "mkdocs-wiki":
        return await build_wiki(url, settings, home_html=home_html, home_final_url=home_final_url, blocking=blocking)
    if site_type == "sphinx-docs":
        return await build_docs(url, settings, blocking=blocking)
    if site_type == "gitbook":
        return await build_gitbook(url, settings, home_html=home_html, home_final_url=home_final_url,
                                   allow_browser=allow_browser, blocking=blocking)
    if site_type == "github-repo":
        return await build_github(url, settings, github_token=github_token)
    if site_type == "cve-poc-db":
        result = await build_cve(url, settings, github_token=github_token)
        if result.retype == "github-repo":
            retyped = await build_github(url, settings, github_token=github_token)
            retyped.retype = "github-repo"
            return retyped
        return result
    raise ValueError(f"no builder for {site_type}")
