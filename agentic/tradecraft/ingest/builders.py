"""One map builder per known site type (port of the 1.x ``_build_sitemap_*`` functions).

A builder answers a ``MapResult``: candidate entries ``{url, title, source, path, extra}``
and the type's metadata (owner, repository and branch of a GitHub repository, the index
URL of a Sphinx site). Every request goes through ``fetch.fetch_raw`` (the GitHub token
only to GitHub hosts) and every cap is a setting whose default is 1.x's value; the wiki's
sitemap, unlimited in 1.x, stops at ``knownTypes.maxMapEntries.wiki`` (20,000). Where 1.x left
a docs site whose search index listed nothing with its homepage alone, its sitemaps map it,
else the pipeline crawls it.

Parsing (XML, HTML, PDF) is CPU work: the pipeline passes ``blocking``, which runs it on
the job runner's thread pool; called alone, a builder parses inline.
"""

from __future__ import annotations

import io
import json
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Optional, Sequence

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
    # A repository's size in KB when its API answer was read: the archive's pre-check (T6.3).
    repo_size_kb: Optional[int] = None
    # Nothing the type reads listed the site's pages: the pipeline crawls it as a website.
    crawl_fallback: bool = False
    # The report's stopReason when the type can build its map more than one way: which source did.
    # Fixed words, codes and counts, never a URL; at most 64 characters.
    report_stop: str = ""


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


def _printable_line(text: str) -> str:
    """Control and format characters (bidi overrides and zero-width marks among them) and line or
    paragraph separators as spaces, runs of spaces as one: a title is one clean line."""
    return " ".join("".join(" " if unicodedata.category(ch)[0] == "C" or unicodedata.category(ch) in ("Zl", "Zp")
                             else ch for ch in text).split())


def _one_line(text: str) -> str:
    """``_printable_line`` with slashes as spaces too: what percent-decoding can bring into a
    title never breaks its line."""
    return _printable_line(text.replace("/", " ").replace("\\", " "))


def title_from_slug(url: str, *, strip_html: bool) -> str:
    """A title guessed from the last segment of a URL's path, percent-decoded once (a ``+`` in a
    path is a plus; bytes that are not UTF-8 stay as written), dashes and underscores as
    spaces; the URL itself when nothing is left of the segment."""
    slug = urllib.parse.urlsplit(url).path.strip("/").split("/")[-1]
    try:
        slug = urllib.parse.unquote(slug, errors="strict")
    except UnicodeDecodeError:
        pass
    if strip_html:
        slug = slug.removesuffix(".html")
    title = _one_line(re.sub(r"[-_]", " ", slug))
    return title.title() if title else _printable_line(re.sub(r"[-_]", " ", url)).title()


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


def preferred_languages(start_url: str, settings: EffectiveSettings) -> list[str]:
    """The languages an index of per-language sitemaps is read in, the first the index has
    wins: none under ``all`` (the listed order); the person's language under ``preferred``;
    under ``auto`` the language of the resource's own folder (``/fr/``), then English. The budget
    then goes to the copies the map keeps, not to pages ``language_filter`` would drop; a
    two-letter folder that names no child (``/go/``) leaves English first."""
    mode = settings.str("knownTypes.language")
    if mode == "all":
        return []
    if mode == "preferred":
        return [settings.str("knownTypes.preferredLanguage").strip().lower() or "en"]
    m = _LANG_RE.match(urllib.parse.urlsplit(start_url).path or "/")
    folder = m.group(1).lower() if m else ""
    return [folder, "en"] if _is_language(folder) and folder != "en" else ["en"]


# ISO 639-1. A two-letter folder is a language only when it is one of these: sites name sections
# that way too (/ad/, /ai/, /go/).
_LANGUAGE_CODES = frozenset("""
    aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce ch co cr cs cu cv cy da de dv dz
    ee el en eo es et eu fa ff fi fj fo fr fy ga gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik
    io is it iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv mg mh mi mk ml
    mn mr ms mt my na nb nd ne ng nl nn no nr nv ny oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa sc sd
    se sg si sk sl sm sn so sq sr ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw ty ug uk ur uz ve vi
    vo wa wo xh yi yo za zh zu""".split())
_LANG_CODE_RE = re.compile(r"[a-z]{2}(?:-[a-z]{2})?")


def _is_language(code: str) -> bool:
    return code.split("-")[0] in _LANGUAGE_CODES


def _child_language(loc: str) -> str:
    """The language a child sitemap of an index is for: a folder named by a language code
    (``/af/sitemap.xml``), else a language code in its file name (``sitemap-af.xml``); "" when
    neither names one."""
    try:
        path = (urllib.parse.urlsplit(loc).path or "/").lower()
    except ValueError:
        return ""
    *folders, name = path.split("/")
    for seg in folders:
        if _LANG_CODE_RE.fullmatch(seg) and _is_language(seg):
            return seg
    return next((t for t in re.split(r"[-_.]", name) if t in _LANGUAGE_CODES), "")


def language_children(locs: list[str], languages: list[str]) -> tuple[list[str], list[str]]:
    """(the children of a sitemap index to read first, the ones read only when those list
    nothing). An index of per-language copies (two languages or more, and most of its children
    named by a language code) is read in the first of ``languages`` it has, with its children
    named by none; any other index, or one with none of them, in its own order. A translated
    wiki lists its languages alphabetically, and the byte budget ran out on the first ones before
    the language the filter keeps."""
    if not languages:
        return locs, []
    tags = [_child_language(loc).split("-")[0] for loc in locs]
    tagged = [t for t in tags if t]
    want = next((lang.split("-")[0] for lang in languages if lang.split("-")[0] in tagged), "")
    if len(set(tagged)) < 2 or len(tagged) <= 0.5 * len(locs) or not want:
        return locs, []
    return ([loc for loc, t in zip(locs, tags) if t in ("", want)],
            [loc for loc, t in zip(locs, tags) if t not in ("", want)])


Stop = Callable[[], Awaitable[str]]


class SitemapBudget:
    """One reading of a site's sitemaps, within the mirror's limits (§5): each file at most
    ``sitemapMaxBytes``, and for the whole reading at most an index and its
    ``sitemapMaxChildren`` children (21 files) and ``sitemapMaxBytes`` in all, however many
    sitemaps robots.txt names. ``should_stop`` is asked before each download (a crawl's time
    budget, a cancel) and answers the reason to stop, or ""."""

    def __init__(self, should_stop: Optional[Stop] = None) -> None:
        self.files = int(constant("sitemapMaxChildren")) + 1
        self.bytes = int(constant("sitemapMaxBytes"))
        self.should_stop = should_stop
        # Why the reading stopped early: a should_stop reason, or "sitemap_limit".
        self.stopped = ""

    async def allow(self) -> bool:
        if not self.stopped and self.should_stop is not None:
            self.stopped = await self.should_stop() or ""
        if not self.stopped and (self.files <= 0 or self.bytes <= 0):
            self.stopped = "sitemap_limit"
        if self.stopped:
            return False
        self.files -= 1
        return True


async def iter_sitemap_urls(url: str, settings: EffectiveSettings, *, budget: SitemapBudget,
                            blocking: Blocking = inline, depth: Optional[int] = None,
                            languages: Sequence[str] = ()) -> AsyncIterator[list[str]]:
    """The page URLs of a sitemap or sitemap index, one urlset at a time, so a reader can stop
    as soon as it has enough: two levels, ``sitemapMaxChildren`` children of an index, within
    ``budget``. With ``languages``, an index of per-language copies is read in the first of them
    it has first (``language_children``). Parsing goes through ``blocking`` (off the event loop in a job)."""
    depth = constant("sitemapMaxDepth") if depth is None else depth
    if depth <= 0 or not await budget.allow():
        return
    max_bytes = min(int(constant("sitemapMaxBytes")), budget.bytes)
    resp = await fetch.fetch_raw(url, settings, max_bytes=max_bytes + 1)
    budget.bytes -= len(resp.body)
    if not resp.ok or resp.truncated or not resp.body:
        return
    kind, locs = await blocking(parse_sitemap_xml, resp.text)
    if kind == "index":
        first, later = language_children(locs, list(languages))
        left = int(constant("sitemapMaxChildren"))
        listed = False
        for group in (first, later):
            if listed:
                break
            for loc in group[:left]:
                left -= 1
                async for batch in iter_sitemap_urls(loc, settings, budget=budget, blocking=blocking, depth=depth - 1,
                                                     languages=languages):
                    listed = listed or bool(batch)
                    yield batch
                if budget.stopped:
                    return
    elif kind == "urlset":
        yield list(locs)


async def sitemap_urls(url: str, settings: EffectiveSettings, *, blocking: Blocking = inline,
                       depth: Optional[int] = None, budget: Optional[SitemapBudget] = None,
                       languages: Sequence[str] = ()) -> list[str]:
    """Every page URL of a sitemap or sitemap index, within ``budget`` (a fresh one when none)."""
    urls: list[str] = []
    async for batch in iter_sitemap_urls(url, settings, budget=budget or SitemapBudget(), blocking=blocking,
                                         depth=depth, languages=languages):
        urls.extend(batch)
    return urls


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


async def _from_sitemaps(url: str, configured: list[str], settings: EffectiveSettings, blocking: Blocking,
                         keep: Optional[Callable[[str], bool]] = None,
                         budget: Optional[SitemapBudget] = None,
                         usable: Optional[Callable[[list[str]], bool]] = None,
                         named: Optional[list[str]] = None) -> tuple[list[str], str]:
    """The first sitemap that lists pages (that ``keep`` accepts, and that ``usable`` takes for a
    map, when given): the resource's own URLs (§6.5; they replace ``/sitemap.xml`` at the
    resource's URL, which is read only when none is set), and the ones a ``Sitemap:`` line of
    robots.txt names; ``named`` replaces that list. An index of per-language copies is read in the
    language the map will keep first (``preferred_languages``)."""
    base = url.rstrip("/")
    if named is None:
        named = [urllib.parse.urljoin(base + "/", sm.strip()) for sm in configured if sm.strip()]
        named += (await robots.read(base, settings)).sitemaps[: int(constant("sitemapMaxChildren"))]
        if not configured:
            named.append(f"{base}/sitemap.xml")
    budget = budget or SitemapBudget()
    languages = preferred_languages(url, settings)
    for sm in dict.fromkeys(named):
        urls = await sitemap_urls(sm, settings, blocking=blocking, budget=budget, languages=languages)
        if keep is not None:
            urls = [u for u in urls if keep(u)]
        if (usable(urls) if usable is not None else urls) or budget.stopped:
            return urls, sm if urls else ""
    return [], ""


def same_page_as(start_url: str) -> Callable[[str], bool]:
    """Whether a URL names the start page: the same host with or without ``www.``, either scheme,
    with or without a trailing slash. A company's root sitemap names its docs root that way."""
    def key(url: str) -> Optional[tuple]:
        try:
            parts = urllib.parse.urlsplit(fetch.canonical_url(url))
            return ((parts.hostname or "").removeprefix("www."), parts.port, parts.path.rstrip("/") or "/", parts.query)
        except ValueError:
            return None

    start = key(start_url)
    return lambda url: key(url) == start


def in_start_folder(start_url: str) -> Callable[[str], bool]:
    """The resource's own pages: its host (with or without ``www.``) and the folder of its URL,
    as the website mirror scopes a start page. A versioned docs host's sitemap also lists the
    other versions' folders, which are not this resource."""
    parts = urllib.parse.urlsplit(start_url)
    host = (parts.hostname or "").lower().removeprefix("www.")
    path = parts.path or "/"
    folder = path[: path.rfind("/") + 1] or "/"

    def keep(url: str) -> bool:
        try:
            other = urllib.parse.urlsplit(url)
            other_host = (other.hostname or "").lower()
        except ValueError:
            return False
        return other_host.removeprefix("www.") == host and (other.path or "/").startswith(folder)

    return keep


# --------------------------------------------------------------------------------------
# MkDocs / mdBook wiki
# --------------------------------------------------------------------------------------

async def build_wiki(url: str, settings: EffectiveSettings, *, home_html: str = "", home_final_url: str = "",
                     blocking: Blocking = inline) -> MapResult:
    """sitemap.xml, else mkdocs.yml's nav, else the links of the rendered menu."""
    base = url.rstrip("/")
    cap = settings.int("knownTypes.maxMapEntries.wiki")
    urls, index_url = await _from_sitemaps(url, settings.list("type.wiki.sitemapUrls"), settings, blocking)
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

DOCS_INDEX_UNUSABLE = "docs_index_unusable"


def _docs_stop(source: str, entries: list[Candidate], cut: bool, timed_out: bool = False) -> str:
    return f"docs: {source} ({len(entries)} pages{', map limit' if cut else ', time budget' if timed_out else ''})"


async def build_docs(url: str, settings: EffectiveSettings, *, blocking: Blocking = inline,
                     should_stop: Optional[Stop] = None) -> MapResult:
    """The search index; when it lists nothing (none found, another tool's file of that name, one
    that does not parse), the sitemaps, kept to the resource's folder, in one budget that
    ``should_stop`` (the job's cancel and time budget) can end. A sitemap that lists nothing there
    but the start page (or an alias of it, ``same_page_as``) is passed over for the next one; when
    none lists more, ``crawl_fallback``: a homepage alone is no map of a docs site. A cancel, or
    the time budget spent with nothing found, ends the builder with nothing, and no crawl is asked
    for."""
    base = url.rstrip("/")
    cap = settings.int("knownTypes.maxMapEntries.docs")
    configured = settings.str("type.docs.searchIndexUrl")
    candidates = [urllib.parse.urljoin(base + "/", configured)] if configured else [base + c for c in _SPHINX_INDEXES]
    # The index gets the bound of every other listing a site serves (a sitemap, a GitHub listing):
    # a large project's Sphinx index is a few MB, and one cut at the bound would not parse.
    for idx_url in candidates:
        resp = await fetch.fetch_raw(idx_url, settings, max_bytes=int(constant("sitemapMaxBytes")))
        if resp.status != 200 or not resp.body or resp.truncated:
            continue
        nav = await blocking(_sphinx_index_entries, resp.text, base)
        entries, cut = _dedupe([Candidate(p, t, "searchindex", p) for t, p in nav], cap)
        if entries:
            return MapResult("sphinx-docs", entries, meta={"indexUrl": idx_url}, index_kind="searchindex",
                             index_url=idx_url, truncated=cut, report_stop=_docs_stop("searchindex", entries, cut))

    # The site's own /sitemap.xml too: Auto reads it, and docs below the site root are often listed
    # only there. Below the root, the docs' own sitemap comes first: a company's index named by
    # robots.txt can spend the whole budget (21 files) on pages outside the folder.
    named_by_robots = (await robots.read(base, settings)).sitemaps[: int(constant("sitemapMaxChildren"))]
    own, site_root = f"{base}/sitemap.xml", f"{robots.origin_of(base)}/sitemap.xml"
    below_root = (urllib.parse.urlsplit(base).path or "/") != "/"
    named = [own] + named_by_robots + [site_root] if below_root else named_by_robots + [own, site_root]
    budget = SitemapBudget(should_stop)
    is_start = same_page_as(url)
    urls, sitemap_url = await _from_sitemaps(url, [], settings, blocking, keep=in_start_folder(url), budget=budget,
                                             usable=lambda found: not all(is_start(u) for u in found),
                                             named=named)
    if budget.stopped == "cancelled":
        return MapResult("sphinx-docs", [], meta={"indexUrl": ""}, note=DOCS_INDEX_UNUSABLE)
    entries, cut = _dedupe([Candidate(u, title_from_slug(u, strip_html=True), "sitemap", u)
                            for u in language_filter(urls, settings)], cap)
    if any(not is_start(e.url) for e in entries):
        source = "sitemap.xml" if sitemap_url == own else "robots" if sitemap_url in named_by_robots else "site sitemap"
        return MapResult("sphinx-docs", entries, meta={"indexUrl": ""}, index_kind="sitemap", index_url=sitemap_url,
                         truncated=cut, note=DOCS_INDEX_UNUSABLE,
                         report_stop=_docs_stop(f"no search index, {source}", entries, cut,
                                                budget.stopped == "time_budget"))
    if budget.stopped == "time_budget":
        # The crawl's time budget is spent: a crawl would start a fresh one (as Auto's own reading,
        # the docs map stops here).
        return MapResult("sphinx-docs", [], meta={"indexUrl": ""}, note=DOCS_INDEX_UNUSABLE,
                         report_stop="docs: no search index, time budget")
    return MapResult("sphinx-docs", [], meta={"indexUrl": ""}, note=DOCS_INDEX_UNUSABLE, crawl_fallback=True)


def _sphinx_index_entries(text: str, base: str) -> list[tuple[str, str]]:
    # The payload runs from the first "{" to the last "}" (Sphinx wraps it in Search.setIndex(...)).
    # A pattern spanning them is quadratic on unclosed braces, and holds the interpreter lock while
    # it runs on the job's thread pool.
    body = text.strip()
    first, last = body.find("{"), body.rfind("}")
    if first < 0 or last < first:
        return []
    try:
        data = json.loads(body[first:last + 1])
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
    urls, index_url = await _from_sitemaps(url, settings.list("type.gitbook.sitemapUrls"), settings, blocking)
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
        rendered = await fetch.render(base, settings)
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
    no such folder stay one entry each. Order: the first file of each group. Linear in the
    number of files (a big repository has tens of thousands)."""
    readme_of: dict[str, str] = {}
    for p in paths:
        if "/" in p and _is_readme(p):
            readme_of.setdefault(p.rsplit("/", 1)[0], p)
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        entry, folder = p, p
        while "/" in folder:
            folder = folder.rsplit("/", 1)[0]
            if folder in readme_of:
                entry = readme_of[folder]
                break
        if entry not in seen:
            seen.add(entry)
            out.append(entry)
    return out


def github_tree_entries(text: str, owner: str, repo: str, branch: str, file_types: list[str], include: list[str],
                        exclude: list[str], by_folder: bool) -> tuple[list[Candidate], bool]:
    """(entries, GitHub cut the tree) from the tree API's answer: CPU work over a repository's
    every file, so the caller runs it through ``blocking`` (off the event loop)."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    items = data.get("tree", []) if isinstance(data, dict) else []
    paths = [str(item.get("path", "")) for item in items if isinstance(item, dict) and item.get("type") == "blob"]
    paths = [p for p in paths if _wanted_path(p, file_types, include, exclude)]
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
    return entries, bool(isinstance(data, dict) and data.get("truncated"))


async def build_github(url: str, settings: EffectiveSettings, *, github_token: Optional[str] = None,
                       blocking: Blocking = inline) -> MapResult:
    """The repository's tree through the GitHub API at ``type.github.branch`` (a branch or a
    tag; the default branch when empty): one entry per text file, or per README folder."""
    parsed = split_github_url(url)
    if not parsed:
        return MapResult("github-repo", error="bad_url", note="github_url_unparsed")
    owner, repo = parsed
    branch = settings.str("type.github.branch")
    meta = {"owner": owner, "repo": repo, "branch": branch or "main"}
    size_kb: Optional[int] = None
    if not branch:
        resp = await fetch.fetch_raw(_api(owner, repo), settings, github_token=github_token)
        if resp.status != 200:
            return MapResult("github-repo", meta=meta, error="fetch_failed",
                             note=resp.error or _status_note(resp.status))
        info = _json_or_none(resp) or {}
        branch = str(info.get("default_branch") or "main") if isinstance(info, dict) else "main"
        meta["branch"] = branch
        if isinstance(info, dict) and isinstance(info.get("size"), int):
            size_kb = info["size"]
    tree_url = _api(owner, repo, f"/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1")
    resp = await fetch.fetch_raw(tree_url, settings, github_token=github_token)
    if resp.status != 200:
        return MapResult("github-repo", meta=meta, error="fetch_failed", note=resp.error or _status_note(resp.status))
    entries, github_cut = await blocking(
        github_tree_entries, resp.text, owner, repo, branch, settings.list("knownTypes.githubFileTypes"),
        settings.list("type.github.includeFolders"), settings.list("type.github.excludeFolders"),
        settings.bool("type.github.folderEntries"))
    entries, cut = await blocking(_dedupe, entries, settings.int("knownTypes.maxMapEntries.github"))
    result = MapResult("github-repo", entries, meta=meta, index_kind="github_tree", index_url=f"https://github.com/{owner}/{repo}",
                       truncated=cut or github_cut, repo_size_kb=size_kb)
    if github_cut:
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
                      blocking: Blocking = inline, forced: bool = False,
                      should_stop: Optional[Stop] = None) -> MapResult:
    """The builder of a known type (not ``pdf``, which needs the document, nor the website
    crawl of ``crawl.py``). A ``forced`` type is the person's choice (R-144): a CVE archive
    without year folders at its root stays one (its files may sit under a path its pattern
    names), where a detected one becomes a plain repository. ``should_stop`` ends a docs site's
    sitemap reading (the one builder that hands a site on to the crawl)."""
    if site_type == "mkdocs-wiki":
        return await build_wiki(url, settings, home_html=home_html, home_final_url=home_final_url, blocking=blocking)
    if site_type == "sphinx-docs":
        return await build_docs(url, settings, blocking=blocking, should_stop=should_stop)
    if site_type == "gitbook":
        return await build_gitbook(url, settings, home_html=home_html, home_final_url=home_final_url,
                                   allow_browser=allow_browser, blocking=blocking)
    if site_type == "github-repo":
        return await build_github(url, settings, github_token=github_token, blocking=blocking)
    if site_type == "cve-poc-db":
        result = await build_cve(url, settings, github_token=github_token)
        if forced:
            result.retype = ""
        if result.retype == "github-repo":
            retyped = await build_github(url, settings, github_token=github_token, blocking=blocking)
            retyped.retype = "github-repo"
            return retyped
        return result
    raise ValueError(f"no builder for {site_type}")
