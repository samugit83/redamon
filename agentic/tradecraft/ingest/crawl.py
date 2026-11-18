"""The crawl of a website (port of 1.x ``tradecraft_crawl.agentic_crawl``), with three
strategies (``crawl.strategy``, §4.4):

- ``llm`` (the default, 1.x's loop): fetch a page (plain GET, the browser when the page is
  small), keep it in the map when it has a title and enough text, offer its links to the
  model, follow the ones it picks, until a limit or the model stops;
- ``rules``: the same loop with no model: every link the follow rules allow is followed;
- ``auto``: the site's sitemap (one named by a ``Sitemap:`` line of robots.txt, else
  ``/sitemap.xml``, within the mirror's limits) becomes the map without visiting the pages,
  up to ``knownTypes.maxMapEntries.website``; with no usable sitemap, the ``llm`` crawl.

The follow rules (``FollowRules``) apply before any model decision and to every entry the map
keeps, so no saved entry breaks them (AC-06): exclude patterns at the start of ANY path
segment (``tag/`` drops ``/blog/tag/x``; ``*`` is any characters; a ``*.`` pattern must reach
the end of the path), include patterns, the starting folder, the host scope, query strings,
and robots.txt (RFC 9309, ``robots.py``). The start pages are always visited, so their links
are found, but are kept only when they pass the rules. A website resource adds its own
fields (§6.5, T4.3): more start pages on the same site (``type.website.startPages``), the
sitemaps Auto reads first (``type.website.sitemapUrls``), and pagination followed
(``type.website.followPagination`` takes ``page/N`` out of its exclude list).

Every limit is a setting and time comes from ``clock``: pages, model calls, time, depth, links
offered per page, the map's size; the crawl ends at the first limit it reaches (R-076). Pages
are fetched ``crawl.parallel`` at a time, at least ``crawl.delaySec`` apart, and processed in
the order they were queued. The model call carries the ``tradecraft_ingest`` purpose and is
never retried after an exception (TD-20): an answer that is not JSON gets one stricter
request, an error stops the crawl with its code. A kept page carries its HTML, so the pipeline
stores it without a second download. The report counts skips by reason: ``excluded``,
``outOfScope``, ``tooLittleText``, ``robots`` (distinct URLs, except ``tooLittleText``).

With a Focused ingestion focus (§6.14 step 4, T5.2) the model-guided crawl spends its budget on
the focus: links are ranked by the focus's keywords (the relevant ones are offered and visited
first, every strategy), and the one call per page also receives the focus and the start of the
page's text (``constants.contentCheckChars``, inside an untrusted block) and answers, besides
which links to follow, whether to keep the page. Keep and follow are separate decisions: a hub
page is followed without being kept, and then stays in the map as a dropped entry with its
reason. A page the model did not judge (no call was made on it, or the answer had no ``keep``)
is left to the focus stage's title triage, so the focus costs no extra call (R-177).
"""

from __future__ import annotations

import asyncio
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from agent_in_the_loop.purpose import llm_purpose
from logging_config import get_logger
from orchestrator_helpers.json_utils import normalize_content
from orchestrator_helpers.web_sources import BeautifulSoup, document_base_href, resolve_link
from prompt_safety import UNTRUSTED_OUTPUT_GUIDANCE, wrap_untrusted
from tradecraft import clock
from tradecraft.contract import ERROR_CODES
from tradecraft.ingest import builders, fetch, robots
from tradecraft.ingest.builders import Blocking, Candidate, inline
from tradecraft.settings import EffectiveSettings, constant

logger = get_logger(__name__)


@dataclass
class CrawlFetch:
    html: str
    final_url: str
    tier: int = 1
    error: str = ""
    # The plain page was cut at fetch.PAGE_MAX_BYTES.
    truncated: bool = False


FetchPage = Callable[[str], Awaitable[CrawlFetch]]
CancelCheck = Callable[[], Awaitable[bool]]
Progress = Callable[[int, int], Awaitable[None]]

_CHROME = ("nav", "footer", "header", "aside")


def _skips() -> dict:
    return {"excluded": 0, "outOfScope": 0, "tooLittleText": 0, "robots": 0}


@dataclass
class CrawlResult:
    entries: list[Candidate] = field(default_factory=list)
    # A code, the report's stopReason unless report_stop says more: max_pages max_llm_calls
    # time_budget max_map_entries frontier_empty no_llm llm_stop llm_error llm_parse_error
    # cancelled sitemap.
    stop_reason: str = ""
    # 1.x's crawl_stopped_because text (the model's own reason when it stopped).
    stopped_because: str = ""
    # 1.x's crawl_stats: pages_fetched, llm_calls, elapsed_sec; plus the strategy that ran.
    stats: dict = field(default_factory=dict)
    skipped: dict = field(default_factory=_skips)
    # A job error code when a model call failed (budget, loop model, unavailable).
    error_code: str = ""
    # Report error codes counted on the way (page_too_large), by code.
    errors: dict = field(default_factory=dict)
    # Set only by Auto, whose code alone hides what ran: which sitemap gave the map, or that
    # none did and the model crawled. Fixed words, codes and counts, never a URL; it must fit
    # the report's 64 characters.
    report_stop: str = ""

    @property
    def llm_calls(self) -> int:
        return int(self.stats.get("llm_calls", 0))

    @property
    def report_stop_reason(self) -> str:
        """The ingestion report's ``stopReason``."""
        return self.report_stop or self.stop_reason


# --------------------------------------------------------------------------------------
# Path patterns and the follow rules
# --------------------------------------------------------------------------------------

def _pattern_regex(pattern: str) -> Optional[re.Pattern]:
    p = pattern.strip().lstrip("/")
    if not p:
        return None
    body = ".*".join(re.escape(part) for part in p.split("*"))
    tail = "$" if p.startswith("*.") else ""
    return re.compile(rf"(?:^|/){body}{tail}", re.IGNORECASE)


class PathMatcher:
    """Matches a URL's path against patterns at the start of any segment."""

    def __init__(self, patterns: list[str]) -> None:
        self._regexes = [r for r in (_pattern_regex(p) for p in patterns) if r is not None]

    def __bool__(self) -> bool:
        return bool(self._regexes)

    def matches(self, url: str) -> bool:
        try:
            path = urllib.parse.urlsplit(url).path or "/"
        except ValueError:
            return True
        return any(r.search(path) for r in self._regexes)


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _folder(url: str) -> str:
    """The starting folder of a URL, as the website mirror takes it: the path up to its last
    ``/`` (``/blog/`` for ``/blog/`` and ``/blog/post``)."""
    path = urllib.parse.urlsplit(url).path or "/"
    return path[: path.rfind("/") + 1] or "/"


def _bare(host: str) -> str:
    return host.removeprefix("www.")


class FollowRules:
    """The §4.4 rules a link must pass to be followed and an entry to be kept."""

    def __init__(self, settings: EffectiveSettings, starts: list[str],
                 exclude_patterns: Optional[list[str]] = None) -> None:
        self.exclude = PathMatcher(settings.list("crawl.excludePaths") if exclude_patterns is None
                                   else exclude_patterns)
        self.include = PathMatcher(settings.list("crawl.includePaths"))
        self.host_scope = settings.str("crawl.hostScope")
        self.stay_in_folder = settings.bool("crawl.stayInFolder")
        self.query_mode = settings.str("crawl.queryStrings")
        self.query_per_path = settings.int("crawl.queryStringsPerPath")
        self.hosts: set[str] = set()
        self.folders: set[str] = set()
        self._variants: dict[str, set[str]] = {}
        for start in starts:
            self.add_start(start)

    def add_start(self, url: str) -> None:
        host = _host(url)
        if host:
            self.hosts.add(host)
            self.folders.add(_folder(url))

    def adopt(self, start: str, final: str) -> None:
        """A start page that redirected to the same site with or without ``www.`` (http to
        https, a missing slash) widens the scope to where it landed, as the mirror does."""
        if _bare(_host(start)) == _bare(_host(final)):
            self.add_start(final)

    def host_ok(self, host: str) -> bool:
        if self.host_scope == "exact":
            return host in self.hosts
        if self.host_scope == "www":
            return _bare(host) in {_bare(h) for h in self.hosts}
        return any(host == _bare(h) or host.endswith("." + _bare(h)) for h in self.hosts)

    def normalize(self, url: str) -> str:
        """The URL the crawl uses for a link: without its query string under ``drop``."""
        if self.query_mode != "drop":
            return url
        parts = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit(parts._replace(query="")) if parts.query else url

    def verdict(self, url: str) -> str:
        """"" when ``url`` passes every rule, else the report's skip reason. Under ``keepN`` a
        query variant counts against its path the first time it is judged."""
        if not fetch.entry_url_ok(url):
            return "excluded"
        parts = urllib.parse.urlsplit(url)
        if not self.host_ok((parts.hostname or "").lower()):
            return "outOfScope"
        if self.stay_in_folder and not any((parts.path or "/").startswith(f) for f in self.folders):
            return "outOfScope"
        if self.exclude.matches(url) or (self.include and not self.include.matches(url)):
            return "excluded"
        if self.query_mode == "keepN" and parts.query:
            key = urllib.parse.urlunsplit(parts._replace(query="", fragment=""))
            seen = self._variants.setdefault(key, set())
            if parts.query not in seen:
                if len(seen) >= self.query_per_path:
                    return "excluded"
                seen.add(parts.query)
        return ""


class Pacer:
    """At least ``delay`` seconds between the starts of two page requests."""

    def __init__(self, delay: float) -> None:
        self._delay = max(0.0, delay)
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if self._delay <= 0:
            return
        async with self._lock:
            now = clock.monotonic()
            if self._next > now:
                await clock.sleep(self._next - now)
            self._next = max(now, self._next) + self._delay


# --------------------------------------------------------------------------------------
# Fetching a crawl page
# --------------------------------------------------------------------------------------

def fetch_page_for(settings: EffectiveSettings, *, allow_browser: bool = True) -> FetchPage:
    """The crawl's fetch: a plain GET of an HTML page, the browser when the HTML is under
    ``fetching.crawlBrowserBelowBytes`` (4,000, as 1.x); a refused address never goes to the
    browser, which would follow the same redirect."""

    always = allow_browser and settings.bool("fetching.browserEnabled") and settings.bool("fetching.alwaysBrowser")

    async def fetch_page(url: str) -> CrawlFetch:
        if always:
            # §6.7 "Always use the browser": no plain request first (never with a login: the
            # caller passes allow_browser=False then, and fetch.render refuses it).
            rendered = await fetch.render(url, settings)
            return CrawlFetch(rendered.html, url, 2, "" if rendered.html else (rendered.error or "http_error"))
        resp = await fetch.fetch_raw(url, settings, headers={"Accept": "text/html,application/xhtml+xml"},
                                     max_bytes=fetch.PAGE_MAX_BYTES)
        if resp.error in ("unsafe_address", "userinfo_refused", "bad_url"):
            return CrawlFetch("", url, 0, resp.error)
        html = resp.text if (resp.status == 200 and "html" in resp.content_type) else ""
        if html and len(html) >= settings.int("fetching.crawlBrowserBelowBytes"):
            return CrawlFetch(html, resp.final_url or url, 1, truncated=resp.truncated)
        if not (allow_browser and settings.bool("fetching.browserEnabled")):
            return CrawlFetch(html, resp.final_url or url, 1 if html else 0, "" if html else (resp.error or "http_error"))
        rendered = await fetch.render(url, settings)
        if rendered.html:
            # The guarded browser script does not say where redirects ended: links resolve
            # against the requested URL, as in 1.x.
            return CrawlFetch(rendered.html, url, 2)
        if html:
            return CrawlFetch(html, resp.final_url or url, 1)
        return CrawlFetch("", url, 0, rendered.error or resp.error or "http_error")

    return fetch_page


# --------------------------------------------------------------------------------------
# Reading a page
# --------------------------------------------------------------------------------------

def page_meta(html: str, base_url: str) -> dict[str, Any]:
    """{title, body_text, links[{title, href, body}], hints}: 1.x's ``_extract_links_and_meta``;
    ``body`` is false for a link inside the page's nav, header, footer or aside."""
    if BeautifulSoup is None:
        return {"title": "", "body_text": html or "", "links": [], "hints": {}}
    soup = BeautifulSoup(html or "", "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    if not title:
        h1 = soup.find("h1")
        title = h1.get_text(strip=True) if h1 else ""
    for sel in ("nav", "footer", "header", "aside", "script", "style", "form", "iframe"):
        for el in soup.select(sel):
            el.decompose()
    body_text = soup.get_text(" ", strip=True)
    links_soup = BeautifulSoup(html or "", "html.parser")
    base_href = document_base_href(links_soup)
    seen: set[str] = set()
    links: list[dict[str, Any]] = []
    for a in links_soup.find_all("a", href=True):
        absolute = resolve_link(base_url, a.get("href") or "", base_href)
        if absolute is None:
            continue
        canon = fetch.canonical_url(absolute)
        if canon in seen:
            continue
        seen.add(canon)
        anchor = (a.get_text(strip=True) or a.get("title") or canon)[:80]
        links.append({"title": anchor, "href": canon, "body": a.find_parent(_CHROME) is None})
    hints = {
        "search_box": bool(links_soup.find("input", {"type": "search"}) or links_soup.select_one("[role='search']")),
        "pagination": bool(re.search(r"older posts|next page|page/\d+", html or "", re.IGNORECASE)),
        "tag_cloud": [(a.get_text(strip=True) or "").lower()
                      for a in links_soup.select(".tag, .tags a, .tag-cloud a")[:8] if a.get_text(strip=True)],
    }
    return {"title": title, "body_text": body_text, "links": links, "hints": hints}


def keep_reason(meta: dict[str, Any], settings: EffectiveSettings) -> str:
    """"" when the page's content earns it a place in the map, else the report's skip reason."""
    if settings.bool("crawl.requireTitle") and not meta.get("title"):
        return "tooLittleText"
    if len(meta.get("body_text") or "") <= settings.int("crawl.minTextChars"):
        return "tooLittleText"
    return ""


_LOCAL_SUFFIXES = (".local", ".internal")
# The start of a page's text the focus-aware crawl's call reads (§6.14 step 4).
EXCERPT_CHARS = int(constant("contentCheckChars"))


@dataclass
class _State:
    base: str
    rules: FollowRules
    visited: set = field(default_factory=set)
    frontier: list = field(default_factory=list)
    entries: list = field(default_factory=list)
    pages_fetched: int = 0
    llm_calls: int = 0
    started: float = 0.0
    excluded: set = field(default_factory=set)
    out_of_scope: set = field(default_factory=set)
    robots: set = field(default_factory=set)
    too_little: int = 0
    too_large: int = 0
    starts: list = field(default_factory=list)
    # A Focused focus (``ingest.focus.Focus``) and its keyword matchers; None otherwise.
    focus: Any = None
    matchers: Any = None
    # The model's keep decision on the page of its last answer: True, False or None (none given).
    keep: Optional[bool] = None
    keep_reason: str = ""
    scores: dict = field(default_factory=dict)

    def link_score(self, title: str, href: str) -> int:
        if self.focus is None:
            return 0
        from tradecraft.ingest import focus as focus_mod
        return focus_mod.presort_score(self.matchers, title, href)[0]

    def enqueue(self, links: list[dict[str, str]], depth: int) -> None:
        """Adds links to the frontier; with a focus the frontier stays ordered by their score
        (map order among equals), so the relevant pages are visited first."""
        for link in links:
            self.scores[link["href"]] = self.link_score(link.get("title", ""), link["href"])
            self.frontier.append((link["href"], depth))
        if self.focus is not None:
            self.frontier.sort(key=lambda item: -self.scores.get(item[0], 0))

    def skip(self, reason: str, url: str) -> None:
        if reason == "excluded":
            self.excluded.add(url)
        elif reason == "outOfScope":
            self.out_of_scope.add(url)
        elif reason == "robots":
            self.robots.add(url)
        elif reason:
            self.too_little += 1

    def skipped(self) -> dict:
        return {"excluded": len(self.excluded), "outOfScope": len(self.out_of_scope),
                "tooLittleText": self.too_little, "robots": len(self.robots)}


def follow_candidates(meta: dict[str, Any], state: _State, settings: EffectiveSettings,
                      limit: Optional[int] = None) -> list[dict[str, str]]:
    """The page's links that pass the follow rules and were not seen, body links first when
    ``crawl.preferBodyLinks`` is on, then (with a focus) the ones that name it; at most ``limit``
    (the links offered to the model)."""
    links = meta["links"]
    if settings.bool("crawl.preferBodyLinks"):
        links = [lk for lk in links if lk.get("body", True)] + [lk for lk in links if not lk.get("body", True)]
    if state.focus is not None:
        links = sorted(links, key=lambda lk: -state.link_score(lk.get("title", ""), lk.get("href") or ""))
    out: list[dict[str, str]] = []
    queued = {f for f, _d in state.frontier}
    for link in links:
        href = state.rules.normalize(link.get("href") or "")
        if href in state.visited or href in queued or any(o["href"] == href for o in out):
            continue
        reason = state.rules.verdict(href)
        if reason:
            state.skip(reason, href)
            continue
        host = _host(href)
        if host in ("localhost",) or host.endswith(_LOCAL_SUFFIXES):
            continue
        out.append({"title": link.get("title", ""), "href": href})
        if limit is not None and len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------------------
# The model's decision
# --------------------------------------------------------------------------------------

_PROMPT_TEMPLATE = """\
You are building a sitemap of pentest/security content from a website
the user added as a tradecraft reference. Pick links to follow next.
Prefer high-signal paths (technique pages, payload writeups, tool guides,
CVE analyses). Avoid low-signal (login, blog metadata, author bios,
empty archive index pages).

""" + UNTRUSTED_OUTPUT_GUIDANCE + """

Site:    {base}
Just visited: {current}  (depth {depth})

Budget remaining: {pages_remaining} pages, {calls_remaining} calls, {seconds_remaining}s wall clock

Sitemap so far ({sitemap_len}): random sample of titles
{sitemap_sample}

Unvisited links on this page:
{links_block}

Page hints: search_box={search_box}, pagination={pagination}, tag_cloud={tag_cloud}

Reply ONLY with JSON. Two valid shapes:
  {{"action": "stop", "reason": "..."}}
  {{"action": "follow", "indices": [1, 4, 7], "reason": "..."}}
"""
_STRICT_SUFFIX = "\n\nReturn ONLY a single line of valid JSON. No prose, no fenced block."
_FOCUS_REPLY = """\
Reply ONLY with JSON. Two valid shapes:
  {{"action": "stop", "keep": true, "reason": "..."}}
  {{"action": "follow", "indices": [1, 4, 7], "keep": false, "reason": "..."}}
"""
_REPLY = """\
Reply ONLY with JSON. Two valid shapes:
  {{"action": "stop", "reason": "..."}}
  {{"action": "follow", "indices": [1, 4, 7], "reason": "..."}}
"""


def _focus_block(state: _State) -> str:
    """The owner's focus, and how keep and follow differ: the person's own words, outside the
    untrusted blocks."""
    from tradecraft.ingest import focus as focus_mod

    f = state.focus
    return (
        "The owner's focus for this resource (keep only pages that fit it):\n"
        f"  {focus_mod.focus_lines(f)}\n"
        "Follow links likely to lead to pages that fit the focus first; a hub page that links to them is worth "
        "following even when you would not keep it. Also decide whether the page just visited fits the focus "
        '("keep": true or false), judged from its excerpt below, and say why in "reason".\n\n'
    )


class _ModelFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def error_code_of(exc: BaseException) -> str:
    """A model error as a job error code (the budget and the loop refusal carry their own)."""
    code = getattr(exc, "code", "")
    return code if isinstance(code, str) and code in ERROR_CODES else "model_unavailable"


def build_prompt(state: _State, settings: EffectiveSettings, current: str, depth: int,
                 candidates: list[dict[str, str]], hints: dict[str, Any], excerpt: str = "") -> str:
    sample = "\n".join(f"  - {e.title}" for e in state.entries[-10:]) or "  (none yet)"
    links_block = "\n".join(
        f"  {i + 1}. \"{c.get('title', '')[:80]}\" -> {urllib.parse.urlsplit(c['href']).path or c['href']}"
        for i, c in enumerate(candidates)) or "  (none)"
    prompt = _PROMPT_TEMPLATE.format(
        base=state.base, current=current, depth=depth,
        pages_remaining=max(0, settings.int("crawl.maxPages") - state.pages_fetched),
        calls_remaining=max(0, settings.int("crawl.maxLlmCalls") - state.llm_calls),
        seconds_remaining=max(0, int(settings.int("crawl.timeBudgetSec") - (clock.monotonic() - state.started))),
        sitemap_len=len(state.entries),
        sitemap_sample=wrap_untrusted(sample, "WEB_CONTENT"),
        links_block=wrap_untrusted(links_block, "WEB_CONTENT"),
        search_box=hints.get("search_box", False),
        pagination=hints.get("pagination", False),
        tag_cloud=hints.get("tag_cloud", []),
    )
    if state.focus is None:
        return prompt
    head = prompt[:-len(_REPLY.format())] if prompt.endswith(_REPLY.format()) else prompt
    excerpt_block = wrap_untrusted(" ".join((excerpt or "").split())[:EXCERPT_CHARS], "WEB_CONTENT")
    return (head + _focus_block(state) + "Excerpt of the page just visited:\n" + excerpt_block + "\n\n"
            + _FOCUS_REPLY.format())


def _parse_keep(content: str) -> Optional[bool]:
    """The answer's ``keep`` when it is a JSON boolean; None otherwise (the page is then judged
    by the title triage)."""
    m = re.search(r"\{.*\}", content, re.DOTALL)
    try:
        data = json.loads(m.group(0)) if m else None
    except ValueError:
        return None
    keep = data.get("keep") if isinstance(data, dict) else None
    return keep if isinstance(keep, bool) else None


def _parse_decision(content: str) -> Optional[tuple[str, list[int], str]]:
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    action = str(data.get("action") or "stop").lower()
    if action not in ("stop", "follow"):
        action = "stop"
    raw = data.get("indices") or []
    indices = [int(i) for i in raw if isinstance(i, (int, str)) and str(i).isdigit()] if isinstance(raw, list) else []
    return action, indices, str(data.get("reason") or "")[:200]


async def llm_decide(llm: Any, prompt: str, state: _State) -> tuple[str, list[int], str]:
    """(action, 1-based indices, reason). One stricter request when the answer is not JSON;
    an exception from the model is never retried."""
    for strict in (False, True):
        state.llm_calls += 1
        try:
            with llm_purpose("tradecraft_ingest", step="crawl"):
                resp = await llm.ainvoke(prompt + (_STRICT_SUFFIX if strict else ""))
        except Exception as exc:
            raise _ModelFailed(error_code_of(exc)) from exc
        content = normalize_content(getattr(resp, "content", "") or "").strip()
        decision = _parse_decision(content)
        if decision is not None:
            state.keep = _parse_keep(content) if state.focus is not None else None
            state.keep_reason = decision[2]
            return decision
    return "parse_error", [], ""


# --------------------------------------------------------------------------------------
# Auto: the sitemap as the map
# --------------------------------------------------------------------------------------

Skip = Callable[[str, str], None]
# The filter yields to the event loop this often while it judges a sitemap's URLs.
_YIELD_EVERY = 500


@dataclass
class SitemapMap:
    entries: list[Candidate] = field(default_factory=list)
    # Where the pages came from: configured, robots or sitemap.xml ("" when none listed any).
    source: str = ""
    # Cut at knownTypes.maxMapEntries.website.
    cut: bool = False
    # Why the reading stopped early: time_budget, cancelled, sitemap_limit, or "".
    stopped: str = ""


async def sitemap_entries(base: str, settings: EffectiveSettings, *, rules: FollowRules,
                          robots_cache: robots.RobotsCache, skip: Optional[Skip] = None,
                          blocking: Blocking = inline, should_stop: Optional[builders.Stop] = None) -> SitemapMap:
    """The map Auto takes from the site's sitemaps: the resource's own sitemap URLs
    (``type.website.sitemapUrls``, relative ones against the start URL), else the ones
    robots.txt names, else ``/sitemap.xml`` when the resource names none (§6.5); the first
    source that lists any page is the one used. Every entry passes the follow rules, and
    robots.txt when ``crawl.respectRobots`` is on; ``skip(reason, url)`` hears about the others.

    The reading stops as soon as the map is full (``knownTypes.maxMapEntries.website``), within
    one ``builders.SitemapBudget`` for the whole reading, and asks ``should_stop`` before each
    download; it never holds more than one sitemap's URLs at a time."""
    robots_txt = await robots_cache.get(base)
    cap = settings.int("knownTypes.maxMapEntries.website")
    respect_robots = settings.bool("crawl.respectRobots")
    budget = builders.SitemapBudget(should_stop)
    configured = [urllib.parse.urljoin(base, u.strip()) for u in settings.list("type.website.sitemapUrls") if u.strip()]
    sources = [("configured", configured), ("robots", robots_txt.sitemaps)]
    if not configured:
        sources.append(("sitemap.xml", [f"{robots.origin_of(base)}/sitemap.xml"]))
    out = SitemapMap()
    seen: set[str] = set()
    for source, named in sources:
        listed = False
        for sm in named[: int(constant("sitemapMaxChildren"))]:
            async for batch in builders.iter_sitemap_urls(sm, settings, budget=budget, blocking=blocking):
                listed = listed or bool(batch)
                for i, raw in enumerate(batch):
                    if i % _YIELD_EVERY == _YIELD_EVERY - 1:
                        await asyncio.sleep(0)
                    url = rules.normalize(fetch.canonical_url(raw))
                    if url in seen:
                        continue
                    seen.add(url)
                    reason = rules.verdict(url)
                    if not reason and respect_robots and not await robots_cache.allows(url):
                        reason = "robots"
                    if reason:
                        if skip is not None:
                            skip(reason, url)
                        continue
                    if len(out.entries) >= cap:
                        out.cut = True
                        break
                    out.entries.append(Candidate(url, builders.title_from_slug(url, strip_html=True), "sitemap", url))
                if out.cut:
                    break
            if out.cut or budget.stopped:
                break
        if listed:
            out.source = source
        if listed or out.cut or budget.stopped:
            break
    out.stopped = budget.stopped
    return out


# --------------------------------------------------------------------------------------
# The crawl
# --------------------------------------------------------------------------------------

def start_pages(base: str, settings: EffectiveSettings) -> list[str]:
    """The resource's URL, then its extra start pages (§6.5), relative ones against it: same
    site only (the same host, with or without ``www.``), each once."""
    out = [base]
    for raw in settings.list("type.website.startPages"):
        try:
            url = fetch.canonical_url(urllib.parse.urljoin(base, raw.strip()))
        except ValueError:
            continue
        if fetch.entry_url_ok(url) and _bare(_host(url)) == _bare(_host(base)) and url not in out:
            out.append(url)
    return out


def exclude_patterns(settings: EffectiveSettings) -> list[str]:
    """``crawl.excludePaths``, without the ``page/N`` patterns when the resource follows
    pagination (§6.5): older posts sit behind "Older posts" links."""
    patterns = settings.list("crawl.excludePaths")
    if not settings.bool("type.website.followPagination"):
        return patterns
    return [p for p in patterns if not p.strip().lstrip("/").lower().startswith("page/")]


async def crawl(url: str, settings: EffectiveSettings, *, fetch_page: Optional[FetchPage] = None, llm: Any = None,
                blocking: Blocking = inline, cancel_check: Optional[CancelCheck] = None,
                progress: Optional[Progress] = None, allow_browser: bool = True, focus: Any = None,
                started: Optional[float] = None) -> CrawlResult:
    """``allow_browser`` is False for a resource with a login (§5): its pages are read with
    plain HTTP only, whatever the browser settings say. ``focus`` is the resource's
    ``ingest.focus.Focus``; only a Focused one with something to judge by changes the crawl.
    ``started`` (``clock.monotonic()``) is when the time budget began, when that was before the
    crawl: a docs site's sitemap reading and the crawl it hands on to share one budget."""
    fetch_page = fetch_page or fetch_page_for(settings, allow_browser=allow_browser)
    base = fetch.canonical_url(url)
    if not _host(base):
        return CrawlResult(stop_reason="frontier_empty", stopped_because="invalid base url")
    starts = start_pages(base, settings)
    state = _State(base=base, rules=FollowRules(settings, starts, exclude_patterns(settings)),
                   started=clock.monotonic() if started is None else started)
    state.starts = starts
    if focus is not None and focus.filters:
        from tradecraft.ingest import focus as focus_mod
        state.focus, state.matchers = focus, focus_mod.keyword_matchers(focus)
    strategy = settings.str("crawl.strategy")
    respect_robots = settings.bool("crawl.respectRobots")
    robots_cache = robots.RobotsCache(settings)

    if strategy == "auto":
        budget_sec = settings.int("crawl.timeBudgetSec")

        async def should_stop() -> str:
            if cancel_check is not None and await cancel_check():
                return "cancelled"
            return "time_budget" if clock.monotonic() - state.started >= budget_sec else ""

        found = await sitemap_entries(state.base, settings, rules=state.rules, robots_cache=robots_cache,
                                      skip=state.skip, blocking=blocking, should_stop=should_stop)
        elapsed = int(clock.monotonic() - state.started)
        stats = {"pages_fetched": 0, "llm_calls": 0, "elapsed_sec": elapsed, "strategy": "auto"}
        if found.stopped in ("cancelled", "time_budget") and (found.stopped == "cancelled" or not found.entries):
            logger.info(f"[tradecraft] crawl done strategy=auto stop={found.stopped} entries={len(found.entries)}")
            return CrawlResult(stop_reason=found.stopped, stopped_because=found.stopped.replace("_", " "),
                               stats=stats, skipped=state.skipped(), report_stop=f"auto: {found.stopped}")
        if found.entries:
            stop = "max_map_entries" if found.cut else ("time_budget" if found.stopped == "time_budget" else "sitemap")
            logger.info(f"[tradecraft] crawl done strategy=auto source={found.source} entries={len(found.entries)} "
                        f"stop={stop}")
            because = (f"auto: {found.source} ({len(found.entries)} pages"
                       f"{', map limit' if found.cut else ', time budget' if stop == 'time_budget' else ''})")
            return CrawlResult(entries=found.entries, stop_reason=stop, stopped_because=because, stats=stats,
                               skipped=state.skipped(), report_stop=because)
        logger.info("[tradecraft] crawl auto found no usable sitemap: llm-guided")
        result = await _loop(state, settings, "llm", fetch_page, llm, blocking, cancel_check, progress,
                             robots_cache if respect_robots else None)
        result.report_stop = f"auto: no usable sitemap, llm-guided ({result.stop_reason})"
        return result
    return await _loop(state, settings, strategy, fetch_page, llm, blocking, cancel_check, progress,
                       robots_cache if respect_robots else None)


def _keep_or_drop(entry: Candidate, state: _State) -> None:
    """The model's keep decision on the page its call was about. None leaves the page to the
    title triage; a dropped page stays in the map's table with its reason (§6.14)."""
    from tradecraft.ingest import focus as focus_mod

    if state.keep is True:
        entry.extra["focus_decision"] = "keep"
    elif state.keep is False:
        entry.extra.update(status="dropped", dropped_by="focus", focus_decision="drop",
                           drop_reason=(" ".join(state.keep_reason.split()) or focus_mod.MODEL_DROP_REASON)
                           [:focus_mod.REASON_MAX])


async def _loop(state: _State, settings: EffectiveSettings, strategy: str, fetch_page: FetchPage, llm: Any,
                blocking: Blocking, cancel_check: Optional[CancelCheck], progress: Optional[Progress],
                robots_cache: Optional[robots.RobotsCache]) -> CrawlResult:
    state.frontier.extend((s, 0) for s in state.starts)
    starts = set(state.starts)
    # The start pages are always visited: ahead of any link the focus ranks.
    state.scores.update({s: 1 << 30 for s in starts})
    max_pages, max_calls = settings.int("crawl.maxPages"), settings.int("crawl.maxLlmCalls")
    budget, max_depth = settings.int("crawl.timeBudgetSec"), settings.int("crawl.maxDepth")
    map_cap = settings.int("knownTypes.maxMapEntries.website")
    links_limit = None if strategy == "rules" else settings.int("crawl.linksPerPage")
    ignore_stop_until = (settings.int("crawl.ignoreStopUntilPages")
                         if settings.str("crawl.onLlmStop") == "ignoreUntil" else 0)
    parallel = settings.int("crawl.parallel")
    semaphore = asyncio.Semaphore(parallel)
    pacer = Pacer(settings.number("crawl.delaySec"))
    guided = strategy == "llm"
    stop_reason, stopped_because, error_code = "", "", ""

    async def fetch_one(target: str) -> CrawlFetch:
        async with semaphore:
            await pacer.wait()
            return await fetch_page(target)

    while state.frontier and not stop_reason:
        if cancel_check is not None and await cancel_check():
            stop_reason, stopped_because = "cancelled", "cancelled"
            break
        if state.pages_fetched >= max_pages:
            stop_reason, stopped_because = "max_pages", "max pages"
            break
        if guided and llm is not None and state.llm_calls >= max_calls:
            stop_reason, stopped_because = "max_llm_calls", "max llm calls"
            break
        if clock.monotonic() - state.started >= budget:
            stop_reason, stopped_because = "time_budget", "time budget"
            break
        if len(state.entries) >= map_cap:
            stop_reason, stopped_because = "max_map_entries", "max map entries"
            break
        batch: list[tuple[str, int]] = []
        while state.frontier and len(batch) < min(parallel, max_pages - state.pages_fetched):
            current, depth = state.frontier.pop(0)
            if current in state.visited:
                continue
            state.visited.add(current)
            if robots_cache is not None and not await robots_cache.allows(current):
                state.skip("robots", current)
                continue
            batch.append((current, depth))
        if not batch:
            continue
        fetched = await asyncio.gather(*(fetch_one(u) for u, _d in batch))

        for (current, depth), got in zip(batch, fetched):
            state.pages_fetched += 1
            if got.truncated:
                state.too_large += 1
            # A redirect target is the same page: never fetch it a second time.
            final = fetch.canonical_url(got.final_url or current)
            state.visited.add(final)
            if current in starts and final != current:
                state.rules.adopt(current, final)
            if progress is not None:
                await progress(state.pages_fetched, max_pages)
            if not got.html:
                continue
            meta = await blocking(page_meta, got.html, got.final_url or current)
            reason = keep_reason(meta, settings) or state.rules.verdict(current)
            entry: Optional[Candidate] = None
            if reason:
                state.skip(reason, current)
            elif len(state.entries) < map_cap:
                entry = Candidate(current, meta["title"], "crawl", current,
                                  {"html": got.html, "final_url": final, "tier": got.tier})
                state.entries.append(entry)
            if stop_reason:
                # A decision earlier in this batch ended the crawl: its other pages were already
                # downloaded, so they are still kept, but nothing more is followed.
                continue
            if guided and llm is None:
                stop_reason, stopped_because = "no_llm", "no llm available"
                continue
            candidates = follow_candidates(meta, state, settings, links_limit)
            logger.info(f"[tradecraft] crawl page {state.pages_fetched}/{max_pages} depth={depth} tier={got.tier} "
                        f"candidates={len(candidates)}")
            if depth + 1 > max_depth or not candidates:
                continue
            if not guided:
                state.enqueue(candidates, depth + 1)
                continue
            if state.llm_calls >= max_calls:
                continue
            try:
                action, indices, why = await llm_decide(
                    llm, build_prompt(state, settings, current, depth, candidates, meta["hints"],
                                      excerpt=meta.get("body_text", "")), state)
            except _ModelFailed as failed:
                stop_reason, stopped_because, error_code = "llm_error", f"model error: {failed.code}", failed.code
                continue
            if action == "parse_error":
                stop_reason, stopped_because = "llm_parse_error", "llm json parse failure"
                continue
            if entry is not None and state.focus is not None:
                _keep_or_drop(entry, state)
            if action == "stop":
                if state.pages_fetched < ignore_stop_until:
                    logger.info(f"[tradecraft] crawl stop ignored at page {state.pages_fetched}")
                    continue
                stop_reason, stopped_because = "llm_stop", why or "llm stop"
                continue
            state.enqueue([candidates[idx - 1] for idx in indices if 1 <= idx <= len(candidates)], depth + 1)

    if not stop_reason:
        stop_reason, stopped_because = "frontier_empty", "frontier empty"
    elapsed = int(clock.monotonic() - state.started)
    logger.info(f"[tradecraft] crawl done strategy={strategy} pages={state.pages_fetched} calls={state.llm_calls} "
                f"elapsed={elapsed}s stop={stop_reason}")
    return CrawlResult(
        entries=state.entries, stop_reason=stop_reason, stopped_because=stopped_because,
        stats={"pages_fetched": state.pages_fetched, "llm_calls": state.llm_calls, "elapsed_sec": elapsed,
               "strategy": strategy},
        skipped=state.skipped(),
        error_code=error_code,
        errors={fetch.PAGE_TOO_LARGE: state.too_large} if state.too_large else {},
    )
