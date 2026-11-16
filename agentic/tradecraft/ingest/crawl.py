"""The model-guided crawl of a website (port of 1.x ``tradecraft_crawl.agentic_crawl``).

The loop is 1.x's: fetch a page (plain GET, the browser when the page is small), keep it in
the map when it has a title and enough text, offer its same-host links to the model, follow
the ones it picks, until a limit or the model stops. What changed:

- every limit is a ``crawl.*`` setting (200 pages, 20 model calls, 180 s, depth 3, 20 links
  per page, more than 500 characters, a title; R-006) and time comes from ``clock``;
- an exclude pattern matches at the start of ANY path segment, so ``tag/`` drops
  ``/blog/tag/x`` too (R-009): ``*`` is any characters, and a pattern that starts with ``*.``
  (a file extension) must reach the end of the path;
- the model call carries the ``tradecraft_ingest`` purpose and is never retried after an
  exception (TD-20): an answer that is not JSON gets one stricter request, an error stops
  the crawl with its code;
- keeping a page and following its links are separate decisions (``keep_reason``,
  ``follow_candidates``), which the focus (T5.2) extends;
- a kept page carries its HTML, so the pipeline stores it without a second download.
"""

from __future__ import annotations

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
from tradecraft import clock, net
from tradecraft.contract import ERROR_CODES
from tradecraft.ingest import fetch
from tradecraft.ingest.builders import Blocking, Candidate, inline
from tradecraft.settings import EffectiveSettings

logger = get_logger(__name__)


@dataclass
class CrawlFetch:
    html: str
    final_url: str
    tier: int = 1
    error: str = ""


FetchPage = Callable[[str], Awaitable[CrawlFetch]]
CancelCheck = Callable[[], Awaitable[bool]]
Progress = Callable[[int, int], Awaitable[None]]


@dataclass
class CrawlResult:
    entries: list[Candidate] = field(default_factory=list)
    # A code for the report: max_pages max_llm_calls time_budget frontier_empty no_llm llm_stop
    # llm_error llm_parse_error cancelled.
    stop_reason: str = ""
    # 1.x's crawl_stopped_because text (the model's own reason when it stopped).
    stopped_because: str = ""
    # 1.x's crawl_stats: pages_fetched, llm_calls, elapsed_sec.
    stats: dict = field(default_factory=dict)
    skipped: dict = field(default_factory=lambda: {"excluded": 0, "outOfScope": 0, "tooLittleText": 0})
    # A job error code when a model call failed (budget, loop model, unavailable).
    error_code: str = ""

    @property
    def llm_calls(self) -> int:
        return int(self.stats.get("llm_calls", 0))


# --------------------------------------------------------------------------------------
# Path patterns
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


# --------------------------------------------------------------------------------------
# Fetching a crawl page
# --------------------------------------------------------------------------------------

def fetch_page_for(settings: EffectiveSettings, *, allow_browser: bool = True) -> FetchPage:
    """The crawl's fetch: a plain GET of an HTML page, the browser when the HTML is under
    ``fetching.crawlBrowserBelowBytes`` (4,000, as 1.x); a refused address never goes to the
    browser, which would follow the same redirect."""

    async def fetch_page(url: str) -> CrawlFetch:
        resp = await fetch.fetch_raw(url, settings, headers={"Accept": "text/html,application/xhtml+xml"})
        if resp.error in ("unsafe_address", "userinfo_refused", "bad_url"):
            return CrawlFetch("", url, 0, resp.error)
        html = resp.text if (resp.status == 200 and "html" in resp.content_type) else ""
        if html and len(html) >= settings.int("fetching.crawlBrowserBelowBytes"):
            return CrawlFetch(html, resp.final_url or url, 1)
        if not (allow_browser and settings.bool("fetching.browserEnabled")):
            return CrawlFetch(html, resp.final_url or url, 1 if html else 0, "" if html else (resp.error or "http_error"))
        rendered = await net.get_fetcher().render(
            url, timeout=float(settings.int("fetching.browserTimeoutSec")),
            wait_until=settings.str("fetching.browserWaitUntil"),
            max_chars=settings.int("fetching.browserMaxChars"))
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
    """{title, body_text, links[{title, href}], hints}: 1.x's ``_extract_links_and_meta``."""
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
    links: list[dict[str, str]] = []
    for a in links_soup.find_all("a", href=True):
        absolute = resolve_link(base_url, a.get("href") or "", base_href)
        if absolute is None:
            continue
        canon = fetch.canonical_url(absolute)
        if canon in seen:
            continue
        seen.add(canon)
        anchor = (a.get_text(strip=True) or a.get("title") or canon)[:80]
        links.append({"title": anchor, "href": canon})
    hints = {
        "search_box": bool(links_soup.find("input", {"type": "search"}) or links_soup.select_one("[role='search']")),
        "pagination": bool(re.search(r"older posts|next page|page/\d+", html or "", re.IGNORECASE)),
        "tag_cloud": [(a.get_text(strip=True) or "").lower()
                      for a in links_soup.select(".tag, .tags a, .tag-cloud a")[:8] if a.get_text(strip=True)],
    }
    return {"title": title, "body_text": body_text, "links": links, "hints": hints}


def keep_reason(meta: dict[str, Any], settings: EffectiveSettings) -> str:
    """"" when the page enters the map, else the report's skip reason."""
    if settings.bool("crawl.requireTitle") and not meta.get("title"):
        return "tooLittleText"
    if len(meta.get("body_text") or "") <= settings.int("crawl.minTextChars"):
        return "tooLittleText"
    return ""


_LOCAL_SUFFIXES = (".local", ".internal")


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


@dataclass
class _State:
    base: str
    host: str
    visited: set = field(default_factory=set)
    frontier: list = field(default_factory=list)
    entries: list = field(default_factory=list)
    pages_fetched: int = 0
    llm_calls: int = 0
    started: float = 0.0
    excluded: set = field(default_factory=set)
    out_of_scope: set = field(default_factory=set)
    too_little: int = 0


def follow_candidates(meta: dict[str, Any], state: _State, settings: EffectiveSettings,
                      exclude: PathMatcher, include: PathMatcher) -> list[dict[str, str]]:
    """The page's links the model may pick: same host, not excluded, not seen, at most
    ``crawl.linksPerPage``."""
    out: list[dict[str, str]] = []
    queued = {f for f, _d in state.frontier}
    limit = settings.int("crawl.linksPerPage")
    for link in meta["links"]:
        href = link.get("href") or ""
        if not href or net.url_problem(href):
            continue
        host = _host(href)
        if host != state.host:
            state.out_of_scope.add(href)
            continue
        if host in ("localhost",) or host.endswith(_LOCAL_SUFFIXES):
            continue
        if exclude.matches(href) or (include and not include.matches(href)):
            state.excluded.add(href)
            continue
        if href in state.visited or href in queued:
            continue
        out.append({"title": link.get("title", ""), "href": href})
        if len(out) >= limit:
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


class _ModelFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def error_code_of(exc: BaseException) -> str:
    """A model error as a job error code (the budget and the loop refusal carry their own)."""
    code = getattr(exc, "code", "")
    return code if isinstance(code, str) and code in ERROR_CODES else "model_unavailable"


def build_prompt(state: _State, settings: EffectiveSettings, current: str, depth: int,
                 candidates: list[dict[str, str]], hints: dict[str, Any]) -> str:
    sample = "\n".join(f"  - {e.title}" for e in state.entries[-10:]) or "  (none yet)"
    links_block = "\n".join(
        f"  {i + 1}. \"{c.get('title', '')[:80]}\" -> {urllib.parse.urlsplit(c['href']).path or c['href']}"
        for i, c in enumerate(candidates)) or "  (none)"
    return _PROMPT_TEMPLATE.format(
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
        decision = _parse_decision(normalize_content(getattr(resp, "content", "") or "").strip())
        if decision is not None:
            return decision
    return "parse_error", [], ""


# --------------------------------------------------------------------------------------
# The crawl
# --------------------------------------------------------------------------------------

async def crawl(url: str, settings: EffectiveSettings, *, fetch_page: Optional[FetchPage] = None, llm: Any = None,
                blocking: Blocking = inline, cancel_check: Optional[CancelCheck] = None,
                progress: Optional[Progress] = None) -> CrawlResult:
    fetch_page = fetch_page or fetch_page_for(settings)
    base = fetch.canonical_url(url)
    host = _host(base)
    if not host:
        return CrawlResult(stop_reason="frontier_empty", stopped_because="invalid base url")
    state = _State(base=base, host=host, started=clock.monotonic())
    state.frontier.append((base, 0))
    exclude = PathMatcher(settings.list("crawl.excludePaths"))
    include = PathMatcher(settings.list("crawl.includePaths"))
    max_pages, max_calls = settings.int("crawl.maxPages"), settings.int("crawl.maxLlmCalls")
    budget, max_depth = settings.int("crawl.timeBudgetSec"), settings.int("crawl.maxDepth")
    stop_reason, stopped_because, error_code = "", "", ""

    while state.frontier:
        if cancel_check is not None and await cancel_check():
            stop_reason, stopped_because = "cancelled", "cancelled"
            break
        if state.pages_fetched >= max_pages:
            stop_reason, stopped_because = "max_pages", "max pages"
            break
        if llm is not None and state.llm_calls >= max_calls:
            stop_reason, stopped_because = "max_llm_calls", "max llm calls"
            break
        if clock.monotonic() - state.started >= budget:
            stop_reason, stopped_because = "time_budget", "time budget"
            break
        current, depth = state.frontier.pop(0)
        if current in state.visited:
            continue
        state.visited.add(current)
        got = await fetch_page(current)
        state.pages_fetched += 1
        # A redirect target is the same page: never fetch it a second time.
        final = fetch.canonical_url(got.final_url or current)
        state.visited.add(final)
        if progress is not None:
            await progress(state.pages_fetched, max_pages)
        if not got.html:
            continue
        meta = await blocking(page_meta, got.html, got.final_url or current)
        reason = keep_reason(meta, settings)
        if reason:
            state.too_little += 1
        else:
            state.entries.append(Candidate(current, meta["title"], "crawl", current,
                                           {"html": got.html, "final_url": final, "tier": got.tier}))
        if llm is None:
            stop_reason, stopped_because = "no_llm", "no llm available"
            break
        candidates = follow_candidates(meta, state, settings, exclude, include)
        logger.info(f"[tradecraft] crawl page {state.pages_fetched}/{max_pages} depth={depth} tier={got.tier} "
                    f"candidates={len(candidates)}")
        if depth + 1 > max_depth or not candidates:
            continue
        try:
            action, indices, why = await llm_decide(
                llm, build_prompt(state, settings, current, depth, candidates, meta["hints"]), state)
        except _ModelFailed as failed:
            stop_reason, stopped_because, error_code = "llm_error", f"model error: {failed.code}", failed.code
            break
        if action == "parse_error":
            stop_reason, stopped_because = "llm_parse_error", "llm json parse failure"
            break
        if action == "stop":
            stop_reason, stopped_because = "llm_stop", why or "llm stop"
            break
        for idx in indices:
            if 1 <= idx <= len(candidates):
                state.frontier.append((candidates[idx - 1]["href"], depth + 1))

    if not stop_reason:
        stop_reason, stopped_because = "frontier_empty", "frontier empty"
    elapsed = int(clock.monotonic() - state.started)
    logger.info(f"[tradecraft] crawl done pages={state.pages_fetched} calls={state.llm_calls} "
                f"elapsed={elapsed}s stop={stop_reason}")
    return CrawlResult(
        entries=state.entries, stop_reason=stop_reason, stopped_because=stopped_because,
        stats={"pages_fetched": state.pages_fetched, "llm_calls": state.llm_calls, "elapsed_sec": elapsed},
        skipped={"excluded": len(state.excluded), "outOfScope": len(state.out_of_scope),
                 "tooLittleText": state.too_little},
        error_code=error_code,
    )
