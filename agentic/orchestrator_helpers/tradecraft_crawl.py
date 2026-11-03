"""
Agentic crawl fallback for the Tradecraft Lookup tool.

When `_detect_type` returns `agentic-crawl`, this bounded LLM-driven
Playwright loop runs once at verify time to build a sitemap of the
user-added knowledge URL. Hard caps on pages, LLM calls, time, and depth.

Designed as a swappable interface so a future v2 can drop in `browser-use`
behind the same `agentic_crawl(url, bounds, llm, mcp_manager) -> CrawlResult`
function signature.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from logging_config import get_logger
from orchestrator_helpers.json_utils import normalize_content
from orchestrator_helpers.web_sources import document_base_href, resolve_link
from prompt_safety import wrap_untrusted, UNTRUSTED_OUTPUT_GUIDANCE

logger = get_logger(__name__)

USER_AGENT = "RedAmon-Tradecraft/1.0"

# Junk path patterns (auth pages, archives, metadata). Borrowed from tradecraft_lookup.
NOISE_PATH_PATTERNS = re.compile(
    r"^/?(login|signup|register|privacy|cookies|contact|about|tos|terms|"
    r"author/|tag/|category/|page/\d+|feed|rss|sitemap|search)",
    re.IGNORECASE,
)
NOISE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".otf",
    ".zip", ".tar", ".gz", ".7z", ".mp4", ".mp3",
)


@dataclass
class CrawlResult:
    sitemap_entries: List[Dict[str, str]] = field(default_factory=list)
    stopped_because: str = ""
    stats: Dict[str, Any] = field(default_factory=dict)


@dataclass
class _CrawlState:
    base_host: str
    visited: set = field(default_factory=set)
    frontier: List[Tuple[str, int]] = field(default_factory=list)
    sitemap: List[Dict[str, str]] = field(default_factory=list)
    pages_fetched: int = 0
    llm_calls: int = 0
    started_at: float = field(default_factory=time.time)


def _canonicalize(url: str) -> str:
    try:
        u = urllib.parse.urlsplit(url)
        scheme = (u.scheme or "https").lower()
        netloc = u.netloc.lower()
        path = u.path or "/"
        qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        qs.sort()
        query = urllib.parse.urlencode(qs)
        return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return url


def _looks_like_noise(href: str) -> bool:
    if not href:
        return True
    if href.startswith(("mailto:", "javascript:", "tel:", "#")):
        return True
    lower = href.lower()
    for ext in NOISE_EXTENSIONS:
        if lower.endswith(ext):
            return True
    try:
        path = urllib.parse.urlsplit(href).path or "/"
        if NOISE_PATH_PATTERNS.match(path):
            return True
    except Exception:
        return True
    return False


def _same_host(href: str, base_host: str) -> bool:
    try:
        u = urllib.parse.urlsplit(href)
        return (u.hostname or "").lower() == base_host
    except Exception:
        return False


def _is_private_host(host: str) -> bool:
    """Lightweight private-IP check; defers heavier validation to caller."""
    if not host:
        return True
    h = host.lower()
    if h in ("localhost", "::1") or h.endswith(".local") or h.endswith(".internal"):
        return True
    return False


async def _http_fetch(url: str, timeout: int = 15, max_redirects: int = 5) -> Tuple[str, str]:
    """Plain Tier 1 HTTP fetch. Returns (html, final_url), or ('', url) on failure.

    The final URL (after redirects) is what relative links on the page resolve
    against.

    Used by the crawl loop FIRST so static blogs / news sites / writeup pages
    get fast unencumbered fetches. Falls back to Playwright only when the
    response is thin or non-HTML.

    STRIDE I18: redirects are followed MANUALLY so every hop's URL is checked by
    the SSRF guard. httpx's built-in follow_redirects hides the redirect target,
    letting a public page 302 the fetch into 169.254.169.254 / an RFC-1918 host;
    following hops by hand lets us re-validate each one. The pinned transport
    re-checks at connect time, which also closes DNS rebinding.

    Raises ``UnsafeFetchURLError`` when the guard refuses a hop, instead of
    returning '': the caller must not retry that URL in the browser.
    """
    from .fetch_guard import assert_safe_fetch_url, pinned_async_transport, UnsafeFetchURLError

    try:
        import httpx as _httpx  # local import keeps top-of-module deps clean

        current = url
        async with _httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml",
            },
            transport=pinned_async_transport(),
        ) as client:
            for _hop in range(max_redirects + 1):
                assert_safe_fetch_url(current)
                resp = await client.get(current)
                if resp.is_redirect:
                    loc = resp.headers.get("location")
                    if not loc:
                        return "", url
                    current = str(resp.url.join(loc))
                    continue
                ct = (resp.headers.get("content-type") or "").lower()
                if resp.status_code != 200 or "html" not in ct:
                    return "", url
                return resp.text, current
            logger.warning(f"[tradecraft] crawl too many redirects for url={url}")
            return "", url
    except UnsafeFetchURLError as e:
        logger.warning(f"[tradecraft] crawl blocked SSRF url={url}: {e}")
        raise
    except Exception as e:
        logger.debug(f"[tradecraft] crawl http fetch error url={url} err={e}")
        return "", url


async def _crawl_fetch(url: str, mcp_manager, *, tier1_threshold_bytes: int = 4000) -> Tuple[str, int, str]:
    """Tier-1-first fetch for the crawl loop.

    Returns (html, tier_used, final_url). Tries raw HTTP first; if response is < threshold
    bytes (likely a JS-only shell or empty body), escalates to Playwright MCP
    for full rendering. The threshold is intentionally higher than Tier 1's
    800-byte default for tradecraft fetches because crawl pages need many
    visible links, not just any content.
    """
    # STRIDE I18: refuse an unsafe seed/frontier URL before EITHER fetcher runs,
    # so a blocked HTTP fetch can't fall through to the Playwright (sandbox) path
    # and reach the same internal address.
    from .fetch_guard import is_safe_fetch_url, UnsafeFetchURLError
    if not is_safe_fetch_url(url):
        logger.warning(f"[tradecraft] crawl skipping unsafe url={url}")
        return "", 0, url

    try:
        html, final_url = await _http_fetch(url)
    except UnsafeFetchURLError:
        # A public URL that redirected or re-resolved into an internal address.
        # The browser would follow that same redirect, so do not fall back.
        return "", 0, url
    if html and len(html) >= tier1_threshold_bytes:
        return html, 1, final_url
    # Fallback to Playwright (handles SPAs, login walls, anti-bot challenges).
    # The guarded browser script does not report where redirects ended, so
    # links on a rendered page resolve against the requested URL.
    rendered = await _playwright_fetch(url, mcp_manager)
    return rendered, 2 if rendered else 0, url


async def _playwright_fetch(url: str, mcp_manager) -> str:
    """Fetch a URL via the existing execute_playwright MCP tool. Returns rendered HTML, or "" on failure."""
    if mcp_manager is None:
        return ""
    try:
        tools = await mcp_manager.get_tools()
    except Exception as e:
        logger.warning(f"[tradecraft] crawl mcp tools error: {type(e).__name__}: {e}")
        return ""
    playwright = next((t for t in tools if getattr(t, "name", "") == "execute_playwright"), None)
    if playwright is None:
        return ""
    from .fetch_guard import guarded_browser_script, parse_guarded_browser_output
    try:
        out = await playwright.ainvoke({"script": guarded_browser_script(url)})
    except Exception as e:
        logger.warning(f"[tradecraft] crawl playwright error url={url} err={type(e).__name__}: {e}")
        return ""
    text = ""
    if isinstance(out, str):
        text = out
    elif isinstance(out, list):
        for it in out:
            if isinstance(it, dict) and "text" in it:
                text += it["text"]
    elif isinstance(out, dict) and "text" in out:
        text = out["text"]
    html, blocked = parse_guarded_browser_output(text)
    if blocked:
        logger.warning(f"[tradecraft] crawl playwright blocked url={url}: {blocked}")
    return html


def _extract_links_and_meta(html: str, base_url: str) -> Dict[str, Any]:
    """Return {title, body_text, links[{title,href}], hints{search_box,pagination,tag_cloud}}."""
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return {"title": "", "body_text": html or "", "links": [], "hints": {}}
    soup = BeautifulSoup(html or "", "html.parser")
    # Title
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    if not title:
        h1 = soup.find("h1")
        title = h1.get_text(strip=True) if h1 else ""
    # Drop noise containers before extracting body text
    for sel in ["nav", "footer", "header", "aside", "script", "style", "form", "iframe"]:
        for el in soup.select(sel):
            el.decompose()
    body_text = soup.get_text(" ", strip=True)
    # Links from the (stripped) page; but for navigation we want links from
    # the original document including nav, so re-soup the original HTML once
    # for href harvesting only.
    soup2 = BeautifulSoup(html or "", "html.parser")
    base_href = document_base_href(soup2)
    links_seen: set = set()
    links: List[Dict[str, str]] = []
    for a in soup2.find_all("a", href=True):
        absolute = resolve_link(base_url, a.get("href") or "", base_href)
        if absolute is None:
            continue
        canon = _canonicalize(absolute)
        if canon in links_seen:
            continue
        links_seen.add(canon)
        anchor = a.get_text(strip=True)
        if not anchor:
            anchor = a.get("title") or canon
        anchor = (anchor or "")[:80]
        links.append({"title": anchor, "href": canon})
    # Hints
    hints = {
        "search_box": bool(soup2.find("input", {"type": "search"}) or soup2.select_one("[role='search']")),
        "pagination": bool(re.search(r"older posts|next page|page/\d+", html or "", re.IGNORECASE)),
        "tag_cloud": [
            (a.get_text(strip=True) or "").lower()
            for a in soup2.select(".tag, .tags a, .tag-cloud a")[:8]
            if a.get_text(strip=True)
        ],
    }
    return {"title": title, "body_text": body_text, "links": links, "hints": hints}


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


async def _llm_decide(
    *,
    llm,
    base_url: str,
    current_url: str,
    depth: int,
    state: _CrawlState,
    bounds: Dict[str, int],
    candidates: List[Dict[str, str]],
    hints: Dict[str, Any],
    retry_strict: bool = False,
) -> Tuple[str, List[int], str]:
    """Returns (action, indices, reason). action is 'stop' or 'follow'."""
    pages_remaining = max(0, bounds.get("max_pages", 30) - state.pages_fetched)
    calls_remaining = max(0, bounds.get("max_llm_calls", 20) - state.llm_calls)
    seconds_remaining = max(0, int(bounds.get("time_budget_sec", 180) - (time.time() - state.started_at)))
    sample_titles = [e.get("title", "") for e in state.sitemap[-10:]]
    sitemap_sample = "\n".join(f"  - {t}" for t in sample_titles) or "  (none yet)"
    links_block = "\n".join(
        f"  {i+1}. \"{c.get('title','')[:80]}\" -> {urllib.parse.urlsplit(c['href']).path or c['href']}"
        for i, c in enumerate(candidates[:20])
    ) or "  (none)"
    prompt = _PROMPT_TEMPLATE.format(
        base=base_url,
        current=current_url,
        depth=depth,
        pages_remaining=pages_remaining,
        calls_remaining=calls_remaining,
        seconds_remaining=seconds_remaining,
        sitemap_len=len(state.sitemap),
        sitemap_sample=wrap_untrusted(sitemap_sample, "WEB_CONTENT"),
        links_block=wrap_untrusted(links_block, "WEB_CONTENT"),
        search_box=hints.get("search_box", False),
        pagination=hints.get("pagination", False),
        tag_cloud=hints.get("tag_cloud", []),
    )
    if retry_strict:
        prompt += "\n\nReturn ONLY a single line of valid JSON. No prose, no fenced block."
    try:
        state.llm_calls += 1
        resp = await llm.ainvoke(prompt)
        content = normalize_content(getattr(resp, "content", "") or "").strip()
        # Strip code fences
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if not m:
            raise ValueError(f"no JSON object in LLM response: {content[:120]}")
        data = json.loads(m.group(0))
    except Exception as e:
        logger.warning(f"[tradecraft] crawl llm parse error: {type(e).__name__}: {e}")
        if not retry_strict:
            return await _llm_decide(
                llm=llm, base_url=base_url, current_url=current_url, depth=depth,
                state=state, bounds=bounds, candidates=candidates, hints=hints,
                retry_strict=True,
            )
        return ("stop", [], f"llm json parse failure: {e}")
    action = (data.get("action") or "stop").lower()
    if action not in ("stop", "follow"):
        action = "stop"
    indices = data.get("indices") or []
    if not isinstance(indices, list):
        indices = []
    indices = [int(i) for i in indices if isinstance(i, (int, str)) and str(i).isdigit()]
    reason = (data.get("reason") or "")[:200]
    return action, indices, reason


async def agentic_crawl(
    url: str,
    *,
    bounds: Dict[str, int],
    llm,
    mcp_manager,
) -> CrawlResult:
    """Bounded LLM-driven Playwright loop. Returns CrawlResult.

    bounds keys: max_pages, max_llm_calls, time_budget_sec, max_depth
    """
    base = _canonicalize(url)
    parsed = urllib.parse.urlsplit(base)
    base_host = (parsed.hostname or "").lower()
    if not base_host:
        return CrawlResult(stopped_because="invalid base url", stats={})
    state = _CrawlState(base_host=base_host)
    state.frontier.append((base, 0))
    max_pages = int(bounds.get("max_pages", 30))
    max_llm = int(bounds.get("max_llm_calls", 20))
    time_budget = int(bounds.get("time_budget_sec", 180))
    max_depth = int(bounds.get("max_depth", 3))

    if llm is None:
        # Without an LLM we cannot drive the loop. Return a single-page sitemap.
        html, _, final_url = await _crawl_fetch(base, mcp_manager)
        meta = _extract_links_and_meta(html, final_url)
        if meta["title"] and len(meta["body_text"]) > 500:
            state.sitemap.append({"title": meta["title"], "path": base})
        return CrawlResult(
            sitemap_entries=state.sitemap,
            stopped_because="no llm available",
            stats={"pages_fetched": 1, "llm_calls": 0, "elapsed_sec": int(time.time() - state.started_at)},
        )

    stopped = ""
    while state.frontier:
        if state.pages_fetched >= max_pages:
            stopped = "max pages"
            break
        if state.llm_calls >= max_llm:
            stopped = "max llm calls"
            break
        if (time.time() - state.started_at) >= time_budget:
            stopped = "time budget"
            break

        current, depth = state.frontier.pop(0)
        canon = _canonicalize(current)
        if canon in state.visited:
            continue
        state.visited.add(canon)

        # Tier-1-first fetch: try plain HTTP, fall back to Playwright on
        # thin / non-HTML / failed responses. Most static blogs return rich
        # HTML on Tier 1 and never need Playwright -> dramatically more
        # links per page than Playwright alone (which hits a 40k cap).
        html, fetch_tier, final_url = await _crawl_fetch(canon, mcp_manager)
        state.pages_fetched += 1
        # A redirect target is the same page: never fetch it a second time.
        state.visited.add(_canonicalize(final_url))
        if not html:
            continue
        meta = _extract_links_and_meta(html, final_url)
        title = meta["title"]
        body_text = meta["body_text"]
        # Add to sitemap if page has content
        if title and len(body_text) > 500:
            state.sitemap.append({"title": title, "path": canon})

        # Filter and dedupe candidate links
        candidates: List[Dict[str, str]] = []
        for link in meta["links"]:
            href = link.get("href") or ""
            if _looks_like_noise(href):
                continue
            if not _same_host(href, base_host):
                continue
            link_host = (urllib.parse.urlsplit(href).hostname or "").lower()
            if _is_private_host(link_host):
                continue
            if _canonicalize(href) in state.visited:
                continue
            if any(_canonicalize(href) == _canonicalize(f[0]) for f in state.frontier):
                continue
            candidates.append({"title": link.get("title", ""), "href": href})
            if len(candidates) >= 20:
                break

        logger.info(
            f"[tradecraft] crawl iter url={canon} depth={depth} "
            f"page={state.pages_fetched}/{max_pages} "
            f"tier={fetch_tier} html_bytes={len(html)} body_chars={len(body_text)} "
            f"raw_links={len(meta['links'])} candidates={len(candidates)}"
        )

        if depth + 1 > max_depth:
            # We can still mine the page but won't enqueue further.
            continue
        if not candidates:
            continue

        action, indices, reason = await _llm_decide(
            llm=llm,
            base_url=base,
            current_url=canon,
            depth=depth,
            state=state,
            bounds=bounds,
            candidates=candidates,
            hints=meta["hints"],
        )
        logger.info(
            f"[tradecraft] crawl iter action={action} indices={indices} reason={reason!r}"
        )
        if action == "stop":
            stopped = reason or "llm stop"
            break
        for idx in indices:
            i = idx - 1
            if 0 <= i < len(candidates):
                state.frontier.append((candidates[i]["href"], depth + 1))

    if not stopped:
        stopped = "frontier empty"

    elapsed = int(time.time() - state.started_at)
    logger.info(
        f"[tradecraft] crawl done url={base} pages={state.pages_fetched} "
        f"calls={state.llm_calls} elapsed={elapsed}s stopped_because={stopped}"
    )
    return CrawlResult(
        sitemap_entries=state.sitemap,
        stopped_because=stopped,
        stats={
            "pages_fetched": state.pages_fetched,
            "llm_calls": state.llm_calls,
            "elapsed_sec": elapsed,
        },
    )
