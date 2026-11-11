"""
Tradecraft Lookup tool.

A Type D (API/HTTP-based) agent tool with Pattern 1 (conditional availability):
the tool is only registered when the user has at least one enabled tradecraft
resource configured in Global Settings.

The user maintains a per-user catalog of curated security knowledge URLs
(HackTricks, PayloadsAllTheThings, pentest-book, h4cker, CVE PoC repos,
arbitrary blogs, ...). Each resource gets a `slug`, a `summary`, and a
`sitemap` at verify time. At runtime the agent picks a resource by slug
from the dynamic TOOL_REGISTRY catalog, the tool narrows the sitemap to a
single page, fetches it (cache-aware, two-tier), and returns the content
wrapped in an untrusted-content envelope.

Five deterministic resource types are supported here. The 6th type
`agentic-crawl` lives in `tradecraft_crawl.py`; this module imports it
lazily so v1 of `tradecraft_lookup.py` builds and runs even if the crawl
module is not yet wired up. PDF handling is a sub-extractor branch inside
Tier 1.

See plan: /home/samuele/.claude/plans/harmonic-inventing-crown.md
See README: docs/readmes/README.TRADECRAFT.md
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import socket
import sqlite3
import textwrap
import contextvars
from project_settings import get_setting

# Per-session tradecraft catalog (concurrency isolation). The parsed resource
# list and its slug index are bound to the current asyncio task so concurrent
# projects don't fetch each other's resources. Backed by ContextVars via the
# _resources/_by_slug properties on the manager; default None falls back to the
# last-set baseline (single-session / non-task callers behave as before).
_tc_resources_ctx: contextvars.ContextVar = contextvars.ContextVar(
    "tc_resources", default=None)
_tc_by_slug_ctx: contextvars.ContextVar = contextvars.ContextVar(
    "tc_by_slug", default=None)
# The section-picker LLM is built from ONE user's "Tradecraft section picker"
# model and keys, so unlike the catalog it has no cross-task baseline: a task
# that never set one gets the constructor's value (None in production), which
# makes the picker use the text match. A shared attribute here ran one user's
# lookups on whichever user's keys loaded last.
_TC_PICKER_UNSET = object()
_tc_section_picker_ctx: contextvars.ContextVar = contextvars.ContextVar(
    "tc_section_picker", default=_TC_PICKER_UNSET)
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx
from langchain_core.tools import tool

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # populated after requirements bump

try:
    import yaml  # pyyaml is already in requirements
except Exception:
    yaml = None

from logging_config import get_logger
from orchestrator_helpers.fetch_guard import (
    _BLOCKED_HOSTNAMES,
    _is_disallowed_ip,
    UnsafeFetchURLError,
    guarded_browser_script,
    parse_guarded_browser_output,
    pinned_async_transport,
)
from orchestrator_helpers.json_utils import normalize_content
# The pure helpers live in web_sources, shared with the workspace importer;
# the private names stay importable from here for every existing caller.
from orchestrator_helpers.web_sources import (  # noqa: F401
    GITHUB_TOKEN_HOSTS as _GITHUB_TOKEN_HOSTS,
    PDF_MAX_PAGES,
    _LANG_RE,
    document_base_href,
    extract_pdf_pages as _extract_pdf_pages,
    html_to_markdown as _html_to_markdown,
    is_github_token_url as _is_github_token_url,
    parse_sitemap_xml,
    prefer_english as _prefer_english,
    resolve_link,
    rewrite_github_url as _rewrite_github_url,
    split_github_url as _split_github_url,
    url_host as _url_host,
)
from prompt_safety import wrap_untrusted, UNTRUSTED_OUTPUT_GUIDANCE

logger = get_logger(__name__)


# =========================================================================
# Constants & defaults
# =========================================================================

CACHE_ROOT_DEFAULT = "/app/tradecraft_cache"
USER_AGENT = "RedAmon-Tradecraft/1.0"
_MAX_REDIRECTS = 5

DEFAULT_TTLS_BY_TYPE: Dict[str, int] = {
    "mkdocs-wiki": 7 * 86400,
    "github-repo": 7 * 86400,
    "cve-poc-db": 30 * 86400,
    "sphinx-docs": 14 * 86400,
    "gitbook": 7 * 86400,
    "agentic-crawl": 1 * 86400,
}

NOISE_PATH_PATTERNS = re.compile(
    r"^/?(login|signup|register|privacy|cookies|contact|about|tos|terms|"
    r"author/|tag/|category/|page/\d+|feed|rss|sitemap)",
    re.IGNORECASE,
)
NOISE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".otf",
    ".zip", ".tar", ".gz", ".7z", ".mp4", ".mp3",
)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


# =========================================================================
# URL helpers and SSRF guard
# =========================================================================

def canonicalize_url(raw: str) -> str:
    """Drop fragment, sort query keys, lowercase host."""
    try:
        u = urllib.parse.urlsplit(raw)
        scheme = (u.scheme or "https").lower()
        netloc = u.netloc.lower()
        path = u.path or "/"
        qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        qs.sort()
        query = urllib.parse.urlencode(qs)
        return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return raw


def is_private_host(host: str) -> bool:
    """True iff the host name resolves to a private/loopback/link-local IP.

    DNS-failure now returns False (handled separately by the caller), so the
    error message can distinguish "DNS resolution failed" from "private
    address blocked". Both still block the request -- they just describe
    different failure modes.
    """
    if not host:
        return True
    h = host.lower()
    if h in ("localhost", "::1") or h.endswith(".local") or h.endswith(".internal"):
        return True
    if h.rstrip(".") in _BLOCKED_HOSTNAMES:
        return True
    try:
        infos = socket.getaddrinfo(h, None)
    except OSError:
        # DNS lookup failed (NXDOMAIN, network down, etc.). The caller surfaces
        # this as a separate error so users see the real reason.
        return False
    # Same address policy as the connect-time guard, so this early check never
    # admits a host (CGNAT, IPv4-mapped IPv6) that the request itself refuses.
    return any(_is_disallowed_ip(info[4][0].split("%")[0]) for info in infos)


def _dns_resolves(host: str) -> bool:
    if not host:
        return False
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def validate_url(raw: str) -> Tuple[bool, str]:
    try:
        u = urllib.parse.urlsplit(raw)
    except Exception:
        return False, "Invalid URL"
    if u.scheme not in ("http", "https"):
        return False, "Only http(s) URLs are allowed"
    if not u.hostname:
        return False, "Missing host"
    # SSRF check first (cheaper, no DNS for special names).
    if is_private_host(u.hostname):
        return False, "private address blocked"
    # DNS failure for non-special host names becomes its own error code so
    # users can tell "domain doesn't exist" from "internal IP blocked".
    if (
        u.hostname not in ("localhost",)
        and not u.hostname.endswith((".local", ".internal"))
        and not _dns_resolves(u.hostname)
    ):
        return False, f"DNS resolution failed for {u.hostname} (NXDOMAIN or unreachable)"
    return True, ""


# =========================================================================
# Cache layer (sqlite + disk)
# =========================================================================

class TradecraftCache:
    """Per-URL content cache with TTL. SQLite index + flat files on disk.

    Uses a small reconnect-on-error wrapper so an externally-deleted database
    file (e.g. someone running `rm /app/tradecraft_cache/*`) doesn't leave
    every subsequent operation failing with "attempt to write a readonly
    database". Each public method calls `_ensure_db()` first to verify the
    sqlite file still exists; if not, it transparently re-opens.
    """

    def __init__(self, root: str = CACHE_ROOT_DEFAULT):
        self.root = root
        os.makedirs(self.root, exist_ok=True)
        self.db_path = os.path.join(self.root, "index.sqlite")
        self._db: Optional[sqlite3.Connection] = None
        # Per-URL asyncio locks to dedupe concurrent fetches.
        # Lives across reconnects (do NOT reset in _ensure_db).
        self._url_locks: Dict[str, asyncio.Lock] = {}
        self._ensure_db()

    def _ensure_db(self) -> None:
        """Open / re-open the sqlite connection if needed."""
        # If the file was removed externally (rm -rf), the existing connection
        # holds a dangling FD. Detect by file existence and force reconnect.
        if self._db is not None and os.path.exists(self.db_path):
            return
        try:
            if self._db is not None:
                try:
                    self._db.close()
                except Exception:
                    pass
        finally:
            self._db = None
        os.makedirs(self.root, exist_ok=True)
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                url TEXT PRIMARY KEY,
                resource_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                fetched_at INTEGER NOT NULL,
                ttl INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                tier INTEGER NOT NULL
            )
            """
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS cache_resource ON cache(resource_id)"
        )
        self._db.commit()

    def lock_for(self, url: str) -> asyncio.Lock:
        url = canonicalize_url(url)
        lock = self._url_locks.get(url)
        if lock is None:
            lock = asyncio.Lock()
            self._url_locks[url] = lock
        return lock

    def _file_path(self, resource_id: str, url: str) -> str:
        d = os.path.join(self.root, resource_id)
        os.makedirs(d, exist_ok=True)
        h = hashlib.sha256(canonicalize_url(url).encode("utf-8")).hexdigest()
        return os.path.join(d, f"{h}.md")

    def pdf_dir(self, resource_id: str, url: str) -> str:
        """Per-PDF directory for storing per-page markdown extracts."""
        d = os.path.join(self.root, resource_id)
        os.makedirs(d, exist_ok=True)
        h = hashlib.sha256(canonicalize_url(url).encode("utf-8")).hexdigest()
        page_dir = os.path.join(d, h)
        os.makedirs(page_dir, exist_ok=True)
        return page_dir

    def store_pdf_pages(
        self, resource_id: str, url: str, page_texts: List[str], ttl: int
    ) -> None:
        """Write each page text as page-N.md and a single sqlite row keyed by url
        (used as a cache-presence flag for the PDF as a whole)."""
        self._ensure_db()
        page_dir = self.pdf_dir(resource_id, url)
        for i, text in enumerate(page_texts, 1):
            with open(os.path.join(page_dir, f"page-{i}.md"), "w", encoding="utf-8") as f:
                f.write(text or "")
        # Cache row uses page_dir as file_path; fetched_at lets TTL invalidate.
        url = canonicalize_url(url)
        total_bytes = sum(len(t or "") for t in page_texts)
        self._db.execute(
            """
            INSERT INTO cache(url, resource_id, file_path, fetched_at, ttl, bytes, tier)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(url) DO UPDATE SET
              resource_id=excluded.resource_id,
              file_path=excluded.file_path,
              fetched_at=excluded.fetched_at,
              ttl=excluded.ttl,
              bytes=excluded.bytes,
              tier=excluded.tier
            """,
            (url, resource_id, page_dir, int(time.time()), int(ttl), total_bytes, 1),
        )
        self._db.commit()

    def lookup_pdf_page(self, resource_id: str, url: str, page_n: int) -> Optional[str]:
        """Return text for a specific PDF page, or None if not cached / missing."""
        self._ensure_db()
        url = canonicalize_url(url)
        cur = self._db.execute(
            "SELECT file_path, fetched_at, ttl FROM cache WHERE url = ?", (url,)
        )
        row = cur.fetchone()
        if not row:
            return None
        page_dir, fetched_at, ttl = row
        if int(time.time()) - int(fetched_at) > int(ttl):
            return None
        path = os.path.join(page_dir, f"page-{page_n}.md")
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except OSError:
            return None

    def lookup(self, url: str) -> Optional[Dict[str, Any]]:
        self._ensure_db()
        url = canonicalize_url(url)
        cur = self._db.execute(
            "SELECT resource_id, file_path, fetched_at, ttl, bytes, tier FROM cache WHERE url = ?",
            (url,),
        )
        row = cur.fetchone()
        if not row:
            return None
        resource_id, file_path, fetched_at, ttl, nbytes, tier = row
        if int(time.time()) - int(fetched_at) > int(ttl):
            return None
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            return None
        return {
            "content": content,
            "fetched_at": int(fetched_at),
            "ttl": int(ttl),
            "bytes": int(nbytes),
            "tier": int(tier),
            "resource_id": resource_id,
        }

    def store(self, resource_id: str, url: str, content: str, ttl: int, tier: int) -> str:
        self._ensure_db()
        url = canonicalize_url(url)
        path = self._file_path(resource_id, url)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self._db.execute(
            """
            INSERT INTO cache(url, resource_id, file_path, fetched_at, ttl, bytes, tier)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(url) DO UPDATE SET
              resource_id=excluded.resource_id,
              file_path=excluded.file_path,
              fetched_at=excluded.fetched_at,
              ttl=excluded.ttl,
              bytes=excluded.bytes,
              tier=excluded.tier
            """,
            (url, resource_id, path, int(time.time()), int(ttl), len(content), int(tier)),
        )
        self._db.commit()
        return path

    def invalidate(self, url: str) -> None:
        self._ensure_db()
        url = canonicalize_url(url)
        cur = self._db.execute("SELECT file_path FROM cache WHERE url = ?", (url,))
        row = cur.fetchone()
        if row and row[0]:
            try:
                os.remove(row[0])
            except OSError:
                pass
        self._db.execute("DELETE FROM cache WHERE url = ?", (url,))
        self._db.commit()


# =========================================================================
# Tier 1 / Tier 2 fetchers
# =========================================================================

@dataclass
class FetchResult:
    text: str
    content_type: str
    status: int
    tier: int  # 1 or 2
    raw_bytes: bytes = b""
    # Set when the egress guard refused a hop. Callers must not retry the URL
    # another way: the browser fallback would follow the same redirect.
    blocked: str = ""
    # Where redirects ended (Tier 1 only): relative links resolve against it.
    final_url: str = ""

    @property
    def ok_textual(self) -> bool:
        return (
            self.status >= 200
            and self.status < 300
            and len(self.text) >= 1
            and ("text" in self.content_type or "json" in self.content_type or "xml" in self.content_type)
        )


async def fetch_tier1(
    url: str,
    *,
    timeout: int = 30,
    github_token: str = "",
    expect_text: bool = True,
) -> FetchResult:
    """Plain HTTP fetch. Routes GitHub blob/tree URLs to raw.githubusercontent.com.

    `raw_bytes` always carries the unconverted body (UTF-8 encoded if it was
    text), so detection rules that need original HTML signatures (mdbook
    generator comments, MkDocs meta tags) can use it before markdown stripping.
    """
    url = _rewrite_github_url(url)
    headers = {"User-Agent": USER_AGENT}
    if github_token and _is_github_token_url(url):
        headers["Authorization"] = f"token {github_token}"
    if _url_host(url) == "api.github.com":
        headers["Accept"] = "application/vnd.github.raw"
    try:
        # Every hop, redirects included, connects through the egress guard.
        # httpx drops Authorization when a redirect leaves the origin.
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            max_redirects=_MAX_REDIRECTS,
            headers=headers,
            transport=pinned_async_transport(),
        ) as client:
            resp = await client.get(url)
            ct = (resp.headers.get("content-type") or "").lower()
            raw = resp.content or b""
            # PDF detection: Content-Type OR PDF magic bytes (some hosts serve
            # PDFs as application/octet-stream; sniff to avoid false negatives).
            is_pdf_response = (
                "application/pdf" in ct
                or (raw[:5] == b"%PDF-")
            )
            if is_pdf_response:
                # Normalize ct so the caller can branch on a single signal.
                pdf_ct = ct if "pdf" in ct else "application/pdf"
                return FetchResult(
                    text="",
                    content_type=pdf_ct,
                    status=resp.status_code,
                    tier=1,
                    raw_bytes=raw,
                    final_url=str(resp.url),
                )
            if not expect_text:
                return FetchResult(
                    text=resp.text,
                    content_type=ct,
                    status=resp.status_code,
                    tier=1,
                    raw_bytes=raw,
                    final_url=str(resp.url),
                )
            # Text path: convert HTML to markdown when applicable.
            # Keep raw_bytes = original bytes so callers can detect on the
            # un-stripped HTML (mdbook generator comment, etc.).
            text = resp.text
            raw_for_detection = (resp.text or "").encode("utf-8", "ignore")
            if "html" in ct:
                text = _html_to_markdown(text)
            return FetchResult(
                text=text,
                content_type=ct,
                status=resp.status_code,
                tier=1,
                raw_bytes=raw_for_detection,
                final_url=str(resp.url),
            )
    except UnsafeFetchURLError as e:
        logger.warning(f"[tradecraft] tier1 blocked url={url}: {e}")
        return FetchResult(text="", content_type="", status=0, tier=1, blocked=str(e))
    except httpx.HTTPError as e:
        logger.warning(f"[tradecraft] tier1 http error url={url} err={type(e).__name__}: {e}")
        return FetchResult(text="", content_type="", status=0, tier=1)


async def fetch_tier2(url: str, mcp_manager) -> FetchResult:
    """Render with the execute_playwright MCP tool, behind the browser egress guard."""
    if mcp_manager is None:
        return FetchResult(text="", content_type="", status=0, tier=2)
    try:
        playwright = None
        try:
            tools = await mcp_manager.get_tools()
            for t in tools:
                if getattr(t, "name", "") == "execute_playwright":
                    playwright = t
                    break
        except Exception as e:
            logger.warning(f"[tradecraft] tier2 cannot get mcp tools: {type(e).__name__}: {e}")
            return FetchResult(text="", content_type="", status=0, tier=2)
        if playwright is None:
            logger.warning("[tradecraft] tier2 execute_playwright not available")
            return FetchResult(text="", content_type="", status=0, tier=2)
        out = await playwright.ainvoke({"script": guarded_browser_script(url)})
        # MCP responses can be list-of-content-blocks or string
        html = ""
        if isinstance(out, str):
            html = out
        elif isinstance(out, list):
            for it in out:
                if isinstance(it, dict) and "text" in it:
                    html += it["text"]
        elif isinstance(out, dict) and "text" in out:
            html = out["text"]
        html, blocked = parse_guarded_browser_output(html)
        if blocked:
            logger.warning(f"[tradecraft] tier2 blocked url={url}: {blocked}")
            return FetchResult(text="", content_type="", status=0, tier=2, blocked=blocked)
        text = _html_to_markdown(html)
        return FetchResult(text=text, content_type="text/html", status=200, tier=2, raw_bytes=html.encode("utf-8", "ignore"))
    except Exception as e:
        logger.warning(f"[tradecraft] tier2 error url={url} err={type(e).__name__}: {e}")
        return FetchResult(text="", content_type="", status=0, tier=2)


async def smart_fetch(
    url: str,
    *,
    mcp_manager,
    github_token: str = "",
    timeout: int = 30,
    tier2_threshold_bytes: int = 800,
) -> FetchResult:
    """Tier 1, escalate to Tier 2 if thin or non-textual."""
    r = await fetch_tier1(url, timeout=timeout, github_token=github_token)
    if r.blocked:
        return r
    if r.content_type and "application/pdf" in r.content_type:
        return r  # pdf path handled by caller
    if r.ok_textual and len(r.text) >= tier2_threshold_bytes:
        return r
    logger.info(
        f"[tradecraft] tier1 thin (status={r.status} ct={r.content_type} bytes={len(r.text)}), escalating to playwright"
    )
    r2 = await fetch_tier2(url, mcp_manager)
    # A browser-side block wins over tier 1's thin page: it carries the reason
    # verify and the tool report, and stops verify before the crawl retries the
    # same URL in the browser.
    if r2.text or r2.blocked:
        return r2
    return r


# =========================================================================
# Type detection
# =========================================================================

_CVE_ID_ANYWHERE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_YEAR_DIR_RE = re.compile(r"(?:19|20)\d{2}")


def detect_type(url: str, body: str, status: int = 200) -> str:
    """Run the 6-rule detection chain. Returns one of the 6 type strings."""
    host = urllib.parse.urlsplit(url).hostname or ""
    host = host.lower()
    body_lc = body.lower() if body else ""
    # 1. CVE PoC DB: an ARCHIVE of many CVEs laid out as {year}/{CVE}.md. A repo
    # built around one or two CVEs is a plain github-repo: as cve-poc-db its
    # lookups only probe archive paths it does not have, so every query
    # answered "PoC not found" (observed: php2shell-poc, whose README repeats
    # its two CVE ids more than 20 times).
    if "github.com" in host:
        m = re.match(r"^https?://github\.com/([^/]+)/([^/]+)", url)
        if m:
            owner, repo = m.groups()
            # Named for CVEs ("cve", "cvelist") but not for ONE ("CVE-2024-1234-poc").
            if re.search(r"cve", repo, re.IGNORECASE) and not _CVE_ID_ANYWHERE_RE.search(repo):
                return "cve-poc-db"
        distinct_cves = {c.upper() for c in _CVE_ID_ANYWHERE_RE.findall(body or "")}
        if len(distinct_cves) > 20:
            return "cve-poc-db"
    # 2. github repo (any github page that isn't a CVE repo)
    if host == "github.com" or host == "raw.githubusercontent.com":
        return "github-repo"
    # 3. mkdocs / mdbook (treat both as mkdocs-wiki: same structural shape -
    # sidebar nav + per-page markdown, sitemap.xml available)
    if (
        'name="generator" content="mkdocs' in body_lc
        or 'name="generator" content="material' in body_lc
        or "<!-- book generated using mdbook -->" in body_lc
        or 'class="mdbook"' in body_lc
        or "mdbook.js" in body_lc
    ):
        return "mkdocs-wiki"
    # 4. sphinx / readthedocs / docusaurus
    # ReadTheDocs always serves Sphinx -> the host alone is a definitive
    # signal even when the rendered homepage HTML does not contain the
    # `_static/searchindex.js` string verbatim (some themes inject it via
    # a separate <script> path or a CDN).
    if (
        host.endswith(".readthedocs.io")
        or 'name="generator" content="docutils' in body_lc
        or "_static/searchindex.js" in body_lc
        or "searchindex.js" in body_lc
        or 'name="generator" content="docusaurus' in body_lc
        or "docusaurus.config" in body_lc
    ):
        return "sphinx-docs"
    # 5. gitbook (custom-domain hosted books also need to be caught — they
    # don't use the gitbook.io host but always emit a `generator=GitBook` meta
    # tag and load assets from `static*.gitbook.com`).
    if (
        "gitbook.io" in host
        or 'application-name" content="gitbook"' in body_lc
        or 'name="generator" content="gitbook' in body_lc
        or "static-2v.gitbook.com" in body_lc
        or "static.gitbook.com" in body_lc
        or "data-rsc-router" in body_lc
    ):
        return "gitbook"
    # 6. fallback
    return "agentic-crawl"


# =========================================================================
# Per-type sitemap builders
# =========================================================================

async def _fetch_sitemap_xml(url: str, max_depth: int = 2) -> List[str]:
    """Fetch sitemap.xml or sitemapindex.xml recursively. Returns flat URL list.

    Handles both shapes:
      <urlset><url><loc>...</loc></url>...</urlset>
      <sitemapindex><sitemap><loc>...</loc></sitemap>...</sitemapindex>
    """
    if max_depth <= 0 or BeautifulSoup is None:
        return []
    r = await fetch_tier1(url, expect_text=False)
    if r.status != 200 or not r.text:
        return []
    kind, locs = parse_sitemap_xml(r.text)
    if kind == "index":
        urls: List[str] = []
        for loc in locs:
            urls.extend(await _fetch_sitemap_xml(loc, max_depth - 1))
        return urls
    if kind == "urlset":
        return locs
    return []


async def _build_sitemap_mkdocs(base_url: str, github_token: str = "") -> Dict[str, Any]:
    """Try sitemap.xml first, then mkdocs.yml, then nav harvest."""
    base = base_url.rstrip("/")
    # 1. sitemap.xml (handles both urlset and sitemapindex shapes)
    urls = await _fetch_sitemap_xml(f"{base}/sitemap.xml")
    if urls:
        urls = _prefer_english(urls)
        nav = []
        for u in urls:
            slug = urllib.parse.urlsplit(u).path.strip("/").split("/")[-1] or u
            title = re.sub(r"[-_]", " ", slug.removesuffix(".html")).title()
            nav.append({"title": title, "path": u})
        return {"nav": nav}
    # 2. mkdocs.yml (rare on hosted)
    if yaml is not None:
        r2 = await fetch_tier1(f"{base}/mkdocs.yml", expect_text=False)
        if r2.status == 200 and r2.text:
            try:
                data = yaml.safe_load(r2.text)
                navlist: List[Dict[str, str]] = []

                def walk(node, prefix=""):
                    if isinstance(node, dict):
                        for k, v in node.items():
                            walk(v, f"{prefix} > {k}".strip(" >"))
                    elif isinstance(node, list):
                        for item in node:
                            walk(item, prefix)
                    elif isinstance(node, str):
                        navlist.append({"title": prefix or node, "path": node})

                walk((data or {}).get("nav") or [])
                if navlist:
                    return {"nav": navlist}
            except Exception:
                pass
    # 3. Rendered nav harvest
    r3 = await fetch_tier1(base, expect_text=False)
    nav: List[Dict[str, str]] = []
    if r3.status == 200 and BeautifulSoup is not None:
        soup = BeautifulSoup(r3.text, "html.parser")
        page_url, base_href = r3.final_url or base, document_base_href(soup)
        for a in soup.select(".md-nav__link, nav a"):
            path = resolve_link(page_url, a.get("href") or "", base_href)
            if not path:
                continue
            title = a.get_text(strip=True)
            if not title:
                continue
            nav.append({"title": title, "path": path})
    return {"nav": nav[:1000]}


async def _build_sitemap_github_repo(base_url: str, github_token: str = "") -> Dict[str, Any]:
    parsed = _split_github_url(base_url)
    if not parsed:
        return {"tree": [], "_error": "could not parse github URL into owner/repo"}
    owner, repo = parsed
    headers = {"User-Agent": USER_AGENT}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    branch = "main"
    try:
        async with httpx.AsyncClient(timeout=30, headers=headers, follow_redirects=True) as client:
            meta = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
            rate_remaining = meta.headers.get("x-ratelimit-remaining", "?")
            if meta.status_code == 403:
                logger.warning(
                    f"[tradecraft] github meta 403 owner={owner} repo={repo} "
                    f"x-ratelimit-remaining={rate_remaining} (anonymous limit is 60/h; "
                    f"add GITHUB token to UserSettings or per-resource override)"
                )
                return {
                    "tree": [], "owner": owner, "repo": repo, "branch": branch,
                    "_error": f"GitHub API rate-limited (403, remaining={rate_remaining}); "
                              f"add a GitHub token in Global Settings -> API Keys",
                }
            if meta.status_code == 404:
                return {
                    "tree": [], "owner": owner, "repo": repo, "branch": branch,
                    "_error": f"GitHub repo {owner}/{repo} not found (404)",
                }
            if meta.status_code != 200:
                return {
                    "tree": [], "owner": owner, "repo": repo, "branch": branch,
                    "_error": f"GitHub meta returned HTTP {meta.status_code}",
                }
            branch = meta.json().get("default_branch", "main")
            tree_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
            )
            if tree_resp.status_code != 200:
                rl = tree_resp.headers.get("x-ratelimit-remaining", "?")
                logger.warning(
                    f"[tradecraft] github tree non-200 owner={owner} repo={repo} "
                    f"branch={branch} status={tree_resp.status_code} rate_remaining={rl}"
                )
                return {
                    "tree": [], "owner": owner, "repo": repo, "branch": branch,
                    "_error": f"GitHub tree HTTP {tree_resp.status_code} (rate_remaining={rl})",
                }
            data = tree_resp.json()
            entries = []
            for item in data.get("tree", []):
                if item.get("type") != "blob":
                    continue
                path = item.get("path", "")
                if not (path.endswith(".md") or path.endswith(".txt") or path.endswith(".rst")):
                    continue
                title = " > ".join(seg.replace("_", " ").replace("-", " ") for seg in path.rsplit(".", 1)[0].split("/"))
                entries.append({"title": title, "path": path})
            result = {"tree": entries[:5000], "owner": owner, "repo": repo, "branch": branch}
            if data.get("truncated"):
                result["_error"] = (
                    f"GitHub tree marked truncated; only {len(entries)} entries indexed "
                    f"(repo too large for single tree call)"
                )
            return result
    except Exception as e:
        logger.warning(f"[tradecraft] github tree exception owner={owner} repo={repo} err={type(e).__name__}: {e}")
        return {
            "tree": [], "owner": owner, "repo": repo, "branch": branch,
            "_error": f"github tree fetch exception: {e}",
        }


async def _build_sitemap_cve_poc_db(base_url: str, github_token: str = "") -> Dict[str, Any]:
    parsed = _split_github_url(base_url)
    if not parsed:
        return {}
    owner, repo = parsed
    branch = "main"
    headers = {"User-Agent": USER_AGENT}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    no_year_dirs = False
    try:
        async with httpx.AsyncClient(timeout=20, headers=headers, follow_redirects=True) as client:
            meta = await client.get(f"https://api.github.com/repos/{owner}/{repo}")
            if meta.status_code == 200:
                branch = meta.json().get("default_branch", "main")
            # Lookups probe {year}/{CVE}.md, so a repo with no year folders at
            # its root is not an archive whatever its name or README says. Only
            # a definite listing decides; an API error keeps the detection.
            root = await client.get(f"https://api.github.com/repos/{owner}/{repo}/contents")
            if root.status_code == 200 and isinstance(root.json(), list):
                no_year_dirs = not any(
                    it.get("type") == "dir" and _YEAR_DIR_RE.fullmatch(it.get("name", ""))
                    for it in root.json()
                )
    except Exception:
        pass
    result: Dict[str, Any] = {"owner": owner, "repo": repo, "branch": branch}
    if no_year_dirs:
        result["_no_year_dirs"] = True
    return result


async def _build_sitemap_sphinx(base_url: str, github_token: str = "") -> Dict[str, Any]:
    base = base_url.rstrip("/")
    for candidate in ("/searchindex.json", "/search-index.json", "/searchindex.js"):
        idx_url = base + candidate
        r = await fetch_tier1(idx_url, expect_text=False)
        if r.status != 200 or not r.text:
            continue
        text = r.text.strip()
        # Sphinx searchindex.js wraps JSON in `Search.setIndex(...)`
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            continue
        try:
            data = json.loads(m.group(0))
        except Exception:
            continue
        # Sphinx schema: { "docnames": [...], "titles": [...], ... }
        docnames = data.get("docnames") or data.get("docNames") or []
        titles = data.get("titles") or []
        nav: List[Dict[str, str]] = []
        for i, doc in enumerate(docnames):
            title = titles[i] if i < len(titles) else doc
            path = f"{base}/{doc}.html"
            nav.append({"title": title, "path": path})
        if not nav:
            # Docusaurus: list of {title, url} entries
            for entry in data if isinstance(data, list) else []:
                if isinstance(entry, dict) and "title" in entry and ("url" in entry or "path" in entry):
                    p = entry.get("url") or entry.get("path")
                    nav.append({"title": entry["title"], "path": urllib.parse.urljoin(base + "/", p)})
        if nav:
            return {"nav": nav[:3000], "indexUrl": idx_url}
    return {"nav": [], "indexUrl": ""}


async def _build_sitemap_gitbook(base_url: str, mcp_manager=None) -> Dict[str, Any]:
    base = base_url.rstrip("/")
    # Try sitemap.xml first (handles sitemapindex too)
    urls = await _fetch_sitemap_xml(f"{base}/sitemap.xml")
    if urls:
        urls = _prefer_english(urls)
        nav = []
        for u in urls:
            slug = urllib.parse.urlsplit(u).path.strip("/").split("/")[-1] or u
            title = re.sub(r"[-_]", " ", slug).title()
            nav.append({"title": title, "path": u})
        return {"nav": nav[:1000]}
    # Fall back to one Tier-2 nav harvest
    r2 = await fetch_tier2(base, mcp_manager)
    if not r2.text or BeautifulSoup is None:
        return {"nav": []}
    # Tier 2 returned cleaned markdown; we need the raw HTML to parse nav.
    # Re-fetch Tier 1 raw HTML (no markdown conversion).
    raw = await fetch_tier1(base, expect_text=False)
    nav = []
    if raw.status == 200 and raw.text:
        soup = BeautifulSoup(raw.text, "html.parser")
        page_url, base_href = raw.final_url or base, document_base_href(soup)
        for a in soup.select("aside nav a, nav a, [role='navigation'] a"):
            path = resolve_link(page_url, a.get("href") or "", base_href)
            title = a.get_text(strip=True)
            if not path or not title:
                continue
            nav.append({"title": title, "path": path})
    return {"nav": nav[:500]}


async def _build_sitemap_agentic_crawl(
    base_url: str, *, llm, mcp_manager, bounds: Dict[str, int]
) -> Dict[str, Any]:
    """Stub for v1: real implementation lives in tradecraft_crawl.py (step 7)."""
    try:
        from orchestrator_helpers.tradecraft_crawl import agentic_crawl
    except Exception:
        logger.info("[tradecraft] agentic_crawl module not yet available; returning empty sitemap")
        return {"nav": [], "_stopped_because": "agentic_crawl not implemented yet", "_stats": {}}
    result = await agentic_crawl(base_url, bounds=bounds, llm=llm, mcp_manager=mcp_manager)
    return {
        "nav": result.sitemap_entries,
        "_stopped_because": result.stopped_because,
        "_stats": result.stats,
    }


# =========================================================================
# Section picker
# =========================================================================

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(s: str) -> set:
    return set(_TOKEN_RE.findall((s or "").lower()))


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _substr_overlap_score(query_tokens: set, entry_tokens: set) -> float:
    """Bonus score: fraction of query tokens that substring-match any entry token.
    Catches near-misses like 'kerberoasting' vs 'kerberoast' that exact Jaccard misses.
    """
    if not query_tokens or not entry_tokens:
        return 0.0
    hits = 0
    for q in query_tokens:
        if len(q) < 4:
            continue  # too short, would match noise like "ai" or "an"
        for t in entry_tokens:
            if q in t or (len(t) >= 4 and t in q):
                hits += 1
                break
    return hits / len(query_tokens)


def _rank_score(query_tokens: set, entry: Dict[str, str]) -> float:
    et = _tokens((entry.get("title") or "") + " " + (entry.get("path") or ""))
    return _jaccard(query_tokens, et) + 0.5 * _substr_overlap_score(query_tokens, et)


def _sitemap_entries(sitemap: Dict[str, Any]) -> List[Dict[str, str]]:
    """Normalize the various sitemap shapes to a flat list of {title, path}."""
    if not sitemap:
        return []
    if isinstance(sitemap.get("nav"), list):
        return [
            {"title": str(e.get("title", "")), "path": str(e.get("path", ""))}
            for e in sitemap["nav"]
            if isinstance(e, dict)
        ]
    if isinstance(sitemap.get("tree"), list):
        return [
            {"title": str(e.get("title", "")), "path": str(e.get("path", ""))}
            for e in sitemap["tree"]
            if isinstance(e, dict)
        ]
    if isinstance(sitemap.get("links"), list):
        return [
            {"title": str(e.get("title", "")), "path": str(e.get("path", ""))}
            for e in sitemap["links"]
            if isinstance(e, dict)
        ]
    return []


async def _pick_section(
    query: str,
    sitemap: Dict[str, Any],
    *,
    section_picker_llm,
    semaphore: asyncio.Semaphore,
    resource_name: str = "",
) -> Optional[Dict[str, str]]:
    entries = _sitemap_entries(sitemap)
    if not entries:
        return None
    qt = _tokens(query)
    scored = [(_rank_score(qt, e), e) for e in entries]
    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:30]
    if not top:
        return None
    # No LLM or sitemap is small or top-1 is a clear winner -> short-circuit.
    if section_picker_llm is None:
        return top[0][1] if top[0][0] > 0 else None
    if len(entries) <= 5 or top[0][0] >= 0.6:
        return top[0][1]
    # Mini LLM call
    candidates = top[:30]
    msg_lines = [f'You pick the single most relevant page for a tradecraft query.',
                 f'Reply with ONLY the number (1-{len(candidates)}). No prose.',
                 f'',
                 f'Query: "{query}"',
                 f'Pages from {resource_name}:']
    for i, (_, e) in enumerate(candidates, 1):
        title = (e.get("title") or e.get("path") or "")[:80]
        path = (e.get("path") or "")[:80]
        msg_lines.append(f"  {i}. {title}  ->  {path}")
    msg_lines.append("Answer with just the number.")
    prompt = "\n".join(msg_lines)
    try:
        async with semaphore:
            resp = await section_picker_llm.ainvoke(prompt)
        out = normalize_content(getattr(resp, "content", str(resp))).strip()
        m = re.search(r"\d+", out)
        if m:
            idx = int(m.group(0)) - 1
            if 0 <= idx < len(candidates):
                logger.info(f"[tradecraft] section_picker llm_call resource={resource_name} candidates={len(candidates)} picked={idx+1}")
                return candidates[idx][1]
    except Exception as e:
        logger.warning(f"[tradecraft] section_picker llm error: {type(e).__name__}: {e}, falling back to top-1 lexical")
    return top[0][1]


# =========================================================================
# Output formatter
# =========================================================================

def _extract_code_blocks(text: str, max_blocks: int = 5) -> str:
    if not text:
        return ""
    blocks = re.findall(r"```(\w*)\n(.*?)```", text, re.DOTALL)
    if not blocks:
        return ""
    parts = []
    for lang, body in blocks[:max_blocks]:
        body = (body or "").strip()
        if not body:
            continue
        parts.append(f"- {lang or 'text'}:\n    " + body.replace("\n", "\n    "))
    return "\n".join(parts)


def format_output(
    *,
    resource_id: str,
    url: str,
    section_title: str,
    content: str,
    cache: str,  # "hit" | "miss"
    tier: int,
) -> str:
    """Wrap fetched content in the untrusted-content envelope.

    No tradecraft-specific truncation is applied here. The agent's global
    `TOOL_OUTPUT_MAX_CHARS` (think_node) is the single source of truth for
    output capping, so tradecraft follows the same cap as every other tool.
    """
    excerpt = content or ""
    code = _extract_code_blocks(content)
    fetched_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    parts = [
        "[BEGIN UNTRUSTED TRADECRAFT RESULT]",
        f"resource: {resource_id}",
        f"url: {url}",
        f"section_title: {section_title}",
        f"fetched_at: {fetched_at} (cache {cache}, tier {tier})",
        "---",
        excerpt,
    ]
    if code:
        parts.append("")
        parts.append("Code blocks:")
        parts.append(code)
    parts.append("[END UNTRUSTED TRADECRAFT RESULT]")
    return "\n".join(parts)


# =========================================================================
# CVE special path
# =========================================================================

async def _cve_lookup(
    cve_id: str,
    sitemap: Dict[str, Any],
    *,
    github_token: str,
) -> Tuple[str, str]:
    """Returns (markdown_content, source_url). Empty content on miss."""
    content, src_url, _err = await _cve_lookup_detailed(
        cve_id, sitemap, github_token=github_token
    )
    return content, src_url


async def _cve_lookup_detailed(
    cve_id: str,
    sitemap: Dict[str, Any],
    *,
    github_token: str,
) -> Tuple[str, str, str]:
    """Returns (markdown_content, source_url, api_error).

    api_error is non-empty when GitHub answered with something other than
    200/404 (rate limit, outage) or the request failed, so a miss can be told
    apart from "the archive has no entry for this CVE".
    """
    if not CVE_ID_RE.match(cve_id or ""):
        return "", "", ""
    owner = sitemap.get("owner")
    repo = sitemap.get("repo")
    branch = sitemap.get("branch") or "main"
    if not (owner and repo):
        return "", "", ""
    year = cve_id.split("-")[1]
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github.raw"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    candidates = [
        f"https://api.github.com/repos/{owner}/{repo}/contents/{year}/{cve_id.upper()}.md",
        f"https://api.github.com/repos/{owner}/{repo}/contents/{year}/{cve_id.upper()}/README.md",
    ]
    api_error = ""

    def _note(resp) -> None:
        nonlocal api_error
        if resp.status_code not in (200, 404) and not api_error:
            api_error = (
                f"GitHub API returned HTTP {resp.status_code} "
                f"(rate_remaining={resp.headers.get('x-ratelimit-remaining', '?')})"
            )

    async with httpx.AsyncClient(timeout=30, headers=headers, follow_redirects=True) as client:
        for url in candidates:
            try:
                r = await client.get(url)
                if r.status_code == 200 and r.text:
                    return r.text, url, ""
                _note(r)
            except Exception as e:
                api_error = api_error or f"GitHub request failed: {type(e).__name__}: {e}"
                continue
        # Fallback: list /contents/{year} and substring match
        try:
            list_resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{year}",
                headers={"User-Agent": USER_AGENT,
                         **({"Authorization": f"token {github_token}"} if github_token else {})},
            )
            if list_resp.status_code == 200:
                items = list_resp.json()
                if isinstance(items, list):
                    for it in items:
                        if cve_id.upper() in it.get("name", "").upper():
                            dl = it.get("download_url")
                            if dl:
                                rd = await client.get(dl)
                                if rd.status_code == 200:
                                    return rd.text, dl, ""
            else:
                _note(list_resp)
        except Exception as e:
            api_error = api_error or f"GitHub request failed: {type(e).__name__}: {e}"
    return "", "", api_error


async def _repo_readme(
    sitemap: Dict[str, Any], *, github_token: str
) -> Tuple[str, str]:
    """Returns (readme_markdown, html_url) of a GitHub resource; ("", "") on any failure."""
    owner = sitemap.get("owner")
    repo = sitemap.get("repo")
    if not (owner and repo):
        return "", ""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github.raw"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    try:
        async with httpx.AsyncClient(timeout=30, headers=headers, follow_redirects=True) as client:
            r = await client.get(f"https://api.github.com/repos/{owner}/{repo}/readme")
            if r.status_code == 200 and r.text:
                return r.text, f"https://github.com/{owner}/{repo}#readme"
    except Exception as e:
        logger.warning(f"[tradecraft] readme fetch failed {owner}/{repo}: {type(e).__name__}: {e}")
    return "", ""


# =========================================================================
# verify_resource (called from /tradecraft/verify endpoint)
# =========================================================================

# Module-level lock map for verify-time URL races
_VERIFY_LOCKS: Dict[str, asyncio.Lock] = {}


def _verify_lock_for(url: str) -> asyncio.Lock:
    url = canonicalize_url(url)
    lock = _VERIFY_LOCKS.get(url)
    if lock is None:
        lock = asyncio.Lock()
        _VERIFY_LOCKS[url] = lock
    return lock


_SUMMARY_PROMPT = (
    "You are summarizing a security-knowledge website so an autonomous "
    "pentest agent can decide when to consult it. Output 250-350 tokens.\n"
    "Mention: domains covered (web, AD, cloud, mobile, ...), structure "
    "(per-CVE, per-payload, per-technique), and the kinds of pentest queries "
    "it answers best. No marketing language. No first person.\n\n"
    + UNTRUSTED_OUTPUT_GUIDANCE
)


async def verify_resource(
    url: str,
    *,
    github_token: str = "",
    force: bool = False,
    llm,
    mcp_manager=None,
    bounds: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Fetch homepage, detect type, build sitemap, summarize. Returns the dict
    persisted by the webapp /verify route."""
    ok, err = validate_url(url)
    if not ok:
        return {"summary": "", "resource_type": "agentic-crawl", "sitemap": {}, "last_error": err}

    logger.info(f"[tradecraft] verify start url={url} force={force}")

    async with _verify_lock_for(url):
        # 1. Fetch homepage / README
        fetched = await smart_fetch(url, mcp_manager=mcp_manager, github_token=github_token)
        if fetched.blocked:
            # Stop here: the sitemap builders and the crawl would fetch this URL
            # again, and the crawl's browser fallback follows redirects itself.
            return {
                "summary": "",
                "resource_type": "agentic-crawl",
                "sitemap": {},
                "crawl_stopped_because": "",
                "crawl_stats": {},
                "last_error": f"blocked: {fetched.blocked}",
            }
        body = fetched.text
        # PDF override (full implementation in step 8)
        is_pdf = "application/pdf" in (fetched.content_type or "")

        # Pre-flight error surfacing (fixes A + B):
        # A. Non-2xx homepage -> set lastError so the UI shows the failure
        #    instead of summarizing a 404 / soft-error page as if it were
        #    valid content. Tier 2 already escalated where possible; if we
        #    still got a non-2xx, treat the resource as degraded.
        # B. Thin body after stripping -> the page rendered but contains no
        #    real content (JS-only shell, infinite scroll, etc.). Surface so
        #    the user knows the catalog entry is degraded.
        preflight_error = ""
        if not is_pdf:
            if fetched.status and fetched.status >= 400:
                preflight_error = f"homepage returned HTTP {fetched.status}"
            elif fetched.status == 0:
                preflight_error = "homepage fetch failed (network or playwright error)"
            elif len(body or "") < 500:
                preflight_error = (
                    f"homepage rendered to thin body ({len(body or '')} chars)"
                )

        # 2. Detect type (skip for PDFs; treat them as a sub-extractor below).
        # Use the raw HTML for detection (markdown conversion strips comments
        # like `<!-- Book generated using mdBook -->`), then keep `body` (the
        # markdown-converted text) for summarization.
        raw_html_for_detection = ""
        try:
            raw_html_for_detection = (fetched.raw_bytes or b"").decode("utf-8", "ignore")
        except Exception:
            raw_html_for_detection = ""
        if is_pdf:
            rtype = "agentic-crawl"  # placeholder; sitemap below will reflect pages
        elif preflight_error:
            # If the homepage is degraded, do not attribute a deterministic type
            # to it (we'd be classifying an error page). Fall to agentic-crawl
            # so the sitemap shape is `nav` / empty and the UI badge reflects
            # the unknown state. This also stops us from running the wrong
            # sitemap builder (e.g. mkdocs-wiki on a 404 HTML).
            rtype = "agentic-crawl"
        else:
            rtype = detect_type(url, raw_html_for_detection or body, fetched.status)
        logger.info(
            f"[tradecraft] verify type_detected url={url} type={rtype} "
            f"status={fetched.status} body_chars={len(body or '')} "
            f"preflight_error={preflight_error!r}"
        )

        # 3. Build sitemap per type
        sitemap: Dict[str, Any] = {}
        crawl_stopped_because = ""
        crawl_stats: Dict[str, Any] = {}
        # Seed with the preflight error if any (it can still be appended to
        # by sitemap-build / summary errors below).
        last_error = preflight_error

        if is_pdf:
            pages_meta, page_texts, pdf_err = _extract_pdf_pages(fetched.raw_bytes or b"")
            sitemap = {"pages": pages_meta}
            if pdf_err:
                last_error = pdf_err
            # Extracted pages are NOT cached at verify time (we don't have the
            # per-resource slug here yet). First query will re-extract and cache.
            # Use first 5 pages of text for the summary so it's grounded.
            if page_texts:
                body = "\n\n".join(page_texts[:5])
        else:
            try:
                if rtype == "mkdocs-wiki":
                    sitemap = await _build_sitemap_mkdocs(url, github_token=github_token)
                elif rtype == "github-repo":
                    sitemap = await _build_sitemap_github_repo(url, github_token=github_token)
                elif rtype == "cve-poc-db":
                    sitemap = await _build_sitemap_cve_poc_db(url, github_token=github_token)
                    if sitemap.pop("_no_year_dirs", False):
                        logger.info(
                            f"[tradecraft] verify {url}: no year folders at the repo root, "
                            f"re-typing cve-poc-db -> github-repo"
                        )
                        rtype = "github-repo"
                        sitemap = await _build_sitemap_github_repo(url, github_token=github_token)
                elif rtype == "sphinx-docs":
                    sitemap = await _build_sitemap_sphinx(url, github_token=github_token)
                elif rtype == "gitbook":
                    sitemap = await _build_sitemap_gitbook(url, mcp_manager=mcp_manager)
                else:  # agentic-crawl
                    crawl_bounds = bounds or {}
                    res = await _build_sitemap_agentic_crawl(
                        url, llm=llm, mcp_manager=mcp_manager, bounds=crawl_bounds
                    )
                    crawl_stopped_because = res.pop("_stopped_because", "")
                    crawl_stats = res.pop("_stats", {})
                    sitemap = res
                # Per-builder errors are surfaced via a `_error` key on the
                # sitemap dict so users can see WHY their resource is empty
                # (e.g. GitHub rate limits) instead of a silent zero-entries.
                builder_err = sitemap.pop("_error", "") if isinstance(sitemap, dict) else ""
                if builder_err:
                    last_error = (last_error + " | " if last_error else "") + builder_err
            except Exception as e:
                logger.error(f"[tradecraft] verify sitemap error url={url} type={rtype} err={type(e).__name__}: {e}")
                last_error = (last_error + " | " if last_error else "") + f"sitemap build error: {e}"

        entries = _sitemap_entries(sitemap)
        # Fix C: when sitemap is empty for non-PDF, non-CVE types, force-add
        # the homepage so the section picker has something to dispatch and the
        # tool can at least return *something* useful at query time. Without
        # this, an enabled-but-empty resource looks present in the catalog
        # but every query returns "no page matched".
        #
        # cve-poc-db is intentionally non-enumerated: its sitemap stores only
        # {owner, repo, branch} and queries route through the `cve_id`
        # parameter (special path), bypassing the section picker entirely.
        # An empty nav/tree is the correct steady state, NOT an error.
        skip_fallback = (
            is_pdf
            or rtype == "cve-poc-db"
        )
        if (
            not skip_fallback
            and not entries
            and fetched.status and fetched.status < 400
            and len(body or "") >= 200
        ):
            host = urllib.parse.urlsplit(url).hostname or url
            # Preserve any type-specific metadata the builder produced
            # (owner/repo/branch for github types, indexUrl for sphinx, etc.)
            # by ATTACHING `nav` rather than replacing the whole dict.
            preserved: Dict[str, Any] = sitemap if isinstance(sitemap, dict) else {}
            preserved["nav"] = [{"title": f"{host} (homepage)", "path": url}]
            sitemap = preserved
            entries = _sitemap_entries(sitemap)
            # For agentic-crawl, an empty sitemap with a clean stop reason is
            # informational, NOT an error -- the crawl ran successfully and
            # `crawl_stopped_because` already explains what happened. Only
            # treat it as an error for deterministic types where empty means
            # the type-specific extractor genuinely failed.
            if rtype != "agentic-crawl" and not last_error:
                last_error = "sitemap empty; only homepage reachable"
        logger.info(f"[tradecraft] verify sitemap_built url={url} type={rtype} entries={len(entries)}")

        # 4. Summarize via LLM
        summary = ""
        if body or entries:
            sample_titles = "\n  - ".join(
                e.get("title", "")[:80] for e in entries[:50] if e.get("title")
            )
            content_excerpt = (body or "")[:6000]
            user_msg = (
                f"URL: {url}\n"
                f"Detected type: {rtype}\n\n"
                f"Homepage / README excerpt (first 6000 chars):\n"
                + wrap_untrusted(content_excerpt, "WEB_CONTENT") + "\n\n"
                + "Sample page titles from sitemap (first 50):\n"
                + wrap_untrusted("  - " + sample_titles, "WEB_CONTENT") + "\n"
            )
            try:
                resp = await llm.ainvoke([
                    {"role": "system", "content": _SUMMARY_PROMPT},
                    {"role": "user", "content": user_msg},
                ])
                summary = normalize_content(getattr(resp, "content", "") or "").strip()
            except Exception as e:
                logger.warning(f"[tradecraft] verify summary error url={url} err={type(e).__name__}: {e}")
                last_error = (last_error + " | " if last_error else "") + f"summary error: {e}"
        logger.info(f"[tradecraft] verify summary_done url={url} chars={len(summary)}")

        return {
            "summary": summary,
            "resource_type": rtype,
            "sitemap": sitemap,
            "crawl_stopped_because": crawl_stopped_because,
            "crawl_stats": crawl_stats,
            "last_error": last_error,
        }


# =========================================================================
# TradecraftLookupManager
# =========================================================================

@dataclass
class _Resource:
    id: str
    slug: str
    name: str
    url: str
    enabled: bool
    resource_type: str
    summary: str
    sitemap: Dict[str, Any]
    cache_ttl_sec: int
    github_token_override: str = ""


class TradecraftLookupManager:
    """Manages the user's tradecraft resource catalog and the runtime tool."""

    def __init__(
        self,
        llm=None,
        mcp_manager=None,
        cache_root: str = CACHE_ROOT_DEFAULT,
        section_picker_llm=None,
        tier2_threshold_bytes: int = 800,
        fetch_timeout: int = 30,
        default_ttl: int = 86400,
        section_picker_concurrency: int = 5,
    ):
        self.llm = llm
        self.mcp_manager = mcp_manager
        self.cache = TradecraftCache(cache_root)
        self._section_picker_base = section_picker_llm
        self.tier2_threshold_bytes = tier2_threshold_bytes
        self.fetch_timeout = fetch_timeout
        self.default_ttl = default_ttl
        self._resources: List[_Resource] = []
        self._by_slug: Dict[str, _Resource] = {}
        self._section_sem = asyncio.Semaphore(max(1, section_picker_concurrency))

    # ---- Per-session catalog (ContextVar-backed; isolates concurrent projects) ----
    # All reads of self._resources / self._by_slug transparently resolve to the
    # current asyncio task's catalog (set by set_resources in _apply_project_
    # settings), falling back to the last-set baseline when the task never set one.
    @property
    def _resources(self):
        v = _tc_resources_ctx.get()
        return v if v is not None else self.__dict__.get("_resources_base", [])

    @_resources.setter
    def _resources(self, value):
        self.__dict__["_resources_base"] = value
        _tc_resources_ctx.set(value)

    @property
    def section_picker_llm(self):
        v = _tc_section_picker_ctx.get()
        return self._section_picker_base if v is _TC_PICKER_UNSET else v

    @section_picker_llm.setter
    def section_picker_llm(self, value):
        _tc_section_picker_ctx.set(value)

    @property
    def _by_slug(self):
        v = _tc_by_slug_ctx.get()
        return v if v is not None else self.__dict__.get("_by_slug_base", {})

    @_by_slug.setter
    def _by_slug(self, value):
        self.__dict__["_by_slug_base"] = value
        _tc_by_slug_ctx.set(value)

    # ---- Setters called from orchestrator._apply_project_settings ----

    def set_resources(self, raw_resources: List[Dict[str, Any]]) -> None:
        """Replace the in-memory catalog. Filters out disabled entries."""
        out: List[_Resource] = []
        for r in raw_resources or []:
            if not r.get("enabled", True):
                continue
            try:
                out.append(_Resource(
                    id=str(r.get("id", "")),
                    slug=str(r.get("slug", "")),
                    name=str(r.get("name", "")),
                    url=str(r.get("url", "")),
                    enabled=bool(r.get("enabled", True)),
                    resource_type=str(r.get("resourceType", "agentic-crawl")),
                    summary=str(r.get("summary", "")),
                    sitemap=r.get("sitemap") or {},
                    cache_ttl_sec=int(r.get("cacheTtlSec", 0) or 0),
                    github_token_override=str(r.get("githubTokenOverride", "") or ""),
                ))
            except Exception as e:
                logger.warning(f"[tradecraft] bad resource row skipped: {type(e).__name__}: {e}")
        self._resources = out
        self._by_slug = {r.slug: r for r in out if r.slug}
        logger.info(f"[tradecraft] manager initialized resources={len(out)}")

    @staticmethod
    def _run_github_token() -> str:
        """The GitHub token of the run being served, read at call time (RBAC T17).

        Only the settings bound to the run's task count, as tools.run_user_settings:
        never a token a previous run left on this shared manager, nor the module-global
        snapshot of the last-loaded (another owner's) project.
        """
        import project_settings
        user_settings = (project_settings._settings_ctx.get() or {}).get("USER_SETTINGS") or {}
        return str(user_settings.get("githubAccessToken") or "")

    # ---- TOOL_REGISTRY entry builder ----

    def build_registry_entry(self) -> Dict[str, str]:
        """Compose the rich per-resource catalog text for the system prompt."""
        if not self._resources:
            return {}
        lines = [
            "**tradecraft_lookup** (Curated technique/payload/PoC fetcher)",
            "   Fetch authoritative exploitation tradecraft from a known knowledge resource.",
            "   Use AFTER `query_graph` and `web_search` when you need a specific exploitation",
            "   page, payload, or PoC, not general background.",
            "",
            "   Available `resource_id` slugs (pick the best one for your query):",
        ]
        for r in self._resources:
            wrapped = textwrap.fill(
                r.summary or "(no summary)",
                width=72,
                initial_indent="       ",
                subsequent_indent="       ",
            )
            lines.append(f"     - `{r.slug}`  ({r.resource_type})  {r.url}")
            lines.append(wrapped)
        lines.append("")
        lines.append('   For cve-poc-db slugs you MUST also pass `cve_id="CVE-YYYY-NNNNN"`.')
        lines.append('   "PoC not found" is final for that slug and CVE: do not retry it with other')
        lines.append("   spellings or sibling slugs of the same repo; move on (web_search, or fetch the")
        lines.append("   repository's README directly with execute_curl).")
        lines.append("   Pass `force_refresh=true` to bypass cache.")
        return {
            "purpose": "Curated technique/payload/PoC fetcher",
            "when_to_use": "Mid-attack: technique lookup, payload pull, CVE PoC code (after query_graph + web_search)",
            "args_format": (
                '"resource_id": "...", "query": "...", '
                '"cve_id": "CVE-YYYY-NNNNN" (optional), '
                '"section_path": "..." (optional), '
                '"force_refresh": false'
            ),
            "description": "\n".join(lines),
        }

    # ---- Tool factory ----

    def get_tool(self) -> Optional[Callable]:
        """Returns the @tool-decorated callable. Always returns the tool (kept
        permanently registered) so its presence never races across concurrent
        sessions; the closure reads this session's resources at call time and
        _invoke returns a graceful "resource not configured" when the current
        session has none (e.g. tradecraft disabled for that project)."""
        manager = self

        @tool
        async def tradecraft_lookup(
            resource_id: str,
            query: str = "",
            cve_id: Optional[str] = None,
            section_path: Optional[str] = None,
            force_refresh: bool = False,
        ) -> str:
            """Fetch curated exploitation tradecraft from a configured knowledge resource.

            The list of available `resource_id` slugs and what each covers is
            provided in the system prompt under TOOL_REGISTRY[tradecraft_lookup].

            Args:
                resource_id: slug of the resource (see system prompt for the catalog)
                query: free-text technique/topic
                cve_id: required when the resource is a cve-poc-db
                section_path: skip auto-pick; force a specific page or "page=N" for PDFs
                force_refresh: bypass cache
            """
            return await manager._invoke(
                resource_id=resource_id,
                query=query or "",
                cve_id=cve_id,
                section_path=section_path,
                force_refresh=force_refresh,
            )

        return tradecraft_lookup

    # ---- Path resolver ----

    # Recognized file extensions for "this path is a real file, do not append README"
    _KNOWN_EXTENSIONS = (
        ".html", ".htm", ".md", ".txt", ".rst",
        ".pdf", ".json", ".yaml", ".yml", ".xml",
    )

    def _resolve_path_for_resource(self, r: "_Resource", path: str) -> str:
        """Resolve a relative or absolute path into a fetchable URL.

        Order of attempts:
          1. Already an absolute URL (http/https) -> return as-is.
          2. Try to locate the path in the resource's stored sitemap by exact
             match on title, exact match on entry path, or substring match on
             entry path. If found, use the entry's stored path/URL verbatim.
             This handles Sphinx module names like 'scapy.layers.l2' that
             would otherwise mis-resolve to a 404 URL.
          3. github-repo: rewrite to raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}.
          4. sphinx-docs: append `.html` if missing.
          5. Generic fallback: urljoin against r.url, URL-encoded.
        """
        if not path:
            return r.url
        if path.startswith(("http://", "https://")):
            return path

        path = path.lstrip("/")

        # Step 2: try the sitemap first. The sitemap was built at verify time
        # with canonical URLs / paths; using one of those guarantees a working
        # URL without per-type guesswork.
        matched_entry = self._find_in_sitemap(r, path)
        if matched_entry:
            mp = matched_entry.get("path") or ""
            if mp.startswith(("http://", "https://")):
                return mp
            # Matched entry has a relative path; fall through to type-specific
            # URL construction with that path instead of the user-provided one.
            path = mp.lstrip("/")

        # Step 3: github-repo gets the raw.githubusercontent.com rewrite.
        if r.resource_type == "github-repo":
            # If path has no recognized file ext, assume it's a folder and
            # target README.md so we get markdown instead of github.com's
            # directory HTML listing.
            looks_like_file = path.lower().endswith(self._KNOWN_EXTENSIONS)
            if not looks_like_file:
                path = path.rstrip("/") + "/README.md"
            encoded = "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/"))
            parsed = _split_github_url(r.url)
            if parsed:
                owner, repo = parsed
                branch = (r.sitemap or {}).get("branch") or "main"
                return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{encoded}"

        # Step 4: Sphinx pages always end in .html.
        if r.resource_type == "sphinx-docs":
            if not path.lower().endswith(self._KNOWN_EXTENSIONS):
                path = path + ".html"
            base = r.url.rstrip("/") + "/"
            encoded = "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/"))
            return urllib.parse.urljoin(base, encoded)

        # Step 5: generic fallback for mkdocs-wiki / gitbook / agentic-crawl.
        encoded = "/".join(urllib.parse.quote(seg, safe="") for seg in path.split("/"))
        base = r.url.rstrip("/") + "/"
        return urllib.parse.urljoin(base, encoded)

    def _find_in_sitemap(self, r: "_Resource", path_or_title: str) -> Optional[Dict[str, str]]:
        """Look up an entry in the resource's sitemap matching by title or path.

        Match priority:
          1. Exact title match (case-insensitive).
          2. Path ends with `/<input>.html` or `/<input>.md` etc (sphinx
             module name -> page).
          3. Path contains `<input>` as a substring (last resort).
        Returns the matched entry dict or None.
        """
        entries = _sitemap_entries(r.sitemap)
        if not entries:
            return None
        needle = path_or_title.strip().lower()
        if not needle:
            return None
        # 1. exact title
        for e in entries:
            if (e.get("title") or "").strip().lower() == needle:
                return e
        # 2. path stem matches (handles "scapy.layers.l2" -> ".../scapy.layers.l2.html")
        for e in entries:
            p = (e.get("path") or "").lower()
            for ext in self._KNOWN_EXTENSIONS:
                if p.endswith(f"/{needle}{ext}") or p.endswith(f"{needle}{ext}"):
                    return e
        # 3. substring on path (very loose)
        for e in entries:
            if needle in (e.get("path") or "").lower():
                return e
        return None

    # ---- Tool invocation core ----

    async def _invoke_pdf(
        self,
        *,
        r: "_Resource",
        query: str,
        section_path: Optional[str],
        force_refresh: bool,
        token: str,
        ttl: int,
        t0: float,
    ) -> str:
        pages_meta = (r.sitemap or {}).get("pages") or []
        if not pages_meta:
            return f"Error: PDF resource '{r.slug}' has no extracted pages."

        # Determine target page
        page_n: Optional[int] = None
        if section_path:
            m = re.search(r"page\s*=\s*(\d+)", section_path) or re.fullmatch(r"\s*(\d+)\s*", section_path)
            if m:
                page_n = int(m.group(1))
            else:
                return f"Error: section_path for PDF must be 'page=N' or just an integer."
        else:
            # Section picker over firstLines
            entries = [{"title": e.get("firstLine", ""), "path": f"page={e.get('page')}"} for e in pages_meta]
            picked = await _pick_section(
                query=query,
                sitemap={"nav": entries},
                section_picker_llm=self.section_picker_llm,
                semaphore=self._section_sem,
                resource_name=r.name or r.slug,
            )
            if picked is None:
                return f"PDF '{r.slug}': no page matched query={query!r}."
            m = re.search(r"page=(\d+)", picked.get("path", ""))
            if not m:
                return f"PDF '{r.slug}': internal error (picker returned bad path)."
            page_n = int(m.group(1))

        if page_n < 1 or page_n > len(pages_meta):
            return f"PDF '{r.slug}': page {page_n} out of range (1..{len(pages_meta)})."

        # Cache lookup
        cached = None if force_refresh else self.cache.lookup_pdf_page(r.slug, r.url, page_n)
        if cached is not None:
            elapsed = int((time.time() - t0) * 1000)
            logger.info(
                f"[tradecraft] tool result resource_id={r.slug} url={r.url}#page={page_n} "
                f"cache=hit tier=1 chars={len(cached)} elapsed_ms={elapsed}"
            )
            return format_output(
                resource_id=r.slug,
                url=f"{r.url}#page={page_n}",
                section_title=f"page {page_n}",
                content=cached,
                cache="hit",
                tier=1,
            )

        # Cache miss: re-fetch and re-extract entire PDF (acceptable on rare miss)
        if force_refresh:
            self.cache.invalidate(r.url)
        fetched = await fetch_tier1(
            r.url,
            timeout=get_setting('TRADECRAFT_FETCH_TIMEOUT', self.fetch_timeout),
            github_token=token,
        )
        if "application/pdf" not in (fetched.content_type or ""):
            return f"PDF '{r.slug}': URL no longer returns a PDF (got {fetched.content_type!r})."
        _, page_texts, pdf_err = _extract_pdf_pages(fetched.raw_bytes or b"")
        if not page_texts:
            return f"PDF '{r.slug}': extraction failed ({pdf_err or 'no pages'})"
        self.cache.store_pdf_pages(r.slug, r.url, page_texts, ttl)
        if page_n > len(page_texts):
            return f"PDF '{r.slug}': page {page_n} not in cached PDF (real pages: {len(page_texts)})."
        text = page_texts[page_n - 1] or ""
        elapsed = int((time.time() - t0) * 1000)
        logger.info(
            f"[tradecraft] tool result resource_id={r.slug} url={r.url}#page={page_n} "
            f"cache=miss tier=1 chars={len(text)} elapsed_ms={elapsed}"
        )
        return format_output(
            resource_id=r.slug,
            url=f"{r.url}#page={page_n}",
            section_title=f"page {page_n}",
            content=text,
            cache="miss",
            tier=1,
        )

    async def _invoke(
        self,
        *,
        resource_id: str,
        query: str,
        cve_id: Optional[str],
        section_path: Optional[str],
        force_refresh: bool,
    ) -> str:
        t0 = time.time()
        r = self._by_slug.get(resource_id or "")
        if r is None:
            return (
                f"Error: resource '{resource_id}' not configured. "
                f"Available: {', '.join(sorted(self._by_slug.keys())) or '(none)'}."
            )
        token = r.github_token_override or self._run_github_token()
        ttl = r.cache_ttl_sec or DEFAULT_TTLS_BY_TYPE.get(
            r.resource_type, get_setting('TRADECRAFT_DEFAULT_TTL_SEC', self.default_ttl))
        cache_status = "miss"
        tier = 1

        # PDF special path: when sitemap has `pages`, the resource is a PDF.
        # Honor section_path="page=N" / "N", or run the picker over firstLines.
        sitemap = r.sitemap or {}
        if isinstance(sitemap.get("pages"), list) and sitemap.get("pages"):
            return await self._invoke_pdf(
                r=r,
                query=query,
                section_path=section_path,
                force_refresh=force_refresh,
                token=token,
                ttl=ttl,
                t0=t0,
            )

        # CVE special path
        if r.resource_type == "cve-poc-db":
            if not cve_id or not CVE_ID_RE.match(cve_id):
                return (
                    f"Error: resource '{resource_id}' is a cve-poc-db; "
                    f"you must pass cve_id='CVE-YYYY-NNNNN'."
                )
            cve_id_norm = cve_id.upper()
            cache_url = f"cve://{r.slug}/{cve_id_norm}"
            if not force_refresh:
                hit = self.cache.lookup(cache_url)
                if hit:
                    elapsed = int((time.time() - t0) * 1000)
                    logger.info(
                        f"[tradecraft] tool result resource_id={r.slug} url={cache_url} "
                        f"cache=hit tier=1 chars={hit['bytes']} elapsed_ms={elapsed}"
                    )
                    return format_output(
                        resource_id=r.slug,
                        url=cache_url,
                        section_title=cve_id_norm,
                        content=hit["content"],
                        cache="hit",
                        tier=1,
                    )
            content, src_url, api_error = await _cve_lookup_detailed(
                cve_id_norm, r.sitemap, github_token=token
            )
            section_title = cve_id_norm
            if not content and api_error:
                # Not a "no PoC" answer: say so, or the agent concludes the
                # PoC does not exist and loops on other resources.
                return (
                    f"Error: could not look up {cve_id_norm} in resource '{resource_id}': "
                    f"{api_error}. This is NOT a 'PoC not found' answer; retry later or "
                    f"add a GitHub token in Global Settings -> API Keys."
                )
            if not content:
                # A repo stored as cve-poc-db before the stricter detection may
                # be a single-PoC repo with no {year}/{CVE} entries. Its README
                # is the PoC when it names the CVE.
                readme, readme_url = await _repo_readme(r.sitemap, github_token=token)
                if readme and cve_id_norm in readme.upper():
                    content, src_url = readme, readme_url
                    section_title = f"{cve_id_norm} (repository README; no {cve_id_norm.split('-')[1]}/{cve_id_norm} entry)"
            if not content:
                return (
                    f"PoC not found for {cve_id_norm} in resource '{resource_id}' "
                    f"(no archive entry, and the repository README does not mention it)."
                )
            self.cache.store(r.slug, cache_url, content, ttl, 1)
            elapsed = int((time.time() - t0) * 1000)
            logger.info(
                f"[tradecraft] tool result resource_id={r.slug} url={src_url} "
                f"cache=miss tier=1 chars={len(content)} elapsed_ms={elapsed}"
            )
            return format_output(
                resource_id=r.slug,
                url=src_url,
                section_title=section_title,
                content=content,
                cache="miss",
                tier=1,
            )

        # Resolve target URL using a single resolver that handles github-repo
        # raw URL rewriting + URL-encoding for both forced section_path and
        # auto-picked entries.
        target_url: str
        section_title = ""
        if section_path:
            target_url = self._resolve_path_for_resource(r, section_path)
            section_title = section_path
        else:
            picked = await _pick_section(
                query=query,
                sitemap=r.sitemap,
                section_picker_llm=self.section_picker_llm,
                semaphore=self._section_sem,
                resource_name=r.name or r.slug,
            )
            if picked is None:
                target_url = r.url
                section_title = "(homepage)"
            else:
                p = picked.get("path") or ""
                target_url = self._resolve_path_for_resource(r, p)
                section_title = picked.get("title") or p

        logger.info(
            f"[tradecraft] tool call resource_id={r.slug} query={query!r} "
            f"cve_id={cve_id} section={'forced' if section_path else 'auto'}"
        )

        # SSRF re-check on the resolved URL
        ok, err = validate_url(target_url)
        if not ok:
            return f"Error: refusing to fetch {target_url}: {err}"

        # Cache lookup
        async with self.cache.lock_for(target_url):
            if not force_refresh:
                hit = self.cache.lookup(target_url)
                if hit:
                    elapsed = int((time.time() - t0) * 1000)
                    logger.info(
                        f"[tradecraft] tool result resource_id={r.slug} url={target_url} "
                        f"cache=hit tier={hit['tier']} chars={hit['bytes']} elapsed_ms={elapsed}"
                    )
                    return format_output(
                        resource_id=r.slug,
                        url=target_url,
                        section_title=section_title,
                        content=hit["content"],
                        cache="hit",
                        tier=hit["tier"],
                    )
            else:
                self.cache.invalidate(target_url)

            fetched = await smart_fetch(
                target_url,
                mcp_manager=self.mcp_manager,
                github_token=token,
                timeout=get_setting('TRADECRAFT_FETCH_TIMEOUT', self.fetch_timeout),
                tier2_threshold_bytes=get_setting(
                    'TRADECRAFT_TIER2_THRESHOLD_BYTES', self.tier2_threshold_bytes),
            )
            tier = fetched.tier
            if fetched.blocked:
                return f"Error: refusing to fetch {target_url}: {fetched.blocked}"
            if not fetched.text:
                return (
                    f"Error: failed to fetch {target_url} "
                    f"(status={fetched.status}, tier={tier})."
                )
            self.cache.store(r.slug, target_url, fetched.text, ttl, tier)
            elapsed = int((time.time() - t0) * 1000)
            logger.info(
                f"[tradecraft] tool result resource_id={r.slug} url={target_url} "
                f"cache={cache_status} tier={tier} chars={len(fetched.text)} elapsed_ms={elapsed}"
            )
            return format_output(
                resource_id=r.slug,
                url=target_url,
                section_title=section_title,
                content=fetched.text,
                cache=cache_status,
                tier=tier,
            )
