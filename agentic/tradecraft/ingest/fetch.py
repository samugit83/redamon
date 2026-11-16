"""Fetching a page for ingestion, and cleaning it to Markdown (port of 1.x ``smart_fetch``).

Tier 1 is a plain GET through ``net.get_fetcher()``; tier 2 renders the page in the sandbox
browser when tier 1 gives too little text (``fetching.browserBelowChars``, 800) or the
resource asks for the browser every time. A refusal by the address guard stops both tiers:
the browser would follow the same redirect.

The GitHub token goes only to the exact GitHub hosts over https (R-114), and only on hops
to the host it was sent to (``same_host_headers``): a redirect elsewhere never carries it.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, Optional, Sequence

from orchestrator_helpers.web_sources import (
    BeautifulSoup,
    _md,
    html_to_markdown,
    is_github_token_url,
    rewrite_github_url,
    url_host,
)
from tradecraft import net
from tradecraft.settings import EffectiveSettings, constant

# Elements 1.x always drops before it looks for the article (web_sources.html_to_markdown).
_NOISE_ELEMENTS = ("nav", "footer", "header", "aside", "script", "style", "form", "iframe")
_ARTICLE_SELECTORS = ("article", "main", ".md-content", "[role='main']", ".post-content", ".content")
# The contract caps a URL at 2,048 characters; a longer one never becomes an entry. Counted
# in UTF-8 bytes, which is what the unique b-tree on (resource_id, url) measures.
MAX_URL_CHARS = 2048

# net error code -> the job's error code (contract.ERROR_CODES).
_NET_TO_JOB = {
    "unsafe_address": "blocked_private_address",
    "userinfo_refused": "userinfo_refused",
    "bad_url": "bad_url",
    "timeout": "timeout",
}


@dataclass
class FetchedPage:
    """One page as ingestion sees it. ``html`` is the raw text (detection reads markers that
    the Markdown loses); ``text`` the cleaned Markdown; ``body`` the bytes (a PDF's)."""

    url: str
    final_url: str = ""
    status: int = 0
    content_type: str = ""
    body: bytes = b""
    html: str = ""
    text: str = ""
    tier: int = 1
    error: str = ""
    headers: dict = field(default_factory=dict)
    truncated: bool = False

    @property
    def is_pdf(self) -> bool:
        return "application/pdf" in self.content_type or self.body[:5] == b"%PDF-"

    @property
    def ok_textual(self) -> bool:
        ct = self.content_type
        return (200 <= self.status < 300 and len(self.text) >= 1
                and ("text" in ct or "json" in ct or "xml" in ct))


def canonical_url(url: str) -> str:
    """The URL a page is stored under: scheme and host lowercased, default port and
    fragment dropped, everything else (path, query) kept as the site wrote it."""
    try:
        parts = urllib.parse.urlsplit(url.strip())
        scheme = parts.scheme.lower()
        hostname = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return url
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    return urllib.parse.urlunsplit((scheme, host, parts.path or "/", parts.query, ""))


def entry_url_ok(url: str) -> bool:
    return bool(url) and len(url.encode("utf-8", "replace")) <= MAX_URL_CHARS and not net.url_problem(url)


def github_headers(url: str, github_token: Optional[str]) -> dict[str, str]:
    """The token for an https URL on a GitHub host; nothing for any other URL."""
    if github_token and is_github_token_url(url):
        return {"Authorization": f"token {github_token}"}
    return {}


def has_login(secrets: Any) -> bool:
    """Whether a job or read carries a login (§6.6): then the browser is never used (§5)."""
    credentials = getattr(secrets, "credentials", None)
    return credentials is not None and not credentials.is_empty()


def request_headers(settings: EffectiveSettings, extra: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    headers = {"User-Agent": settings.str("fetching.userAgent")}
    language = settings.str("fetching.acceptLanguage")
    if language:
        headers["Accept-Language"] = language
    headers.update(extra or {})
    return headers


def render_options(settings: EffectiveSettings) -> dict[str, Any]:
    """How every 2.0 browser render runs (§4.1): the page timeout, when the page counts as
    loaded, the element to wait for, and the transfer limit, applied after the page was
    cleaned in the browser (§7 item 9), so the limit spends itself on the article, not on
    inline scripts and styles."""
    return {
        "timeout": float(settings.int("fetching.browserTimeoutSec")),
        "wait_until": settings.str("fetching.browserWaitUntil"),
        "max_chars": settings.int("fetching.browserMaxChars"),
        "clean": True,
        "wait_for": settings.str("fetching.waitForSelector") or None,
    }


def clean_page(html: str, *, body_selector: Optional[str] = None, remove: Sequence[str] = ()) -> str:
    """HTML to Markdown, the same function for ingestion and reading. With no selector and no
    removals it is exactly 1.x's ``html_to_markdown``; ``body_selector`` names the article
    (``content.bodySelector``) and ``remove`` extra elements to drop (``content.removeSelectors``)."""
    if not html:
        return ""
    if not body_selector and not remove:
        return html_to_markdown(html)
    if BeautifulSoup is None:
        return re.sub(r"<[^>]+>", " ", html)
    soup = BeautifulSoup(html, "html.parser")
    for sel in (*_NOISE_ELEMENTS, *remove):
        try:
            for el in soup.select(sel):
                el.decompose()
        except Exception:  # an invalid selector from the person's settings: skip it
            continue
    body_html = None
    for sel in ((body_selector,) if body_selector else ()) + _ARTICLE_SELECTORS:
        try:
            el = soup.select_one(sel)
        except Exception:
            continue
        if el and (sel == body_selector or len(el.get_text(strip=True)) > 200):
            body_html = str(el)
            break
    if body_html is None:
        body_html = str(soup.body or soup)
    if _md is not None:
        try:
            return _md(body_html, heading_style="ATX")
        except Exception:
            pass
    return re.sub(r"<[^>]+>", " ", body_html)


def clean_page_args(html: str, body_selector: Optional[str] = None, remove: Sequence[str] = ()) -> str:
    """``clean_page`` with positional arguments only, for a thread pool's ``run_blocking``."""
    return clean_page(html, body_selector=body_selector, remove=remove)


def content_options(settings: EffectiveSettings) -> dict[str, Any]:
    return {"body_selector": settings.str("content.bodySelector") or None,
            "remove": tuple(settings.list("content.removeSelectors"))}


async def fetch_raw(url: str, settings: EffectiveSettings, *, github_token: Optional[str] = None,
                    headers: Optional[Mapping[str, str]] = None, max_bytes: Optional[int] = None) -> net.Response:
    """One GET (tier 1 only) with the resource's request headers: sitemaps, indexes, API answers."""
    extra = dict(headers or {})
    if url_host(url) == "api.github.com" and "Accept" not in extra:
        extra["Accept"] = "application/vnd.github+json"
    return await net.get_fetcher().get(
        url,
        headers=request_headers(settings, extra),
        same_host_headers=github_headers(url, github_token) or None,
        timeout=float(settings.int("fetching.requestTimeoutSec")),
        max_bytes=max_bytes,
        max_redirects=int(constant("maxRedirects")),
    )


Cleaner = Callable[[str], Awaitable[str]]


async def smart_fetch(url: str, settings: EffectiveSettings, *, github_token: Optional[str] = None,
                      allow_browser: bool = True, cleaner: Optional[Cleaner] = None) -> FetchedPage:
    """Tier 1, then the browser when tier 1's cleaned text is under the threshold or not text
    (and the browser is allowed).

    ``cleaner`` turns HTML into Markdown; a job passes one that runs ``clean_page`` on its
    thread pool, and the default runs it here with the resource's content settings."""
    target = rewrite_github_url(url)
    extra = {"Accept": "application/vnd.github.raw"} if url_host(target) == "api.github.com" else {}
    if cleaner is None:
        options = content_options(settings)

        async def cleaner(html: str) -> str:
            return clean_page(html, **options)

    page = FetchedPage(url=url)
    if not settings.bool("fetching.alwaysBrowser") or not allow_browser:
        resp = await fetch_raw(target, settings, github_token=github_token, headers=extra)
        page = await _from_response(url, resp, cleaner)
        if page.error in ("unsafe_address", "userinfo_refused", "bad_url"):
            return page
        if page.is_pdf:
            return page
        if page.ok_textual and len(page.text) >= settings.int("fetching.browserBelowChars"):
            return page
    if not (allow_browser and settings.bool("fetching.browserEnabled")):
        return page
    rendered = await net.get_fetcher().render(url, **render_options(settings))
    if rendered.error == "unsafe_address":
        # The browser saw the hop the address guard refuses: that wins over a thin tier 1.
        return FetchedPage(url=url, final_url=url, error="unsafe_address", tier=2)
    if rendered.html:
        text = await cleaner(rendered.html)
        if text:
            return FetchedPage(url=url, final_url=url, status=200, content_type="text/html",
                               body=rendered.html.encode("utf-8", "ignore"), html=rendered.html,
                               text=text, tier=2)
    return page


async def _from_response(url: str, resp: net.Response, cleaner: Cleaner) -> FetchedPage:
    page = FetchedPage(url=url, final_url=resp.final_url or url, status=resp.status,
                       content_type=resp.content_type, body=resp.body, error=resp.error,
                       headers=dict(resp.headers), truncated=resp.truncated, tier=1)
    if resp.error or page.is_pdf:
        if page.is_pdf and "pdf" not in page.content_type:
            page.content_type = "application/pdf"
        return page
    page.html = resp.text
    page.text = await cleaner(page.html) if "html" in page.content_type else page.html
    return page


def homepage_problem(page: FetchedPage, settings: EffectiveSettings) -> str:
    """1.x's pre-flight check of the start page, as a job error code ("" when usable): a
    refused address or login in the URL, no answer, an HTTP error, or a thin page (a PDF is
    never thin)."""
    if page.error:
        return _NET_TO_JOB.get(page.error, "fetch_failed")
    if page.is_pdf:
        return ""
    if page.status >= 400:
        return "homepage_http_error"
    if page.status == 0:
        return "fetch_failed"
    if len(page.text or "") < settings.int("detection.thinHomepageChars"):
        return "thin_homepage"
    return ""
