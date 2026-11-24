"""Fetching a page for ingestion, and cleaning it to Markdown (port of 1.x ``smart_fetch``).

Tier 1 is a plain GET through ``net.get_fetcher()``; tier 2 renders the page in the sandbox
browser when tier 1 gives too little text (``fetching.browserBelowChars``, 800) or the
resource asks for the browser every time. A refusal by the address guard stops both tiers:
the browser would follow the same redirect.

The GitHub token goes only to the exact GitHub hosts over https (R-114), and only on hops
to the host it was sent to (``same_host_headers``): a redirect elsewhere never carries it.

A resource's login (§6.6, T6.4: a cookie, custom headers, basic authentication) is bound for
the job, read or check that uses it (``use_login``, from the job's or the catalog's
credentials only). Every request this module sends to the resource's own host (the host of its
URL; its http to https upgrade) then carries the login as ``same_host_headers``, which
``net`` adds again only on a hop to that host, never on a redirect elsewhere. While a login is
bound the browser is never used (§5): ``smart_fetch`` and ``render`` refuse it whatever
"always use the browser" says, so no script, which other commands in the sandbox can read,
ever holds a login value; ``render`` takes no headers anyway.
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, AsyncContextManager, Awaitable, Callable, Iterator, Mapping, Optional, Sequence

from orchestrator_helpers.web_sources import (
    BeautifulSoup,
    _md,
    html_to_markdown,
    is_github_token_url,
    rewrite_github_url,
    url_host,
)
from logging_config import get_logger
from tradecraft import net
from tradecraft.settings import EffectiveSettings, constant, setting

logger = get_logger(__name__)

# Elements 1.x always drops before it looks for the article (web_sources.html_to_markdown).
_NOISE_ELEMENTS = ("nav", "footer", "header", "aside", "script", "style", "form", "iframe")
_ARTICLE_SELECTORS = ("article", "main", ".md-content", "[role='main']", ".post-content", ".content")
# The contract caps a URL at 2,048 characters; a longer one never becomes an entry. Counted
# in UTF-8 bytes, which is what the unique b-tree on (resource_id, url) measures.
MAX_URL_CHARS = 2048
# A plain page is read up to the ceiling of the browser's transfer limit (EX-2: 1,000,000
# characters came back intact), so a crawl's 8 parallel requests hold at most about 8 MB of
# bodies, not 8 x net.HARD_MAX_BYTES. A longer page is cut and counted ``page_too_large``; a
# PDF, which is read whole, is fetched again without this cap.
PAGE_MAX_BYTES = int(setting("fetching.browserMaxChars")["ceiling"])
PAGE_TOO_LARGE = "page_too_large"

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


_PDF_PAGE_FRAGMENT = re.compile(r"page=\d+")


def page_url(url: str) -> str:
    """The URL an entry of the map is stored under: ``canonical_url``, keeping a PDF page's
    ``#page=N``, the only fragment an entry holds (any other fragment is not a page)."""
    base, sep, fragment = (url or "").strip().partition("#")
    canonical = canonical_url(base)
    return f"{canonical}#{fragment}" if sep and _PDF_PAGE_FRAGMENT.fullmatch(fragment) else canonical


def entry_url_ok(url: str) -> bool:
    return bool(url) and len(url.encode("utf-8", "replace")) <= MAX_URL_CHARS and not net.url_problem(url)


_GITHUB_REPO_HOSTS = ("github.com", "raw.githubusercontent.com", "api.github.com")


def github_repo(url: str) -> Optional[tuple[str, str]]:
    """The repository a GitHub URL names, as (owner, repo) lowercased: ``github.com/<o>/<r>``,
    ``raw.githubusercontent.com/<o>/<r>`` and ``api.github.com/repos/<o>/<r>``. None for any other
    URL, and for a path holding a dot segment, which the client resolves before sending
    (``<o>/<r>/main/../../<other>/<repo>`` reaches another repository)."""
    try:
        parts = urllib.parse.urlsplit((url or "").strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or host not in _GITHUB_REPO_HOSTS:
        return None
    segments = [urllib.parse.unquote(s) for s in parts.path.split("/")[1:]]
    if any(s in (".", "..") or "/" in s or "\\" in s for s in segments):
        return None
    if host == "api.github.com":
        if not segments or segments[0] != "repos":
            return None
        segments = segments[1:]
    if len(segments) < 2 or not segments[0] or not segments[1]:
        return None
    return segments[0].lower(), segments[1].lower().removesuffix(".git")


def repo_token(url: str, github_token: Optional[str], resource_url: str) -> Optional[str]:
    """``github_token`` for a request to ``url`` only when ``url`` is inside the repository the
    resource's own URL names; None for every other URL, a resource that is no GitHub repository
    included. A run's read is steered by the agent's arguments and by page text, so the token
    must not reach the rest of the token's GitHub account through it."""
    if not github_token or not is_github_token_url(url):
        return None
    repo = github_repo(resource_url)
    return github_token if repo is not None and github_repo(url) == repo else None


def github_headers(url: str, github_token: Optional[str]) -> dict[str, str]:
    """The token for an https URL on a GitHub host; nothing for any other URL."""
    if github_token and is_github_token_url(url):
        return {"Authorization": f"token {github_token}"}
    return {}


def has_login(secrets: Any) -> bool:
    """Whether a job or read carries a login (§6.6): then the browser is never used (§5)."""
    credentials = getattr(secrets, "credentials", None)
    return credentials is not None and not credentials.is_empty()


# Header names a login may not set (the webapp refuses them when the login is saved; a login
# that bypassed it is still not sent with them). Cookie and Authorization come from their own fields.
FORBIDDEN_LOGIN_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection", "cookie",
                                     "authorization"})
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_LINE_BREAKS = ("\r", "\n", "\x00")


def _breaks(value: str) -> bool:
    """A CR, LF or NUL in a login value would add a header line."""
    return any(c in value for c in _LINE_BREAKS)


def login_headers(credentials: Any) -> dict[str, str]:
    """The request headers of a login: ``Cookie``, the custom headers, ``Authorization: Basic``.
    A part the webapp would have refused (a forbidden or malformed name, a line break, a ``:`` in
    the user name) is left out and logged by its field name only, never its value."""
    if credentials is None or credentials.is_empty():
        return {}
    out: dict[str, str] = {}
    left_out: list[str] = []
    for header in credentials.headers:
        name, value = header.name.strip(), header.value
        if not _TOKEN.match(name) or name.lower() in FORBIDDEN_LOGIN_HEADERS or not value or _breaks(value):
            left_out.append("header")
            continue
        out[name] = value
    if credentials.cookie:
        if _breaks(credentials.cookie):
            left_out.append("cookie")
        else:
            out["Cookie"] = credentials.cookie
    basic = credentials.basic_auth
    if basic is not None:
        user, password = basic.username or "", basic.password or ""
        if ":" in user or _breaks(user) or _breaks(password):
            left_out.append("basic_auth")
        else:
            out["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    if left_out:
        logger.warning(f"[tradecraft] login code=login_part_refused fields={','.join(sorted(set(left_out)))}")
    return out


@dataclass(frozen=True)
class _Login:
    origin: str
    headers: Mapping[str, str]


_LOGIN: contextvars.ContextVar[Optional[_Login]] = contextvars.ContextVar("tradecraft_login", default=None)


@contextlib.contextmanager
def use_login(resource_url: str, credentials: Any) -> Iterator[bool]:
    """Binds one resource's login for what runs inside (the task and the tasks it starts):
    every request to the resource's own host carries it, and the browser is refused. A resource
    without a login binds none, also inside another resource's binding. Yields whether a login
    is bound."""
    has = credentials is not None and not credentials.is_empty()
    token = _LOGIN.set(_Login(origin=resource_url, headers=login_headers(credentials)) if has else None)
    try:
        yield has
    finally:
        _LOGIN.reset(token)


def login_bound() -> bool:
    return _LOGIN.get() is not None


def login_for(url: str) -> dict[str, str]:
    """The bound login's headers for a request to ``url``: only on the resource's own host."""
    login = _LOGIN.get()
    if login is None or not login.headers:
        return {}
    try:
        same = net.carries_same_host_headers(login.origin, url)
    except ValueError:
        return {}
    return dict(login.headers) if same else {}


def _same_host(url: str, github_token: Optional[str]) -> Optional[dict[str, str]]:
    headers = {**github_headers(url, github_token), **login_for(url)}
    return headers or None


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
        same_host_headers=_same_host(url, github_token),
        timeout=float(settings.int("fetching.requestTimeoutSec")),
        max_bytes=max_bytes,
        max_redirects=int(constant("maxRedirects")),
    )


def stream_raw(url: str, settings: EffectiveSettings, *, github_token: Optional[str] = None,
               max_bytes: Optional[int] = None) -> AsyncContextManager[net.Streamed]:
    """``fetch_raw`` for a body read as it arrives (a repository archive): the same headers, token
    rule and redirect limit, through the same guarded hops."""
    return net.get_fetcher().stream(
        url,
        headers=request_headers(settings),
        same_host_headers=_same_host(url, github_token),
        timeout=float(settings.int("fetching.requestTimeoutSec")),
        max_bytes=max_bytes,
        max_redirects=int(constant("maxRedirects")),
    )


async def render(url: str, settings: EffectiveSettings) -> net.Rendered:
    """The sandbox browser's render of ``url`` with the 2.0 options: the one way tradecraft
    renders a page. Refused (``browser_unavailable``, no browser call) while a login is bound."""
    if login_bound():
        return net.Rendered(url=url, html="", error="browser_unavailable")
    return await net.get_fetcher().render(url, **render_options(settings))


Cleaner = Callable[[str], Awaitable[str]]


async def smart_fetch(url: str, settings: EffectiveSettings, *, github_token: Optional[str] = None,
                      allow_browser: bool = True, cleaner: Optional[Cleaner] = None,
                      max_bytes: Optional[int] = PAGE_MAX_BYTES,
                      headers: Optional[Mapping[str, str]] = None) -> FetchedPage:
    """Tier 1, then the browser when tier 1's cleaned text is under the threshold or not text
    (and the browser is allowed).

    ``cleaner`` turns HTML into Markdown; a job passes one that runs ``clean_page`` on its
    thread pool, and the default runs it here with the resource's content settings. Tier 1
    reads at most ``max_bytes``; a PDF cut there is read again whole (a PDF needs its end).
    ``headers`` go with tier 1 (an incremental refresh's validators): a 304 answer is returned as
    it is, never rendered."""
    target = rewrite_github_url(url)
    extra = dict(headers or {})
    if url_host(target) == "api.github.com":
        extra["Accept"] = "application/vnd.github.raw"
    if cleaner is None:
        options = content_options(settings)

        async def cleaner(html: str) -> str:
            return clean_page(html, **options)

    # §5: never the browser while a login is bound, whatever the caller allows.
    allow_browser = allow_browser and not login_bound()
    page = FetchedPage(url=url)
    if not settings.bool("fetching.alwaysBrowser") or not allow_browser:
        resp = await fetch_raw(target, settings, github_token=github_token, headers=extra, max_bytes=max_bytes)
        if resp.truncated and ("application/pdf" in resp.content_type or resp.body[:5] == b"%PDF-"):
            resp = await fetch_raw(target, settings, github_token=github_token, headers=extra)
        page = await _from_response(url, resp, cleaner)
        if page.error in ("unsafe_address", "userinfo_refused", "bad_url") or page.status == 304:
            return page
        if page.is_pdf:
            return page
        if page.ok_textual and len(page.text) >= settings.int("fetching.browserBelowChars"):
            return page
    if not (allow_browser and settings.bool("fetching.browserEnabled")):
        return page
    rendered = await render(url, settings)
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
