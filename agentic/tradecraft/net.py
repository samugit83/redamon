"""The boundary between tradecraft and the web: every page, sitemap, API answer and
rendered page tradecraft reads comes through a ``Fetcher``.

Production uses ``GuardedFetcher``: httpx over ``pinned_async_transport()`` (each
connection judged and dialled on the address it judged), redirects followed one hop
at a time with ``assert_safe_fetch_url`` on every hop, and the sandbox browser through
the ``execute_playwright`` MCP tool. Tests swap in ``FixtureFetcher``
(``tests/tradecraft_doubles.py``) with ``use_fetcher``; one contract suite holds both
to the same behaviour.

Failures never raise: a ``Response``/``Rendered`` carries a fixed ``error`` code
(see ``ERRORS``), never page text, so callers can report it and the job's
``errorCode`` stays a closed set.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Optional, Protocol
from urllib.parse import urljoin, urlsplit

import httpx

from logging_config import get_logger
from orchestrator_helpers.fetch_guard import (
    UnsafeFetchURLError,
    assert_safe_fetch_url,
    guarded_browser_script,
    parse_guarded_browser_output,
    pinned_async_transport,
)

logger = get_logger(__name__)

USER_AGENT = "RedAmon-Tradecraft/2.0"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

ERRORS = frozenset({
    "bad_url",              # not http(s), or no host
    "userinfo_refused",     # user name or password in the URL or a redirect target
    "unsafe_address",       # the egress guard refused a hop (loopback, private, metadata...)
    "too_many_redirects",
    "unreachable",          # name does not resolve, or the connection failed
    "timeout",
    "http_error",           # any other transport or protocol failure
    "browser_unavailable",  # no MCP manager, or no execute_playwright tool
    "browser_error",        # the MCP call failed
    "navigation_failed",    # the browser could not load the page
})

# No response body is read past this, whatever `max_bytes` asks: the per-page setting (2 MB at most) is far
# below it, so it only stops a caller that forgot `max_bytes` from reading an endless or decompressing body.
HARD_MAX_BYTES = 100 * 1024 * 1024

# The guarded script waits up to 30 s for the page and the sandbox kills a script at
# 60 s (mcp/servers/playwright_server.py); this outer bound only stops an MCP call that
# hangs beyond both.
_BROWSER_MARGIN_S = 30.0


@dataclass
class Response:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    content_type: str
    # The URLs that answered with a redirect, in order (the requested URL first).
    redirects: list[str] = field(default_factory=list)
    error: str = ""
    # The body was cut at max_bytes.
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass
class Rendered:
    url: str
    html: str
    error: str = ""


class Fetcher(Protocol):
    async def get(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        same_host_headers: Optional[Mapping[str, str]] = None,
        timeout: float = 30.0,
        max_bytes: Optional[int] = None,
        max_redirects: int = 5,
    ) -> Response: ...

    async def render(
        self,
        url: str,
        *,
        timeout: float = 30.0,
        wait_until: str = "networkidle",
        max_chars: int = 40000,
        clean: bool = False,
        wait_for: Optional[str] = None,
    ) -> Rendered: ...


def url_problem(url: str) -> str:
    """The error code that refuses ``url`` before any request, or ""."""
    try:
        parts = urlsplit((url or "").strip())  # raises ValueError on an unmatched "[" or "]"
        parts.port  # noqa: B018 - raises ValueError for a port outside 0-65535
        # An empty label ("a..b") or one over 63 characters fails here, before the resolver,
        # whose IDNA encoding would raise UnicodeError instead of failing the lookup.
        if parts.hostname:
            parts.hostname.encode("idna")
    except ValueError:
        return "bad_url"
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return "bad_url"
    # Any "@" in the authority: credentials in a URL would be sent to whoever the URL
    # (or a redirect) names, and end up in logs and maps. Logins have their own fields.
    if "@" in parts.netloc:
        return "userinfo_refused"
    return ""


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, (parts.hostname or "").lower().rstrip("."), port


def carries_same_host_headers(first_url: str, hop_url: str) -> bool:
    """Whether a hop may receive the caller's ``same_host_headers`` (logins).

    Same host and port as the first URL, or the http:80 -> https:443 upgrade of it.
    A downgrade to http, another port or another host never gets them.
    """
    f_scheme, f_host, f_port = _origin(first_url)
    h_scheme, h_host, h_port = _origin(hop_url)
    if f_host != h_host:
        return False
    if (f_scheme, f_port) == (h_scheme, h_port):
        return True
    return (f_scheme, f_port, h_scheme, h_port) == ("http", 80, "https", 443)


def _log_failure(code: str, url: str) -> None:
    # The host only: a path or query can carry a token the person pasted.
    try:
        host = urlsplit(url).hostname or "?"
    except ValueError:
        host = "?"
    logger.warning(f"[tradecraft] net {code} host={host}")


class GuardedFetcher:
    def __init__(self, mcp_manager: Any = None) -> None:
        self._mcp_manager = mcp_manager

    async def get(
        self,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        same_host_headers: Optional[Mapping[str, str]] = None,
        timeout: float = 30.0,
        max_bytes: Optional[int] = None,
        max_redirects: int = 5,
    ) -> Response:
        def failed(code: str, at: str, redirects: list[str]) -> Response:
            _log_failure(code, at)
            return Response(url=url, final_url=at, status=0, headers={}, body=b"",
                            content_type="", redirects=redirects, error=code)

        redirects: list[str] = []
        current = url
        base = {"user-agent": USER_AGENT}
        base.update({k.lower(): v for k, v in (headers or {}).items()})
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                transport=pinned_async_transport(),
            ) as client:
                for _hop in range(max_redirects + 1):
                    problem = url_problem(current)
                    if problem:
                        return failed(problem, current, redirects)
                    assert_safe_fetch_url(current)
                    hop_headers = dict(base)
                    if same_host_headers and carries_same_host_headers(url, current):
                        hop_headers.update({k.lower(): v for k, v in same_host_headers.items()})
                    async with client.stream("GET", current, headers=hop_headers) as resp:
                        location = resp.headers.get("location")
                        if resp.status_code in REDIRECT_STATUSES and location:
                            redirects.append(current)
                            current = urljoin(current, location)
                            continue
                        body, truncated = await _read_capped(resp, effective_max_bytes(max_bytes))
                        return Response(
                            url=url,
                            final_url=current,
                            status=resp.status_code,
                            headers=dict(resp.headers.items()),
                            body=body,
                            content_type=(resp.headers.get("content-type") or "").lower(),
                            redirects=redirects,
                            truncated=truncated,
                        )
                return failed("too_many_redirects", current, redirects)
        except UnsafeFetchURLError:
            return failed("unsafe_address", current, redirects)
        except (httpx.InvalidURL, ValueError):
            # A URL httpx cannot parse even though urlsplit could (stray characters, a bad port).
            return failed("bad_url", current, redirects)
        except httpx.TimeoutException:
            return failed("timeout", current, redirects)
        except httpx.ConnectError:
            return failed("unreachable", current, redirects)
        except httpx.HTTPError:
            return failed("http_error", current, redirects)

    async def render(
        self,
        url: str,
        *,
        timeout: float = 30.0,
        wait_until: str = "networkidle",
        max_chars: int = 40000,
        clean: bool = False,
        wait_for: Optional[str] = None,
    ) -> Rendered:
        problem = url_problem(url)
        if problem:
            _log_failure(problem, url)
            return Rendered(url=url, html="", error=problem)
        try:
            # Refuse before the browser runs: it would follow the same redirect into an
            # internal address that the HTTP path just refused.
            assert_safe_fetch_url(url)
        except UnsafeFetchURLError:
            _log_failure("unsafe_address", url)
            return Rendered(url=url, html="", error="unsafe_address")
        except ValueError:
            # A host the resolver cannot even encode; get() answers the same.
            _log_failure("bad_url", url)
            return Rendered(url=url, html="", error="bad_url")
        try:
            script = guarded_browser_script(url, timeout_ms=int(timeout * 1000), wait_until=wait_until,
                                            max_chars=max_chars, clean=clean, wait_for=wait_for)
        except ValueError:
            # An option outside what the script accepts (the settings' clamp keeps them inside).
            _log_failure("browser_error", url)
            return Rendered(url=url, html="", error="browser_error")
        output, error = await self.run_browser_script(script, timeout=timeout)
        if error:
            _log_failure(error, url)
            return Rendered(url=url, html="", error=error)
        html, blocked = parse_guarded_browser_output(output)
        if blocked:
            _log_failure("unsafe_address", url)
            return Rendered(url=url, html="", error="unsafe_address")
        if not html.strip():
            _log_failure("navigation_failed", url)
            return Rendered(url=url, html="", error="navigation_failed")
        return Rendered(url=url, html=html)

    async def run_browser_script(self, script: str, *, timeout: float = 30.0) -> tuple[str, str]:
        """Run an ``execute_playwright`` script; returns (output, error code).

        The tool gets the script and nothing else: without ``_redamon_ctx`` the sandbox
        never routes the page through the capture proxy, so a library page never lands
        in a project's recorded traffic (mcp/servers/playwright_server.py).
        """
        if self._mcp_manager is None:
            return "", "browser_unavailable"
        try:
            tools = await self._mcp_manager.get_tools()
        except Exception as e:
            logger.warning(f"[tradecraft] net mcp tools error: {type(e).__name__}")
            return "", "browser_unavailable"
        tool = next((t for t in tools or [] if getattr(t, "name", "") == "execute_playwright"), None)
        if tool is None:
            return "", "browser_unavailable"
        try:
            out = await asyncio.wait_for(tool.ainvoke({"script": script}), timeout=timeout + _BROWSER_MARGIN_S)
        except asyncio.TimeoutError:
            return "", "timeout"
        except Exception as e:
            logger.warning(f"[tradecraft] net browser error: {type(e).__name__}")
            return "", "browser_error"
        return _mcp_text(out), ""


def effective_max_bytes(max_bytes: Optional[int]) -> int:
    return HARD_MAX_BYTES if max_bytes is None else min(max_bytes, HARD_MAX_BYTES)


async def _read_capped(resp: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in resp.aiter_bytes():
        if size + len(chunk) > max_bytes:
            chunks.append(chunk[: max_bytes - size])
            return b"".join(chunks), True
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks), False


def _mcp_text(out: Any) -> str:
    # MCP answers come back as a string, a content block, or a list of blocks.
    if isinstance(out, str):
        return out
    if isinstance(out, dict):
        return str(out.get("text") or "")
    if isinstance(out, list):
        return "".join(str(it.get("text") or "") for it in out if isinstance(it, dict))
    return ""


_DEFAULT = GuardedFetcher()
_current: contextvars.ContextVar[Fetcher] = contextvars.ContextVar("tradecraft_fetcher", default=_DEFAULT)


def get_fetcher() -> Fetcher:
    return _current.get()


@contextlib.contextmanager
def use_fetcher(fetcher: Fetcher) -> Iterator[Fetcher]:
    token = _current.set(fetcher)
    try:
        yield fetcher
    finally:
        _current.reset(token)
