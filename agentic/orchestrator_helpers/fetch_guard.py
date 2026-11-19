"""Strict SSRF egress guard for agent-initiated fetches of EXTERNAL content
(STRIDE I18 — tradecraft crawl).

Unlike ``llm_url_guard`` (which deliberately *allows* loopback / RFC-1918 so the
self-hosted-model feature works), this guard is for fetching untrusted TARGET
web content: it must reject every internal destination. A crawl seed or a
redirect ``Location`` that points at loopback, an RFC-1918 host, link-local /
cloud metadata (``169.254.169.254``), CGNAT, or any non-global address is an
SSRF and is refused.

Reuses ``llm_url_guard._resolve_ips`` for DNS resolution (handles literal IPs,
IPv6 scope ids). Checking a URL up front is not enough on its own: httpx resolves
the name again when it connects, so a rebinding DNS answer slips through. Use
``pinned_async_transport()`` for the request itself; it judges the address at
connect time and dials exactly the address it judged (CVE-2026-111323).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpcore
import httpx

from .llm_url_guard import _resolve_ips, _BLOCKED_HOSTNAMES

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class UnsafeFetchURLError(ValueError):
    """Raised when a URL is not safe to fetch (SSRF into an internal address)."""


def _is_disallowed_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → refuse
    # Judge IPv4-mapped IPv6 (::ffff:10.0.0.1) on the embedded v4 value.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or ip in _CGNAT
    )


def is_safe_fetch_url(url: str) -> bool:
    try:
        assert_safe_fetch_url(url)
        return True
    except UnsafeFetchURLError:
        return False


def assert_safe_fetch_url(url: str) -> None:
    """Raise ``UnsafeFetchURLError`` if ``url`` must not be fetched.

    An unresolvable host is allowed (it cannot be an SSRF into a known internal
    IP, and the request will simply fail); every resolved address must be a
    global/public IP.
    """
    parsed = urlparse((url or "").strip())
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise UnsafeFetchURLError(
            f"refusing to fetch non-http(s) URL (scheme '{scheme or 'none'}')"
        )

    host = parsed.hostname
    if not host:
        raise UnsafeFetchURLError("refusing to fetch URL with no host")

    if host.lower().rstrip(".") in _BLOCKED_HOSTNAMES:
        raise UnsafeFetchURLError("refusing to fetch cloud-metadata host")

    for ip in _resolve_ips(host):
        if _is_disallowed_ip(ip):
            raise UnsafeFetchURLError(
                f"refusing to fetch URL resolving to non-public address {ip} "
                "(loopback / private / link-local / metadata)"
            )


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolves, judges and dials in one step, for every TCP connection.

    That closes the rebinding window (one DNS answer for the check, another for
    the connect) and covers redirect hops without re-checking URLs, since each
    hop opens its connection here. TLS still verifies the original hostname:
    httpcore takes SNI from the request origin, not from the address dialled.

    ``UnsafeFetchURLError`` is not an httpcore exception, so httpx re-raises it
    unmapped and callers can tell "refused" apart from "network failed".
    """

    def __init__(self, inner: httpcore.AsyncNetworkBackend) -> None:
        self._inner = inner

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host.lower().rstrip(".") in _BLOCKED_HOSTNAMES:
            raise UnsafeFetchURLError("refusing to connect to cloud-metadata host")
        ips = list(dict.fromkeys(await asyncio.to_thread(_resolve_ips, host)))
        if not ips:
            raise httpcore.ConnectError(f"could not resolve {host}")
        for ip in ips:
            if _is_disallowed_ip(ip):
                raise UnsafeFetchURLError(
                    f"refusing to connect to {host}: it resolves to non-public "
                    f"address {ip} (loopback / private / link-local / metadata)"
                )
        last_error: Exception = httpcore.ConnectError(f"could not connect to {host}")
        for ip in ips:
            try:
                return await self._inner.connect_tcp(
                    ip, port, timeout=timeout,
                    local_address=local_address, socket_options=socket_options,
                )
            except httpcore.ConnectError as e:
                last_error = e
        raise last_error

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise UnsafeFetchURLError("refusing to connect to a unix socket")

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


def pinned_async_transport() -> httpx.AsyncHTTPTransport:
    """An httpx transport whose every connection passes the egress check.

    httpx has no public hook for the network backend, so this wraps the one the
    connection pool dials with. If a future httpcore renames that attribute,
    this raises instead of handing back an unguarded transport.
    """
    transport = httpx.AsyncHTTPTransport()
    pool = transport._pool
    if not isinstance(getattr(pool, "_network_backend", None), httpcore.AsyncNetworkBackend):
        raise RuntimeError("httpcore pool has no _network_backend; cannot pin egress")
    pool._network_backend = _PinnedNetworkBackend(pool._network_backend)
    return transport


# Run by the execute_playwright MCP tool in script mode, which provides `page`.
# Two layers, because page.route() never sees HTTP redirect hops: Chromium
# follows a 302 internally, even one fulfilled from inside the handler
# (measured on Playwright 1.63). The route handler stops JS navigations and
# subresources aimed at internal hosts; the redirect chain is checked after
# load, and a page that crossed an internal hop is never printed. page.route()
# does not see a WebSocket, a popup's requests or a peer connection either: the
# same check refuses a WebSocket and a popup's requests on the page's context
# (fresh for every script, playwright_server.py), and an init script removes
# RTCPeerConnection and service-worker registration from every frame. A
# Playwright without route_web_socket raises before the page is opened, which
# net.render reads as browser_error. What stays open: the browser resolves names
# itself, so rebinding inside the browser, and the blind GET a redirect hop makes
# before the post-load check, are not closed.
_BROWSER_GUARD_SCRIPT = '''\
import ipaddress as _rd_ipaddress
import re as _rd_re
import socket as _rd_socket
import urllib.parse as _rd_urlparse
_rd_blocked_names = {blocked_names}
_rd_cgnat = _rd_ipaddress.ip_network("100.64.0.0/10")
_rd_verdicts = {{}}
def _rd_host_public(host):
    if host in _rd_blocked_names:
        return False
    try:
        infos = _rd_socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        ip = _rd_ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified or ip in _rd_cgnat):
            return False
    return True
def _rd_public(url):
    parts = _rd_urlparse.urlsplit(url)
    if parts.scheme in ("data", "blob"):
        return True
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ("http", "https") or not host:
        return False
    if host not in _rd_verdicts:
        _rd_verdicts[host] = _rd_host_public(host)
    return _rd_verdicts[host]
def _rd_route(route):
    if _rd_public(route.request.url):
        route.continue_()
    else:
        route.abort("blockedbyclient")
page.route("**/*", _rd_route)
def _rd_ws(ws):
    if _rd_public("http" + ws.url[2:] if ws.url.startswith("ws") else ws.url):
        ws.connect_to_server()
    else:
        ws.close(code=1008, reason="blocked")
_rd_ctx = page.context
_rd_ctx.route("**/*", _rd_route)
_rd_ctx.route_web_socket(_rd_re.compile(r".*"), _rd_ws)
_rd_ctx.add_init_script({no_peer_js})
try:
    _rd_resp = page.goto({url}, wait_until={wait_until}, timeout={timeout_ms})
except Exception as _rd_exc:
    print("[ERROR] Navigation failed: " + str(_rd_exc).splitlines()[0])
else:
{wait_for}    _rd_hops = [page.url]
    _rd_req = _rd_resp.request if _rd_resp is not None else None
    while _rd_req is not None:
        _rd_hops.append(_rd_req.url)
        _rd_req = _rd_req.redirected_from
    _rd_bad = [h for h in _rd_hops if not _rd_public(h)]
    if _rd_bad:
        print("[BLOCKED] navigation reached a non-public address: " + _rd_bad[0])
    else:
{read_page}
'''


# The in-page cleaning measured in EX-2 (Tradecraft 2.0, §7 item 9): inline script and style
# texts are emptied but the elements stay, so `script[src]` and every attribute marker
# survive; svg, noscript and template go; comments, meta, link and anchors are never touched,
# so type detection still sees its markers and the crawl every link. On a 1 MB page it
# brought the HTML under 40,000 characters with the whole article. One line on purpose:
# the MCP wrapper re-indents the script line by line.
_CLEAN_JS = (
    "() => { for (const s of document.querySelectorAll('script:not([src])')) s.textContent = ''; "
    "for (const s of document.querySelectorAll('style')) s.textContent = ''; "
    "for (const n of document.querySelectorAll('svg, noscript, template')) n.remove(); }"
)
# Run in every frame before the page's own scripts: no peer connection (its ICE traffic goes
# to any address, past every route) and no service worker (its requests pass no page route).
# One line on purpose, as _CLEAN_JS.
_NO_PEER_JS = (
    "for (const k of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel']) "
    "{ try { delete window[k]; } catch (e) {} } "
    "if (navigator.serviceWorker) { try { Object.defineProperty(navigator.serviceWorker, 'register', "
    "{ value: () => Promise.reject(new Error('blocked')) }); } catch (e) {} }"
)
_WAIT_UNTIL = ("load", "domcontentloaded", "networkidle", "commit")
CLEAN_FAILED = "[ERROR] Cleaning failed"
# The sandbox stops a script at 60 s (mcp/servers/playwright_server.py); the wait for an
# element gets what the page load leaves of 55 s, keeping 5 s to start and send the page.
_SCRIPT_BUDGET_MS = 55_000
_MIN_WAIT_FOR_MS = 1_000


def guarded_browser_script(
    url: str,
    *,
    timeout_ms: int = 30000,
    wait_until: str = "networkidle",
    max_chars: int = 40000,
    clean: bool = False,
    wait_for: Optional[str] = None,
) -> str:
    """execute_playwright ``script`` that renders ``url`` and returns its HTML,
    refusing to return a page reached through an internal address.

    With no option the script is the one 1.x tradecraft sent, plus the context's guards
    (WebSockets, popups, peer connections, service workers). ``clean``
    runs the EX-2 cleaning before the page is cut at ``max_chars``; ``wait_for`` is a CSS
    selector the page is given time to show (a page without it is still returned). Every
    variant keeps the same address checks, and the cleaning runs only on a page that passed
    them.
    """
    if wait_until not in _WAIT_UNTIL:
        raise ValueError(f"wait_until must be one of {', '.join(_WAIT_UNTIL)}")
    timeout_ms, max_chars = int(timeout_ms), int(max_chars)
    if timeout_ms < 1 or max_chars < 1:
        raise ValueError("timeout_ms and max_chars must be positive")
    wait_block = ""
    if wait_for:
        wait_ms = max(_MIN_WAIT_FOR_MS, min(timeout_ms, _SCRIPT_BUDGET_MS - timeout_ms))
        wait_block = (
            "    try:\n"
            f"        page.wait_for_selector({ascii(wait_for)}, timeout={wait_ms})\n"
            "    except Exception:\n"
            "        pass\n"
        )
    # ascii() gives a literal with every non-ASCII character escaped, so the
    # URL (or the selector) can neither break out of the string nor split the
    # line when the MCP wrapper re-indents the script with str.splitlines().
    read_page = f"        print(page.content()[:{max_chars}])"
    if clean:
        # The cleaning runs in the page's own JavaScript, which the page can break (a replaced
        # querySelectorAll, a throwing setter): then nothing is printed but a fixed error line,
        # never a traceback that would be taken for the page.
        read_page = (
            "        try:\n"
            f"            page.evaluate({ascii(_CLEAN_JS)})\n"
            "        except Exception:\n"
            f"            print({ascii(CLEAN_FAILED)})\n"
            "        else:\n"
            f"            print(page.content()[:{max_chars}])"
        )
    return _BROWSER_GUARD_SCRIPT.format(
        url=ascii(url),
        blocked_names=ascii(frozenset(_BLOCKED_HOSTNAMES)),
        wait_until=json.dumps(wait_until),
        timeout_ms=timeout_ms,
        wait_for=wait_block,
        read_page=read_page,
        no_peer_js=ascii(_NO_PEER_JS),
    )


def parse_guarded_browser_output(output: str) -> Tuple[str, str]:
    """Split guarded_browser_script output into (html, blocked_reason)."""
    text = (output or "").strip()
    if text.startswith("[BLOCKED]"):
        return "", text[len("[BLOCKED]"):].strip()
    if text.startswith(("[ERROR]", "[INFO]")):
        return "", ""
    return output or "", ""
