"""One guarded HTTP fetcher for every request a URL import makes.

Redirects are followed by hand, at most 5 hops, and every hop is checked:
`assert_safe_fetch_url` first, then the caller's optional hop policy (the
website mirror adds the hard guardrail, RoE and scope there). The transport is
`pinned_async_transport()`, which judges and dials the same address, so DNS
rebinding cannot slip a hop into an internal address either. The user's GitHub
token is attached only on hops to an exact GitHub host over https; a redirect
to codeload (whose URL carries its own temporary token) never gets it.

Bodies stream to disk in 64 KiB chunks with real byte caps.
"""
from __future__ import annotations

import asyncio
import email.message
import hashlib
import inspect
import json
import os
import socket
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional, Union

import httpx

from orchestrator_helpers.fetch_guard import UnsafeFetchURLError, assert_safe_fetch_url, pinned_async_transport
from orchestrator_helpers.web_sources import is_github_token_url
from workspace_import.errors import ImportFailure
from workspace_import.names import sanitize_name
from workspace_import.redact import redact_text, redact_url  # noqa: F401  (import code logs through these)

USER_AGENT = "RedAmon-WorkspaceImport/1.0"
MAX_REDIRECTS = 5
# httpx's timeout bounds each read, so a server that sends a byte every few
# seconds would hold a job forever: a body must deliver this much per window.
STALL_WINDOW_SEC = 60.0
STALL_MIN_BYTES = 64 * 1024
PROBE_BYTES = 64 * 1024
_CHUNK = 64 * 1024

HopPolicy = Callable[[str, int], Union[None, Awaitable[None]]]


@dataclass
class Probe:
    final_url: str
    status: int
    headers: httpx.Headers
    head: bytes
    hops: list = field(default_factory=list)


@dataclass
class Download:
    final_url: str
    status: int
    content_type: str
    filename: str
    bytes: int
    sha256: str
    hops: list = field(default_factory=list)


def disposition_filename(value: Optional[str]) -> str:
    """The filename of a Content-Disposition header, sanitized, or ''."""
    if not value:
        return ""
    msg = email.message.Message()
    msg["content-disposition"] = value
    try:
        name = msg.get_filename()
    except Exception:
        return ""
    return sanitize_name(name, fallback="") if name else ""


class _Pace:
    """Refuses a body that delivers less than `min_bytes` in any `window` seconds."""

    def __init__(self, window: float, min_bytes: int, clock: Callable[[], float]):
        self.window, self.min_bytes, self.clock = window, min_bytes, clock
        self.start, self.got = clock(), 0

    def add(self, n: int) -> None:
        self.got += n
        now = self.clock()
        if now - self.start >= self.window:
            if self.got < self.min_bytes:
                raise ImportFailure("timeout")
            self.start, self.got = now, 0


def _is_dns_failure(e: BaseException) -> bool:
    seen = 0
    while e is not None and seen < 6:
        if isinstance(e, socket.gaierror) or "could not resolve" in str(e).lower() \
                or "name or service not known" in str(e).lower():
            return True
        e = e.__cause__ or e.__context__
        seen += 1
    return False


class GuardedFetcher:
    def __init__(self, github_token: str = "", transport: Optional[httpx.AsyncBaseTransport] = None,
                 timeout: float = 20.0, hop_policy: Optional[HopPolicy] = None,
                 assert_safe: Callable[[str], None] = assert_safe_fetch_url,
                 stall_window: float = STALL_WINDOW_SEC, stall_min_bytes: int = STALL_MIN_BYTES,
                 clock: Callable[[], float] = time.monotonic):
        self._token = github_token or ""
        self._pace = lambda: _Pace(stall_window, stall_min_bytes, clock)
        self._transport = transport
        self._timeout = timeout
        self._hop_policy = hop_policy
        self._assert_safe = assert_safe
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "GuardedFetcher":
        self._client = httpx.AsyncClient(
            transport=self._transport or pinned_async_transport(),
            follow_redirects=False, timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _check_hop(self, url: str, hop: int, policy: Optional[HopPolicy] = None) -> None:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ImportFailure("unsupported_scheme")
        try:
            await asyncio.to_thread(self._assert_safe, url)
        except UnsafeFetchURLError:
            raise ImportFailure("blocked_address", detail=redact_url(url)) from None
        for check in (self._hop_policy, policy):
            if check is not None:
                result = check(url, hop)
                if inspect.isawaitable(result):
                    await result

    async def _send(self, url: str, accept: Optional[str] = None,
                    policy: Optional[HopPolicy] = None) -> tuple[httpx.Response, str, list]:
        """The open (streaming) response at the end of the redirect chain.
        `policy` runs on every hop of this request only, after the fetcher's own."""
        assert self._client is not None, "use GuardedFetcher as an async context manager"
        current, hops = url, []
        for hop in range(MAX_REDIRECTS + 1):
            await self._check_hop(current, hop, policy)
            headers = {"User-Agent": USER_AGENT}
            if accept:
                headers["Accept"] = accept
            if self._token and is_github_token_url(current):
                headers["Authorization"] = f"token {self._token}"
            request = self._client.build_request("GET", current, headers=headers)
            try:
                resp = await self._client.send(request, stream=True)
            except UnsafeFetchURLError:
                raise ImportFailure("blocked_address", detail=redact_url(current)) from None
            except httpx.TimeoutException:
                raise ImportFailure("timeout", detail=redact_url(current)) from None
            except httpx.HTTPError as e:
                code = "dns_failed" if _is_dns_failure(e) else "network_error"
                raise ImportFailure(code, detail=redact_url(current)) from None
            if resp.is_redirect and resp.headers.get("location"):
                nxt = str(resp.url.join(resp.headers["location"]))
                await resp.aclose()
                if urllib.parse.urlsplit(nxt).scheme.lower() not in ("http", "https"):
                    raise ImportFailure("unsupported_scheme")
                hops.append(redact_url(nxt))
                current = nxt
                continue
            return resp, current, hops
        raise ImportFailure("too_many_redirects", detail=redact_url(url))

    async def _read(self, resp: httpx.Response, max_bytes: int, *, truncate: bool = False) -> bytes:
        declared = resp.headers.get("content-length", "")
        if not truncate and declared.isdigit() and int(declared) > max_bytes:
            raise ImportFailure("too_large")
        body = bytearray()
        pace = self._pace()
        try:
            async for chunk in resp.aiter_bytes(_CHUNK):
                pace.add(len(chunk))
                body += chunk
                if len(body) > max_bytes:
                    if truncate:
                        return bytes(body[:max_bytes])
                    raise ImportFailure("too_large")
        except httpx.TimeoutException:
            raise ImportFailure("timeout") from None
        except httpx.HTTPError:
            raise ImportFailure("network_error") from None
        return bytes(body)

    async def probe(self, url: str) -> Probe:
        """Status, headers and the first 64 KiB of the body."""
        resp, final_url, hops = await self._send(url)
        try:
            head = await self._read(resp, PROBE_BYTES, truncate=True)
        finally:
            await resp.aclose()
        return Probe(final_url=final_url, status=resp.status_code, headers=resp.headers, head=head, hops=hops)

    async def get_json(self, url: str, *, max_bytes: int = 8 * 1024 * 1024, accept: Optional[str] = None):
        """(status, parsed JSON or None, headers)."""
        resp, _final, _hops = await self._send(url, accept=accept)
        try:
            raw = await self._read(resp, max_bytes)
        finally:
            await resp.aclose()
        try:
            obj = json.loads(raw) if raw else None
        except ValueError:
            obj = None
        return resp.status_code, obj, resp.headers

    async def get_text(self, url: str, *, max_bytes: int, accept: Optional[str] = None,
                       policy: Optional[HopPolicy] = None):
        """(status, text, final_url, headers)."""
        resp, final_url, _hops = await self._send(url, accept=accept, policy=policy)
        try:
            raw = await self._read(resp, max_bytes)
        finally:
            await resp.aclose()
        return resp.status_code, raw.decode(resp.encoding or "utf-8", "replace"), final_url, resp.headers

    async def download(self, url: str, dest, *, max_bytes: int,
                       progress: Optional[Callable[[int, Optional[int]], None]] = None,
                       on_bytes: Optional[Callable[[int], None]] = None,
                       cancel_event=None, policy: Optional[HopPolicy] = None,
                       check_response: Optional[Callable[[httpx.Response], None]] = None) -> Download:
        """Stream the body into `dest` (created, never overwritten). `on_bytes`
        sees the running total and may raise (a refused disk reservation);
        `check_response` sees a 2xx answer before any byte is written, and may
        raise to refuse it."""
        dest = Path(dest)
        resp, final_url, hops = await self._send(url, policy=policy)
        try:
            if resp.status_code == 404:
                raise ImportFailure("not_found", detail=redact_url(final_url))
            if not 200 <= resp.status_code < 300:
                raise ImportFailure("upstream_status", detail=str(resp.status_code))
            if check_response is not None:
                check_response(resp)
            declared = resp.headers.get("content-length", "")
            total = int(declared) if declared.isdigit() else None
            if total is not None and total > max_bytes:
                raise ImportFailure("too_large")
            digest, written = hashlib.sha256(), 0
            pace = self._pace()
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
            try:
                try:
                    async for chunk in resp.aiter_bytes(_CHUNK):
                        if cancel_event is not None and cancel_event.is_set():
                            raise ImportFailure("cancelled")
                        pace.add(len(chunk))
                        written += len(chunk)
                        if written > max_bytes:
                            raise ImportFailure("too_large")
                        if on_bytes is not None:
                            on_bytes(written)
                        view = memoryview(chunk)
                        while view:
                            view = view[os.write(fd, view):]
                        digest.update(chunk)
                        if progress is not None:
                            progress(written, total)
                except httpx.TimeoutException:
                    raise ImportFailure("timeout") from None
                except httpx.HTTPError:
                    raise ImportFailure("network_error") from None
            finally:
                os.close(fd)
        except BaseException:
            try:
                dest.unlink()
            except OSError:
                pass
            raise
        finally:
            await resp.aclose()
        return Download(
            final_url=final_url, status=resp.status_code,
            content_type=(resp.headers.get("content-type") or "").split(";")[0].strip().lower(),
            filename=disposition_filename(resp.headers.get("content-disposition")),
            bytes=written, sha256=digest.hexdigest(), hops=hops,
        )
