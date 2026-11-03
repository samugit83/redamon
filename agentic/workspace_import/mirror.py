"""A bounded website mirror: one site, breadth first, into a staging folder.

Every request (pages, assets, redirect hops, robots.txt, the sitemap) goes
through the guarded fetcher, so the SSRF guard and the pinned transport judge
every hop. Each request also passes this crawl's hop policy: the hard
guardrail, the project's RoE exclusions, robots.txt when asked, the page
scope, and the politeness gap. When the seed fails a check, the job ends with
that check's code. Any other URL is skipped and recorded in _manifest.jsonl.

Out of scope: JavaScript rendering, authenticated crawls, and rewriting links
inside the saved pages.
"""
from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import logging
import os
import posixpath
import shutil
import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Awaitable, Callable, Iterable, Optional

from orchestrator_helpers.hard_guardrail import is_hard_blocked
from orchestrator_helpers.web_sources import SITEMAP_MAX_BYTES, html_to_markdown, parse_sitemap_xml, prefer_english
from workspace_import import executor, pdf_text
from workspace_import.errors import ImportFailure, map_os_error
from workspace_import.fetch import USER_AGENT
from workspace_import.mirror_paths import (canonical_url, extract_css_urls, extract_links, is_css, is_html, is_pdf,
                                           media_type, url_to_relpath)
from workspace_import.redact import safe_traceback

logger = logging.getLogger(__name__)

MiB = 1024 * 1024
PER_FILE_BYTES = 25 * MiB
TOTAL_BYTES_CEILING = 500 * MiB
TIME_BUDGET_SEC = 30 * 60
CONCURRENCY = 4
SAME_HOST_GAP_SEC = 0.25
MAX_QUERY_VARIANTS = 20
MAX_SUB_SITEMAPS = 20
PROJECT_CHECK_SEC = 300
ROBOTS_MAX_BYTES = 512 * 1024
MANIFEST = "_manifest.jsonl"
READABLE_AS_IS = frozenset({"text/plain", "text/markdown", "application/json"})

DEFAULTS = {
    "website": {"outputMode": "raw", "maxPages": 300, "maxDepth": 3, "respectRobots": False,
                "englishOnly": False, "externalAssets": False},
    "docs-site": {"outputMode": "readable", "maxPages": 1000, "maxDepth": 6, "respectRobots": False,
                  "englishOnly": True, "externalAssets": False},
}
CEILINGS = {"maxPages": 2000, "maxDepth": 10}
OPTION_KEYS = tuple(DEFAULTS["website"])

# Failures that end the whole crawl even when a non-seed URL hit them.
_FATAL = frozenset({"insufficient_storage", "project_deleted", "settings_unavailable", "cancelled",
                    "roe_outside_window"})


@dataclass(frozen=True)
class MirrorOptions:
    output_mode: str = "raw"
    max_pages: int = 300
    max_depth: int = 3
    respect_robots: bool = False
    english_only: bool = False
    external_assets: bool = False
    max_bytes: int = TOTAL_BYTES_CEILING
    per_file_bytes: int = PER_FILE_BYTES
    time_budget_sec: float = TIME_BUDGET_SEC

    @property
    def readable(self) -> bool:
        return self.output_mode == "readable"

    @classmethod
    def for_kind(cls, kind: str, requested: Optional[dict] = None, *, total_cap: int) -> "MirrorOptions":
        """The kind's defaults, overridden by `requested` and clamped to the
        ceilings, whatever the request says. A wrong type is invalid_option."""
        if kind not in DEFAULTS:
            raise ImportFailure("kind_not_supported")
        values = dict(DEFAULTS[kind])
        for key, value in (requested or {}).items():
            if key not in OPTION_KEYS:
                continue
            if key == "outputMode":
                if value not in ("raw", "readable"):
                    raise ImportFailure("invalid_option", detail=key)
            elif key in CEILINGS:
                if type(value) is not int:
                    raise ImportFailure("invalid_option", detail=key)
                value = max(1 if key == "maxPages" else 0, min(value, CEILINGS[key]))
            elif type(value) is not bool:
                raise ImportFailure("invalid_option", detail=key)
            values[key] = value
        return cls(output_mode=values["outputMode"], max_pages=values["maxPages"], max_depth=values["maxDepth"],
                   respect_robots=values["respectRobots"], english_only=values["englishOnly"],
                   external_assets=values["externalAssets"],
                   max_bytes=max(1, min(total_cap, TOTAL_BYTES_CEILING)))

    def record(self) -> dict:
        """The options as .import.json stores them, so a Re-sync reuses them."""
        return {"outputMode": self.output_mode, "maxPages": self.max_pages, "maxDepth": self.max_depth,
                "respectRobots": self.respect_robots, "englishOnly": self.english_only,
                "externalAssets": self.external_assets}


@dataclass
class MirrorStats:
    pages: int = 0
    assets: int = 0
    bytes: int = 0
    skipped: int = 0
    stopped_because: str = "complete"

    def record(self) -> dict:
        return {"files": self.pages + self.assets, "bytes": self.bytes, "pages": self.pages,
                "assets": self.assets, "skipped": self.skipped, "stoppedBecause": self.stopped_because}


class Skip(Exception):
    """This URL is not saved; the crawl goes on."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _Stop(Exception):
    """The crawl ends early but keeps what it saved."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class _Item:
    url: str
    depth: int
    role: str  # "page" | "asset"


def no_userinfo(url: str) -> str:
    """The URL without user:password@ (a query stays: it is the site's data)."""
    parts = urllib.parse.urlsplit(url)
    if "@" not in parts.netloc:
        return url
    return urllib.parse.urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[1]))


def _host(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def _same_but_www(a: str, b: str) -> bool:
    return a.removeprefix("www.") == b.removeprefix("www.")


def _decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", "replace")


def _read_page(path: str, final_url: str, readable: bool, source: str):
    """On the import pool: (page links, asset links, markdown or None)."""
    with open(path, "rb") as f:
        html = _decode(f.read())
    pages, assets = extract_links(html, final_url)
    if not readable:
        return pages, assets, None
    header = f"<!-- source: {urllib.parse.quote(source, safe=':/?#[]@!$&()*+,;=%~')} -->\n\n"
    return pages, assets, (header + html_to_markdown(html)).encode("utf-8")


def _read_css(path: str, css_url: str):
    with open(path, "rb") as f:
        return extract_css_urls(_decode(f.read()), css_url)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Pacer:
    """At least `gap_for(host)` seconds between the starts of two requests to
    one host, redirect hops included."""

    def __init__(self, gap_for: Callable[[str], float], sleep, now):
        self._gap_for, self._sleep, self._now = gap_for, sleep, now
        self._next: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def wait(self, host: str) -> None:
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            now = self._now()
            due = self._next.get(host, now)
            if due > now:
                await self._sleep(due - now)
            self._next[host] = max(now, due) + self._gap_for(host)


class _Robots:
    """robots.txt per origin, read through the crawl's own fetcher (RFC 9309:
    a 4xx allows everything; a 5xx or no answer disallows everything)."""

    def __init__(self, fetch_text: Callable[[str], Awaitable[tuple]]):
        self._fetch_text = fetch_text
        self._rules: dict[str, object] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def verdict(self, url: str) -> str:
        """"allow", "disallow" or "unavailable"."""
        from urllib.robotparser import RobotFileParser

        parts = urllib.parse.urlsplit(url)
        origin = f"{parts.scheme.lower()}://{parts.netloc.rsplit('@', 1)[-1].lower()}"
        lock = self._locks.setdefault(origin, asyncio.Lock())
        async with lock:
            if origin not in self._rules:
                try:
                    status, text = await self._fetch_text(origin + "/robots.txt")
                except (ImportFailure, Skip):
                    status, text = None, ""
                if status is not None and 200 <= status < 300:
                    parser = RobotFileParser()
                    parser.parse(text.splitlines())
                    self._rules[origin] = parser
                elif status is not None and 400 <= status < 500:
                    self._rules[origin] = "allow"
                else:
                    self._rules[origin] = "unavailable"
        rules = self._rules[origin]
        if isinstance(rules, str):
            return rules
        return "allow" if rules.can_fetch(USER_AGENT, url) else "disallow"


class _Crawl:
    def __init__(self, seed: str, out_dir: Path, opts: MirrorOptions, *, fetcher_factory, hard_blocked,
                 roe_excluded, sleep, now, cancel_event, progress, grow, still_exists, concurrency, gap_for,
                 pdf_timeout):
        self.seed = seed
        self.out = Path(out_dir)
        self.tmp = self.out.parent / f"{self.out.name}.tmp"
        self.opts = opts
        self.fetcher_factory = fetcher_factory
        self.hard_blocked = hard_blocked
        self.roe_excluded = roe_excluded
        self.now = now
        self.cancel_event = cancel_event or threading.Event()
        self.progress = progress
        self.grow = grow
        self.still_exists = still_exists
        self.concurrency = max(1, concurrency)
        self.pdf_timeout = pdf_timeout
        self.pacer = _Pacer(gap_for or (lambda _h: SAME_HOST_GAP_SEC), sleep, now)
        self.robots = _Robots(self._robots_text) if opts.respect_robots else None

        self.stats = MirrorStats()
        self.manifest: list[dict] = []
        self.queue: asyncio.Queue[_Item] = asyncio.Queue()
        self.seen: set[str] = set()
        self.variants: Counter = Counter()
        self.files: set[str] = set()
        self.dirs: set[str] = set()
        self.saved_final: set[str] = set()
        self.scope_hosts: frozenset[str] = frozenset()
        self.scope_dir = "/"
        self.scope_scheme = "https"
        self.pages_started = 0
        self.page_cap_hit = False
        self.depth_cut = False
        self.downloaded = 0
        self.disk_bytes = 0
        self.stop_reason: Optional[str] = None
        self.fatal: Optional[BaseException] = None
        # Set on a fatal failure: the other workers are cancelled at once.
        self.halt = asyncio.Event()
        self.started = now()
        self.last_project_check = self.started
        self._check_lock = asyncio.Lock()
        self._names = itertools.count()
        self.fetcher = None

    # --- scope -------------------------------------------------------------

    def _set_scope(self, final_url: str) -> None:
        final_host, seed_host = _host(final_url), _host(self.seed)
        hosts = {final_host}
        if seed_host and seed_host != final_host and _same_but_www(seed_host, final_host):
            hosts.add(seed_host)
        self.scope_hosts = frozenset(hosts)
        self.scope_scheme = urllib.parse.urlsplit(final_url).scheme.lower() or "https"
        path = urllib.parse.urlsplit(final_url).path or "/"
        self.scope_dir = path[: path.rfind("/") + 1] or "/"

    def _in_page_scope(self, url: str) -> bool:
        parts = urllib.parse.urlsplit(url)
        return (parts.scheme.lower() in ("http", "https") and (parts.hostname or "").lower() in self.scope_hosts
                and (parts.path or "/").startswith(self.scope_dir))

    def _asset_allowed(self, url: str) -> bool:
        return _host(url) in self.scope_hosts or self.opts.external_assets

    # --- the hop policy ----------------------------------------------------

    def _refuse(self, seed: bool, code: str, reason: str):
        if seed:
            raise ImportFailure(code)
        raise Skip(reason)

    def _policy(self, role: str, *, seed: bool = False):
        async def check(url: str, hop: int) -> None:
            parts = urllib.parse.urlsplit(url)
            host = (parts.hostname or "").lower()
            if parts.username is not None or parts.password is not None:
                self._refuse(seed, "credentials_in_url", "credentials_in_url")
            if self.hard_blocked(host)[0]:
                self._refuse(seed, "hard_blocked", "hard_blocked")
            if self.roe_excluded is not None and self.roe_excluded(host):
                self._refuse(seed, "roe_excluded", "roe")
            if not seed and hop > 0:
                if role == "page" and not self._in_page_scope(url):
                    raise Skip("redirect_offsite")
                if role == "asset" and not self._asset_allowed(url):
                    raise Skip("redirect_offsite")
            if self.robots is not None and role != "robots":
                verdict = await self.robots.verdict(url)
                if verdict != "allow":
                    self._refuse(seed, "robots_disallowed" if verdict == "disallow" else "robots_unavailable",
                                 "robots")
            await self.pacer.wait(host)
        return check

    async def _robots_text(self, url: str) -> tuple:
        status, text, _final, _headers = await self.fetcher.get_text(
            url, max_bytes=ROBOTS_MAX_BYTES, policy=self._policy("robots"))
        return status, text

    # --- bookkeeping -------------------------------------------------------

    def _record(self, url: str, depth: int, *, skipped: Optional[str] = None, **fields) -> None:
        line = {"url": no_userinfo(url), "finalUrl": None, "status": None, "contentType": None, "bytes": 0,
                "sha256": None, "path": None, "depth": depth, "hops": [], "skipped": skipped}
        line.update(fields)
        self.manifest.append(line)
        if skipped:
            self.stats.skipped += 1

    def _report(self) -> None:
        if self.progress is not None:
            self.progress.update(phase="crawling", pages=self.stats.pages, assets=self.stats.assets,
                                 bytes=self.stats.bytes, queued=self.queue.qsize(), skipped=self.stats.skipped)

    def _on_bytes(self):
        last = 0

        def count(written: int) -> None:
            nonlocal last
            self.downloaded += written - last
            self.disk_bytes += written - last
            last = written
            if self.downloaded > self.opts.max_bytes:
                raise _Stop("max_bytes")
            if self.grow is not None:
                self.grow(self.disk_bytes)
        return count

    def _claim(self, rel: str) -> bool:
        """Reserve `rel` in the mirror: False when it clashes with a saved file
        or folder (/a saved as a file, then /a/b needing a folder a/)."""
        parts = rel.split("/")
        ancestors = ["/".join(parts[:i]) for i in range(1, len(parts))]
        if rel in self.files or rel in self.dirs or any(a in self.files for a in ancestors):
            return False
        self.dirs.update(ancestors)
        self.files.add(rel)
        return True

    def _place(self, tmp: Path, rel: str) -> Path:
        dest = self.out / rel
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o777)
        os.rename(tmp, dest)
        return dest

    def _write(self, rel: str, data: bytes) -> None:
        dest = self.out / rel
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o777)
        self.disk_bytes += len(data)
        if self.grow is not None:
            self.grow(self.disk_bytes)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)

    # --- the crawl ---------------------------------------------------------

    def _enqueue(self, url: str, depth: int, role: str) -> None:
        canon = canonical_url(url)
        if canon in self.seen:
            return
        if role == "page":
            if not self._in_page_scope(url):
                return
            if depth > self.opts.max_depth:
                self.depth_cut = True
                return
        elif not self._asset_allowed(url):
            return
        self.seen.add(canon)
        if urllib.parse.urlsplit(canon).query:
            key = canon.split("?", 1)[0]
            if self.variants[key] >= MAX_QUERY_VARIANTS:
                self._record(url, depth, skipped="query_variants")
                return
            self.variants[key] += 1
        self.queue.put_nowait(_Item(url, depth, role))

    def _check_budget(self) -> None:
        if self.cancel_event.is_set():
            raise ImportFailure("cancelled")
        if self.now() - self.started >= self.opts.time_budget_sec:
            raise _Stop("time_budget")

    async def _check_project(self) -> None:
        if self.still_exists is None:
            return
        async with self._check_lock:
            if self.now() - self.last_project_check < PROJECT_CHECK_SEC:
                return
            self.last_project_check = self.now()
            await self.still_exists()

    def _type_gate(self, resp) -> None:
        if not self.opts.readable:
            return
        media = media_type(resp.headers.get("content-type"))
        if not (is_html(media) or is_pdf(media) or media in READABLE_AS_IS):
            raise Skip("not_text")

    async def _fetch(self, item: _Item, *, seed: bool = False) -> None:
        tmp = self.tmp / str(next(self._names))
        try:
            dl = await self.fetcher.download(
                item.url, tmp, max_bytes=self.opts.per_file_bytes, on_bytes=self._on_bytes(),
                cancel_event=self.cancel_event, policy=self._policy(item.role, seed=seed),
                check_response=self._type_gate)
        except Skip as s:
            self._record(item.url, item.depth, skipped=s.reason)
            return
        except ImportFailure as e:
            if seed:
                raise ImportFailure("upstream_status") if e.code == "not_found" else e
            if e.code in _FATAL:
                raise
            status = 404 if e.code == "not_found" else int(e.detail) if e.detail.isdigit() else None
            self._record(item.url, item.depth, skipped="status" if status else e.code, status=status)
            return
        try:
            await self._save(item, tmp, dl, seed=seed)
        finally:
            if tmp.exists():
                tmp.unlink()

    async def _save(self, item: _Item, tmp: Path, dl, *, seed: bool) -> None:
        if seed:
            self._set_scope(dl.final_url)
        line = {"finalUrl": no_userinfo(dl.final_url), "status": dl.status, "contentType": dl.content_type,
                "hops": dl.hops}
        final = canonical_url(dl.final_url)
        self.seen.add(final)
        if final in self.saved_final:
            self._record(item.url, item.depth, skipped="duplicate", **line)
            return
        rel = url_to_relpath(dl.final_url, dl.content_type, mode=self.opts.output_mode, scope_host=self.scope_hosts)
        if not self._claim(rel):
            self._record(item.url, item.depth, skipped="path_conflict", **line)
            return
        self.saved_final.add(final)

        pages: Iterable[str] = ()
        assets: Iterable[str] = ()
        if self.opts.readable and (is_html(dl.content_type) or is_pdf(dl.content_type)):
            if is_html(dl.content_type):
                pages, _assets, data = await executor.run_blocking(
                    _read_page, str(tmp), dl.final_url, True, no_userinfo(dl.final_url))
            else:
                status, text = await pdf_text.pdf_to_text(tmp, timeout=self.pdf_timeout)
                if status != "ok":
                    self.files.discard(rel)
                    self.saved_final.discard(final)
                    self._record(item.url, item.depth,
                                 skipped="convert_timeout" if status == "timeout" else "convert_failed", **line)
                    return
                data = text.encode("utf-8")
            self._write(rel, data)
            nbytes, digest = len(data), await executor.run_blocking(_sha256, data)
        else:
            # Raw bytes, or a readable mirror's text file kept as it is.
            self._place(tmp, rel)
            nbytes, digest = dl.bytes, dl.sha256
            if not self.opts.readable and is_html(dl.content_type):
                pages, assets, _ = await executor.run_blocking(
                    _read_page, str(self.out / rel), dl.final_url, False, "")
            elif not self.opts.readable and is_css(dl.content_type):
                assets = await executor.run_blocking(_read_css, str(self.out / rel), dl.final_url)

        if item.role == "page":
            self.stats.pages += 1
        else:
            self.stats.assets += 1
        self.stats.bytes += nbytes
        self._record(item.url, item.depth, bytes=nbytes, sha256=digest, path=rel, **line)
        if item.role == "page":
            for url in pages:
                self._enqueue(url, item.depth + 1, "page")
        if not self.opts.readable:
            for url in assets:
                self._enqueue(url, item.depth, "asset")

    async def _sitemap(self) -> None:
        if self.opts.max_depth < 1:
            return
        locs: list[str] = []
        for host in sorted(self.scope_hosts):
            found = await self._sitemap_locs(f"{self.scope_scheme}://{host}/sitemap.xml", nested=True)
            locs.extend(found)
        locs = [u for u in locs if self._in_page_scope(u)]
        if self.opts.english_only:
            locs = prefer_english(locs)
        for url in locs:
            self._enqueue(url, 1, "page")

    async def _sitemap_locs(self, url: str, *, nested: bool) -> list[str]:
        try:
            status, text, _final, _headers = await self.fetcher.get_text(
                url, max_bytes=SITEMAP_MAX_BYTES, policy=self._policy("sitemap"))
        except (ImportFailure, Skip) as e:
            if isinstance(e, ImportFailure) and e.code in _FATAL:
                raise
            return []
        if not 200 <= status < 300:
            return []
        shape, locs = await executor.run_blocking(parse_sitemap_xml, text)
        if shape == "index" and nested:
            out: list[str] = []
            for sub in locs[:MAX_SUB_SITEMAPS]:
                out.extend(await self._sitemap_locs(sub, nested=False))
            return out
        return locs if shape == "urlset" else []

    async def _worker(self) -> None:
        while True:
            item = await self.queue.get()
            try:
                if self.stop_reason is not None or self.fatal is not None:
                    continue
                self._check_budget()
                await self._check_project()
                if item.role == "page":
                    if self.pages_started >= self.opts.max_pages:
                        self.page_cap_hit = True
                        continue
                    self.pages_started += 1
                await self._fetch(item)
            except _Stop as s:
                # In-flight items finish; the rest of the queue is dropped.
                self.stop_reason = self.stop_reason or s.reason
            except ImportFailure as e:
                self._fail(e)
            except OSError as e:
                failure = map_os_error(e)
                if failure is None:
                    logger.warning(f"[workspace-mirror] write failed: {type(e).__name__}\n{safe_traceback(e)}")
                self._fail(failure or ImportFailure("internal_error"))
            except Exception as e:
                logger.error(f"[workspace-mirror] unexpected error: {type(e).__name__}\n{safe_traceback(e)}")
                self._fail(ImportFailure("internal_error"))
            finally:
                self.queue.task_done()
                self._report()

    def _fail(self, failure: ImportFailure) -> None:
        self.fatal = self.fatal or failure
        self.halt.set()

    async def run(self) -> MirrorStats:
        self.out.mkdir(parents=True, exist_ok=True, mode=0o777)
        self.tmp.mkdir(mode=0o777)
        try:
            async with self.fetcher_factory() as fetcher:
                self.fetcher = fetcher
                self._check_budget()
                self.pages_started = 1
                self.seen.add(canonical_url(self.seed))
                try:
                    await self._fetch(_Item(self.seed, 0, "page"), seed=True)
                except _Stop as s:
                    self.stop_reason = s.reason
                except OSError as e:
                    raise map_os_error(e) or e
                if self.scope_hosts and self.stop_reason is None:
                    await self._sitemap()
                self._report()
                workers = [asyncio.ensure_future(self._worker()) for _ in range(self.concurrency)]
                drained = asyncio.ensure_future(self.queue.join())
                halted = asyncio.ensure_future(self.halt.wait())
                try:
                    await asyncio.wait({drained, halted}, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in (drained, halted, *workers):
                        task.cancel()
                    await asyncio.gather(drained, halted, *workers, return_exceptions=True)
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)
        if self.fatal is not None:
            raise self.fatal
        if self.stats.pages + self.stats.assets == 0:
            raise ImportFailure("nothing_saved")
        self.stats.stopped_because = (self.stop_reason or ("max_pages" if self.page_cap_hit else None)
                                      or ("max_depth" if self.depth_cut else "complete"))
        data = "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in self.manifest).encode("utf-8")
        self._write(MANIFEST, data)
        return self.stats


async def mirror(seed: str, out_dir, opts: MirrorOptions, *, fetcher_factory,
                 hard_blocked: Callable[[str], tuple] = is_hard_blocked,
                 roe_excluded: Optional[Callable[[str], bool]] = None,
                 sleep=asyncio.sleep, now: Callable[[], float] = time.monotonic,
                 cancel_event: Optional[threading.Event] = None, progress=None,
                 grow: Optional[Callable[[int], None]] = None,
                 still_exists: Optional[Callable[[], Awaitable[None]]] = None,
                 concurrency: int = CONCURRENCY, gap_for: Optional[Callable[[str], float]] = None,
                 pdf_timeout: float = pdf_text.TIMEOUT_SEC) -> MirrorStats:
    """Mirror `seed` into `out_dir` (a fresh staging folder) with `opts`.

    `fetcher_factory()` returns a GuardedFetcher (an async context manager).
    `grow(total_bytes)` grows the job's disk reservation and raises
    insufficient_storage when refused; `still_exists()` raises when the
    project was deleted, and runs at most every 5 minutes. `gap_for(host)` is
    the politeness gap in seconds (RoE rate caps and stealth raise it).
    """
    crawl = _Crawl(seed, Path(out_dir), opts, fetcher_factory=fetcher_factory, hard_blocked=hard_blocked,
                   roe_excluded=roe_excluded, sleep=sleep, now=now, cancel_event=cancel_event, progress=progress,
                   grow=grow, still_exists=still_exists, concurrency=concurrency, gap_for=gap_for,
                   pdf_timeout=pdf_timeout)
    return await crawl.run()
