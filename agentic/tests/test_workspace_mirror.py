"""The website mirror: a fake site behind httpx.MockTransport, example.test hosts only."""
from __future__ import annotations

import asyncio
import errno
import json
import multiprocessing
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import httpx

from orchestrator_helpers.hard_guardrail import is_hard_blocked
from workspace_import import mirror as mirror_mod
from workspace_import.errors import ImportFailure
from workspace_import.fetch import GuardedFetcher
from workspace_import.mirror import MirrorOptions, mirror

PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 32


def tiny_pdf(text: str) -> bytes:
    """A one-page PDF whose text pypdf can extract."""
    stream = f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode()
    bodies = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, body in enumerate(bodies, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(bodies) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(bodies) + 1, xref)
    return bytes(out)


def html(body: str, status: int = 200, **headers):
    return lambda r: httpx.Response(status, content=f"<html><body>{body}</body></html>".encode(),
                                    headers={"content-type": "text/html; charset=utf-8", **headers})


def typed(content: bytes, ctype: str, status: int = 200):
    return lambda r: httpx.Response(status, content=content, headers={"content-type": ctype})


def redirect(location: str, status: int = 302):
    return lambda r: httpx.Response(status, headers={"location": location})


def site():
    return {
        "https://example.test/docs/": html(
            '<a href="intro.html">Intro</a><a href="guide/">Guide</a><a href="/other/x.html">out</a>'
            '<a href="https://elsewhere.test/a.html">ext</a><a href="http://example.test/docs/plain.html">http</a>'
            '<link rel="stylesheet" href="/static/site.css"><img src="/img/logo.png">'
            '<script src="https://cdn.example.test/lib.js"></script><a href="manual.pdf">PDF</a>'),
        "https://example.test/docs/intro.html": html('<h1>Intro</h1><p>Intro text.</p><a href="guide/">g</a>'),
        "https://example.test/docs/guide/": html("<h1>Guide</h1><p>Guide text.</p>"),
        "http://example.test/docs/plain.html": html("<p>plain</p>"),
        "https://example.test/static/site.css": typed(b"body { background: url(../img/bg.png) }", "text/css"),
        "https://example.test/img/logo.png": typed(PNG, "image/png"),
        "https://example.test/img/bg.png": typed(PNG, "image/png"),
        "https://cdn.example.test/lib.js": typed(b"console.log(1)", "text/javascript"),
        "https://example.test/docs/manual.pdf": typed(tiny_pdf("Mirror manual text"), "application/pdf"),
    }


class Clock:
    def __init__(self):
        self.t = 1000.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.t

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.t += seconds
        await asyncio.sleep(0)


class MirrorBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mirror-"))
        self.out = self.tmp / "out"
        self.routes = site()
        self.seen: list[httpx.Request] = []
        self.clock = Clock()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def handler(self, request: httpx.Request):
        self.seen.append(request)
        route = self.routes.get(str(request.url))
        return route(request) if route else httpx.Response(404)

    def factory(self):
        return GuardedFetcher(transport=httpx.MockTransport(self.handler), assert_safe=lambda _u: None)

    async def run_mirror(self, seed="https://example.test/docs/", opts=None, **kw):
        kw.setdefault("sleep", self.clock.sleep)
        kw.setdefault("now", self.clock.now)
        kw.setdefault("hard_blocked", lambda h: (h == "blocked.example.test", ""))
        return await mirror(seed, self.out, opts or MirrorOptions(), fetcher_factory=self.factory, **kw)

    def requested(self) -> list[str]:
        return [str(r.url) for r in self.seen]

    def files(self) -> list[str]:
        return sorted(str(p.relative_to(self.out)) for p in self.out.rglob("*") if p.is_file())

    def manifest(self) -> list[dict]:
        return [json.loads(line) for line in (self.out / "_manifest.jsonl").read_text().splitlines()]


class Saving(MirrorBase):
    async def test_raw_mirror_saves_pages_and_assets_at_mapped_paths(self):
        stats = await self.run_mirror()
        self.assertEqual(self.files(), [
            "_manifest.jsonl", "docs/guide/index.html", "docs/index.html", "docs/intro.html", "docs/manual.pdf",
            "docs/plain.html", "img/bg.png", "img/logo.png", "static/site.css",
        ])
        self.assertEqual((self.out / "img/logo.png").read_bytes(), PNG)
        self.assertEqual((stats.pages, stats.assets, stats.stopped_because), (5, 3, "complete"))
        self.assertFalse(self.out.parent.joinpath("out.tmp").exists())

    async def test_readable_mirror_writes_markdown_and_pdf_text_only(self):
        stats = await self.run_mirror(opts=MirrorOptions(output_mode="readable"))
        self.assertEqual(self.files(), ["_manifest.jsonl", "docs/guide/index.md", "docs/index.md", "docs/intro.md",
                                        "docs/manual.txt", "docs/plain.md"])
        intro = (self.out / "docs/intro.md").read_text()
        self.assertTrue(intro.startswith("<!-- source: https://example.test/docs/intro.html -->\n"))
        self.assertIn("Intro text.", intro)
        self.assertIn("Mirror manual text", (self.out / "docs/manual.txt").read_text())
        self.assertFalse(any(u.endswith((".png", ".css", ".js")) for u in self.requested()))
        self.assertEqual(stats.assets, 0)

    async def test_css_urls_followed_as_assets(self):
        await self.run_mirror()
        self.assertIn("https://example.test/img/bg.png", self.requested())
        line = next(m for m in self.manifest() if m["url"].endswith("/img/bg.png"))
        self.assertEqual((line["path"], line["depth"]), ("img/bg.png", 0))

    async def test_links_resolved_against_final_url_and_base_href(self):
        self.routes = {
            "https://example.test/docs": redirect("https://example.test/docs/", 301),
            "https://example.test/docs/": html('<a href="intro.html">i</a><a href="v2/">v2</a>'),
            "https://example.test/docs/intro.html": html("intro"),
            "https://example.test/docs/v2/": html('<base href="/docs/v2/api/"><a href="ref.html">ref</a>'),
            "https://example.test/docs/v2/api/ref.html": html("ref"),
        }
        await self.run_mirror(seed="https://example.test/docs")
        self.assertIn("https://example.test/docs/intro.html", self.requested())
        self.assertIn("https://example.test/docs/v2/api/ref.html", self.requested())
        self.assertNotIn("https://example.test/docs/v2/ref.html", self.requested())
        self.assertIn("docs/v2/api/ref.html", self.files())

    async def test_sitemap_seeds_in_scope_only_and_english_only(self):
        locs = ["https://example.test/en/a.html", "https://example.test/fr/a.html", "https://example.test/en/b.html",
                "https://example.test/de/b.html", "https://elsewhere.test/en/c.html"]
        sitemap = "<urlset>" + "".join(f"<url><loc>{u}</loc></url>" for u in locs) + "</urlset>"
        self.routes = {"https://example.test/": html("home"),
                       "https://example.test/sitemap.xml": typed(sitemap.encode(), "application/xml")}
        for u in locs:
            self.routes[u] = html("page")
        await self.run_mirror(seed="https://example.test/", opts=MirrorOptions(english_only=True))
        fetched = [u for u in self.requested() if u.endswith(".html")]
        self.assertEqual(sorted(fetched), ["https://example.test/en/a.html", "https://example.test/en/b.html"])
        line = next(m for m in self.manifest() if m["url"].endswith("/en/a.html"))
        self.assertEqual(line["depth"], 1)

    async def test_sitemap_with_doctype_is_refused(self):
        sitemap = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]>'
                   '<urlset><url><loc>https://example.test/secret.html</loc></url></urlset>')
        self.routes = {"https://example.test/": html("home"),
                       "https://example.test/sitemap.xml": typed(sitemap.encode(), "application/xml"),
                       "https://example.test/secret.html": html("x")}
        await self.run_mirror(seed="https://example.test/")
        self.assertNotIn("https://example.test/secret.html", self.requested())


class Scope(MirrorBase):
    async def test_page_scope_is_host_and_seed_directory(self):
        self.routes = {
            "https://example.test/docs/": html(
                '<a href="/docs/in.html">in</a><a href="/docsx/out.html">x</a><a href="/other.html">o</a>'
                '<a href="https://www.example.test/docs/w.html">www</a>'),
            "https://example.test/docs/in.html": html("in"),
        }
        await self.run_mirror()
        pages = [u for u in self.requested() if u.endswith(".html")]
        self.assertEqual(pages, ["https://example.test/docs/in.html"])

    async def test_www_only_redirect_keeps_seed_host_in_scope(self):
        self.routes = {
            "https://example.test/docs/": redirect("https://www.example.test/docs/"),
            "https://www.example.test/docs/": html('<a href="https://example.test/docs/a.html">a</a>'),
            "https://example.test/docs/a.html": html("a"),
        }
        await self.run_mirror()
        self.assertIn("https://example.test/docs/a.html", self.requested())

    async def test_external_assets_only_when_enabled(self):
        await self.run_mirror()
        self.assertNotIn("https://cdn.example.test/lib.js", self.requested())
        shutil.rmtree(self.out)
        self.seen.clear()
        await self.run_mirror(opts=MirrorOptions(external_assets=True))
        self.assertIn("https://cdn.example.test/lib.js", self.requested())
        self.assertIn("_external/cdn.example.test/lib.js", self.files())

    async def test_redirect_offsite_recorded_not_followed(self):
        self.routes = {
            "https://example.test/docs/": html('<a href="moved.html">m</a>'),
            "https://example.test/docs/moved.html": redirect("https://elsewhere.test/landing.html"),
            "https://elsewhere.test/landing.html": html("never"),
        }
        await self.run_mirror()
        self.assertNotIn("https://elsewhere.test/landing.html", self.requested())
        line = next(m for m in self.manifest() if m["url"].endswith("moved.html"))
        self.assertEqual(line["skipped"], "redirect_offsite")


class Limits(MirrorBase):
    def chain(self, n):
        self.routes = {}
        for i in range(n):
            nxt = f'<a href="p{i + 1}.html">next</a>' if i + 1 < n else ""
            self.routes[f"https://example.test/docs/{'p%d.html' % i if i else ''}"] = html(nxt)

    async def test_depth_and_page_limits_stop_with_reason(self):
        self.chain(6)
        stats = await self.run_mirror(opts=MirrorOptions(max_depth=2))
        self.assertEqual((stats.pages, stats.stopped_because), (3, "max_depth"))
        shutil.rmtree(self.out)
        stats = await self.run_mirror(opts=MirrorOptions(max_pages=2))
        self.assertEqual((stats.pages, stats.stopped_because), (2, "max_pages"))
        shutil.rmtree(self.out)
        stats = await self.run_mirror(opts=MirrorOptions(max_depth=10))
        self.assertEqual((stats.pages, stats.stopped_because), (6, "complete"))

    async def test_total_and_per_file_byte_caps(self):
        big = b"x" * 5000
        self.routes = {"https://example.test/docs/": html('<a href="big.bin">b</a><a href="small.txt">s</a>'),
                       "https://example.test/docs/big.bin": typed(big, "application/octet-stream"),
                       "https://example.test/docs/small.txt": typed(b"small", "text/plain")}
        await self.run_mirror(opts=MirrorOptions(per_file_bytes=4000))
        line = next(m for m in self.manifest() if m["url"].endswith("big.bin"))
        self.assertEqual(line["skipped"], "too_large")
        self.assertIn("docs/small.txt", self.files())
        shutil.rmtree(self.out)
        stats = await self.run_mirror(opts=MirrorOptions(max_bytes=3000), concurrency=1)
        self.assertEqual(stats.stopped_because, "max_bytes")
        self.assertNotIn("docs/big.bin", self.files())

    async def test_a_huge_sitemap_never_queues_more_than_the_page_limit(self):
        locs = [f"https://example.test/p{i}.html" for i in range(30000)]
        sitemap = "<urlset>" + "".join(f"<url><loc>{u}</loc></url>" for u in locs) + "</urlset>"
        self.routes = {"https://example.test/": html("home"),
                       "https://example.test/sitemap.xml": typed(sitemap.encode(), "application/xml")}
        for u in locs[:50]:
            self.routes[u] = html("page")
        seen_sizes = []
        real_enqueue = mirror_mod._Crawl._enqueue

        def spy(crawl, url, depth, role):
            real_enqueue(crawl, url, depth, role)
            seen_sizes.append((crawl.queue.qsize(), len(crawl.seen)))
        with mock.patch.object(mirror_mod._Crawl, "_enqueue", spy):
            stats = await self.run_mirror(seed="https://example.test/", opts=MirrorOptions(max_pages=10))
        self.assertEqual((stats.pages, stats.stopped_because), (10, "max_pages"))
        self.assertLessEqual(max(q for q, _ in seen_sizes), 10)
        self.assertLessEqual(max(n for _, n in seen_sizes), 10)

    def test_assets_queued_per_page_are_capped(self):
        crawl = mirror_mod._Crawl("https://example.test/", self.out, MirrorOptions(max_pages=2),
                                  fetcher_factory=self.factory, hard_blocked=lambda _h: (False, ""),
                                  roe_excluded=None, sleep=self.clock.sleep, now=self.clock.now, cancel_event=None,
                                  progress=None, grow=None, still_exists=None, concurrency=1, gap_for=None,
                                  pdf_timeout=1, request_allowed=None)
        crawl._set_scope("https://example.test/")
        for i in range(500):
            crawl._enqueue(f"https://example.test/img/{i}.png", 0, "asset")
        self.assertEqual(crawl.queue.qsize(), 2 * mirror_mod.ASSETS_PER_PAGE)
        self.assertEqual(len(crawl.seen), 2 * mirror_mod.ASSETS_PER_PAGE)

    async def test_query_variants_capped(self):
        links = "".join(f'<a href="list.html?page={i}">{i}</a>' for i in range(25))
        self.routes = {"https://example.test/docs/": html(links)}
        for i in range(25):
            self.routes[f"https://example.test/docs/list.html?page={i}"] = html(str(i))
        await self.run_mirror()
        fetched = [u for u in self.requested() if "list.html" in u]
        self.assertEqual(len(fetched), mirror_mod.MAX_QUERY_VARIANTS)
        self.assertEqual(sum(1 for m in self.manifest() if m["skipped"] == "query_variants"), 5)

    async def test_politeness_delay_between_same_host_requests(self):
        times: dict[str, list[float]] = {}
        base = self.handler

        def timed(request):
            times.setdefault(request.url.host, []).append(self.clock.t)
            return base(request)
        self.handler = timed
        # One worker: with four, a request's start could be logged after another worker's wait.
        await self.run_mirror(opts=MirrorOptions(external_assets=True), concurrency=1)
        starts = times["example.test"]
        self.assertGreater(len(starts), 5)
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        self.assertTrue(all(g >= mirror_mod.SAME_HOST_GAP_SEC - 1e-9 for g in gaps), gaps)
        self.assertTrue(self.clock.sleeps)

    async def test_a_request_still_running_at_the_budget_ends_the_crawl(self):
        import time as _time
        never = asyncio.Event()

        async def hang():
            yield b"<html>"
            await never.wait()
        self.routes["https://example.test/docs/intro.html"] = lambda r: httpx.Response(
            200, content=hang(), headers={"content-type": "text/html"})
        began = _time.monotonic()
        stats = await self.run_mirror(opts=MirrorOptions(time_budget_sec=1.0), now=_time.monotonic, concurrency=1)
        self.assertEqual(stats.stopped_because, "time_budget")
        self.assertGreaterEqual(stats.pages, 1)
        self.assertLess(_time.monotonic() - began, 15)
        self.assertNotIn("docs/intro.html", self.files())

    async def test_time_budget_stops(self):
        self.chain(6)
        base = self.handler

        def slow(request):
            self.clock.t += 400
            return base(request)
        self.handler = slow
        stats = await self.run_mirror(opts=MirrorOptions(max_depth=10, time_budget_sec=1000))
        self.assertEqual(stats.stopped_because, "time_budget")
        self.assertLess(stats.pages, 6)


class HardGuardrail(MirrorBase):
    def test_default_is_the_real_guardrail(self):
        self.assertIs(mirror.__kwdefaults__["hard_blocked"], is_hard_blocked)

    async def test_hard_blocked_seed_fails_before_any_request(self):
        with self.assertRaises(ImportFailure) as ctx:
            await self.run_mirror(seed="https://blocked.example.test/docs/")
        self.assertEqual(ctx.exception.code, "hard_blocked")
        self.assertEqual(self.seen, [])

    async def test_hard_blocked_redirect_hop_and_asset_host_skipped(self):
        self.routes = {
            "https://example.test/docs/": html('<a href="go.html">go</a><img src="https://blocked.example.test/i.png">'),
            "https://example.test/docs/go.html": redirect("https://blocked.example.test/docs/x.html"),
        }
        await self.run_mirror(opts=MirrorOptions(external_assets=True))
        self.assertFalse(any("blocked.example.test" in u for u in self.requested()))
        reasons = {m["url"]: m["skipped"] for m in self.manifest()}
        self.assertEqual(reasons["https://example.test/docs/go.html"], "hard_blocked")
        self.assertEqual(reasons["https://blocked.example.test/i.png"], "hard_blocked")


class Results(MirrorBase):
    async def test_manifest_lines_complete(self):
        self.routes["https://example.test/docs/guide/"] = lambda r: httpx.Response(500)
        await self.run_mirror()
        keys = {"url", "finalUrl", "status", "contentType", "bytes", "sha256", "path", "depth", "hops", "skipped"}
        lines = self.manifest()
        self.assertTrue(lines)
        for line in lines:
            self.assertEqual(set(line), keys, line)
        saved = next(m for m in lines if m["url"].endswith("/img/logo.png"))
        self.assertEqual((saved["status"], saved["contentType"], saved["bytes"], saved["skipped"]),
                         (200, "image/png", len(PNG), None))
        self.assertEqual(len(saved["sha256"]), 64)
        failed = next(m for m in lines if m["url"].endswith("/guide/"))
        self.assertEqual((failed["skipped"], failed["status"], failed["path"]), ("status", 500, None))

    async def test_userinfo_link_never_requested(self):
        self.routes = {"https://example.test/docs/": html('<a href="https://u:secret@example.test/docs/a.html">a</a>')}
        await self.run_mirror()
        self.assertEqual(self.requested(), ["https://example.test/docs/", "https://example.test/sitemap.xml"])
        text = (self.out / "_manifest.jsonl").read_text()
        self.assertNotIn("secret", text)
        self.assertIn('"skipped": "credentials_in_url"', text)

    async def test_cancel_stops_and_leaves_nothing(self):
        cancel = threading.Event()
        gate = asyncio.Event()

        async def slow_body():
            yield b"<html>"
            await gate.wait()
            yield b"</html>"
        self.routes["https://example.test/docs/intro.html"] = lambda r: httpx.Response(
            200, content=slow_body(), headers={"content-type": "text/html"})
        task = asyncio.ensure_future(self.run_mirror(cancel_event=cancel, concurrency=1))
        for _ in range(200):
            await asyncio.sleep(0.01)
            if any(u.endswith("intro.html") for u in self.requested()):
                break
        cancel.set()
        gate.set()
        with self.assertRaises(ImportFailure) as ctx:
            await task
        self.assertEqual(ctx.exception.code, "cancelled")
        self.assertFalse((self.tmp / "out.tmp").exists())

    async def test_nothing_saved_code(self):
        self.routes = {"https://example.test/docs/": typed(PNG, "image/png")}
        with self.assertRaises(ImportFailure) as ctx:
            await self.run_mirror(opts=MirrorOptions(output_mode="readable"))
        self.assertEqual(ctx.exception.code, "nothing_saved")

    async def test_seed_error_status_fails_upstream_status(self):
        self.routes = {}
        with self.assertRaises(ImportFailure) as ctx:
            await self.run_mirror()
        self.assertEqual(ctx.exception.code, "upstream_status")


class DiskAndPool(MirrorBase):
    async def test_reservation_grows_and_refusal_fails_insufficient_storage(self):
        totals: list[int] = []

        def grow(total):
            totals.append(total)
            if total > 300:
                raise ImportFailure("insufficient_storage")
        with self.assertRaises(ImportFailure) as ctx:
            await self.run_mirror(grow=grow)
        self.assertEqual(ctx.exception.code, "insufficient_storage")
        self.assertEqual(totals, sorted(totals))
        self.assertFalse((self.tmp / "out.tmp").exists())

    async def test_enospc_while_saving_is_insufficient_storage_and_leaves_nothing(self):
        real = mirror_mod._Crawl._place

        def full(crawl, tmp, rel):
            if rel.endswith(".png"):
                raise OSError(errno.ENOSPC, "No space left on device")
            return real(crawl, tmp, rel)
        with mock.patch.object(mirror_mod._Crawl, "_place", full):
            with self.assertRaises(ImportFailure) as ctx:
                await self.run_mirror()
        self.assertEqual(ctx.exception.code, "insufficient_storage")
        self.assertFalse((self.tmp / "out.tmp").exists())

    async def test_markdown_conversion_runs_on_import_pool(self):
        threads: list[str] = []
        real = mirror_mod.html_to_markdown

        def spy(text):
            threads.append(threading.current_thread().name)
            return real(text)
        with mock.patch.object(mirror_mod, "html_to_markdown", spy):
            await self.run_mirror(opts=MirrorOptions(output_mode="readable"))
        self.assertTrue(threads)
        self.assertTrue(all(t.startswith("workspace-import") for t in threads), threads)

    async def test_unexpected_error_logs_frames_never_its_text(self):
        real = mirror_mod._read_page
        # Built at run time: a logged frame shows its source line, never the values.
        message = "-".join(("SECRET", "IN", "MESSAGE")) + " https://example.test/?token=" + "SECRET-QUERY-VALUE"

        def boom(path, final_url, *rest):
            if final_url.endswith("/intro.html"):
                raise RuntimeError(message)
            return real(path, final_url, *rest)
        with mock.patch.object(mirror_mod, "_read_page", boom), self.assertLogs("workspace_import.mirror", "ERROR") as logs:
            with self.assertRaises(ImportFailure) as ctx:
                await self.run_mirror()
        self.assertEqual(ctx.exception.code, "internal_error")
        text = "\n".join(logs.output)
        self.assertIn("RuntimeError", text)
        self.assertNotIn("SECRET-IN-MESSAGE", text)
        self.assertNotIn("SECRET-QUERY-VALUE", text)

    def test_readable_converter_parses_with_the_stdlib_parser(self):
        import inspect as _inspect
        from orchestrator_helpers import web_sources
        source = _inspect.getsource(web_sources.html_to_markdown)
        self.assertIn('BeautifulSoup(html, "html.parser")', source)
        self.assertEqual(source.count("BeautifulSoup("), 1)

    async def test_pdf_conversion_timeout_kills_child_and_skips(self):
        # A spawned interpreter needs far longer than 1 ms to answer.
        await self.run_mirror(opts=MirrorOptions(output_mode="readable"), pdf_timeout=0.001)
        line = next(m for m in self.manifest() if m["url"].endswith("manual.pdf"))
        self.assertEqual((line["skipped"], line["path"]), ("convert_timeout", None))
        self.assertNotIn("docs/manual.txt", self.files())
        self.assertEqual(multiprocessing.active_children(), [])

    async def test_deleted_project_stops_crawl(self):
        base = self.handler

        def slow(request):
            self.clock.t += 200
            return base(request)
        self.handler = slow

        async def gone():
            raise ImportFailure("project_deleted")
        with self.assertRaises(ImportFailure) as ctx:
            await self.run_mirror(still_exists=gone)
        self.assertEqual(ctx.exception.code, "project_deleted")


class Robots(MirrorBase):
    async def test_robots_not_fetched_by_default(self):
        await self.run_mirror()
        self.assertFalse(any(u.endswith("/robots.txt") for u in self.requested()))

    async def test_robots_disallow_skips_and_records(self):
        self.routes["https://example.test/robots.txt"] = typed(b"User-agent: *\nDisallow: /docs/guide/\n", "text/plain")
        await self.run_mirror(opts=MirrorOptions(respect_robots=True))
        self.assertNotIn("https://example.test/docs/guide/", self.requested())
        line = next(m for m in self.manifest() if m["url"].endswith("/docs/guide/"))
        self.assertEqual(line["skipped"], "robots")
        self.assertEqual(sum(1 for u in self.requested() if u.endswith("/robots.txt")), 2)  # https and http

    async def test_robots_disallowed_seed_fails(self):
        self.routes["https://example.test/robots.txt"] = typed(b"User-agent: *\nDisallow: /\n", "text/plain")
        with self.assertRaises(ImportFailure) as ctx:
            await self.run_mirror(opts=MirrorOptions(respect_robots=True))
        self.assertEqual(ctx.exception.code, "robots_disallowed")
        self.assertEqual(self.requested(), ["https://example.test/robots.txt"])

    async def test_robots_4xx_allows_all(self):
        stats = await self.run_mirror(opts=MirrorOptions(respect_robots=True))
        self.assertEqual(stats.pages, 5)

    async def test_robots_5xx_disallows_all(self):
        self.routes["https://example.test/robots.txt"] = lambda r: httpx.Response(503)
        with self.assertRaises(ImportFailure) as ctx:
            await self.run_mirror(opts=MirrorOptions(respect_robots=True))
        self.assertEqual(ctx.exception.code, "robots_unavailable")
        self.assertEqual(self.requested(), ["https://example.test/robots.txt"])

    async def test_robots_matches_our_user_agent(self):
        self.routes["https://example.test/robots.txt"] = typed(
            b"User-agent: RedAmon-WorkspaceImport\nDisallow: /docs/intro.html\n\nUser-agent: *\nDisallow: /\n",
            "text/plain")
        await self.run_mirror(opts=MirrorOptions(respect_robots=True))
        self.assertIn("https://example.test/docs/guide/", self.requested())
        self.assertNotIn("https://example.test/docs/intro.html", self.requested())


class Options(unittest.TestCase):
    def test_website_defaults(self):
        o = MirrorOptions.for_kind("website", None, total_cap=2 * 1024 ** 3)
        self.assertEqual((o.output_mode, o.max_pages, o.max_depth, o.respect_robots, o.english_only,
                          o.external_assets), ("raw", 300, 3, False, False, False))
        self.assertEqual(o.max_bytes, mirror_mod.TOTAL_BYTES_CEILING)

    def test_docs_site_defaults_applied(self):
        o = MirrorOptions.for_kind("docs-site", None, total_cap=2 * 1024 ** 3)
        self.assertEqual((o.output_mode, o.max_pages, o.max_depth, o.respect_robots, o.english_only,
                          o.external_assets), ("readable", 1000, 6, False, True, False))
        o = MirrorOptions.for_kind("docs-site", {"outputMode": "raw", "englishOnly": False}, total_cap=10)
        self.assertEqual((o.output_mode, o.english_only, o.max_pages), ("raw", False, 1000))

    def test_options_clamped_to_ceilings(self):
        o = MirrorOptions.for_kind("website", {"maxPages": 999_999, "maxDepth": 99}, total_cap=10 * 1024 ** 3)
        self.assertEqual((o.max_pages, o.max_depth), (2000, 10))
        o = MirrorOptions.for_kind("website", {"maxPages": 0, "maxDepth": -5}, total_cap=100)
        self.assertEqual((o.max_pages, o.max_depth, o.max_bytes), (1, 0, 100))
        self.assertEqual(MirrorOptions.for_kind("website", None, total_cap=10 * 1024 ** 3).max_bytes,
                         mirror_mod.TOTAL_BYTES_CEILING)

    def test_mirror_suggested_names(self):
        from workspace_import.detect import suggested_name
        for url, name in (("https://docs.example.test/", "docs.example.test"),
                          ("https://example.test/docs/intro.html", "example.test-docs"),
                          ("https://example.test/docs/v2/", "example.test-docs"),
                          ("https://Example.TEST", "example.test")):
            self.assertEqual(suggested_name("website", {}, url=url), name, url)
            self.assertEqual(suggested_name("docs-site", {}, url=url), name, url)

    def test_bad_option_type_is_invalid_option(self):
        for bad in ({"maxPages": "10"}, {"maxPages": True}, {"respectRobots": 1}, {"outputMode": "pdf"},
                    {"externalAssets": None}):
            with self.assertRaises(ImportFailure) as ctx:
                MirrorOptions.for_kind("website", bad, total_cap=10)
            self.assertEqual(ctx.exception.code, "invalid_option", bad)

    def test_unknown_keys_ignored_and_record_round_trips(self):
        o = MirrorOptions.for_kind("website", {"subpath": "x", "maxDepth": 2}, total_cap=10)
        self.assertEqual(o.max_depth, 2)
        self.assertEqual(MirrorOptions.for_kind("website", o.record(), total_cap=10), o)


if __name__ == "__main__":
    unittest.main()
