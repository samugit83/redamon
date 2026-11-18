"""Test doubles for tradecraft: the web, the browser, the model and the clock.

``FixtureFetcher`` serves the synthetic sites of ``fixtures/tradecraft_sites/`` behind the
same ``Fetcher`` interface as production's ``GuardedFetcher``, and the contract suites
at the bottom of this file hold the two to the same behaviour (run on the double by
``test_tradecraft_fetcher_contract.py``, on the real fetcher by its ``_integration`` and
``_live`` twins). No double opens a socket, calls a model or reads the real clock.

Not a test module itself (no ``test_`` prefix): the suites are mixins that a ``Test*``
class picks up.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import mimetypes
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import unquote, urljoin, urlsplit

import pytest

from orchestrator_helpers.fetch_guard import _is_disallowed_ip
from orchestrator_helpers.llm_url_guard import _BLOCKED_HOSTNAMES
from tradecraft import net
from tradecraft.net import REDIRECT_STATUSES, USER_AGENT, Rendered, Response, carries_same_host_headers, url_problem

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tradecraft_sites"

# Files of a host folder that describe the site and are never served as pages.
_CONTROL_NAMES = {"_redirects.json", "_status.json", "_headers.json", "_unreachable", "_rendered"}

_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
    ".json": "application/json",
    ".xml": "application/xml",
    ".txt": "text/plain; charset=utf-8",
    ".js": "application/javascript",
    ".css": "text/css",
    ".yml": "text/yaml",
    ".yaml": "text/yaml",
    ".yar": "text/plain; charset=utf-8",
    ".pdf": "application/pdf",
}


@dataclass
class Answer:
    status: int
    headers: Dict[str, str]
    body: bytes
    location: str = ""


class FixtureSite:
    """What a fixture host answers for a path; shared by the double and the local test server.

    ``port`` is the serving port (``None`` for the double): redirect targets written with
    ``{port}`` point back at the same server.
    """

    def __init__(self, root: Path = FIXTURES, port: Optional[int] = None) -> None:
        self.root = root
        self.port_suffix = f":{port}" if port else ""

    def host_dir(self, host: str) -> Optional[Path]:
        d = self.root / host.lower().rstrip(".")
        if not host or not d.is_dir() or (d / "_unreachable").exists():
            return None
        return d

    def _control(self, d: Path, name: str) -> Dict[str, Any]:
        f = d / name
        return json.loads(f.read_text()) if f.exists() else {}

    def file_for(self, d: Path, path: str) -> Optional[Path]:
        parts = [p for p in unquote(path).split("/") if p]
        if any(p in ("..", ".") for p in parts) or (parts and parts[0] in _CONTROL_NAMES):
            return None
        target = d.joinpath(*parts) if parts else d
        if target.is_dir():
            for index in ("index.html", "index.json"):
                if (target / index).is_file():
                    return target / index
            return None
        return target if target.is_file() else None

    def answer(self, host: str, path: str) -> Optional[Answer]:
        """None when the host is unreachable."""
        d = self.host_dir(host)
        if d is None:
            return None
        path = path or "/"
        redirect = self._control(d, "_redirects.json").get(path)
        if redirect is not None:
            if isinstance(redirect, str):
                redirect = {"location": redirect}
            location = redirect["location"].replace("{port}", self.port_suffix)
            return Answer(int(redirect.get("status", 302)), {"location": location}, b"", location)
        status = int(self._control(d, "_status.json").get(path, 200))
        f = self.file_for(d, path)
        if f is None:
            return Answer(404 if status == 200 else status, {"content-type": "text/plain"}, b"not found")
        headers = {"content-type": _TYPES.get(f.suffix) or mimetypes.guess_type(f.name)[0]
                   or "application/octet-stream"}
        headers.update({k.lower(): v for k, v in self._control(d, "_headers.json").get(path, {}).items()})
        return Answer(status, headers, f.read_bytes())

    def rendered(self, host: str, path: str) -> Optional[str]:
        """What a browser shows: the ``_rendered`` copy, else the static HTML page."""
        d = self.host_dir(host)
        if d is None:
            return None
        rel = unquote(path or "/").lstrip("/")
        if rel == "" or rel.endswith("/"):
            rel += "index.html"
        elif not rel.endswith(".html"):
            rel += ".html"
        copy = d / "_rendered" / rel
        if ".." not in Path(rel).parts and copy.is_file():
            return copy.read_text(encoding="utf-8")
        ans = self.answer(host, path)
        if ans and ans.status == 200 and "html" in ans.headers.get("content-type", ""):
            return ans.body.decode("utf-8", errors="replace")
        return None


def double_unsafe(url: str) -> bool:
    """The double's egress check: literal internal addresses and metadata names.

    Fixture host names count as public; the real guard resolves names, the double
    cannot, so redirects into internal space in the fixtures use literal addresses.
    """
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    if host in _BLOCKED_HOSTNAMES or host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return _is_disallowed_ip(host)


class FakeBrowser:
    def __init__(self, site: Optional[FixtureSite] = None) -> None:
        self.site = site or FixtureSite()
        self.renders: List[str] = []

    async def render(self, url: str, *, timeout: float = 30.0, wait_until: str = "networkidle",
                     max_chars: int = 40000, clean: bool = False, wait_for: Optional[str] = None) -> Rendered:
        problem = url_problem(url)
        if problem:
            return Rendered(url=url, html="", error=problem)
        if double_unsafe(url):
            return Rendered(url=url, html="", error="unsafe_address")
        self.renders.append(url)
        parts = urlsplit(url)
        html = self.site.rendered(parts.hostname or "", parts.path)
        if not html:
            return Rendered(url=url, html="", error="navigation_failed")
        return Rendered(url=url, html=html[:max_chars])


class FixtureFetcher:
    """``Fetcher`` over the fixture sites, recording every request it sends."""

    def __init__(self, root: Path = FIXTURES, *, browser: Optional[FakeBrowser] = None,
                 port: Optional[int] = None) -> None:
        self.site = FixtureSite(root, port)
        self.browser = browser or FakeBrowser(self.site)
        self.requests: List[Tuple[str, Dict[str, str]]] = []

    async def get(self, url: str, *, headers: Optional[Mapping[str, str]] = None,
                  same_host_headers: Optional[Mapping[str, str]] = None, timeout: float = 30.0,
                  max_bytes: Optional[int] = None, max_redirects: int = 5) -> Response:
        def failed(code: str, at: str) -> Response:
            return Response(url=url, final_url=at, status=0, headers={}, body=b"",
                            content_type="", redirects=redirects, error=code)

        redirects: List[str] = []
        current = url
        base = {"user-agent": USER_AGENT}
        base.update({k.lower(): v for k, v in (headers or {}).items()})
        for _hop in range(max_redirects + 1):
            problem = url_problem(current)
            if problem:
                return failed(problem, current)
            if double_unsafe(current):
                return failed("unsafe_address", current)
            parts = urlsplit(current)
            ans = self.site.answer(parts.hostname or "", parts.path)
            if ans is None:
                return failed("unreachable", current)
            hop_headers = dict(base)
            if same_host_headers and carries_same_host_headers(url, current):
                hop_headers.update({k.lower(): v for k, v in same_host_headers.items()})
            self.requests.append((current, hop_headers))
            if ans.status in REDIRECT_STATUSES and ans.location:
                redirects.append(current)
                current = urljoin(current, ans.location)
                continue
            body, truncated = ans.body, False
            cap = net.effective_max_bytes(max_bytes)
            if len(body) > cap:
                body, truncated = body[:cap], True
            return Response(url=url, final_url=current, status=ans.status, headers=dict(ans.headers),
                            body=body, content_type=ans.headers.get("content-type", "").lower(),
                            redirects=redirects, truncated=truncated)
        return failed("too_many_redirects", current)

    @contextlib.asynccontextmanager
    async def stream(self, url: str, **kwargs: Any):
        """``get``'s answer handed over in chunks, as ``GuardedFetcher.stream`` hands its body."""
        yield net.Streamed.of(await self.get(url, **kwargs), chunk_size=4096)

    async def render(self, url: str, **kwargs: Any) -> Rendered:
        return await self.browser.render(url, **kwargs)


class ScriptedChatModel:
    """A chat model that answers from a queue: strings become ``AIMessage``s, exceptions raise.

    Records every prompt and counts calls. An empty queue raises, so a test never gets
    an answer it did not script.
    """

    def __init__(self, *replies: Any) -> None:
        self._queue: deque = deque(replies)
        self.prompts: List[Any] = []
        self.calls = 0

    def queue(self, *replies: Any) -> "ScriptedChatModel":
        self._queue.extend(replies)
        return self

    @property
    def pending(self) -> int:
        return len(self._queue)

    def _next(self, messages: Any) -> Any:
        from langchain_core.messages import AIMessage

        self.calls += 1
        self.prompts.append(messages)
        if not self._queue:
            raise AssertionError("ScriptedChatModel: no reply queued")
        item = self._queue.popleft()
        if isinstance(item, BaseException):
            raise item
        return item if isinstance(item, AIMessage) else AIMessage(content=item)

    async def ainvoke(self, messages: Any, config: Any = None, **kwargs: Any) -> Any:
        return self._next(messages)

    def invoke(self, messages: Any, config: Any = None, **kwargs: Any) -> Any:
        return self._next(messages)


class FakeClock:
    """A clock that moves only when told to; ``sleep`` advances it and returns at once."""

    def __init__(self, start: Optional[datetime] = None, monotonic_start: float = 1000.0) -> None:
        self._now = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
        self._mono = monotonic_start
        self.sleeps: List[float] = []

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)
        self._mono += seconds

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(max(0.0, seconds))
        await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# The fetcher contract: one behaviour suite, run against every Fetcher
# ---------------------------------------------------------------------------

CONTRACT_HOST = "contract.tc-fixture.test"
OTHER_HOST = "other.tc-fixture.test"
DOWN_HOST = "down.tc-fixture.test"
FAKE_COOKIE = "cookie=fake-session"


@dataclass
class ContractHarness:
    """What a contract suite needs from a fetcher under test.

    ``base(host)`` is the scheme://host[:port] the fetcher reaches a fixture host at;
    ``requests()`` returns (url, lowercase headers) of every request the site received;
    ``browser_calls()`` counts what reached the browser.
    """

    fetcher: Any
    base: Any
    requests: Any
    browser_calls: Any = lambda: 0
    can_render_fixture_pages: bool = True
    close: Any = lambda: None

    def url(self, host: str, path: str) -> str:
        return self.base(host) + path


def double_harness() -> ContractHarness:
    fetcher = FixtureFetcher()
    return ContractHarness(
        fetcher=fetcher,
        base=lambda host: f"http://{host}",
        requests=lambda: list(fetcher.requests),
        browser_calls=lambda: len(fetcher.browser.renders),
    )


def run(coro):
    return asyncio.run(coro)


# Refused as "bad_url" by every Fetcher, before any request, browser call or name lookup.
BAD_URLS = (
    "ftp://contract.tc-fixture.test/x",
    "file:///etc/passwd",
    "http:///nohost",
    "http://[::1/",                           # unmatched bracket: urlsplit raises
    "https://wiki.tc-fixture.test]/",
    "https://a..b/",                          # empty label: IDNA encoding raises
    "https://" + "a" * 64 + ".tc-fixture.test/",   # label over 63 characters
    "http://contract.tc-fixture.test:99999/",  # port out of range
)


class FetcherContractSuite:
    """Mixin: a ``Test*`` subclass defines ``make_harness()``."""

    def make_harness(self) -> ContractHarness:  # pragma: no cover - abstract
        raise NotImplementedError

    def setup_method(self, _method=None):
        self.h = self.make_harness()

    def teardown_method(self, _method=None):
        self.h.close()

    def get(self, path: str, host: str = CONTRACT_HOST, **kw) -> Response:
        return run(self.h.fetcher.get(self.h.url(host, path), **kw))

    def requested(self) -> List[str]:
        return [u for u, _h in self.h.requests()]

    def test_200(self):
        r = self.get("/ok.html")
        assert r.error == "" and r.status == 200 and r.ok
        assert b"tc-contract-ok" in r.body
        assert r.content_type.startswith("text/html")
        assert r.final_url == r.url == self.h.url(CONTRACT_HOST, "/ok.html")
        assert r.redirects == []

    def test_status_is_passed_through(self):
        r = self.get("/missing.html")
        assert r.error == "" and r.status == 404 and not r.ok
        assert self.get("/gone.html").status == 410

    def test_response_headers_lowercase(self):
        r = self.get("/data.txt")
        assert r.headers.get("x-fixture") == "yes"
        assert r.content_type.startswith("text/plain")

    def test_redirect_chain_within_limit(self):
        r = self.get("/r1", max_redirects=5)
        assert r.error == "" and r.status == 200
        assert r.final_url == self.h.url(CONTRACT_HOST, "/ok.html")
        assert r.redirects == [self.h.url(CONTRACT_HOST, "/r1"), self.h.url(CONTRACT_HOST, "/r2")]

    def test_redirect_limit_exceeded(self):
        r = self.get("/chain3", max_redirects=2)
        assert r.error == "too_many_redirects" and r.status == 0
        assert len(self.requested()) == 3
        assert self.get("/chain3", max_redirects=3).status == 200

    def test_redirect_to_private_address_refused(self):
        r = self.get("/to-private")
        assert r.error == "unsafe_address"
        assert r.body == b""
        # Refused before the second request: the metadata address was never asked.
        assert self.requested() == [self.h.url(CONTRACT_HOST, "/to-private")]

    def test_same_host_headers_only_on_same_host(self):
        login = {"Cookie": FAKE_COOKIE}
        r = self.get("/same", same_host_headers=login, headers={"Accept": "text/html"})
        assert r.status == 200
        sent = self.h.requests()
        assert len(sent) == 2
        assert all(h.get("cookie") == FAKE_COOKIE for _u, h in sent)
        assert all(h.get("accept") == "text/html" for _u, h in sent)

        before = len(self.h.requests())
        r = self.get("/cross", same_host_headers=login, headers={"Accept": "text/html"})
        assert r.status == 200 and r.final_url == self.h.url(OTHER_HOST, "/landing.html")
        first, second = self.h.requests()[before:]
        assert first[1].get("cookie") == FAKE_COOKIE
        assert "cookie" not in second[1]
        assert second[1].get("accept") == "text/html"

    def test_max_bytes_cut(self):
        r = self.get("/big.bin", max_bytes=1000)
        assert len(r.body) == 1000 and r.truncated
        full = self.get("/big.bin")
        assert len(full.body) == 20_000 and not full.truncated
        assert full.body[:1000] == r.body

    def test_hard_ceiling_without_max_bytes(self, monkeypatch):
        monkeypatch.setattr(net, "HARD_MAX_BYTES", 5000)
        r = self.get("/big.bin")
        assert len(r.body) == 5000 and r.truncated
        r = self.get("/big.bin", max_bytes=8000)
        assert len(r.body) == 5000 and r.truncated

    def test_unreachable_error(self):
        r = self.get("/", host=DOWN_HOST)
        assert r.error == "unreachable" and r.status == 0 and r.body == b""

    def test_userinfo_refused(self):
        url = self.h.url(CONTRACT_HOST, "/ok.html").replace("://", "://user:secret@", 1)
        r = run(self.h.fetcher.get(url))
        assert r.error == "userinfo_refused"
        assert self.requested() == []
        r = self.get("/to-userinfo")
        assert r.error == "userinfo_refused"
        assert self.requested() == [self.h.url(CONTRACT_HOST, "/to-userinfo")]

    def test_bad_url(self):
        for url in BAD_URLS:
            assert run(self.h.fetcher.get(url)).error == "bad_url", url
        assert self.requested() == []

    def _stream(self, path: str, host: str = CONTRACT_HOST, **kw):
        async def go():
            async with self.h.fetcher.stream(self.h.url(host, path), **kw) as s:
                return s, await s.read()
        return run(go())

    def test_stream_reads_like_get(self):
        s, body = self._stream("/big.bin", max_bytes=1000)
        assert s.ok and len(body) == 1000 and s.truncated
        s, body = self._stream("/big.bin")
        assert len(body) == 20_000 and not s.truncated
        s, body = self._stream("/r1")
        assert s.status == 200 and b"tc-contract-ok" in body
        assert s.final_url == self.h.url(CONTRACT_HOST, "/ok.html")
        assert s.redirects == [self.h.url(CONTRACT_HOST, "/r1"), self.h.url(CONTRACT_HOST, "/r2")]

    def test_stream_refusals_and_logins(self):
        before = len(self.h.requests())
        s, body = self._stream("/to-private")
        assert s.error == "unsafe_address" and body == b"" and not s.ok
        assert self.requested()[before:] == [self.h.url(CONTRACT_HOST, "/to-private")]
        for url in BAD_URLS:
            async def go(url=url):
                async with self.h.fetcher.stream(url) as st:
                    return st
            assert run(go()).error == "bad_url", url
        before = len(self.h.requests())
        s, _body = self._stream("/cross", same_host_headers={"Cookie": FAKE_COOKIE})
        first, second = self.h.requests()[before:]
        assert first[1].get("cookie") == FAKE_COOKIE and "cookie" not in second[1]


class RenderContractSuite:
    """Mixin for ``render``: refusals happen before the browser runs."""

    def make_harness(self) -> ContractHarness:  # pragma: no cover - abstract
        raise NotImplementedError

    def setup_method(self, _method=None):
        self.h = self.make_harness()

    def teardown_method(self, _method=None):
        self.h.close()

    def test_render_refuses_private_address(self):
        r = run(self.h.fetcher.render("http://169.254.169.254/latest/meta-data/"))
        assert r.error == "unsafe_address" and r.html == ""
        assert self.h.browser_calls() == 0

    def test_render_refuses_userinfo(self):
        r = run(self.h.fetcher.render("https://user:secret@contract.tc-fixture.test/rendered.html"))
        assert r.error == "userinfo_refused"
        assert self.h.browser_calls() == 0

    def test_render_bad_url(self):
        for url in BAD_URLS:
            assert run(self.h.fetcher.render(url)).error == "bad_url", url
        assert self.h.browser_calls() == 0

    def test_render_returns_page(self):
        if not self.h.can_render_fixture_pages:
            pytest.skip("this harness's browser cannot reach the fixture sites")
        r = run(self.h.fetcher.render(self.h.url(CONTRACT_HOST, "/rendered.html")))
        assert r.error == "" and "tc-rendered-marker" in r.html


@dataclass
class RecordingMcp:
    """An MCP manager whose ``execute_playwright`` records its arguments and answers ``reply``."""

    reply: Any = "<html><body>ok</body></html>"
    calls: List[Dict[str, Any]] = field(default_factory=list)

    async def get_tools(self):
        outer = self

        class _Tool:
            name = "execute_playwright"

            async def ainvoke(self, args):
                outer.calls.append(dict(args))
                if not callable(outer.reply):
                    return outer.reply
                out = outer.reply(args)
                return await out if asyncio.iscoroutine(out) else out

        return [_Tool()]
