"""Per-resource logins in fetching (T6.4, §5, §6.6; R-110, R-115, R-116, AC-47, AC-48).

A login (cookie, custom headers, basic authentication) reaches only the resource's own host,
hop by hop, never another host after a redirect; a resource with a login never uses the browser,
so no browser script ever holds a login value; the address guard applies as always. Every value
here is fake (``cookie=fake-session``).
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import logging
import re
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import check_url, net, runtime  # noqa: E402
from tradecraft.contract import BasicAuth, CheckUrlRequest, Credentials, Header  # noqa: E402
from tradecraft.ingest import fetch  # noqa: E402
from tradecraft.library import reader  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import CONTRACT_HOST, FAKE_COOKIE, OTHER_HOST, FixtureFetcher, RecordingMcp  # noqa: E402
from tradecraft_job_harness import JobHarness  # noqa: E402
from tradecraft_memory_store import MemoryStore, padded_sites  # noqa: E402

FAKE_HEADER = "fake-api-key-value"
FAKE_PASSWORD = "fake-password"
LOGIN = {"cookie": FAKE_COOKIE, "headers": [{"name": "X-Api-Key", "value": FAKE_HEADER}],
         "basic_auth": {"username": "fake-user", "password": FAKE_PASSWORD}}
BASIC = "Basic " + base64.b64encode(f"fake-user:{FAKE_PASSWORD}".encode()).decode()
SECRETS = {"github_token": None, "credentials": LOGIN}
SECRET_VALUES = (FAKE_COOKIE, FAKE_HEADER, FAKE_PASSWORD, BASIC.split()[1])
WIKI = "https://wiki.tc-fixture.test/"
BLOG = "https://blog.tc-fixture.test/"
CONTRACT = f"http://{CONTRACT_HOST}"


def creds(data=None):
    return Credentials.model_validate(LOGIN if data is None else data)


def carries_login(headers: dict) -> bool:
    return any(k in headers for k in ("cookie", "x-api-key", "authorization"))


def has_full_login(headers: dict) -> bool:
    return (headers.get("cookie") == FAKE_COOKIE and headers.get("x-api-key") == FAKE_HEADER
            and headers.get("authorization") == BASIC)


def host_of(url: str) -> str:
    return (httpx.URL(url).host or "").lower()


def run_with(fetcher, coro_fn):
    async def go():
        with net.use_fetcher(fetcher):
            return await coro_fn()
    return contextvars.Context().run(asyncio.run, go())


# --------------------------------------------------------------------------------------
# The login headers
# --------------------------------------------------------------------------------------

def test_login_headers():
    assert fetch.login_headers(creds()) == {"X-Api-Key": FAKE_HEADER, "Cookie": FAKE_COOKIE, "Authorization": BASIC}
    assert fetch.login_headers(None) == {} and fetch.login_headers(Credentials()) == {}


def test_a_login_part_the_webapp_would_refuse_is_never_sent(caplog):
    # model_construct: values the contract and the webapp refuse, as if they had got past both.
    bad = Credentials.model_construct(
        cookie="a=b\r\nX-Injected: 1",
        headers=[Header.model_construct(name=n, value=v)
                 for n, v in (("Host", "x"), ("Authorization", "y"), ("Bad Name", "z"), ("X-Ok", "line\nbreak"),
                              ("X-Nul", "a\x00b"), ("X-Fine", "fake-fine-value"))],
        basic_auth=BasicAuth.model_construct(username="user:colon", password="p"),
    )
    with caplog.at_level(logging.WARNING):
        assert fetch.login_headers(bad) == {"X-Fine": "fake-fine-value"}
    text = " ".join(r.getMessage() for r in caplog.records)
    assert "login_part_refused" in text and "fields=basic_auth,cookie,header" in text
    assert "X-Injected" not in text and "fake-fine-value" not in text and "line" not in text


# --------------------------------------------------------------------------------------
# Only the resource's own host, hop by hop (AC-47)
# --------------------------------------------------------------------------------------

def _get(fetcher, url, login_url=CONTRACT + "/", credentials=None):
    async def go():
        with fetch.use_login(login_url, creds() if credentials is None else credentials):
            return await fetch.fetch_raw(url, EffectiveSettings({}))
    return run_with(fetcher, go)


def test_redirect_other_host():
    f = FixtureFetcher()
    resp = _get(f, CONTRACT + "/cross")
    assert resp.status == 200 and host_of(resp.final_url) == OTHER_HOST
    (first_url, first), (second_url, second) = f.requests
    assert host_of(first_url) == CONTRACT_HOST and has_full_login(first)
    assert host_of(second_url) == OTHER_HOST and not carries_login(second)


def test_same_host_redirect_keeps_login():
    f = FixtureFetcher()
    assert _get(f, CONTRACT + "/same").status == 200
    assert len(f.requests) == 2 and all(has_full_login(h) for _u, h in f.requests)


def test_a_request_to_another_host_never_carries_the_login():
    f = FixtureFetcher()
    _get(f, f"http://{OTHER_HOST}/landing.html")
    assert len(f.requests) == 1 and not carries_login(f.requests[0][1])
    # Nothing is bound outside the binding.
    f2 = FixtureFetcher()
    run_with(f2, lambda: fetch.fetch_raw(CONTRACT + "/ok.html", EffectiveSettings({})))
    assert not carries_login(f2.requests[0][1])


def test_a_resource_without_a_login_binds_none_inside_another():
    async def go():
        with fetch.use_login(CONTRACT + "/", creds()):
            with fetch.use_login(CONTRACT + "/", None) as bound:
                assert bound is False and not fetch.login_bound()
                await fetch.fetch_raw(CONTRACT + "/ok.html", EffectiveSettings({}))
            assert fetch.login_bound()
    f = FixtureFetcher()
    run_with(f, go)
    assert not carries_login(f.requests[0][1])


def test_a_job_sends_its_login_only_to_its_host(tmp_path):
    root = padded_sites(tmp_path)
    redirects = root / "wiki.tc-fixture.test" / "_redirects.json"
    redirects.write_text('{"/sqli/union-based/": "https://other.tc-fixture.test/landing.html"}')
    h = JobHarness(tmp_path, WIKI, mode="stored", root=root, secrets=SECRETS)
    assert h.run().status == "succeeded"
    assert h.fetcher.requests
    to_other = [(u, hd) for u, hd in h.fetcher.requests if host_of(u) != "wiki.tc-fixture.test"]
    assert any(host_of(u) == OTHER_HOST for u, _ in to_other)
    assert all(not carries_login(hd) for _u, hd in to_other)
    assert all(has_full_login(hd) for u, hd in h.fetcher.requests if host_of(u) == "wiki.tc-fixture.test")
    # Nothing the job wrote holds a login value.
    written = repr(h.store.resources) + repr(h.store.entries) + repr(h.store.jobs) + repr(h.store.calls)
    assert not any(v in written for v in SECRET_VALUES)


def test_guard_with_login():
    f = FixtureFetcher()
    resp = _get(f, CONTRACT + "/to-private")
    assert resp.error == "unsafe_address"
    assert [u for u, _ in f.requests] == [CONTRACT + "/to-private"]
    f2 = FixtureFetcher()
    resp = _get(f2, "http://169.254.169.254/latest/meta-data/", login_url="http://169.254.169.254/")
    assert resp.error == "unsafe_address" and f2.requests == []


def test_a_job_with_a_login_on_a_private_address_is_refused(tmp_path):
    h = JobHarness(tmp_path, "http://169.254.169.254/latest/", secrets=SECRETS)
    outcome = h.run()
    assert outcome.status == "failed" and outcome.error_code == "blocked_private_address"
    assert h.fetcher.requests == [] and h.fetcher.browser.renders == []


# --------------------------------------------------------------------------------------
# Never the browser (AC-48)
# --------------------------------------------------------------------------------------

ALWAYS = {"fetching.alwaysBrowser": True}


@pytest.mark.parametrize("url,mode,settings", [
    (BLOG, "live", {**ALWAYS, "crawl.strategy": "rules", "crawl.maxPages": 6}),
    (BLOG, "stored", {**ALWAYS, "crawl.strategy": "rules", "crawl.maxPages": 6}),
    (WIKI, "stored", ALWAYS),
    (WIKI, "live", ALWAYS),
    ("https://book.tc-fixture.test/", "live", ALWAYS),
])
def test_never_browser(tmp_path, url, mode, settings):
    without = JobHarness(tmp_path / "a", url, mode=mode, settings=settings)
    without.run()
    assert without.fetcher.browser.renders, "the case must use the browser without a login"
    h = JobHarness(tmp_path / "b", url, mode=mode, settings=settings, secrets=SECRETS)
    h.run()
    assert h.fetcher.browser.renders == []
    assert h.fetcher.requests and all(has_full_login(hd) for u, hd in h.fetcher.requests if host_of(u) == host_of(url))


def test_render_is_refused_while_a_login_is_bound():
    async def go():
        with fetch.use_login(BLOG, creds()):
            return await fetch.render(BLOG, EffectiveSettings({}))
    f = FixtureFetcher()
    assert run_with(f, go).error == "browser_unavailable" and f.browser.renders == []


def test_only_fetch_renders():
    """Every render goes through fetch.render, which refuses it under a login."""
    base = Path(__file__).resolve().parent.parent / "tradecraft"
    callers = [p.relative_to(base).as_posix() for p in base.rglob("*.py")
               if re.search(r"get_fetcher\(\)\s*\.\s*render\(", p.read_text()) and p.name != "fetch.py"]
    assert callers == []


class _Hybrid(FixtureFetcher):
    """The fixture sites over plain HTTP, and the real browser path (the guarded script handed to
    a recording MCP tool) for renders."""

    def __init__(self, root):
        super().__init__(root)
        self.mcp = RecordingMcp(reply=lambda args: "<html><body><article>" + "rendered text " * 200 + "</article></body></html>")
        self.guarded = net.GuardedFetcher(self.mcp)

    async def render(self, url, **kw):
        return await self.guarded.render(url, **kw)


def test_no_login_value_in_browser_script(tmp_path, monkeypatch):
    monkeypatch.setattr(net, "assert_safe_fetch_url", lambda url: None)
    settings = {**ALWAYS, "crawl.strategy": "rules", "crawl.maxPages": 4}
    plain = JobHarness(tmp_path / "a", BLOG, settings=settings, fetcher=_Hybrid(padded_sites(tmp_path / "a")))
    plain.run()
    assert plain.fetcher.mcp.calls, "without a login the case renders through the browser script"
    h = JobHarness(tmp_path / "b", BLOG, settings=settings, secrets=SECRETS, fetcher=_Hybrid(padded_sites(tmp_path / "b")))
    h.run()
    assert h.fetcher.mcp.calls == []
    scripts = " ".join(c["script"] for c in plain.fetcher.mcp.calls + h.fetcher.mcp.calls)
    assert not any(v in scripts for v in SECRET_VALUES)


# --------------------------------------------------------------------------------------
# The read path and Check URL
# --------------------------------------------------------------------------------------

OWNER = "user_owner_fake"


def _read_live(fetcher, *, credentials, settings=None, url=WIKI + "sqli/union-based/"):
    store = MemoryStore()
    store.add_resource(OWNER, "r1", url=WIKI, slug="wiki", storage_mode="live", map_version=3,
                       resource_type="mkdocs-wiki", has_login=credentials is not None,
                       sitemap={"nav": [{"title": "Union based", "path": url}]})
    store.entries.append({"id": 1, "user_id": OWNER, "resource_id": "r1", "generation": 0, "page_id": 1, "url": url,
                          "title": "Union based", "stored_text": None, "stored_bytes": 0})
    store.page_ids[("r1", url)] = 1
    catalog = {"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None, "search": {},
               "resources": [{"id": "r1", "slug": "wiki", "name": "wiki", "url": WIKI, "type": "mkdocs-wiki",
                              "storage_mode": "live", "summary": "s", "has_login": credentials is not None,
                              "priority": "normal", "map_version": 3, "read_settings": settings or {},
                              "github_token": None, "credentials": credentials}]}

    async def go():
        with net.use_fetcher(fetcher), runtime.use_store(store):
            assert runtime.bind_run_catalog(catalog)
            return await reader.lookup(page="wiki:1")

    return contextvars.Context().run(asyncio.run, go())


def test_live_read_carries_the_login_and_never_the_browser():
    f = FixtureFetcher()
    out = _read_live(f, credentials=LOGIN, settings=ALWAYS)
    assert "Union" in out and f.browser.renders == []
    assert f.requests and all(has_full_login(h) for _u, h in f.requests)
    plain = FixtureFetcher()
    _read_live(plain, credentials=None, settings=ALWAYS)
    assert plain.browser.renders and not any(carries_login(h) for _u, h in plain.requests)


def test_a_read_outside_lookup_carries_the_login_too():
    """The librarian reads pages through reader._text_of, not lookup: the login is bound there."""
    from tradecraft.contract import CatalogResource, V2Catalog

    resource = CatalogResource(id="r1", slug="wiki", name="wiki", url=WIKI, type="mkdocs-wiki", storage_mode="live",
                               has_login=True, map_version=3, read_settings=ALWAYS, credentials=LOGIN)
    catalog = V2Catalog(v2=True, owner_id=OWNER, person_id=OWNER, resources=[resource])
    read = reader._Read(catalog, resource, {"url": WIKI, "storage_mode": "live", "has_login": True}, MemoryStore())
    f = FixtureFetcher()
    text, _src, _note, error = run_with(f, lambda: reader._text_of(read, WIKI + "sqli/union-based/", None, False))
    assert not error and text and f.browser.renders == []
    assert f.requests and all(has_full_login(h) for _u, h in f.requests)


def test_check_url_with_a_login():
    f = FixtureFetcher()
    req = CheckUrlRequest(user_id="u1", url=WIKI, settings=ALWAYS, secrets=SECRETS)
    result = run_with(f, lambda: check_url.check_url(req))
    assert result.ok and f.browser.renders == []
    assert all(has_full_login(h) for u, h in f.requests if host_of(u) == "wiki.tc-fixture.test")
    assert not any(carries_login(h) for u, h in f.requests if host_of(u) != "wiki.tc-fixture.test")
    assert not any(v in result.model_dump_json() for v in SECRET_VALUES)


def test_no_login_value_in_the_logs(tmp_path, caplog):
    with caplog.at_level(logging.DEBUG):
        JobHarness(tmp_path / "a", WIKI, mode="stored", secrets=SECRETS).run()
        JobHarness(tmp_path / "b", "https://github.com/tc-fixture/payloads", mode="stored", secrets=SECRETS).run()
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "[tradecraft] job" in text
    assert not any(v in text for v in SECRET_VALUES)


# --------------------------------------------------------------------------------------
# What the installed httpx does on its own (why net follows redirects by hand)
# --------------------------------------------------------------------------------------

def test_installed_httpx_behaviour():
    """httpx's own redirect handling, for ``01_current_state.md`` §3: on a redirect to another
    host it keeps custom headers (an API key would leak) and drops Authorization; it drops the
    Cookie header on every redirect, the same host's included. net.GuardedFetcher therefore
    follows redirects itself, one hop at a time, adding the login only on hops to its host."""
    seen = []

    def handler(req):
        seen.append((str(req.url), {k.lower(): v for k, v in req.headers.items()}))
        if req.url.path == "/cross":
            return httpx.Response(302, headers={"location": "https://b.tc-fixture.test/land"})
        if req.url.path == "/same":
            return httpx.Response(302, headers={"location": "https://a.tc-fixture.test/land"})
        return httpx.Response(200, text="ok")

    sent = {"Cookie": FAKE_COOKIE, "X-Api-Key": FAKE_HEADER, "Authorization": BASIC}

    async def go(path):
        seen.clear()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True) as c:
            await c.get("https://a.tc-fixture.test" + path, headers=sent)
        return [h for _u, h in seen]

    first, cross = asyncio.run(go("/cross"))
    assert has_full_login(first)
    assert cross.get("x-api-key") == FAKE_HEADER          # kept on another host
    assert "authorization" not in cross and "cookie" not in cross
    _first, same = asyncio.run(go("/same"))
    assert same.get("authorization") == BASIC and same.get("x-api-key") == FAKE_HEADER
    assert "cookie" not in same                           # dropped even on the same host
