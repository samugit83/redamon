"""Read now (T6.6, §6.10, R-166, R-229, AC-38): one page downloaded the way the agent's tool reads it,
kept nowhere; a resource with a login reads only its map, checked against the store, never the
request; its login only to its own host, never the browser."""

from __future__ import annotations

import asyncio
import contextvars
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net, read_now as read_now_mod, runtime  # noqa: E402
from tradecraft.contract import ReadNowRequest, ReadNowResult  # noqa: E402
from tradecraft.library import reader  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FAKE_COOKIE, FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

OWNER, RID = "user_owner_fake", "r1"
WIKI = "https://wiki.tc-fixture.test/"
UNION = WIKI + "sqli/union-based/"
KERB = WIKI + "kerberos/kerberoasting/"
LOGIN = {"cookie": FAKE_COOKIE, "headers": [], "basic_auth": None}
PLAIN = {"fetching.browserEnabled": False}


def _store(*, login=False, mode="live", urls=(UNION,), stored=None, url=WIKI, resource_type="mkdocs-wiki"):
    store = MemoryStore()
    store.add_resource(OWNER, RID, url=url, slug="wiki", storage_mode=mode, map_version=3,
                       resource_type=resource_type, has_login=login)
    for i, u in enumerate(urls, 1):
        store.page_ids[(RID, u)] = i
        text = (stored or {}).get(u)
        store.entries.append({"id": i, "user_id": OWNER, "resource_id": RID, "generation": 0, "page_id": i, "url": u,
                              "title": "t", "stored_text": text, "stored_bytes": len(text or "")})
    return store


def _request(url=UNION, *, credentials=None, settings=None, user=OWNER, resource=RID):
    return ReadNowRequest(user_id=user, resource_id=resource, url=url, read_settings=settings or PLAIN,
                          secrets={"github_token": None, "credentials": credentials})


def run(store, request, fetcher=None):
    fetcher = fetcher or FixtureFetcher()

    async def go():
        with net.use_fetcher(fetcher):
            return await read_now_mod.read_now(request, store=store)

    before = store.snapshot_counts()
    out = contextvars.Context().run(asyncio.run, go())
    assert store.snapshot_counts() == before, "Read now wrote to the store"
    assert ReadNowResult.model_validate(out.model_dump()) == out
    return out, fetcher


def test_keeps_nothing():
    out, fetcher = run(_store(), _request())
    assert out.error_code == "" and "Union" in out.text and out.source == "live" and out.fetched_at
    assert [u for u, _h in fetcher.requests] == [UNION]


def test_same_text_as_tool():
    """AC-38: the text the Map view shows is the text the agent's tool reads."""
    store = _store()
    out, _f = run(store, _request())
    catalog = {"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None, "search": {},
               "resources": [{"id": RID, "slug": "wiki", "name": "wiki", "url": WIKI, "type": "mkdocs-wiki",
                              "storage_mode": "live", "summary": "s", "has_login": False, "priority": "normal",
                              "map_version": 3, "read_settings": PLAIN, "github_token": None, "credentials": None}]}

    async def tool():
        with net.use_fetcher(FixtureFetcher()), runtime.use_store(store):
            assert runtime.bind_run_catalog(catalog)
            whole = await reader.live_page(UNION, EffectiveSettings(PLAIN), github_token=None, has_login=False)
            return whole, await reader.lookup(page="wiki:1")

    whole, answer = contextvars.Context().run(asyncio.run, tool())
    assert out.text == whole.text
    body = answer.split("\n---\n", 1)[1].rsplit("\n", 1)[0].strip()
    assert body and body.splitlines()[0] in out.text and body.splitlines()[-1] in out.text


def test_login_map_only():
    store = _store(login=True, urls=(UNION,))
    out, fetcher = run(store, _request(credentials=LOGIN))
    assert out.error_code == "" and fetcher.requests[0][1].get("cookie") == FAKE_COOKIE
    # Not in the map: refused before any request, whatever the request says.
    out, fetcher = run(store, _request(KERB, credentials=LOGIN))
    assert out.error_code == "outside_map" and fetcher.requests == []
    # A pin on its own host that no refresh has listed yet: read; another host's: refused.
    store.curate(RID, KERB, pinned=True)
    out, fetcher = run(store, _request(KERB, credentials=LOGIN))
    assert out.error_code == "" and fetcher.requests
    store.curate(RID, "https://other.tc-fixture.test/landing.html", pinned=True)
    out, fetcher = run(store, _request("https://other.tc-fixture.test/landing.html", credentials=LOGIN))
    assert out.error_code == "outside_map" and fetcher.requests == []


def test_a_dropped_entry_is_outside_a_login_map():
    """S10 review 2, finding 2: Read now sends a login only to a kept page of the map."""
    store = _store(login=True, urls=(UNION,))
    store.entries[0]["status"] = "dropped"
    out, fetcher = run(store, _request(credentials=LOGIN))
    assert out.error_code == "outside_map" and fetcher.requests == []


def test_the_login_flag_is_the_stores():
    # A request that carries a login for a resource the store says has none sends no login.
    out, fetcher = run(_store(login=False), _request(credentials=LOGIN))
    assert out.error_code == "" and "cookie" not in fetcher.requests[0][1]
    # The store says it has one: the map rule applies even when the request carries none.
    out, fetcher = run(_store(login=True), _request(KERB))
    assert out.error_code == "outside_map" and fetcher.requests == []


def test_never_browser_with_a_login():
    always = {"fetching.alwaysBrowser": True}
    out, fetcher = run(_store(login=True), _request(credentials=LOGIN, settings=always))
    assert out.error_code == "" and fetcher.browser.renders == []
    out, fetcher = run(_store(), _request(settings=always))
    assert fetcher.browser.renders == [UNION]


def test_blocked_refused():
    store = _store()
    store.curate(RID, UNION, blocked=True)
    out, fetcher = run(store, _request())
    assert out.error_code == "page_blocked" and fetcher.requests == []


def test_deleted_or_another_owners_resource():
    out, fetcher = run(_store(), _request(user="someone_else"))
    assert out.error_code == "resource_deleted" and fetcher.requests == []
    out, fetcher = run(_store(), _request(resource="r-gone"))
    assert out.error_code == "resource_deleted"


def test_refusals_of_the_address():
    out, fetcher = run(_store(), _request("https://user:pw@wiki.tc-fixture.test/x"))
    assert out.error_code == "userinfo_refused" and fetcher.requests == []
    out, fetcher = run(_store(url="http://contract.tc-fixture.test/", urls=("http://contract.tc-fixture.test/to-private",)),
                       _request("http://contract.tc-fixture.test/to-private"))
    assert out.error_code == "blocked_private_address"
    assert [u for u, _h in fetcher.requests] == ["http://contract.tc-fixture.test/to-private"]
    out, _f = run(_store(), _request(WIKI + "no/such/page/"))
    assert out.error_code == "fetch_failed" and out.text == ""


def test_stored_resource_sources():
    store = _store(mode="stored", urls=(UNION, KERB), stored={UNION: "# the stored copy"})
    out, _f = run(store, _request(UNION))
    assert out.source == "live" and "the stored copy" not in out.text
    out, _f = run(store, _request(KERB))
    assert out.source == "live_not_stored"


def test_a_pdf_page():
    pdf = "https://files.tc-fixture.test/guide.pdf"
    store = _store(url=pdf, urls=(pdf + "#page=2",), resource_type="agentic-crawl")
    out, fetcher = run(store, _request(pdf + "#page=2"))
    assert out.error_code == "" and out.text.strip()
    assert [u for u, _h in fetcher.requests] == [pdf]
