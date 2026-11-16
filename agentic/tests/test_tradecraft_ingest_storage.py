"""The ``store`` stage (T1.8): what a Stored resource keeps, within its limits, the owner's
quota and the install's ceiling (§4.5, OQ-26); a PDF always, a CVE archive never (R-082).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net  # noqa: E402
from tradecraft.contract import JobContext, JobStartRequest  # noqa: E402
from tradecraft.ingest import storage  # noqa: E402
from tradecraft.ingest.builders import Candidate  # noqa: E402
from tradecraft.ingest.pipeline import Cancelled, IngestState  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
MB = 1024 * 1024
WIKI = "https://wiki.tc-fixture.test/"


def html_page(n, size):
    return Candidate(f"{WIKI}p{n}", f"P{n}", "crawl", extra={"html": f"<html><body><main><p>{'x' * size}</p></main></body></html>"})


def state_for(entries, *, mode="stored", site_type="agentic-crawl", settings=None, store=None, cancel=lambda: False):
    req = JobStartRequest.model_validate(dict(FIXTURE, user_id="u1", resource_id="r1"))

    async def is_cancelled():
        return cancel()

    async def set_stage(stage, progress=None):
        pass

    ctx = JobContext(request=req, settings=EffectiveSettings(settings or {}), target_generation=1,
                     is_cancelled=is_cancelled, set_stage=set_stage)

    async def blocking(fn, *args):
        return fn(*args)

    st = store or MemoryStore()
    if "r1" not in st.resources:
        st.add_resource("u1", "r1")
    return IngestState(ctx=ctx, store=st, blocking=blocking, build_llm=None, owner_id="u1", resource_id="r1",
                       storage_mode=mode, site_type=site_type, entries=list(entries))


def stored_live(store, user, rid, url, size, generation=0):
    """A stored page of the live generation (generation 0 is live on a new resource)."""
    store.page_ids[(rid, url)] = len(store.page_ids) + 1000
    store.entries.append({"id": len(store.entries) + 1, "user_id": user, "resource_id": rid, "generation": generation,
                          "page_id": store.page_ids[(rid, url)], "url": url, "stored_bytes": size})


def run(coro):
    return asyncio.run(coro)


def test_live_stores_nothing():
    st = state_for([html_page(1, 1000)], mode="live")
    run(storage.store(st))
    assert st.texts == {} and st.stored_counts["pages"] == 0


def test_stored_row_content():
    st = state_for([html_page(1, 1000)])
    run(storage.store(st))
    page = st.texts[f"{WIKI}p1"]
    assert page.text.strip() == "x" * 1000 and page.bytes == len(page.text.encode())
    assert page.text_hash == storage.text_hash(page.text) and len(page.text_hash) == 64
    assert page.fetched_at.tzinfo is not None and not page.truncated
    assert st.stored_counts == {"pages": 1, "bytes": page.bytes, "notStoredQuota": 0, "notStoredSize": 0}


def test_limits():
    # Per page: cut at storage.maxPageKb.
    st = state_for([html_page(1, 30 * 1024)], settings={"storage.maxPageKb": 10})
    run(storage.store(st))
    page = st.texts[f"{WIKI}p1"]
    assert page.truncated and page.bytes == 10 * 1024
    # Pages per resource.
    st = state_for([html_page(i, 100) for i in range(5)], settings={"storage.maxPages": 2})
    run(storage.store(st))
    assert len(st.texts) == 2 and st.stored_counts["notStoredSize"] == 3
    # Bytes per resource: 1 MB, 400 KB pages -> two fit.
    st = state_for([html_page(i, 400 * 1024) for i in range(4)], settings={"storage.maxResourceMb": 1, "storage.maxPageKb": 500})
    run(storage.store(st))
    assert len(st.texts) == 2 and st.stored_counts["notStoredSize"] == 2


def test_quota():
    """R-089: once the owner's quota is used, storing stops and the report counts the rest."""
    store = MemoryStore()
    store.add_resource("u1", "other")
    stored_live(store, "u1", "other", "https://elsewhere.tc-fixture.test/a", MB - 250 * 1024)
    st = state_for([html_page(i, 100 * 1024) for i in range(5)], settings={"storage.userQuotaMb": 1}, store=store)
    run(storage.store(st))
    assert len(st.texts) == 2 and st.stored_counts["notStoredQuota"] == 3
    # The resource's own live generation does not count: the refresh replaces it.
    store2 = MemoryStore()
    store2.add_resource("u1", "r1")
    stored_live(store2, "u1", "r1", f"{WIKI}old", MB)
    st = state_for([html_page(i, 100 * 1024) for i in range(5)], settings={"storage.userQuotaMb": 1}, store=store2)
    run(storage.store(st))
    assert len(st.texts) == 5 and st.stored_counts["notStoredQuota"] == 0


def test_quota_never_counts_another_users_pages():
    store = MemoryStore()
    store.add_resource("u2", "theirs")
    stored_live(store, "u2", "theirs", "https://elsewhere.tc-fixture.test/a", 5 * MB)
    st = state_for([html_page(i, 100 * 1024) for i in range(3)], settings={"storage.userQuotaMb": 1}, store=store)
    run(storage.store(st))
    assert len(st.texts) == 3


def test_instance_ceiling(monkeypatch):
    """OQ-26: the install's total stops storing too, whoever's pages fill it."""
    store = MemoryStore()
    store.add_resource("u2", "theirs")
    stored_live(store, "u2", "theirs", "https://elsewhere.tc-fixture.test/a", 900 * 1024)
    real = storage.constant
    monkeypatch.setattr(storage, "constant", lambda n: MB if n == "instanceStoredBytesCeiling" else real(n))
    st = state_for([html_page(i, 50 * 1024) for i in range(4)], store=store)
    run(storage.store(st))
    assert len(st.texts) == 2 and st.stored_counts["notStoredQuota"] == 2


def test_pdf_always_cve_never():
    pdf = state_for([Candidate("https://files.tc-fixture.test/g.pdf#page=1", "P1", "pdf", "1",
                               {"page": 1, "text": "page one text", "first_line": "page one"})],
                    mode="live", site_type="pdf")
    run(storage.store(pdf))
    assert pdf.texts["https://files.tc-fixture.test/g.pdf#page=1"].text == "page one text"
    cve = state_for([html_page(1, 100)], mode="stored", site_type="cve-poc-db")
    run(storage.store(cve))
    assert cve.texts == {}


def test_dropped_pages_are_not_stored():
    dropped = html_page(2, 100)
    dropped.extra["status"] = "dropped"
    st = state_for([html_page(1, 100), dropped])
    run(storage.store(st))
    assert list(st.texts) == [f"{WIKI}p1"]


def test_pages_are_fetched_when_the_map_has_no_text():
    fetcher = FixtureFetcher()
    entries = [Candidate(f"{WIKI}sqli/union-based/", "Union", "sitemap"),
               Candidate("https://down.tc-fixture.test/x", "Down", "sitemap")]
    st = state_for(entries, site_type="mkdocs-wiki", settings={"fetching.browserEnabled": False})
    with net.use_fetcher(fetcher):
        run(storage.store(st))
    assert list(st.texts) == [f"{WIKI}sqli/union-based/"] and "UNION" in st.texts[f"{WIKI}sqli/union-based/"].text
    assert st.errors == {"unreachable": 1} and st.visited == 2


def test_cancel_between_pages():
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 2

    st = state_for([html_page(i, 100) for i in range(5)], cancel=cancel)
    with pytest.raises(Cancelled):
        run(storage.store(st))
    assert len(st.texts) == 2


def test_cut_on_a_character_boundary():
    text, cut = storage.cut_utf8("é" * 10, 5)
    assert cut and text == "éé" and len(text.encode()) <= 5
