"""Map curation at ingestion (T6.6, §6.10, R-167, R-168, AC-14, AC-39, AC-40): pins, blocks and
renames survive every refresh; a restored dropped page stays; a blocked page is never stored,
also when it is blocked while the refresh runs.

The curation rows are what the Map view writes (``W/src/lib/tradecraft/curation.ts``), seeded in
the memory store; the job is the real pipeline on the fixture sites.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.ingest import storage  # noqa: E402
from tradecraft_doubles import FAKE_COOKIE  # noqa: E402
from tradecraft_job_harness import RID, JobHarness  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402

WIKI = "https://wiki.tc-fixture.test/"
UNION = WIKI + "sqli/union-based/"
ERROR = WIKI + "sqli/error-based/"
# A page of the wiki its sitemap does not list (written into each test's copy of the sites).
EXTRA = WIKI + "extra/pinned/"
OTHER = "https://other.tc-fixture.test/landing.html"
PLAIN = {"fetching.browserEnabled": False}
LOGIN = {"github_token": None, "credentials": {"cookie": FAKE_COOKIE, "headers": [], "basic_auth": None}}


def _root(tmp_path):
    root = padded_sites(tmp_path)
    page = root / "wiki.tc-fixture.test" / "extra" / "pinned" / "index.html"
    page.parent.mkdir(parents=True)
    page.write_text("<html><head><title>Pinned</title></head><body><article><h1>Pinned by hand</h1><p>"
                    + "notes the sitemap does not list " * 20 + "</p></article></body></html>")
    return root


def _wiki(tmp_path, **kw):
    h = JobHarness(tmp_path, WIKI, mode="stored", settings=PLAIN, root=_root(tmp_path), **kw)
    assert h.run().status == "succeeded"
    return h


def test_survive_refresh(tmp_path):
    h = _wiki(tmp_path)
    assert EXTRA not in h.live_by_url() and ERROR in h.live_by_url()
    h.store.curate(RID, ERROR, blocked=True)
    h.store.curate(RID, UNION, renamed_title="  My union\nnotes  ")
    h.store.curate(RID, EXTRA, pinned=True)
    h.store.curate(RID, OTHER, pinned=True)
    for _ in range(2):
        h.fetcher.requests.clear()
        assert h.refresh().status == "succeeded"
        live = h.live_by_url()
        # Blocked: out of the map, never asked for again.
        assert ERROR not in live and ERROR not in h.requested()
        # Renamed: the person's title, on one line; the page itself is still read and stored.
        assert live[UNION]["title"] == "My union notes" and live[UNION]["title_source"] == "renamed"
        assert live[UNION]["stored_text"]
        # Pinned: added though the refresh did not find it, and stored like any kept page (a
        # resource without a login may pin another host's page).
        for pin in (EXTRA, OTHER):
            assert live[pin]["source"] == "pin" and live[pin]["status"] == "kept" and live[pin]["stored_text"]
        legacy = {e["path"]: e["title"] for e in h.row["sitemap"]["nav"]}
        assert legacy[UNION] == "My union notes" and EXTRA in legacy and ERROR not in legacy


def test_a_rename_survives_real_titles(tmp_path):
    h = _wiki(tmp_path, resource=None)
    h.settings["knownTypes.realTitles"] = True
    h.store.curate(RID, UNION, renamed_title="Mine")
    h.refresh()
    assert h.live_by_url()[UNION]["title"] == "Mine"
    assert h.live_by_url()[WIKI + "sqli/time-blind/"]["title_source"] == "real"


def test_restore_survives(tmp_path):
    focus = {"mode": "focused", "topics": ["xss"], "strictness": "strict"}
    h = _wiki(tmp_path, resource={"focus": focus})
    dropped = h.live_by_url()[UNION]
    assert dropped["status"] == "dropped" and dropped["drop_reason"] and not dropped["stored_text"]
    # The Map view's Restore: the entry kept now, and a pinned, restored curation row (AC-14).
    h.store.curate(RID, UNION, pinned=True, restored_from_drop=True)
    for _ in range(2):
        h.refresh()
        union = h.live_by_url()[UNION]
        assert union["status"] == "kept" and union["drop_reason"] == "" and union["stored_text"]
        others = h.live_by_url()[WIKI + "sqli/error-based/"]
        assert others["status"] == "dropped"
    report = h.row["ingestion_report"]
    assert report["focus"]["mode"] == "focused" and report["focus"]["dropped"] >= 1


def test_blocked_never_stored(tmp_path):
    h = _wiki(tmp_path)
    h.store.curate(RID, ERROR, blocked=True)
    h.fetcher.requests.clear()
    h.refresh()
    assert ERROR not in h.requested()
    assert not [e for e in h.store.entries if e["url"] == ERROR and e["generation"] == h.row["generation"]]


def test_blocked_while_the_refresh_runs(tmp_path, monkeypatch):
    """S09's second reviewer: the Map view's block reaches the rows that exist when it is made; a
    page blocked after this job's curation stage loses the text the job wrote for it."""
    h = _wiki(tmp_path)
    original = storage.store

    async def store_then_block(state):
        out = await original(state)
        h.store.curate(RID, UNION, blocked=True)
        return out

    monkeypatch.setattr(storage, "store", store_then_block)
    h.refresh()
    live = h.live_by_url()
    assert UNION in live and live[UNION]["stored_text"] is None and live[UNION]["stored_bytes"] == 0
    assert not [s for s in h.store.sections if s["entry_id"] == live[UNION]["id"]]
    stored = [e for e in live.values() if e["stored_text"]]
    report = h.row["ingestion_report"]["stored"]
    assert report["pages"] == len(stored) and report["bytes"] == sum(e["stored_bytes"] for e in stored)


def test_pins_on_a_login_resource_stay_on_its_host(tmp_path):
    h = JobHarness(tmp_path, WIKI, settings=PLAIN, secrets=LOGIN, root=_root(tmp_path))
    h.run()
    h.store.curate(RID, OTHER, pinned=True)
    h.store.curate(RID, EXTRA, pinned=True)
    h.fetcher.requests.clear()
    h.refresh()
    live = h.live_by_url()
    assert EXTRA in live and OTHER not in live
    assert not any(u.startswith("https://other.") for u in h.requested())


def test_a_pin_must_be_an_entry_url(tmp_path):
    h = JobHarness(tmp_path, WIKI, settings=PLAIN)
    h.run()
    h.store.curate(RID, WIKI + "page#part", pinned=True)
    h.store.curate(RID, "ftp://wiki.tc-fixture.test/x", pinned=True)
    h.store.curate(RID, "https://user:pw@wiki.tc-fixture.test/x", pinned=True)
    h.store.curate(RID, "https://wiki.tc-fixture.test/" + "a" * 3000, pinned=True)
    h.store.curate(RID, "https://WIKI.tc-fixture.test:443/sqli/pinned-elsewhere/", pinned=True)
    h.refresh()
    pins = {e["url"] for e in h.live() if e["source"] == "pin"}
    # Only the last, read as its canonical URL, is a URL an entry may hold.
    assert pins == {WIKI + "sqli/pinned-elsewhere/"}


def test_no_pins_on_a_pdf(tmp_path):
    pdf = "https://files.tc-fixture.test/guide.pdf"
    h = JobHarness(tmp_path, pdf)
    h.run()
    h.store.curate(RID, pdf + "#page=9", pinned=True)
    h.store.curate(RID, "https://files.tc-fixture.test/other.pdf", pinned=True)
    h.refresh()
    assert {e["source"] for e in h.live()} == {"pdf"}


def test_a_curation_of_another_resource_is_not_read(tmp_path):
    h = _wiki(tmp_path)
    h.store.add_resource("u1", "r2", url=WIKI, slug="other")
    h.store.curate("r2", UNION, blocked=True)
    h.refresh()
    assert UNION in h.live_by_url()
    assert ("curation_rows", ("u1", RID)) in h.store.calls
