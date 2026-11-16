"""The 2.0 read path (T1.9, Q1.1-Q1.3): its order, Live and Stored, the refusals that come
before any request, the deleted resource, today's title match on 1.x maps, CVE archives
live and PDFs from the store. Reading never writes.

The store is ``MemoryStore``; the sites are the fixture sites (``FixtureFetcher``).
"""

from __future__ import annotations

import asyncio
import contextvars
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net, runtime  # noqa: E402
from tradecraft.library import reader  # noqa: E402
from tradecraft_doubles import FAKE_COOKIE, FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

OWNER = "user_owner_fake"
WIKI = "https://wiki.tc-fixture.test/"
PAGES = {
    "SQL injection: Union based": WIKI + "sqli/union-based/",
    "Kerberos: Kerberoasting": WIKI + "kerberos/kerberoasting/",
    "Kerberos: Golden ticket": WIKI + "kerberos/golden-ticket/",
}
WIKI_MAP = {"nav": [{"title": t, "path": u} for t, u in PAGES.items()]}
COPY_DATE = "2026-11-10T08:00:00+00:00"


class Library:
    """A catalog bound to a run, its rows in the store, the fixture sites."""

    def __init__(self, fetcher=None):
        self.store, self.fetcher = MemoryStore(), fetcher or FixtureFetcher()
        self.resources: list[dict] = []

    def add(self, rid, slug, url, *, type_="mkdocs-wiki", mode="live", map_version=3, sitemap=None,
            has_login=False, credentials=None, read_settings=None):
        self.resources.append({"id": rid, "slug": slug, "name": slug, "url": url, "type": type_, "storage_mode": mode,
                               "summary": "s", "has_login": has_login, "priority": "normal",
                               "map_version": map_version, "read_settings": read_settings or {},
                               "github_token": None, "credentials": credentials})
        self.store.add_resource(OWNER, rid, url=url, slug=slug, storage_mode=mode, map_version=map_version,
                                resource_type="agentic-crawl" if type_ == "pdf" else type_,
                                sitemap=sitemap if sitemap is not None else WIKI_MAP, has_login=has_login)
        return self

    def entry(self, rid, url, text=None, fetched_at=COPY_DATE):
        pid = self.store.page_ids.setdefault((rid, url), len(self.store.page_ids) + 1)
        gen = self.store.resources[rid]["generation"]
        self.store.entries.append({"id": len(self.store.entries) + 1, "user_id": OWNER, "resource_id": rid,
                                   "generation": gen, "page_id": pid, "url": url, "title": "", "stored_text": text,
                                   "stored_bytes": len(text.encode()) if text else 0, "fetched_at": fetched_at})
        return self

    def catalog(self):
        return {"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None, "search": {},
                "resources": self.resources}

    def read(self, **kw):
        async def go():
            with net.use_fetcher(self.fetcher), runtime.use_store(self.store):
                assert runtime.bind_run_catalog(self.catalog())
                return await reader.lookup(**kw)

        before = self.store.snapshot_counts()
        out = contextvars.Context().run(asyncio.run, go())
        after = self.store.snapshot_counts()
        assert after == before, "reading wrote to the store"
        return out

    def requested(self):
        return [u for u, _ in self.fetcher.requests] + list(self.fetcher.browser.renders)


def header(result, name):
    for line in result.splitlines():
        if line.startswith(f"{name}: "):
            return line[len(name) + 2:]
    return None


def no_browser():
    return {"fetching.browserEnabled": False}


# --------------------------------------------------------------------------------------

def test_order():
    """Q1.1: deleted -> stored copy -> download -> unreachable."""
    lib = Library().add("r1", "wiki", WIKI, mode="stored", read_settings=no_browser())
    lib.entry("r1", PAGES["Kerberos: Kerberoasting"], "stored kerberoast text")
    stored = lib.read(resource_id="wiki", query="kerberoasting")
    assert "stored kerberoast text" in stored and lib.requested() == []
    downloaded = lib.read(resource_id="wiki", query="golden ticket")
    assert header(downloaded, "source") == "live (not stored)" and lib.requested() == [PAGES["Kerberos: Golden ticket"]]
    lib.store.delete_resource("r1")
    before = len(lib.requested())
    assert lib.read(resource_id="wiki", query="kerberoasting") == reader.DELETED.format(slug="wiki")
    assert len(lib.requested()) == before

    down = Library().add("r2", "down", "https://down.tc-fixture.test/",
                         sitemap={"nav": [{"title": "Notes", "path": "https://down.tc-fixture.test/notes"}]},
                         read_settings=no_browser())
    answer = down.read(resource_id="down", query="notes")
    assert answer.startswith("Error: could not read https://down.tc-fixture.test/notes (unreachable)")
    assert "is Live: no copy" in answer


def test_live_keeps_nothing():
    """R-079 / AC-17: a Live resource is read from the site at every read, nothing is kept."""
    lib = Library().add("r1", "wiki", WIKI, read_settings=no_browser())
    first = lib.read(resource_id="wiki", query="union based")
    second = lib.read(resource_id="wiki", query="union based")
    assert header(first, "source") == header(second, "source") == "live"
    assert lib.requested() == [PAGES["SQL injection: Union based"]] * 2
    assert lib.store.writes == 0 and lib.store.entries == []


def test_stored_and_not_stored():
    """R-080: the stored copy when there is one; a page that was not stored is read live, not kept."""
    lib = Library().add("r1", "wiki", WIKI, mode="stored", read_settings=no_browser())
    lib.entry("r1", PAGES["SQL injection: Union based"], "stored union text")
    lib.entry("r1", PAGES["Kerberos: Golden ticket"], None)  # in the map, not stored (a limit)
    assert "stored union text" in lib.read(resource_id="wiki", query="union based")
    live = lib.read(resource_id="wiki", query="golden ticket")
    assert header(live, "source") == "live (not stored)" and "stored" not in live.split("---", 1)[1][:20]
    assert lib.requested() == [PAGES["Kerberos: Golden ticket"]]


def test_stored_offline():
    """AC-16: a Stored resource answers while its site is down."""
    url = "https://down.tc-fixture.test/notes"
    lib = Library().add("r1", "down", "https://down.tc-fixture.test/", mode="stored",
                        sitemap={"nav": [{"title": "Notes", "path": url}]})
    lib.entry("r1", url, "kept while the site is down")
    answer = lib.read(resource_id="down", query="notes")
    assert "kept while the site is down" in answer and header(answer, "source") == "stored copy from 2026-11-10"


def test_force_refresh():
    """Q1.3: Live -> no effect; Stored -> read from the site, the copy untouched; Stored and
    unreachable -> the copy, with a warning."""
    live = Library().add("r1", "wiki", WIKI, read_settings=no_browser())
    assert header(live.read(resource_id="wiki", query="union based", force_refresh=True), "source") == "live"

    lib = Library().add("r1", "wiki", WIKI, mode="stored", read_settings=no_browser())
    lib.entry("r1", PAGES["SQL injection: Union based"], "old stored text")
    fresh = lib.read(resource_id="wiki", query="union based", force_refresh=True)
    assert header(fresh, "source") == "live" and "stored copy from 2026-11-10 was not used" in header(fresh, "note")
    assert "old stored text" not in fresh
    assert lib.store.entries[0]["stored_text"] == "old stored text"

    url = "https://down.tc-fixture.test/notes"
    down = Library().add("r2", "down", "https://down.tc-fixture.test/", mode="stored",
                         sitemap={"nav": [{"title": "Notes", "path": url}]}, read_settings=no_browser())
    down.entry("r2", url, "the copy")
    answer = down.read(resource_id="down", query="notes", force_refresh=True)
    assert "the copy" in answer and "could not be reached" in header(answer, "note")
    assert header(answer, "source") == "stored copy from 2026-11-10"


def test_blocked_refused():
    """R-169: a blocked page is refused before any request, stored copy or not."""
    lib = Library().add("r1", "wiki", WIKI, mode="stored")
    lib.entry("r1", PAGES["SQL injection: Union based"], "should never be shown")
    lib.store.curations.append({"resource_id": "r1", "url": PAGES["SQL injection: Union based"], "blocked": True})
    answer = lib.read(resource_id="wiki", query="union based")
    assert answer.startswith("Error: refusing to read") and "blocked" in answer
    assert "should never be shown" not in answer and lib.requested() == []


def test_login_outside_map_refused():
    """R-117: a resource with a login reads only the pages of its map, refused before any request."""
    creds = {"cookie": FAKE_COOKIE, "headers": [], "basic_auth": None}
    lib = Library().add("r1", "kb", WIKI, has_login=True, credentials=creds, read_settings=no_browser())
    lib.entry("r1", PAGES["SQL injection: Union based"])  # the only page of its map
    outside = lib.read(resource_id="kb", section_path=WIKI + "admin/secret")
    assert outside.startswith("Error: refusing to read") and "site login" in outside
    assert lib.requested() == []
    inside = lib.read(resource_id="kb", query="union based")
    assert header(inside, "source") == "live" and lib.requested() == [PAGES["SQL injection: Union based"]]


def test_deleted_resource():
    """R-207: the tool checks the resource still exists at each call; a deleted one reads nothing."""
    lib = Library().add("r1", "wiki", WIKI)
    lib.store.resources.pop("r1")
    assert lib.read(resource_id="wiki", query="union") == reader.DELETED.format(slug="wiki")
    assert lib.requested() == []


def test_another_owners_resource_is_never_read():
    lib = Library().add("r1", "wiki", WIKI, mode="stored")
    lib.entry("r1", PAGES["SQL injection: Union based"], "owner text")
    lib.store.resources["r1"]["user_id"] = "someone-else"
    assert lib.read(resource_id="wiki", query="union based") == reader.DELETED.format(slug="wiki")


def test_legacy_title_match():
    """R-217: an unconverted resource is read with today's title match on its 1.x map."""
    lib = Library().add("r1", "wiki", WIKI, map_version=1, read_settings=no_browser())
    answer = lib.read(resource_id="wiki", query="kerberoast attack")
    assert header(answer, "url") == PAGES["Kerberos: Kerberoasting"]
    assert header(answer, "section_title") == "Kerberos: Kerberoasting" and header(answer, "source") == "live"
    nothing = lib.read(resource_id="wiki", query="zzzz")
    assert header(nothing, "section_title") == "(homepage)" and header(nothing, "url") == WIKI


def test_section_path_and_github_paths():
    lib = Library().add("r1", "payloads", "https://github.com/tc-fixture/payloads", type_="github-repo",
                        sitemap={"tree": [{"title": "sqli > union", "path": "sqli/union.md"}],
                                 "owner": "tc-fixture", "repo": "payloads", "branch": "main"},
                        read_settings=no_browser())
    answer = lib.read(resource_id="payloads", section_path="sqli/union.md")
    assert header(answer, "url") == "https://raw.githubusercontent.com/tc-fixture/payloads/main/sqli/union.md"
    assert lib.requested() == ["https://raw.githubusercontent.com/tc-fixture/payloads/main/sqli/union.md"]


def test_cve_live_pdf_stored():
    """R-307: a CVE archive is read live, one CVE at a time; a PDF page comes from the store."""
    lib = Library().add("r1", "cves", "https://github.com/tc-fixture/cve", type_="cve-poc-db",
                        sitemap={"owner": "tc-fixture", "repo": "cve", "branch": "main"})
    answer = lib.read(resource_id="cves", cve_id="cve-2022-0001")
    assert "Synthetic entry CVE-2022-0001." in answer and header(answer, "source") == "live"
    assert header(answer, "url") == "https://raw.githubusercontent.com/tc-fixture/cve/main/2022/CVE-2022-0001.json"
    assert "you must pass cve_id" in lib.read(resource_id="cves", query="x")
    missing = lib.read(resource_id="cves", cve_id="CVE-2022-9999")
    assert missing.startswith("PoC not found for CVE-2022-9999")

    pdf_url = "https://files.tc-fixture.test/guide.pdf"
    pdf = Library().add("r2", "guide", pdf_url, type_="pdf", mode="stored",
                        sitemap={"pages": [{"page": n, "firstLine": f"Chapter {n}"} for n in (1, 2, 3)]})
    for n in (1, 2, 3):
        pdf.entry("r2", f"{pdf_url}#page={n}", f"stored text of page {n}")
    answer = pdf.read(resource_id="guide", section_path="page=2")
    assert "stored text of page 2" in answer and pdf.requested() == []
    assert header(answer, "url") == f"{pdf_url}#page=2"
    assert "is not in this resource's map" in pdf.read(resource_id="guide", section_path="9")


def test_unstored_pdf_page_is_read_from_the_document():
    pdf_url = "https://files.tc-fixture.test/guide.pdf"
    lib = Library().add("r2", "guide", pdf_url, type_="pdf", map_version=1,
                        sitemap={"pages": [{"page": n, "firstLine": f"Chapter {n}"} for n in (1, 2, 3)]})
    answer = lib.read(resource_id="guide", section_path="3")
    assert header(answer, "source") == "live" and lib.requested() == [pdf_url]


def test_unknown_resource_lists_the_catalog():
    lib = Library().add("r1", "wiki", WIKI)
    assert lib.read(resource_id="nope", query="x") == "Error: resource 'nope' not configured. Available: wiki."
    assert lib.requested() == []


def test_a_path_outside_the_web_is_refused():
    lib = Library().add("r1", "wiki", WIKI, read_settings=no_browser())
    path = "http://169.254.169.254/latest/meta-data/"
    answer = lib.read(resource_id="wiki", section_path=path)
    assert answer.startswith(f"Error: refusing to read {path}: unsafe_address")
    assert lib.requested() == []


def test_a_non_web_path_stays_on_the_resources_site():
    """As 1.x resolves it: anything that is not an http(s) URL is a path of the resource."""
    lib = Library().add("r1", "wiki", WIKI, read_settings=no_browser())
    lib.read(resource_id="wiki", section_path="file:///etc/passwd")
    assert [u.split("/")[2] for u in lib.requested()] == ["wiki.tc-fixture.test"]


def test_pdf_pages_are_the_maps_own_numbers():
    """Finding D: a PDF ingested from page 5 with page 7 skipped: its stored pages are read by
    their real numbers, and an excluded page is refused, never fetched live."""
    pdf_url = "https://files.tc-fixture.test/guide.pdf"
    numbers = [n for n in range(5, 15) if n != 7]
    lib = Library().add("r2", "guide", pdf_url, type_="pdf", mode="stored",
                        sitemap={"pages": [{"page": n, "firstLine": f"Chapter {n}"} for n in numbers]})
    for n in numbers:
        lib.entry("r2", f"{pdf_url}#page={n}", f"stored text of page {n}")
    answer = lib.read(resource_id="guide", section_path="page=12")
    assert "stored text of page 12" in answer and header(answer, "url") == f"{pdf_url}#page=12"
    for excluded in ("page=3", "7", "page=15"):
        refused = lib.read(resource_id="guide", section_path=excluded)
        assert "is not in this resource's map (pages 5..14)" in refused, excluded
    assert lib.requested() == []
