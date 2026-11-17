"""Incremental refresh (T6.2, §4.5, R-083, R-342, AC-18): a refresh of a Stored resource downloads
only what changed. The site answers 304 to a conditional request, or the text's fingerprint
shows no change; an unchanged page is copied forward with its sections, and the stages that
rebuild from text skip it.

The sites are the fixture sites; ``ValidatingSite`` adds the validators a real server sends
(an ETag and a Last-Modified on every 200) and answers 304 when they come back unchanged.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft.net import Response  # noqa: E402
from tradecraft.ingest import storage  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_job_harness import RID, JobHarness  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402

WIKI = "https://wiki.tc-fixture.test/"
UNION = WIKI + "sqli/union-based/"
LAST_MODIFIED = "Mon, 02 Nov 2026 10:00:00 GMT"


class ValidatingSite(FixtureFetcher):
    def __init__(self, root):
        super().__init__(root)
        self.full: list[str] = []
        self.not_modified: list[str] = []
        self.conditional: list[str] = []

    def reset(self):
        self.requests.clear()
        self.full.clear()
        self.not_modified.clear()
        self.conditional.clear()

    async def get(self, url, *, headers=None, **kw):
        resp = await super().get(url, headers=headers, **kw)
        if resp.status != 200:
            return resp
        etag = '"' + hashlib.sha256(resp.body).hexdigest()[:16] + '"'
        sent = {k.lower(): v for k, v in (headers or {}).items()}
        if "if-none-match" in sent or "if-modified-since" in sent:
            self.conditional.append(resp.final_url)
        if sent.get("if-none-match") == etag:
            self.not_modified.append(resp.final_url)
            return Response(url=resp.url, final_url=resp.final_url, status=304, headers={"etag": etag}, body=b"",
                            content_type="", redirects=resp.redirects)
        self.full.append(resp.final_url)
        resp.headers.update({"etag": etag, "last-modified": LAST_MODIFIED})
        return resp


# The fixture wiki's pages are short: the browser would read them (fetching.browserBelowChars), and
# a rendered copy keeps no validator (its scripts may change what the HTML's ETag does not cover).
PLAIN = {"fetching.browserEnabled": False}


def _stored_site(tmp_path, *, settings=None, fetcher_cls=ValidatingSite):
    root = padded_sites(tmp_path)
    h = JobHarness(tmp_path, WIKI, mode="stored", fetcher=fetcher_cls(root), settings={**PLAIN, **(settings or {})})
    assert h.run().status == "succeeded"
    return h, root


def _pages(h):
    return {e["url"] for e in h.live() if e["stored_text"]}


def _sections_of(h, url):
    entry = h.live_by_url()[url]
    return [(s["ord"], s["heading"], s["text"]) for s in h.store.sections if s["entry_id"] == entry["id"]]


def _copied(h):
    calls = [args for name, args in h.store.calls if name == "copy_forward"]
    return [pid for args in calls for pid in args[4]]


def test_unchanged_site(tmp_path):
    h, _root = _stored_site(tmp_path)
    first = {e["url"]: e for e in h.live()}
    pages = _pages(h)
    assert len(pages) > 10
    h.fetcher.reset()
    prompts_before = len(h.model.prompts)
    assert h.refresh().status == "succeeded"
    # AC-18: every stored page answered 304; the only whole downloads are the start page (read
    # before the map, to detect the site) and the sitemap.
    assert set(h.fetcher.not_modified) == pages
    assert sorted(h.fetcher.full) == [WIKI, WIKI + "sitemap.xml"]
    second = h.live()
    assert {e["url"] for e in second if e["stored_text"]} == pages and h.row["generation"] == 2
    for e in second:
        if e["url"] in pages:
            old = first[e["url"]]
            assert e["generation"] == 2 and e["stored_text"] == old["stored_text"]
            assert e["text_hash"] == old["text_hash"] and e["fetched_at"] == old["fetched_at"]
            assert _sections_of(h, e["url"]) and _sections_of(h, e["url"]) == [
                (s["ord"], s["heading"], s["text"]) for s in h.store.sections if s["entry_id"] == old["id"]]
    assert sorted(_copied(h)) == sorted(first[u]["page_id"] for u in pages)
    report = h.row["ingestion_report"]
    assert report["stored"]["pages"] == len(pages)
    assert report["stored"]["bytes"] == sum(first[u]["stored_bytes"] for u in pages)
    # An unchanged page the model tagged last time costs no call: only those left without a topic
    # are asked again (as every refresh asks for them).
    tagging = [p for p in h.model.prompts[prompts_before:] if isinstance(p, str) and "You tag the pages" in p]
    asked = {line.split(". ", 1)[1].split(" — ")[0] for p in tagging for line in p.splitlines()
             if re.match(r"^\d+\. ", line)}
    untagged = {e["title"] for e in first.values() if e["status"] == "kept" and not e["topics"]}
    assert asked <= untagged and not asked & {e["title"] for e in first.values() if e["topics"]}


def test_changed_page_rebuilt(tmp_path):
    h, root = _stored_site(tmp_path)
    old_union = h.live_by_url()[UNION]
    page = root / "wiki.tc-fixture.test" / "sqli" / "union-based" / "index.html"
    page.write_text(page.read_text().replace("</article>", "<h2>New section</h2><p>" + "fresh text " * 30
                                             + "</p></article>", 1))
    h.fetcher.reset()
    h.refresh()
    assert UNION in h.fetcher.full and UNION not in h.fetcher.not_modified
    new_union = h.live_by_url()[UNION]
    assert "fresh text" in new_union["stored_text"] and new_union["text_hash"] != old_union["text_hash"]
    assert any(heading == "New section" for _o, heading, _t in _sections_of(h, UNION))
    assert new_union["page_id"] not in _copied(h)
    assert len(_copied(h)) == len(_pages(h)) - 1


def test_fingerprint_fallback(tmp_path):
    # A site that sends no validators: every page is downloaded, and the ones whose text did not
    # change are still carried (no text kept twice, no sections rebuilt).
    h, root = _stored_site(tmp_path, fetcher_cls=FixtureFetcher)
    first = {e["url"]: e for e in h.live()}
    page = root / "wiki.tc-fixture.test" / "sqli" / "union-based" / "index.html"
    page.write_text(page.read_text().replace("</article>", "<p>" + "changed words " * 30 + "</p></article>", 1))
    h.fetcher.requests.clear()
    h.refresh()
    requested = {u for u, hd in h.fetcher.requests}
    assert _pages(h) <= requested
    assert not any("if-none-match" in hd or "if-modified-since" in hd for _u, hd in h.fetcher.requests)
    copied = set(_copied(h))
    assert first[UNION]["page_id"] not in copied
    assert copied == {first[u]["page_id"] for u in _pages(h) if u != UNION}
    for url in _pages(h) - {UNION}:
        assert h.live_by_url()[url]["fetched_at"] == first[url]["fetched_at"]


def test_off_downloads_all(tmp_path):
    h, _root = _stored_site(tmp_path, settings={"storage.incremental": False})
    pages = _pages(h)
    h.fetcher.reset()
    h.refresh()
    assert h.fetcher.conditional == [] and h.fetcher.not_modified == []
    assert pages <= set(h.fetcher.full)
    assert _copied(h) == [] and "refresh_basis" not in h.store.names()


def test_a_live_resource_is_never_compared(tmp_path):
    root = padded_sites(tmp_path)
    h = JobHarness(tmp_path, WIKI, fetcher=ValidatingSite(root), settings=PLAIN)
    h.run()
    h.refresh()
    assert "refresh_basis" not in h.store.names() and h.fetcher.conditional == []


def test_new_validators_replace_the_copys(tmp_path):
    h, root = _stored_site(tmp_path)
    old = h.live_by_url()[UNION]
    assert old["etag"] and old["last_modified"] == LAST_MODIFIED

    class NewDate(ValidatingSite):
        async def get(self, url, *, headers=None, **kw):
            # The same text, a server that lost its ETags: the fingerprint decides, the new date stays.
            resp = await FixtureFetcher.get(self, url, headers=headers, **kw)
            if resp.status == 200:
                resp.headers["last-modified"] = "Tue, 03 Nov 2026 10:00:00 GMT"
            return resp

    h.fetcher = NewDate(root)
    h.refresh()
    new = h.live_by_url()[UNION]
    assert new["page_id"] in _copied(h)
    assert new["last_modified"] == "Tue, 03 Nov 2026 10:00:00 GMT" and new["etag"] == old["etag"]


def test_new_settings_are_not_trusted_to_a_304(tmp_path):
    """A 304 says the page did not change, not that a new body selector stores the same text: with
    other ingestion settings than the copy's, every page is downloaded and judged by its text."""
    h, _root = _stored_site(tmp_path)
    first = h.live_by_url()
    h.fetcher.reset()
    h.settings["content.removeSelectors"] = ["h2"]
    h.settings_hash = "fedcba9876543210"
    h.refresh()
    assert h.fetcher.conditional == [] and h.fetcher.not_modified == []
    second = h.live_by_url()
    with_h2 = [u for u, e in first.items() if e["stored_text"] and "\n## " in e["stored_text"]]
    assert with_h2
    for url in with_h2:
        assert "\n## " not in second[url]["stored_text"] and second[url]["page_id"] not in _copied(h)
    # The pages the new settings store alike are still carried, by their fingerprint.
    same = [u for u, e in first.items() if e["stored_text"] and u not in with_h2]
    assert all(first[u]["page_id"] in _copied(h) for u in same)
    # Back on the same settings, the next refresh asks with the validators again.
    h.fetcher.reset()
    h.refresh()
    assert h.fetcher.conditional and h.fetcher.not_modified


def test_conditional_headers():
    assert storage.conditional_headers({"etag": '"abc"', "last_modified": LAST_MODIFIED}) == {
        "If-None-Match": '"abc"', "If-Modified-Since": LAST_MODIFIED}
    assert storage.conditional_headers({"etag": "", "last_modified": None}) == {}
    # A validator a site wrote with a line break never becomes a header line.
    assert storage.conditional_headers({"etag": 'x"\r\nX-Evil: 1', "last_modified": "a\nb"}) == {}


def test_a_page_dropped_since_is_not_carried(tmp_path):
    h, _root = _stored_site(tmp_path)
    union_id = h.live_by_url()[UNION]["page_id"]
    h.fetcher.reset()
    focus = {"mode": "focused", "topics": ["xss"], "strictness": "strict"}
    h.resource_spec = {"focus": focus}
    h.refresh()
    union = h.live_by_url()[UNION]
    assert union["status"] == "dropped" and not union["stored_text"]
    assert union_id not in _copied(h)
    assert h.store.resources[RID]["generation"] == 2



class TaggingModel:
    """Tags every page the model pass asks about as SQL injection; a summary otherwise."""

    def __init__(self):
        self.prompts: list = []

    async def ainvoke(self, prompt, config=None, **kwargs):
        import json

        from langchain_core.messages import AIMessage
        self.prompts.append(prompt)
        if isinstance(prompt, str) and "You tag the pages" in prompt:
            n = max(int(m) for m in re.findall(r"\n(\d+)\. ", prompt))
            return AIMessage(content=json.dumps({"entries": [{"n": i, "topics": ["sql_injection"], "kinds": []}
                                                             for i in range(1, n + 1)]}))
        return AIMessage(content="A synthetic library.")


def test_an_untagged_unchanged_page_is_tagged_again(tmp_path):
    """S10 review 1, finding 3: a refresh whose model tagging failed leaves pages without a topic;
    copied forward, they go to the model pass again (R-008: every page is tagged)."""
    h, _root = _stored_site(tmp_path)
    untagged = {e["url"] for e in h.live() if e["status"] == "kept" and not e["topics"]}
    assert untagged
    h.model = TaggingModel()
    h.fetcher.reset()
    h.refresh()
    assert set(h.fetcher.not_modified) >= untagged  # unchanged: copied forward
    live = h.live_by_url()
    assert all("sql_injection" in live[u]["topics"] for u in untagged)
