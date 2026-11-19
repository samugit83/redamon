"""A CVE archive's index (the owner's decision Q-C of 2026-11-18, option A of NQ-6): at ingestion
the archive's CVE files become text-less entries, a CVE id each, so that search's exact-entity
wording and Library now find a CVE the archive holds; a page read of one goes to the CVE reader.

- the index lists the year folders through the git trees API (the contents API stops at 1,000
  entries), one call per folder, with the job's GitHub token; a CVE counts once, at the first of
  the archive's path patterns that names its file, and only where the reader reads it;
- over the cap (the map ceiling every type shares) the largest files are kept, and the report says so;
- a folder it could not list is counted, a rate limit stops the listing, and a refresh that could
  not list the whole archive keeps the previous index (a first ingestion takes what it listed);
- no page text is downloaded or stored, and no model is asked about the CVE ids;
- search reads the index with the exact-entity wording only; a page read of an entry answers as
  ``cve_id`` does, and a read of a CVE marks its entry read.

The sites are the fixture tree (``FixtureFetcher``; ``tc-fixture/cve`` is laid out as
``{year}/{cve}.json``), the store ``MemoryStore``. On Postgres: ``test_tradecraft_cve_index_integration.py``.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_tradecraft_ingest_pipeline import RID, Harness as _Harness  # noqa: E402
from test_tradecraft_read_sections import read  # noqa: E402
from test_tradecraft_reader import OWNER, Library, header  # noqa: E402
from tradecraft import agent_tools, net  # noqa: E402
from tradecraft.ingest import builders, entities, pipeline  # noqa: E402
from tradecraft.ingest.builders import Candidate  # noqa: E402
from tradecraft.library import reader, search  # noqa: E402
from tradecraft.library.types import BrowseLevel  # noqa: E402
from tradecraft.settings import EffectiveSettings, constant  # noqa: E402
from tradecraft_doubles import FIXTURES, FixtureFetcher, run  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402

URL = "https://github.com/tc-fixture/cve"
API = "https://api.github.com/repos/tc-fixture/cve"
RAW = "https://raw.githubusercontent.com/tc-fixture/cve/main"
JSON = {"type.cve.pathPatterns": ["{year}/{cve}.json"]}
TOKEN = "ghp_fake_token_for_tests"
# The fixture archive: 4 files in 2021, 4 in 2022, 1,050 in 2023.
FILES = 4 + 4 + 1050


def year_sha(year) -> str:
    return f"{5000 + int(year):040x}"


def archive(tmp_path, files=None, statuses=None) -> Path:
    """A copy of the fixture sites with ``files`` written over it (a dict becomes JSON) and
    ``statuses`` ({path: status}) answered by the API host."""
    root = tmp_path / "sites"
    shutil.copytree(FIXTURES, root)
    for path, content in (files or {}).items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    if statuses:
        (root / "api.github.com" / "_status.json").write_text(json.dumps(statuses))
    return root


def tree_file(year) -> str:
    return f"api.github.com/repos/tc-fixture/cve/git/trees/{year_sha(year)}/index.json"


def tree(*items, truncated=False) -> dict:
    """A git tree answer: (path, size) blobs."""
    return {"sha": "x", "truncated": truncated,
            "tree": [{"path": p, "type": "blob", "mode": "100644", "size": s, "sha": f"{i:040x}"}
                     for i, (p, s) in enumerate(items)]}


def build(root=None, *, settings=None, forced=True, should_stop=None, token=TOKEN):
    fetcher = FixtureFetcher(root or FIXTURES)
    with net.use_fetcher(fetcher):
        result = run(builders.build_known("cve-poc-db", URL, EffectiveSettings(JSON if settings is None else settings),
                                          github_token=token,
                                          forced=forced, should_stop=should_stop))
    return result, fetcher


def urls(fetcher):
    return [u for u, _h in fetcher.requests]


# --------------------------------------------------------------------------------------
# The index
# --------------------------------------------------------------------------------------

def test_the_patterns_the_index_lists():
    pats = builders.index_patterns(["{year}/{cve}.md", "{year}/{cve_lower}/README.md", "exploits/{year}/{cve}.yaml",
                                    "{cve}.md", "{year}/../{cve}.md", "{year}/no-placeholder.md", "{year}/{cve}.json"])
    assert [(p.rank, p.head, p.deep) for p in pats] == [(0, "", False), (1, "", True), (2, "exploits", False),
                                                       (6, "", False)]
    assert pats[0].regex.fullmatch("2021/CVE-2021-41773.md").group(1) == "CVE-2021-41773"
    assert pats[1].regex.fullmatch("2021/cve-2021-41773/README.md").group(1) == "cve-2021-41773"
    assert pats[0].regex.fullmatch("2021/CVE-2021-41773.md.bak") is None
    assert builders.cve_index_cap() == 20000


def test_the_archives_files_become_text_less_entries():
    """Every file at the archive's pattern, the 2023 folder whole (its contents listing stops at
    1,000), one listing per year folder with the token, and no file downloaded."""
    result, fetcher = build(token=TOKEN)
    assert not result.error and not result.index_incomplete and not result.truncated
    assert len(result.entries) == FILES == len({e.url for e in result.entries})
    e = next(x for x in result.entries if x.title == "CVE-2023-1050")
    assert (e.url, e.source, e.path, e.extra) == (f"{RAW}/2023/CVE-2023-1050.json", "tree", "2023/CVE-2023-1050.json",
                                                   {"cve": "CVE-2023-1050"})
    assert result.meta == {"owner": "tc-fixture", "repo": "cve", "branch": "main"}
    assert result.report_stop == f"cve index: {FILES} of {FILES} files"
    assert urls(fetcher) == [API, f"{API}/contents"] + [f"{API}/git/trees/{year_sha(y)}" for y in (2023, 2022, 2021)]
    assert all(h.get("authorization") == f"token {TOKEN}" for _u, h in fetcher.requests)
    assert not [u for u in urls(fetcher) if u.startswith("https://raw.")]


def test_a_file_at_no_pattern_gets_no_entry():
    """The default patterns name .md files; the fixture archive holds .json ones: the reader still
    finds them through its listing, but no pattern names them, so the index holds none."""
    result, _ = build(settings={})
    assert result.entries == [] and not result.index_incomplete and not result.error
    assert result.report_stop == "cve index: 0 of 0 files"


def test_the_first_pattern_wins_and_a_file_counts_where_the_reader_reads_it(tmp_path):
    root = archive(tmp_path, {tree_file(2021): tree(
        ("CVE-2021-0001.md", 10), ("CVE-2021-0001.json", 900),  # both: the first pattern's file
        ("CVE-2020-0009.md", 10),  # a 2020 id in the 2021 folder: the reader looks in 2020
        ("cve-2021-0002.md", 10),  # {cve} is upper case
        ("CVE-2021-0003.json", 10), ("notes.md", 10), ("CVE-2021-0004.md.orig", 10))})
    result, _ = build(root, settings={"type.cve.pathPatterns": ["{year}/{cve}.md", "{year}/{cve}.json"]})
    got = {e.title: e.path for e in result.entries if e.path.startswith("2021/")}
    assert got == {"CVE-2021-0001": "2021/CVE-2021-0001.md", "CVE-2021-0003": "2021/CVE-2021-0003.json"}


def test_over_the_cap_the_largest_files_are_kept(tmp_path, monkeypatch):
    root = archive(tmp_path, {tree_file(2021): tree(("CVE-2021-0001.json", 50), ("CVE-2021-0002.json", 9000),
                                                    ("CVE-2021-0003.json", 300), ("CVE-2021-0004.json", 300)),
                              tree_file(2022): tree(("CVE-2022-0001.json", 7000)),
                              tree_file(2023): tree(("CVE-2023-0001.json", 1))})
    monkeypatch.setattr(builders, "cve_index_cap", lambda: 3)
    result, _ = build(root)
    # The ties go to the later id; the entries keep the archive's order.
    assert [e.title for e in result.entries] == ["CVE-2021-0002", "CVE-2021-0004", "CVE-2022-0001"]
    assert result.truncated and result.report_stop == "cve index: largest 3 of 6 files"
    assert not result.index_incomplete


def test_a_folder_not_listed_is_counted_and_a_rate_limit_stops_the_listing(tmp_path):
    root = archive(tmp_path, statuses={f"/repos/tc-fixture/cve/git/trees/{year_sha(2023)}": 403})
    result, fetcher = build(root)
    # 2023 is listed first and refused: 2022 and 2021 are never asked for.
    assert [u for u in urls(fetcher) if "/git/trees/" in u] == [f"{API}/git/trees/{year_sha(2023)}"]
    assert result.entries == [] and result.index_incomplete
    assert result.counted == {"cve_index_folder_unread": 3}
    assert result.report_stop == "cve index: 0 of 0 files, 3 folders unread"
    other = archive(tmp_path / "b", statuses={f"/repos/tc-fixture/cve/git/trees/{year_sha(2022)}": 500})
    result, _ = build(other)
    assert len(result.entries) == FILES - 4 and result.index_incomplete
    assert result.counted == {"cve_index_folder_unread": 1}


def test_a_listing_over_the_size_bound_or_cut_by_github(tmp_path, monkeypatch):
    """Both are the same at every refresh: counted, what was listed is indexed, and the index is
    complete as far as it can ever be (a refresh is not failed for it, so it is never stuck)."""
    root = archive(tmp_path, {tree_file(2021): tree(("CVE-2021-0001.json", 5), truncated=True)})
    result, _ = build(root)
    assert "CVE-2021-0001" in {e.title for e in result.entries} and not result.index_incomplete
    assert result.counted == {"cve_index_listing_cut": 1}
    monkeypatch.setattr(builders, "CVE_LISTING_MAX_BYTES", 4096)
    result, _ = build()
    # The 2023 tree (1,050 files) is over the bound; the small years are read.
    assert {e.title[:8] for e in result.entries} == {"CVE-2021", "CVE-2022"} and not result.index_incomplete
    assert result.counted == {"cve_index_listing_cut": 1}
    assert result.report_stop == "cve index: 8 of 8 files, 1 folders unread"


def test_an_answer_that_is_not_a_tree_is_a_folder_missed_this_time(tmp_path):
    root = archive(tmp_path, {tree_file(2022): "<html>an error page</html>", tree_file(2021): {"message": "x"}})
    result, _ = build(root)
    assert {e.title[:8] for e in result.entries} == {"CVE-2023"} and result.index_incomplete
    assert result.counted == {"cve_index_folder_unread": 2}
    assert result.report_stop == "cve index: 1050 of 1050 files, 2 folders unread"


def test_the_time_budget_stops_the_listing_and_what_was_listed_goes_live():
    """A listing slower than the budget would be as slow at the next refresh: it is counted, and the
    refresh is not failed for it (an archive whose listing never fits the budget is never stuck)."""
    calls = []

    async def spent_after_one():
        calls.append(1)
        return "time_budget" if len(calls) > 1 else ""

    result, fetcher = build(should_stop=spent_after_one)
    assert [u for u in urls(fetcher) if "/git/trees/" in u] == [f"{API}/git/trees/{year_sha(2023)}"]
    assert len(result.entries) == 1050 and not result.index_incomplete
    assert result.counted == {"cve_index_time_budget": 2}
    assert result.report_stop == "cve index: 1050 of 1050 files, 2 folders unread"


def test_a_cancel_during_the_listing_ends_the_job_with_no_further_call(tmp_path):
    h = Harness(tmp_path, URL, settings=JSON, cancel_after="build_map")
    outcome = h.run()
    assert outcome.status == "cancelled" and h.store.live_entries(RID) == []
    assert not [u for u, _h in h.fetcher.requests if "/git/trees/" in u]


def test_a_branch_and_a_folder_before_the_year(tmp_path):
    exploits = [{"name": "2021", "path": "exploits/2021", "type": "dir", "size": 0, "sha": year_sha(1999)}]
    root = archive(tmp_path, {
        "api.github.com/repos/tc-fixture/cve/contents/exploits/index.json": exploits,
        f"api.github.com/repos/tc-fixture/cve/git/trees/{year_sha(1999)}/index.json":
            tree(("CVE-2021-0042/poc.py", 70), ("CVE-2021-0043/README.md", 70)),
    })
    result, fetcher = build(root, settings={"type.cve.branch": "dev",
                                            "type.cve.pathPatterns": ["exploits/{year}/{cve}/poc.py"]})
    assert [(e.title, e.url) for e in result.entries] == [
        ("CVE-2021-0042", "https://raw.githubusercontent.com/tc-fixture/cve/dev/exploits/2021/CVE-2021-0042/poc.py")]
    assert f"{API}/contents?ref=dev" in urls(fetcher) and f"{API}/contents/exploits?ref=dev" in urls(fetcher)
    # A file below a CVE folder: the year folder is listed recursively.
    assert f"{API}/git/trees/{year_sha(1999)}?recursive=1" in urls(fetcher)


def test_without_a_github_token_there_is_no_index_and_no_call_for_one():
    """The owner's decision of 2026-11-18 (option A): without a token GitHub allows 60 API calls an hour,
    and a full archive's index takes about 30, so none is built. The archive is read by CVE id as
    it always was, with the calls it always made, and the report says what to add."""
    result, fetcher = build(token=None)
    assert urls(fetcher) == [API, f"{API}/contents"] and result.entries == []
    assert result.report_stop == builders.NEEDS_TOKEN_STOP == "cve index: add a GitHub token to index this archive"
    assert result.counted == {"cve_index_needs_token": 1} and not result.index_incomplete and not result.error
    assert all("authorization" not in h for _u, h in fetcher.requests)
    with_token, fetcher = build()
    assert len(with_token.entries) == FILES and "cve_index_needs_token" not in with_token.counted


def test_the_branch_is_encoded_like_the_path(tmp_path):
    from tradecraft.library import cve

    assert cve.raw_url("o", "r", "feat/x#y z", "2021/CVE-2021-0001.md") == \
        "https://raw.githubusercontent.com/o/r/feat/x%23y%20z/2021/CVE-2021-0001.md"
    root = archive(tmp_path, {tree_file(2021): tree(("CVE-2021-0001.json", 5), ("CVE-2021-0002.json", 5))})
    result, _ = build(root, settings={**JSON, "type.cve.branch": "rel#1"})
    urls_2021 = [e.url for e in result.entries if e.path.startswith("2021/")]
    assert urls_2021 == [f"https://raw.githubusercontent.com/tc-fixture/cve/rel%231/2021/CVE-2021-000{n}.json"
                         for n in (1, 2)]


def test_only_ascii_digits_make_a_cve_id(tmp_path):
    from tradecraft.library import cve

    arabic = "CVE-2021-\u0664\u0661\u0667\u0667\u0663"
    root = archive(tmp_path, {tree_file(2021): tree((f"{arabic}.json", 900), ("CVE-2021-0001.json", 5))})
    result, _ = build(root)
    assert [e.title for e in result.entries if e.path.startswith("2021/")] == ["CVE-2021-0001"]
    assert cve.CVE_ID_RE.match(arabic) is None and cve.pattern_path("{year}/{cve}.md", arabic) is None


def test_a_folder_a_pattern_names_that_the_repository_lacks_holds_nothing():
    """A 404 for the folder before ``{year}`` is GitHub's word that it is not there: counted, never a
    miss, so the archive's other patterns index as before and no refresh fails for it."""
    result, fetcher = build(settings={"type.cve.pathPatterns": ["exploits/{year}/{cve}.md", "{year}/{cve}.json"]})
    assert f"{API}/contents/exploits" in urls(fetcher) and len(result.entries) == FILES
    assert result.counted == {"cve_index_folder_missing": 1} and not result.index_incomplete
    assert result.report_stop == f"cve index: {FILES} of {FILES} files"


class Bounds(FixtureFetcher):
    """The fixture fetcher, recording the size bound each request asked for."""

    def __init__(self, root):
        super().__init__(root)
        self.bounds = {}

    async def get(self, url, **kwargs):
        self.bounds[url] = kwargs.get("max_bytes")
        return await super().get(url, **kwargs)


def _bounded_build(root, settings):
    fetcher = Bounds(root)
    with net.use_fetcher(fetcher):
        result = run(builders.build_known("cve-poc-db", URL, EffectiveSettings(settings), github_token=TOKEN,
                                          forced=True))
    return result, fetcher


def test_every_listing_of_the_index_reads_up_to_one_bound(tmp_path):
    """The root listing, a folder before ``{year}`` and each year's tree: one bound, one constant."""
    exploits = [{"name": "2021", "path": "exploits/2021", "type": "dir", "size": 0, "sha": year_sha(1999)}]
    root = archive(tmp_path, {"api.github.com/repos/tc-fixture/cve/contents/exploits/index.json": exploits,
                              f"api.github.com/repos/tc-fixture/cve/git/trees/{year_sha(1999)}/index.json":
                                  tree(("CVE-2021-0042.md", 70))})
    result, fetcher = _bounded_build(root, {"type.cve.pathPatterns": ["exploits/{year}/{cve}.md", "{year}/{cve}.json"]})
    listings = [u for u in fetcher.bounds if "/contents" in u or "/git/trees/" in u]
    assert f"{API}/contents" in listings and f"{API}/contents/exploits" in listings and len(listings) == 6
    bound = builders.CVE_LISTING_MAX_BYTES
    assert {fetcher.bounds[u] for u in listings} == {bound} and bound == int(constant("sitemapMaxBytes"))
    assert len(result.entries) == FILES + 1


def test_a_root_listing_over_the_bound_is_cut_like_a_tree(tmp_path, monkeypatch):
    """Over the bound the answer would be cut at every refresh: counted, never a miss (the archive
    keeps its other patterns' folders, and no refresh fails for it)."""
    monkeypatch.setattr(builders, "CVE_LISTING_MAX_BYTES", 300)
    result, fetcher = _bounded_build(FIXTURES, JSON)
    assert fetcher.bounds[f"{API}/contents"] == 300 and not [u for u in fetcher.bounds if "/git/trees/" in u]
    assert result.counted == {"cve_index_listing_cut": 1} and not result.index_incomplete and not result.retype
    assert result.report_stop == "cve index: 0 of 0 files, 1 folders unread"


def test_a_folder_listing_over_the_bound_is_cut_like_a_tree(tmp_path, monkeypatch):
    exploits = [{"name": f"pad-{n:03d}", "path": f"exploits/pad-{n:03d}", "type": "dir", "size": 0,
                 "sha": f"{n:040x}"} for n in range(40)]
    root = archive(tmp_path, {"api.github.com/repos/tc-fixture/cve/contents/exploits/index.json": exploits})
    monkeypatch.setattr(builders, "CVE_LISTING_MAX_BYTES", 2000)
    result, fetcher = _bounded_build(root, {"type.cve.pathPatterns": ["exploits/{year}/{cve}.md"]})
    assert fetcher.bounds[f"{API}/contents/exploits"] == 2000 and fetcher.bounds[f"{API}/contents"] == 2000
    assert result.counted == {"cve_index_listing_cut": 1} and not result.index_incomplete
    assert result.report_stop == "cve index: 0 of 0 files, 1 folders unread"


@pytest.mark.parametrize("token", [TOKEN, None])
def test_patterns_that_name_no_year_folder_say_why_there_is_no_index(token):
    """A forced archive whose path patterns name no ``{year}`` folder is read by CVE id only, and no
    token changes that: the report says so (a stop reason in the ``cve index:`` family the card
    reads), and no listing is made for it."""
    result, fetcher = build(settings={"type.cve.pathPatterns": ["{cve}.md", "pocs/{cve_lower}.json"]}, token=token)
    assert result.entries == [] and urls(fetcher) == [API, f"{API}/contents"]
    assert result.report_stop == builders.NO_YEAR_STOP == "cve index: none, no path pattern names a year folder"
    assert len(result.report_stop) <= 64 and result.counted == {"cve_index_no_year_pattern": 1}
    assert not result.index_incomplete and not result.error


@pytest.mark.parametrize("settings,token,statuses", [
    ({"type.cve.pathPatterns": ["{cve}.md"]}, TOKEN, None),  # no pattern with a year folder
    (JSON, None, None),  # no GitHub token
    (JSON, TOKEN, None),  # an index
    ({"type.cve.pathPatterns": ["{year}/{cve}.md"]}, TOKEN, None),  # an index of nothing
    (JSON, TOKEN, {"/repos/tc-fixture/cve/contents": 502}),  # no root listing
])
def test_every_exit_of_the_index_writes_a_cve_index_stop_reason(tmp_path, settings, token, statuses):
    """The card reads a report with no ``cve index:`` stop reason as one from before the index (and
    asks for a Refresh): every way ``index_cve`` ends writes one."""
    result, _ = build(archive(tmp_path, statuses=statuses), settings=settings, token=token)
    assert result.report_stop.startswith("cve index: ") and len(result.report_stop) <= 64


def test_a_detected_repository_without_year_folders_is_not_listed():
    fetcher = FixtureFetcher()
    with net.use_fetcher(fetcher):
        result = run(builders.build_known("cve-poc-db", "https://github.com/tc-fixture/payloads",
                                          EffectiveSettings(JSON)))
    assert result.type == "github-repo" and result.retype == "github-repo"
    assert not [u for u in urls(fetcher) if "/git/trees/" in u and "payloads/git/trees/main" not in u]


# --------------------------------------------------------------------------------------
# The pipeline
# --------------------------------------------------------------------------------------

def Harness(*args, secrets=None, **kwargs):  # noqa: N802 - the pipeline tests' harness, with a token
    """The pipeline tests' harness with the job's GitHub token: an archive is indexed only with one."""
    return _Harness(*args, secrets=secrets or {"github_token": TOKEN, "credentials": None}, **kwargs)

def test_the_index_is_written_text_less_and_no_model_is_asked(tmp_path):
    h = Harness(tmp_path, URL, mode="stored", settings=JSON)
    outcome = h.run()
    entries = h.store.live_entries(RID)
    assert outcome.status == "succeeded" and len(entries) == FILES
    e = next(x for x in entries if x["title"] == "CVE-2021-0001")
    assert (e["url"], e["breadcrumb"], e["entities"], e["topics"], e["kinds"], e["stored_text"], e["stored_bytes"]) == (
        f"{RAW}/2021/CVE-2021-0001.json", ["2021"], ["CVE-2021-0001"], [], [], None, 0)
    report = outcome.report
    # The summary is the one model call: no tagging, no focus, no folder description.
    assert report.llmCalls == 1 and report.kept == FILES and report.readiness == {} and report.stored.pages == 0
    assert report.stopReason == f"cve index: {FILES} of {FILES} files"
    assert not [u for u, _h in h.fetcher.requests if "/main/2021/" in u or "/main/2023/" in u]
    # The 1.x map is the archive's metadata, as before.
    assert h.resource["sitemap"] == {"owner": "tc-fixture", "repo": "cve", "branch": "main"}
    # The summary's input is the homepage, not thousands of CVE ids.
    assert "CVE-2021-0001" not in json.dumps(h.model.summary_prompts, default=str)


def test_a_focus_sent_to_an_archive_judges_nothing(tmp_path):
    h = Harness(tmp_path, URL, settings=JSON,
                resource={"focus": {"mode": "focused", "topics": ["sql_injection"], "strictness": "strict"}})
    outcome = h.run()
    assert outcome.status == "succeeded" and len(h.store.live_entries(RID)) == FILES
    assert outcome.report.llmCalls == 1 and outcome.report.skipped.outsideFocus == 0


def _unlistable(tmp_path):
    root = padded_sites(tmp_path)
    (root / "api.github.com" / "_status.json").write_text(
        json.dumps({f"/repos/tc-fixture/cve/git/trees/{year_sha(2022)}": 502}))
    return root


def test_a_refresh_that_cannot_list_the_whole_archive_keeps_the_previous_index(tmp_path):
    h = Harness(tmp_path, URL, settings=JSON, root=_unlistable(tmp_path))
    h.store.resources[RID]["sitemap"] = {"owner": "tc-fixture", "repo": "cve", "branch": "main"}
    outcome = h.run()
    assert outcome.status == "failed" and outcome.error_code == "fetch_failed" and not outcome.swapped
    assert h.resource["generation"] == 2
    # With "replace", the listed part goes live and the error is on the card.
    h = Harness(tmp_path / "b", URL, settings={**JSON, "refreshing.onFailure": "replace"},
                root=_unlistable(tmp_path / "b"))
    h.store.resources[RID]["sitemap"] = {"owner": "tc-fixture", "repo": "cve", "branch": "main"}
    outcome = h.run()
    assert outcome.swapped and len(h.store.live_entries(RID)) == FILES - 4 and h.resource["last_error"] == "fetch_failed"


def test_a_first_ingestion_takes_what_it_listed(tmp_path):
    """No map names the repository yet, so without this job no CVE of it could be read at all."""
    h = Harness(tmp_path, URL, settings=JSON, root=_unlistable(tmp_path))
    outcome = h.run()
    assert outcome.status == "succeeded" and len(h.store.live_entries(RID)) == FILES - 4
    assert {"code": "cve_index_folder_unread", "count": 1} in [e.model_dump() for e in outcome.report.errors]
    assert outcome.report.stopReason == f"cve index: {FILES - 4} of {FILES - 4} files, 1 folders unread"


def test_a_folder_over_the_listing_bound_does_not_stop_a_refresh(tmp_path, monkeypatch):
    monkeypatch.setattr(builders, "CVE_LISTING_MAX_BYTES", 4096)
    h = Harness(tmp_path, URL, settings=JSON)
    h.store.resources[RID]["sitemap"] = {"owner": "tc-fixture", "repo": "cve", "branch": "main"}
    outcome = h.run()
    assert outcome.status == "succeeded" and len(h.store.live_entries(RID)) == 8
    assert {"code": "cve_index_listing_cut", "count": 1} in [e.model_dump() for e in outcome.report.errors]


def test_a_refresh_without_a_token_drops_the_index_and_reads_by_cve_id_as_before(tmp_path):
    """The token was removed since the last refresh: the archive goes back to no index, as an archive
    without a token is (its CVE ids are read by ``cve_id``, and Library now shows no row for it),
    and the report says why. Keeping an index the archive can no longer refresh is not chosen: it
    would go stale while every refresh claimed success."""
    h = _Harness(tmp_path, URL, settings=JSON)
    h.store.resources[RID]["sitemap"] = {"owner": "tc-fixture", "repo": "cve", "branch": "main"}
    url = f"{RAW}/2021/CVE-2021-0001.json"
    h.store.page_ids[(RID, url)] = 1
    h.store.entries.append({"id": 1, "user_id": "u1", "resource_id": RID, "generation": 2, "page_id": 1, "url": url,
                            "title": "CVE-2021-0001", "entities": ["CVE-2021-0001"], "status": "kept",
                            "stored_text": None, "stored_bytes": 0})
    outcome = h.run()
    assert outcome.status == "succeeded" and outcome.swapped and h.store.live_entries(RID) == []
    assert outcome.report.stopReason == builders.NEEDS_TOKEN_STOP
    assert {"code": "cve_index_needs_token", "count": 1} in [e.model_dump() for e in outcome.report.errors]
    assert not [u for u, _h in h.fetcher.requests if "/git/trees/" in u]
    assert h.resource["sitemap"] == {"owner": "tc-fixture", "repo": "cve", "branch": "main"}


def _budget_after_one_folder(monkeypatch):
    """The listing's time budget runs out after its first year folder (2023)."""
    def stop(state, started):
        asked = []

        async def should_stop():
            asked.append(1)
            return "time_budget" if len(asked) > 1 else ""
        return should_stop

    monkeypatch.setattr(pipeline, "_reading_stop", stop)


def _indexed_before(h, **row):
    """The archive as a whole earlier index left it: readable, its report's index kept."""
    h.store.resources[RID].update({"sitemap": {"owner": "tc-fixture", "repo": "cve", "branch": "main"},
                                   "ingestion_report": {"kept": FILES, "errors": []}, "last_error": "",
                                   "last_verified_at": datetime(2026, 11, 17, 9, tzinfo=timezone.utc),
                                   "last_refreshed_at": datetime(2026, 11, 17, 9, tzinfo=timezone.utc), **row})


def test_a_slow_refresh_does_not_replace_a_whole_index_with_a_cut_one(tmp_path, monkeypatch):
    _budget_after_one_folder(monkeypatch)
    h = Harness(tmp_path, URL, settings=JSON)
    _indexed_before(h)
    outcome = h.run()
    assert outcome.status == "failed" and outcome.error_code == "timeout" and not outcome.swapped
    assert h.resource["generation"] == 2 and h.resource["ingestion_report"] == {"kept": FILES, "errors": []}


@pytest.mark.parametrize("before", [
    # the last refresh failed on the budget: it left its code and its time, and no swap
    {"last_error": "timeout", "last_verified_at": datetime(2026, 11, 18, 9, tzinfo=timezone.utc)},
    # the live index is itself a cut one
    {"ingestion_report": {"kept": 1050, "errors": [{"code": "cve_index_time_budget", "count": 2}]}},
    # there is no index to keep
    {"ingestion_report": {"kept": 0, "errors": [{"code": "cve_index_needs_token", "count": 1}]}},
])
def test_a_listing_the_budget_cuts_twice_goes_live(tmp_path, monkeypatch, before):
    """A listing the budget never fits is not a passing slowness: failing it again would keep the
    archive on an old index for ever. So does a first index."""
    _budget_after_one_folder(monkeypatch)
    h = Harness(tmp_path, URL, settings=JSON)
    _indexed_before(h, **before)
    outcome = h.run()
    assert outcome.status == "succeeded" and len(h.store.live_entries(RID)) == 1050
    assert outcome.report.stopReason == "cve index: 1050 of 1050 files, 2 folders unread"
    assert {"code": "cve_index_time_budget", "count": 2} in [e.model_dump() for e in outcome.report.errors]


def test_a_first_ingestion_cut_by_the_budget_takes_what_it_listed(tmp_path, monkeypatch):
    _budget_after_one_folder(monkeypatch)
    outcome = (h := Harness(tmp_path, URL, settings=JSON)).run()
    assert outcome.status == "succeeded" and len(h.store.live_entries(RID)) == 1050


def test_a_missing_pattern_folder_never_fails_a_refresh(tmp_path):
    h = Harness(tmp_path, URL, settings={"type.cve.pathPatterns": ["exploits/{year}/{cve}.md", "{year}/{cve}.json"]})
    _indexed_before(h)
    outcome = h.run()
    assert outcome.status == "succeeded" and len(h.store.live_entries(RID)) == FILES
    assert {"code": "cve_index_folder_missing", "count": 1} in [e.model_dump() for e in outcome.report.errors]


def test_the_entity_is_the_files_cve_id_whatever_the_title():
    url = f"{RAW}/2021/CVE-2021-0001.json"

    class State:
        site_type = "cve-poc-db"
        entries = [Candidate(url, "Apache traversal, renamed CVE-2020-1111", "tree", "2021/CVE-2021-0001.json",
                             {"cve": "CVE-2021-0001"})]
        cards = [{"url": url, "title": "Apache traversal, renamed CVE-2020-1111", "breadcrumb": ["2021"],
                  "entities": ["CVE-1999-0001"]}]

    asyncio.run(entities.extract(State))
    assert State.cards[0]["entities"] == ["CVE-2021-0001"]


# --------------------------------------------------------------------------------------
# Search, the read, browse
# --------------------------------------------------------------------------------------

class Index:
    """Records every statement's resources. Each archive of ``archives`` answers its entry for the
    CVE ids it holds; with ``crowd``, the wiki answers every text and fuzzy wording with 45 pages,
    found by several wordings each."""

    def __init__(self, crowd=False, archives=("a1",), holds=("CVE-2021-0001",)):
        self.calls, self.crowd, self.archives, self.holds = [], crowd, archives, holds

    async def rows(self, name, params):
        self.calls.append((name, list(params.get("rids") or [])))
        if name == "archive_entries" and any(a in params["rids"] for a in self.archives):
            return [self.row(7 + 100 * i + 10 * j, a, f"{RAW}/{a}/{c[4:8]}/{c}.json", c, [c])
                    for i, a in enumerate(self.archives) if a in params["rids"]
                    for j, c in enumerate(self.holds) if c in params["ents"]]
        if name == "entries_entities" and "w1" in params["rids"]:
            # A wiki page naming the CVE, which covers more of the step's words than the archive's entry.
            return [self.row(3, "w1", "https://wiki.tc-fixture.test/traversal/", "Path traversal", ["CVE-2021-0001"])]
        if self.crowd and name in ("entries_text", "entries_fuzzy") and "w1" in params["rids"]:
            return [self.row(1000 + n, "w1", f"https://wiki.tc-fixture.test/p{n}/", f"Page {n}", []) for n in range(45)]
        if name == "assess":
            return [{"id": i, "total": 6, "title": 6 if i == 3 else 1, "strong": 6 if i == 3 else 1,
                     "anywhere": 6 if i == 3 else (3 if i % 100 == 7 else 2), "named": 1, "file_name": ""}
                    for i in params["ids"]]
        return []

    @staticmethod
    def row(n, rid, url, title, ents):
        return {"id": n, "page_id": n, "resource_id": rid, "url": url, "title": title, "title_source": "guessed",
                "breadcrumb": [], "headings": [], "description": "", "topics": [], "kinds": [], "technologies": [],
                "entities": ents, "size_chars": 0, "fetched_at": None, "stored": False, "rank": 1.0}


def _catalog(*types, archives=None):
    """A wiki ("mkdocs-wiki", w1) and CVE archives: one per "cve-poc-db" (a1, a2, ...), or
    ``archives`` as [(id, priority)]."""
    from tradecraft.contract import V2Catalog

    resources = []
    if "mkdocs-wiki" in types:
        resources.append(("w1", "mkdocs-wiki", "normal"))
    archives = archives or [(f"a{i + 1}", "normal") for i in range(types.count("cve-poc-db"))]
    resources += [(rid, "cve-poc-db", priority) for rid, priority in archives]
    return V2Catalog.model_validate({"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None, "search": {},
                                     "resources": [{"id": rid, "slug": rid, "name": rid,
                                                    "url": URL if t == "cve-poc-db" else "https://wiki.tc-fixture.test/",
                                                    "type": t, "storage_mode": "live", "summary": "s",
                                                    "priority": priority, "map_version": 3}
                                                   for rid, t, priority in resources]})


STEP = "exploit CVE-2021-0001 path traversal"


def test_the_archive_is_read_by_the_cve_ids_the_need_names_only():
    index = Index()
    answer = run(search.search(OWNER, _catalog("mkdocs-wiki", "cve-poc-db"), STEP, index=index))
    # The archive's entry leads the pages that only name its CVE, which cover more of the step.
    assert answer.verdict == "FOUND" and [h.card.page_id for h in answer.hits] == ["a1:7", "w1:3"]
    by_name = {}
    for name, rids in index.calls:
        by_name.setdefault(name, []).append(rids)
    # The wordings read the wiki; the archive is read once, for the step's CVE id.
    assert by_name["entries_entities"] == [["w1"]] and by_name["archive_entries"] == [["a1"]]
    assert by_name["assess"] == [["w1", "a1"]]
    for name in ("entries_text", "sections_text", "entries_fuzzy"):
        assert by_name[name] and all(rids == ["w1"] for rids in by_name[name]), name
    # An archive alone and a need naming no CVE id: no statement runs at all.
    alone = Index()
    run(search.search(OWNER, _catalog("cve-poc-db"), "cve 2021 apache", index=alone))
    assert alone.calls == []


def test_the_merges_cut_never_drops_the_archives_entry():
    crowd = Index(crowd=True)
    first = run(search.free_first_pass(OWNER, _catalog("mkdocs-wiki", "cve-poc-db"), STEP, index=crowd))
    assert len(first.candidates) == search.MERGED + 1
    archive = [c for c in first.candidates if c.archive]
    assert [c.row["page_id"] for c in archive] == [7] and archive[0].entity_match
    assert sorted(first.candidates, key=search._order)[0] is archive[0]
    assert archive[0].score == pytest.approx(1 / (search.RRF_K + 1))


@pytest.mark.parametrize("archives,chosen", [
    ([("a1", "normal"), ("a2", "normal")], "a1"),
    ([("a1", "normal"), ("a2", "high"), ("a3", "normal")], "a2"),
    ([("a3", "low"), ("a2", "normal"), ("a1", "low")], "a2"),
    ([("b2", "normal"), ("b1", "normal"), ("b3", "normal")], "b1"),
])
def test_one_archive_row_per_cve_whatever_the_number_of_archives(archives, chosen):
    """Two or three archives hold the same CVE: one row stands for it, the archive of the highest
    priority, then the first by slug (a stable rule the person can steer). Each other CVE the need
    names keeps its own row."""
    ids = [rid for rid, _p in archives]
    index = Index(archives=ids, holds=("CVE-2021-0001", "CVE-2021-0002"))
    cat = _catalog("mkdocs-wiki", archives=archives)
    answer = run(search.search(OWNER, cat, "exploit CVE-2021-0001 and CVE-2021-0002", index=index))
    archive_hits = [h for h in answer.hits if not h.card.page_id.startswith("w1:")]
    assert sorted(h.card.title for h in archive_hits) == ["CVE-2021-0001", "CVE-2021-0002"]
    assert {h.card.resource_slug for h in archive_hits} == {chosen}
    first = run(search.free_first_pass(OWNER, cat, "exploit CVE-2021-0001 path traversal", index=index))
    assert [c.row["resource_id"] for c in first.candidates if c.archive] == [chosen]


def test_the_librarian_is_never_handed_an_archive_entry():
    """The librarian cannot read an archive's entry: its search keeps the archives out, so a CVE only
    an archive holds is NOT FOUND with no model call, as before the index."""
    from tradecraft.librarian.tools import LibraryTools

    index = Index()
    tools = LibraryTools(OWNER, _catalog("mkdocs-wiki", "cve-poc-db"), index=index, store=object())
    found = run(tools.search(STEP))
    assert [c.page_id for c in found.cards] == ["w1:3"]
    assert ["a1"] not in [rids for _n, rids in index.calls]
    alone = LibraryTools(OWNER, _catalog("cve-poc-db"), index=Index(), store=object())
    assert run(alone.search("CVE-2021-0001")).verdict == "NOT FOUND"


ENTRY = "### CVE-2021-0001\n\nSynthetic entry.\n\n" + "\n".join(f"- https://github.com/tc-fixture/poc-{n:04d}"
                                                             for n in range(600)) + "\n"


def _archive_library(tmp_path, read_settings=None, **entry):
    root = archive(tmp_path, {"raw.githubusercontent.com/tc-fixture/cve/main/2021/CVE-2021-0001.json": ENTRY})
    lib = Library(FixtureFetcher(root)).add("a1", "cves", URL, type_="cve-poc-db",
                                            sitemap={"owner": "tc-fixture", "repo": "cve", "branch": "main"},
                                            read_settings=JSON if read_settings is None else read_settings)
    url = f"{RAW}/2021/CVE-2021-0001.json"
    lib.store.page_ids[("a1", url)] = 41
    lib.store.entries.append({"id": 1, "user_id": OWNER, "resource_id": "a1",
                              "generation": lib.store.resources["a1"]["generation"], "page_id": 41,
                              "url": url, "title": "CVE-2021-0001", "stored_text": None, "stored_bytes": 0,
                              "fetched_at": None, "entities": ["CVE-2021-0001"], "status": "kept", **entry})
    return lib


def test_a_page_of_the_archive_is_read_as_its_cve(tmp_path):
    lib = _archive_library(tmp_path)
    state = {"session_id": "s1", "current_objective_index": 0}
    first = read(lib, state=state, page="cves:41", search={"reading.charsPerRead": 2000})
    assert header(first, "url") == f"{RAW}/2021/CVE-2021-0001.json" and header(first, "source") == "live"
    assert header(first, "part").startswith("1 of ")
    assert header(first, "next") == 'tradecraft_lookup(resource_id="cves", cve_id="CVE-2021-0001", part=2)'
    assert state["tradecraft_seen_pages"] == ["cves:41"]
    # The same answer as the CVE's own read, inside its own envelope.
    whole = read(lib, page="cves:41", search={"reading.charsPerRead": 40000})
    by_id = read(lib, resource_id="cves", cve_id="CVE-2021-0001", search={"reading.charsPerRead": 40000})
    assert whole.splitlines()[1:-1] == by_id.splitlines()[1:-1] and ENTRY.strip() in whole
    # A part that does not exist is refused as a cve_id read refuses it, and is not a page read.
    state = {"session_id": "s2", "current_objective_index": 0}
    beyond = read(lib, state=state, page="cves:41", part=99)
    assert beyond.startswith("Error: this read of resource 'cves' has ") and not state.get("tradecraft_seen_pages")


def test_a_cve_read_marks_the_archives_entry_read(tmp_path):
    lib = _archive_library(tmp_path)
    state = {"session_id": "s1", "current_objective_index": 0}
    read(lib, state=state, resource_id="cves", cve_id="cve-2021-0001")
    assert state["tradecraft_seen_pages"] == ["cves:41"]
    # A CVE the index does not hold is read all the same, and marks nothing.
    state = {"session_id": "s2", "current_objective_index": 0}
    found = read(lib, state=state, resource_id="cves", cve_id="CVE-2021-0002")
    assert "PoC not found" not in found and not state.get("tradecraft_seen_pages")


def test_a_blocked_or_removed_page_of_the_archive(tmp_path):
    """A refusal names the page by its ID and the resource by its slug: the entry's URL holds the
    archive's branch, which its owner chose."""
    lib = _archive_library(tmp_path)
    lib.store.curate("a1", f"{RAW}/2021/CVE-2021-0001.json", blocked=True)
    blocked = read(lib, page="cves:41")
    assert blocked == reader.PAGE_BLOCKED.format(page_id="cves:41", slug="cves") and "https://" not in blocked
    assert lib.fetcher.requests == []
    lib = _archive_library(tmp_path / "b")
    lib.store.entries.clear()
    assert read(lib, page="cves:41").startswith("Error: page cves:41 is no longer in resource 'cves'")


def test_a_cve_id_read_of_a_blocked_file_is_refused_without_a_request(tmp_path):
    """The person blocked the archive's file for a CVE in the Map: no route reads it, before or
    after a refresh drops its entry. Each file the CVE reader would request is checked first, the
    one a pattern names and the one the year folder's listing names alike."""
    lib = _archive_library(tmp_path)
    blocked_url = f"{RAW}/2021/CVE-2021-0001.json"
    lib.store.curate("a1", blocked_url, blocked=True)
    state = {"session_id": "s1", "current_objective_index": 0}
    out = read(lib, state=state, resource_id="cves", cve_id="CVE-2021-0001")
    assert out == reader.CVE_BLOCKED.format(cve="CVE-2021-0001", slug="cves") and not state.get("tradecraft_seen_pages")
    assert blocked_url not in [u for u, _h in lib.fetcher.requests]
    lib.store.entries.clear()
    assert read(lib, resource_id="cves", cve_id="CVE-2021-0001") == out
    # Found through the listing (no pattern names a .json file): the listed file is checked too.
    by_listing = _archive_library(tmp_path / "b", read_settings={})
    listed_url = f"{RAW}/2021/CVE-2021-0002.json"
    by_listing.store.curate("a1", listed_url, blocked=True)
    out = read(by_listing, resource_id="cves", cve_id="CVE-2021-0002")
    assert out == reader.CVE_BLOCKED.format(cve="CVE-2021-0002", slug="cves")
    requested = [u for u, _h in by_listing.fetcher.requests]
    assert "https://api.github.com/repos/tc-fixture/cve/contents/2021" in requested and listed_url not in requested
    # Another CVE of the same archive reads as before.
    assert "Synthetic entry CVE-2021-0003." in read(by_listing, resource_id="cves", cve_id="CVE-2021-0003")


@pytest.mark.parametrize("owner,repo", [("TC-Fixture", "CVE"), ("tc-fixture", "old-cve")])
def test_a_block_holds_however_github_spells_the_repository(tmp_path, owner, repo):
    """The person typed the archive's URL in other capitals, or GitHub renamed the repository: the
    year folder's listing names the file by GitHub's spelling, and the block, on the archive's own
    URL for it (as its entry stores it), still refuses it, with no request."""
    listing = [{"name": "CVE-2021-0002.json", "path": "2021/CVE-2021-0002.json", "type": "file", "size": 120,
                "download_url": f"{RAW}/2021/CVE-2021-0002.json"}]
    root = archive(tmp_path, {f"api.github.com/repos/{owner}/{repo}/contents/2021/index.json": listing})
    lib = Library(FixtureFetcher(root)).add("a1", "cves", f"https://github.com/{owner}/{repo}", type_="cve-poc-db",
                                            sitemap={"owner": owner, "repo": repo, "branch": "main"})
    own = f"https://raw.githubusercontent.com/{owner}/{repo}/main/2021/CVE-2021-0002.json"
    lib.store.curate("a1", own, blocked=True)
    out = read(lib, resource_id="cves", cve_id="CVE-2021-0002")
    assert out == reader.CVE_BLOCKED.format(cve="CVE-2021-0002", slug="cves")
    assert f"{RAW}/2021/CVE-2021-0002.json" not in [u for u, _h in lib.fetcher.requests]
    lib.store.curations.clear()
    assert "Synthetic entry CVE-2021-0002." in read(lib, resource_id="cves", cve_id="CVE-2021-0002")


def test_browsing_an_archive_lists_no_cve_ids():
    card = search.card_of({"page_id": 41, "url": f"{RAW}/2021/CVE-2021-0001.json", "title": "CVE-2021-0001"},
                          _catalog("cve-poc-db").resources[0])
    level = BrowseLevel(resource_slug="a1", path="", breadcrumb=("a1",), page_count=20000, pages=(card,), more=19999,
                        summary="An archive.")
    text = agent_tools.render_browse(level, _catalog("cve-poc-db").resources[0])
    assert "a1:41" not in text and "more" not in text and 'cve_id="CVE-YYYY-NNNNN"' in text
