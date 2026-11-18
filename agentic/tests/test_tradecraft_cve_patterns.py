"""CVE archive path patterns (T4.2, §6.5 "CVE archive", R-146, AC-08): an ordered list of paths
with ``{year}``, ``{cve}`` and ``{cve_lower}`` finds a CVE in a year folder too big for GitHub to
list; the archive's branch and its README fallback are its own settings. They reach the agent's
lookup in the catalog's ``read_settings``, as the webapp sends them (``catalog.ts``).

The fixture archive ``tc-fixture/cve`` is laid out as ``{year}/{cve}.json``; its 2023 listing
stops at 1,000 of its 1,050 entries, as the GitHub contents API does. Lookups go through the
reader with a bound catalog, over ``FixtureFetcher``.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net, runtime  # noqa: E402
from tradecraft.library import cve, reader, split  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FIXTURES, FixtureFetcher, run  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

OWNER = "user_owner_fake"
META = {"owner": "tc-fixture", "repo": "cve", "branch": "main"}
RAW = "https://raw.githubusercontent.com/tc-fixture/cve"


def archive(tmp_path, files=None) -> Path:
    root = tmp_path / "sites"
    shutil.copytree(FIXTURES, root)
    for path, text in (files or {}).items():
        target = root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def read(root, cve_id, read_settings=None, *, part=None, search=None):
    """The agent's lookup in a run whose catalog lists the archive with ``read_settings`` (and the
    owner's ``search`` settings), for ``part`` of the entry."""
    store = MemoryStore()
    store.add_resource(OWNER, "r1", url="https://github.com/tc-fixture/cve", slug="cves", storage_mode="live",
                       map_version=3, resource_type="cve-poc-db", sitemap=dict(META))
    catalog = {"v2": True, "owner_id": OWNER, "person_id": OWNER, "actor_id": None, "search": search or {},
               "resources": [{"id": "r1", "slug": "cves", "name": "cves", "url": "https://github.com/tc-fixture/cve",
                              "type": "cve-poc-db", "storage_mode": "live", "summary": "s", "has_login": False,
                              "priority": "normal", "map_version": 3, "read_settings": read_settings or {},
                              "github_token": None, "credentials": None}]}
    fetcher = FixtureFetcher(root)

    async def go():
        with net.use_fetcher(fetcher), runtime.use_store(store):
            assert runtime.bind_run_catalog(catalog)
            return await reader.lookup(resource_id="cves", cve_id=cve_id, part=part)

    return contextvars.Context().run(asyncio.run, go()), [u for u, _h in fetcher.requests]


# --------------------------------------------------------------------------------------

def test_big_year(tmp_path):
    """AC-08: CVE-2023-1050 is past the 1,000 entries GitHub lists for 2023; the archive's
    pattern finds it without the listing."""
    root = archive(tmp_path)
    found, requested = read(root, "CVE-2023-1050", {"type.cve.pathPatterns": ["{year}/{cve}.json"]})
    assert "PoC not found" not in found and "CVE-2023-1050" in found
    assert f"url: {RAW}/main/2023/CVE-2023-1050.json" in found
    assert requested == [f"{RAW}/main/2023/CVE-2023-1050.json"]  # no listing, no README
    # With 1.x's fixed paths (the default), only the listing is left, and it stops at 1,000.
    missing, requested = read(root, "CVE-2023-1050")
    assert "PoC not found for CVE-2023-1050" in missing
    assert "https://api.github.com/repos/tc-fixture/cve/contents/2023" in requested
    # A CVE the listing still holds is found that way, as in 1.x.
    listed, _ = read(root, "CVE-2023-0003")
    assert "PoC not found" not in listed and f"{RAW}/main/2023/CVE-2023-0003.json" in listed


def test_pattern_order(tmp_path):
    root = archive(tmp_path, {
        "raw.githubusercontent.com/tc-fixture/cve/main/2021/CVE-2021-0001.md": "the markdown copy",
        "raw.githubusercontent.com/tc-fixture/cve/main/2021/cve-2021-0002/README.md": "the lower-case folder",
    })
    first, _ = read(root, "CVE-2021-0001", {"type.cve.pathPatterns": ["{year}/{cve}.md", "{year}/{cve}.json"]})
    assert "the markdown copy" in first
    second, requested = read(root, "CVE-2021-0001", {"type.cve.pathPatterns": ["{year}/{cve}.json", "{year}/{cve}.md"]})
    assert "the markdown copy" not in second and requested == [f"{RAW}/main/2021/CVE-2021-0001.json"]
    lower, requested = read(root, "CVE-2021-0002", {"type.cve.pathPatterns": ["{year}/{cve}.md", "{year}/{cve_lower}/README.md"]})
    assert "the lower-case folder" in lower
    assert requested == [f"{RAW}/main/2021/CVE-2021-0002.md", f"{RAW}/main/2021/cve-2021-0002/README.md"]


@pytest.mark.parametrize("pattern", [
    "{year}/no-placeholder.md", "/{year}/{cve}.md", "{year}/../{cve}.md", "https://evil.tc-fixture.test/{cve}",
    "{year}/{other}/{cve}.md", "{year}//{cve}.md", "{year}/{cve.__class__}.md", "{0}/{cve}.md", "{year}\\{cve}.md",
])
def test_a_pattern_outside_the_repository_is_skipped(pattern):
    assert cve.pattern_path(pattern, "CVE-2021-0001") is None


def test_pattern_path():
    assert cve.pattern_path("{year}/{cve}.md", "cve-2023-1234") == "2023/CVE-2023-1234.md"
    assert cve.pattern_path("exploits/{year}/{cve_lower}/poc.py", "CVE-2023-1234") == "exploits/2023/cve-2023-1234/poc.py"
    assert cve.pattern_path("{year}/{cve}.md", "not-a-cve") is None
    assert cve.raw_url("o", "r", "dev", "a b/CVE-1.md") == "https://raw.githubusercontent.com/o/r/dev/a%20b/CVE-1.md"


def test_readme_fallback(tmp_path):
    """A repository whose README names the CVE answers with the README, unless the archive
    turns the fallback off."""
    root = archive(tmp_path, {"api.github.com/repos/tc-fixture/cve/readme/index.json":
                              "# tc-fixture/cve\nKnown issue CVE-2020-0042 is described here.\n"})
    on, _ = read(root, "CVE-2020-0042")
    assert "repository README; no 2020/CVE-2020-0042 entry" in on and "Known issue CVE-2020-0042" in on
    off, requested = read(root, "CVE-2020-0042", {"type.cve.readmeFallback": False})
    assert "PoC not found for CVE-2020-0042" in off
    assert not any(u.endswith("/readme") for u in requested)


def test_branch(tmp_path):
    root = archive(tmp_path, {"raw.githubusercontent.com/tc-fixture/cve/dev/2021/CVE-2021-0001.json": "on the dev branch"})
    found, requested = read(root, "CVE-2021-0001", {"type.cve.branch": "dev", "type.cve.pathPatterns": ["{year}/{cve}.json"]})
    assert "on the dev branch" in found and requested == [f"{RAW}/dev/2021/CVE-2021-0001.json"]
    # The branch also reaches the listing and the README.
    _miss, requested = read(root, "CVE-2021-0009", {"type.cve.branch": "dev"})
    assert "https://api.github.com/repos/tc-fixture/cve/contents/2021?ref=dev" in requested
    assert "https://api.github.com/repos/tc-fixture/cve/readme?ref=dev" in requested
    # No branch set: the one ingestion recorded in the map.
    assert cve.branch_of({"branch": "trunk"}, EffectiveSettings({})) == "trunk"
    assert cve.branch_of({}, EffectiveSettings({})) == "main"


def test_api_error_is_not_a_miss(tmp_path):
    """GitHub answering 429 to a pattern is an error the agent reports, not "no PoC"."""
    root = archive(tmp_path, {"raw.githubusercontent.com/_status.json":
                              json.dumps({"/tc-fixture/cve/main/2022/CVE-2022-0009.json": 429})})
    with net.use_fetcher(FixtureFetcher(root)):
        text, url, error = run(cve.lookup("CVE-2022-0009", META, EffectiveSettings({"type.cve.pathPatterns": ["{year}/{cve}.json"]})))
    assert (text, url, error) == ("", "", "github_http_429")
    answer, _ = read(root, "CVE-2022-0009", {"type.cve.pathPatterns": ["{year}/{cve}.json"]})
    assert "NOT a 'PoC not found' answer" in answer and "github_http_429" in answer


def body(result):
    """A read's text: the lines after its header, inside the envelope."""
    lines = result.splitlines()
    return "\n".join(lines[lines.index("---") + 1:-1])


def header(result, name):
    return next((ln[len(name) + 2:] for ln in result.splitlines() if ln.startswith(f"{name}: ")), None)


def every_part(root, cve_id, read_settings=None, search=None):
    """Each part of a CVE read, following the ``next:`` line from the first one."""
    parts = [read(root, cve_id, read_settings, search=search)[0]]
    while header(parts[-1], "next"):
        call = header(parts[-1], "next")
        assert call == f'tradecraft_lookup(resource_id="cves", cve_id="{cve_id}", part={len(parts) + 1})'
        parts.append(read(root, cve_id, read_settings, part=len(parts) + 1, search=search)[0])
    return parts


POC_LINES = "\n".join(f"- https://github.com/tc-fixture/poc-{n:04d} synthetic proof of concept number {n}"
                      for n in range(450))


def test_a_long_entry_is_read_in_parts_within_the_read_limit(tmp_path):
    """The archive's entry keeps the per-read limit of a page read, with the call that reads its next
    part, and no line of it is lost across the parts."""
    entry = ("### [CVE-2021-4242](https://cve.example.invalid/CVE-2021-4242)\n\n### Description\nSynthetic.\n\n"
             f"### POC\n\n#### Github\n{POC_LINES}\n")
    root = archive(tmp_path, {"raw.githubusercontent.com/tc-fixture/cve/main/2021/CVE-2021-4242.md": entry})
    patterns = {"type.cve.pathPatterns": ["{year}/{cve}.md"]}
    parts = every_part(root, "CVE-2021-4242", patterns)
    count = len(split.parts(entry, 12_000))
    assert len(entry) > 30_000 and len(parts) == count >= 3
    assert [header(p, "part") for p in parts] == [f"{n} of {count}" for n in range(1, count + 1)]
    assert all(len(body(p)) <= 12_000 and header(p, "source") == "live" for p in parts)
    assert all(f"poc-{n:04d} " in "\n".join(body(p) for p in parts) for n in range(450))
    assert header(parts[-1], "next") is None
    beyond, _ = read(root, "CVE-2021-4242", patterns, part=count + 1)
    assert beyond == f"Error: this read of resource 'cves' has {count} part(s); ask for part 1 to {count}."
    # The owner's own limit decides: at 40,000 characters it is one read, as before.
    whole, _ = read(root, "CVE-2021-4242", patterns, search={"reading.charsPerRead": 40_000})
    assert header(whole, "part") is None and header(whole, "next") is None and POC_LINES in whole


def test_a_long_readme_fallback_is_read_in_parts_too(tmp_path):
    readme = f"# tc-fixture/cve\nKnown issue CVE-2020-0043 is listed here.\n\n{POC_LINES}\n"
    root = archive(tmp_path, {"api.github.com/repos/tc-fixture/cve/readme/index.json": readme})
    parts = every_part(root, "CVE-2020-0043")
    assert len(parts) >= 3 and all(len(body(p)) <= 12_000 for p in parts)
    assert all("repository README; no 2020/CVE-2020-0043 entry" in header(p, "section_title") for p in parts)
