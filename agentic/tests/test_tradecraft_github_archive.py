"""A Stored GitHub repository from one archive download (T6.3, §4.5, §5, R-113, EX-4).

The fixture repository ``tc-fixture/payloads`` serves its ``.tar.gz`` behind GitHub's redirect
(``github.com/.../archive/refs/heads/main.tar.gz`` -> ``codeload.github.com``); a test that needs
another archive or another redirect writes it into its own copy of the fixture tree.
"""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net  # noqa: E402
from tradecraft.ingest import github_archive  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_job_harness import JobHarness  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402

REPO = "https://github.com/tc-fixture/payloads"
RAW = "https://raw.githubusercontent.com/tc-fixture/payloads/main/"
ARCHIVE = "https://github.com/tc-fixture/payloads/archive/refs/heads/main.tar.gz"
CODELOAD = "https://codeload.github.com/tc-fixture/payloads/tar.gz/refs/heads/main"
TOKEN = "ghp_fake_token_never_sent_elsewhere"
SITES = Path(__file__).resolve().parent / "fixtures" / "tradecraft_sites"


def _raw(h):
    return [u for u in h.requested() if u.startswith(RAW)]


def _tarball(members: dict, prefix: str = "payloads-main") -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path, data in members.items():
            info = tarfile.TarInfo(f"{prefix}/{path}")
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            tar.addfile(info, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def _replace_archive(root: Path, data: bytes) -> None:
    (root / "codeload.github.com/tc-fixture/payloads/tar.gz/refs/heads/main").write_bytes(data)


def test_archive_used_under_ceiling(tmp_path):
    h = JobHarness(tmp_path, REPO, mode="stored", secrets={"github_token": TOKEN, "credentials": None})
    assert h.run().status == "succeeded"
    assert _raw(h) == []
    assert h.requested().count(ARCHIVE) == 1 and h.requested().count(CODELOAD) == 1
    live = h.live()
    assert live and all(e["stored_text"] for e in live)
    for e in live:
        expected = (SITES / "raw.githubusercontent.com/tc-fixture/payloads/main" / e["url"][len(RAW):]).read_text()
        assert e["stored_text"] == expected, e["url"]
    report = h.row["ingestion_report"]
    assert report["stored"]["pages"] == len(live)
    assert not [e for e in report["errors"] if e["code"].startswith("archive") or e["code"] == "page_too_large"]
    # The token went to github.com's hop and no further: codeload, a different host, got none.
    headers = {u: hd for u, hd in h.fetcher.requests}
    assert headers[ARCHIVE].get("authorization") == f"token {TOKEN}"
    assert "authorization" not in headers[CODELOAD]


def test_file_by_file_over_ceiling(tmp_path, monkeypatch):
    # The repository API says 4 KB: a 1,000-byte ceiling sends it file by file, the archive unasked.
    monkeypatch.setattr(github_archive, "ARCHIVE_MAX_BYTES", 1000)
    h = JobHarness(tmp_path, REPO, mode="stored")
    assert h.run().status == "succeeded"
    assert ARCHIVE not in h.requested() and CODELOAD not in h.requested()
    assert len(_raw(h)) == len(h.live()) and all(e["stored_text"] for e in h.live())


def test_live_repository_never_downloads_the_archive(tmp_path):
    h = JobHarness(tmp_path, REPO)
    h.run()
    assert ARCHIVE not in h.requested() and _raw(h) == []


def test_stream_filters_types_and_folders(tmp_path):
    h = JobHarness(tmp_path, REPO, mode="stored", settings={"knownTypes.githubFileTypes": [".md", ".yml"],
                                                             "type.github.includeFolders": ["xss"]})
    h.run()
    assert _raw(h) == []
    stored = sorted(e["url"][len(RAW):] for e in h.live() if e["stored_text"])
    assert stored == ["xss/README.md", "xss/filters.yml", "xss/polyglots.md"]


def _source(data: bytes):
    chunks = [data[i:i + 1000] for i in range(0, len(data), 1000)] + [b""]
    pulled = []

    def pull():
        pulled.append(1)
        return chunks.pop(0) if chunks else b""

    return github_archive._Source(pull, github_archive.UNPACKED_MAX_BYTES), pulled


def test_unpack_keeps_only_the_wanted_files():
    members = {"a.md": b"# A\n", "b.md": b"# B\n", "c/d.md": b"# D\n", "link-target.md": b"x"}
    src, _pulled = _source(_tarball(members))
    got = github_archive.unpack(src, {"a.md", "c/d.md", "missing.md"}, max_file_bytes=1000,
                                max_total_bytes=10_000, max_files=10)
    assert got.texts == {"a.md": "# A\n", "c/d.md": "# D\n"} and not got.error and not got.cut


def test_oversize_file_skipped():
    big = ("x" * 50_000).encode()
    members = {"big.md": big, "after.md": "# After é\n".encode()}
    src, _pulled = _source(_tarball(members))
    got = github_archive.unpack(src, {"big.md", "after.md"}, max_file_bytes=10_000, max_total_bytes=10**6,
                                max_files=10)
    # The big file keeps its first 10,000 bytes; the rest is skipped in the stream and the next
    # file reads whole.
    assert got.texts["big.md"] == "x" * 10_000 and got.cut == {"big.md"}
    assert got.texts["after.md"] == "# After é\n" and not got.error


def test_oversize_file_cut_in_a_job(tmp_path):
    root = padded_sites(tmp_path)
    members = {p.relative_to(root / "raw.githubusercontent.com/tc-fixture/payloads/main").as_posix(): p.read_bytes()
               for p in (root / "raw.githubusercontent.com/tc-fixture/payloads/main").rglob("*") if p.is_file()}
    members["sqli/union.md"] = b"# Union-based\n" + b"y" * 30_000
    _replace_archive(root, _tarball(members))
    h = JobHarness(tmp_path, REPO, mode="stored", root=root, settings={"storage.maxPageKb": 10})
    h.run()
    union = h.live_by_url()[RAW + "sqli/union.md"]
    assert len(union["stored_text"].encode()) == 10 * 1024 and union["stored_text"].startswith("# Union-based")
    assert {"code": "page_too_large", "count": 1} in h.row["ingestion_report"]["errors"]
    assert _raw(h) == []


def test_unpacked_ceiling_falls_back_to_file_by_file(tmp_path, monkeypatch):
    monkeypatch.setattr(github_archive, "UNPACKED_MAX_BYTES", 100)
    h = JobHarness(tmp_path, REPO, mode="stored")
    assert h.run().status == "succeeded"
    errors = {e["code"] for e in h.row["ingestion_report"]["errors"]}
    assert "archive_too_large" in errors
    assert all(e["stored_text"] for e in h.live()) and len(_raw(h)) == len(h.live())


def test_declared_length_over_the_ceiling_is_not_read(tmp_path, monkeypatch):
    root = padded_sites(tmp_path)
    headers = root / "codeload.github.com/_headers.json"
    spec = json.loads(headers.read_text())
    spec["/tc-fixture/payloads/tar.gz/refs/heads/main"]["content-length"] = str(github_archive.ARCHIVE_MAX_BYTES + 1)
    headers.write_text(json.dumps(spec))
    h = JobHarness(tmp_path, REPO, mode="stored", root=root)
    assert h.run().status == "succeeded"
    assert "archive_too_large" in {e["code"] for e in h.row["ingestion_report"]["errors"]}
    assert len(_raw(h)) == len(h.live())


def test_redirect_hops_checked(tmp_path):
    root = padded_sites(tmp_path)
    (root / "github.com/_redirects.json").write_text(json.dumps({
        "/tc-fixture/payloads/archive/refs/heads/main.tar.gz": "http://169.254.169.254/latest/meta-data/"}))
    h = JobHarness(tmp_path, REPO, mode="stored", root=root)
    assert h.run().status == "succeeded"
    # The guard refused the hop before any request to the metadata address; the files came one by one.
    assert not any("169.254.169.254" in u for u in h.requested())
    assert ARCHIVE in h.requested()
    assert all(e["stored_text"] for e in h.live()) and len(_raw(h)) == len(h.live())


def test_a_broken_archive_falls_back(tmp_path):
    root = padded_sites(tmp_path)
    _replace_archive(root, b"\x1f\x8b not really gzip")
    h = JobHarness(tmp_path, REPO, mode="stored", root=root)
    assert h.run().status == "succeeded"
    assert "archive_unreadable" in {e["code"] for e in h.row["ingestion_report"]["errors"]}
    assert all(e["stored_text"] for e in h.live())


def test_read_stops_when_the_job_is_cancelled():
    async def go():
        async def stop():
            return True

        with net.use_fetcher(FixtureFetcher()):
            return await github_archive.read("tc-fixture", "payloads", "main", EffectiveSettings({}),
                                             github_token=None, wanted={"README.md"}, max_file_bytes=1000,
                                             max_total_bytes=10_000, max_files=10, should_stop=stop)

    got = asyncio.run(go())
    assert got.error == "cancelled" and got.texts == {}


@pytest.mark.parametrize("size,ok", [(4, True), (0, True), (None, False), (True, False), ("4", False),
                                     (github_archive.ARCHIVE_MAX_BYTES // 1024 + 1, False)])
def test_eligible(size, ok):
    assert github_archive.eligible(size) is ok


def test_archive_url_quotes_the_branch():
    assert github_archive.archive_url("o", "r", "feat/x y") == \
        "https://github.com/o/r/archive/refs/heads/feat/x%20y.tar.gz"
    assert github_archive.repo_path("payloads-main/a/b.md") == "a/b.md" and github_archive.repo_path("x") == ""
