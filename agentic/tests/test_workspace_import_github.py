"""GitHub resolution and download strategies, on canned answers shaped like E2's."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import httpx

from workspace_import import github
from workspace_import.errors import ImportFailure
from workspace_import.fetch import GuardedFetcher

SHA = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
API = "https://api.github.com/repos/o/r"


def tree(entries, truncated=False):
    return {"sha": SHA, "tree": [{"path": p, "type": t, "size": s, "mode": m} for p, t, s, m in entries],
            "truncated": truncated}


class GithubBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-gh-"))
        self.calls = []
        self.routes = {
            API: httpx.Response(200, json={"default_branch": "main", "size": 12, "private": False}),
            f"{API}/commits/main": httpx.Response(200, text=SHA),
            f"{API}/git/trees/{SHA}?recursive=1": httpx.Response(200, json=tree([
                ("README", "blob", 13, "100644"), ("docs", "tree", 0, "040000"),
                ("docs/a.md", "blob", 5, "100644"), ("docs/sub", "tree", 0, "040000"),
                ("docs/sub/b.md", "blob", 7, "100644"), ("docs/link", "blob", 4, "120000"),
                ("vendor/lib", "commit", 0, "160000"),
            ])),
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fetcher(self):
        def handler(request):
            self.calls.append(str(request.url))
            r = self.routes.get(str(request.url))
            return r(request) if callable(r) else (r or httpx.Response(404))
        return GuardedFetcher(transport=httpx.MockTransport(handler), assert_safe=lambda _u: None)

    async def resolve(self, rest=""):
        async with self.fetcher() as f:
            return await github.resolve_repo(f, "o", "r", rest)

    async def assertCode(self, code, coro):
        with self.assertRaises(ImportFailure) as ctx:
            await coro
        self.assertEqual(ctx.exception.code, code)


class Resolve(GithubBase):
    async def test_whole_repository(self):
        info = await self.resolve()
        self.assertEqual((info.ref, info.sha, info.subpath, info.files, info.bytes), ("main", SHA, "", 4, 29))
        self.assertTrue(info.has_submodules)
        self.assertFalse(info.raw_strategy)

    async def test_meta_404_rate_limit_401_codes(self):
        for resp, code in ((httpx.Response(404), "not_found"),
                           (httpx.Response(403, headers={"x-ratelimit-remaining": "0"}), "rate_limited"),
                           (httpx.Response(429), "rate_limited"),
                           (httpx.Response(401), "auth_failed"),
                           (httpx.Response(503), "upstream_status")):
            self.routes[API] = resp
            await self.assertCode(code, self.resolve())

    async def test_ref_with_slashes_resolved_in_at_most_four_calls(self):
        self.routes[f"{API}/commits/feature/x"] = httpx.Response(200, text=SHA)
        self.routes[f"{API}/commits/feature"] = httpx.Response(422)
        info = await self.resolve("feature/x/docs")
        self.assertEqual((info.ref, info.subpath), ("feature/x", "docs"))
        commit_calls = [c for c in self.calls if "/commits/" in c]
        self.assertEqual(commit_calls, [f"{API}/commits/feature", f"{API}/commits/feature/x"])
        self.calls.clear()
        await self.assertCode("ref_not_found", self.resolve("a/b/c/d/e/f"))
        self.assertEqual(len([c for c in self.calls if "/commits/" in c]), 4)

    async def test_subpath_counts_and_invalid_subpath(self):
        info = await self.resolve("main/docs")
        self.assertEqual((info.subpath, info.files, info.bytes), ("docs", 3, 16))
        self.assertTrue(info.raw_strategy)
        await self.assertCode("invalid_subpath", self.resolve("main/nope"))
        await self.assertCode("invalid_subpath", self.resolve("main/README"))  # a file is not a folder

    async def test_truncated_tree_chooses_tarball(self):
        self.routes[f"{API}/git/trees/{SHA}?recursive=1"] = httpx.Response(200, json=tree(
            [("docs/a.md", "blob", 5, "100644")], truncated=True))
        info = await self.resolve("main/docs")
        self.assertTrue(info.truncated)
        self.assertFalse(info.raw_strategy)
        self.assertEqual(github.tarball_url("o", "r", SHA, with_token=False),
                         f"https://codeload.github.com/o/r/tar.gz/{SHA}")
        self.assertEqual(github.tarball_url("o", "r", SHA, with_token=True), f"{API}/tarball/{SHA}")


class RawStrategy(GithubBase):
    def raw(self, path, body):
        self.routes[f"https://raw.githubusercontent.com/o/r/{SHA}/{path}"] = httpx.Response(200, content=body)

    async def test_raw_strategy_skips_symlink_and_submodule_entries(self):
        self.raw("docs/a.md", b"aaaaa")
        self.raw("docs/sub/b.md", b"bbbbbbb")
        info = await self.resolve("main/docs")
        async with self.fetcher() as f:
            out = await github.fetch_subpath_raw(f, info, self.tmp, max_bytes=10_000, max_entries=100)
        self.assertEqual((out["files"], out["bytes"]), (2, 12))
        self.assertEqual(out["skipped"], [("link", "link")])
        self.assertEqual(sorted(str(p.relative_to(self.tmp)) for p in self.tmp.rglob("*")),
                         ["a.md", "sub", "sub/b.md"])
        self.assertFalse(any("README" in c for c in self.calls if "raw." in c))

    async def test_tree_path_traversal_rejected(self):
        info = github.RepoInfo(owner="o", repo="r", default_branch="main", ref="main", sha=SHA, subpath="docs",
                               private=False, size_kb=1, files=1, bytes=1, truncated=False, has_submodules=False,
                               blobs=[("docs/../../etc/passwd", 1, "100644")])
        async with self.fetcher() as f:
            await self.assertCode("unsafe_path", github.fetch_subpath_raw(f, info, self.tmp, max_bytes=10, max_entries=10))
        self.assertEqual(list(self.tmp.iterdir()), [])

    async def test_caps_checked_before_any_download(self):
        info = await self.resolve("main/docs")
        async with self.fetcher() as f:
            await self.assertCode("too_large", github.fetch_subpath_raw(f, info, self.tmp, max_bytes=5, max_entries=100))
            await self.assertCode("too_many_entries", github.fetch_subpath_raw(f, info, self.tmp, max_bytes=99, max_entries=1))
        self.assertFalse(any("raw." in c for c in self.calls))


class Gists(GithubBase):
    async def test_gist_files_and_names(self):
        self.routes["https://api.github.com/gists/abc123"] = httpx.Response(200, json={"files": {
            "hello.rb": {"raw_url": "https://gist.githubusercontent.com/u/abc123/raw/x/hello.rb", "size": 5},
            "../evil.sh": {"raw_url": "https://gist.githubusercontent.com/u/abc123/raw/x/evil.sh", "size": 4},
            ".import.json": {"raw_url": "https://gist.githubusercontent.com/u/abc123/raw/x/i.json", "size": 2},
            "plain.txt": {"raw_url": "http://gist.githubusercontent.com/insecure", "size": 1},
        }})
        self.routes["https://gist.githubusercontent.com/u/abc123/raw/x/hello.rb"] = httpx.Response(200, content=b"puts1")
        self.routes["https://gist.githubusercontent.com/u/abc123/raw/x/evil.sh"] = httpx.Response(200, content=b"rm -")
        self.routes["https://gist.githubusercontent.com/u/abc123/raw/x/i.json"] = httpx.Response(200, content=b"{}")
        async with self.fetcher() as f:
            out = await github.fetch_gist(f, "abc123", self.tmp, max_bytes=100)
        self.assertEqual(out["files"], 3)
        # Leading dots are trimmed, so neither a traversal nor a reserved name survives.
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["_evil.sh", "hello.rb", "import.json"])

    async def test_blob_and_raw_links_become_raw_urls(self):
        self.assertEqual(github.raw_file_url({"owner": "o", "repo": "r", "rest": "main/docs/a b.md"}),
                         "https://raw.githubusercontent.com/o/r/main/docs/a%20b.md")
        self.assertEqual(github.raw_file_url({"owner": "o", "repo": "r", "ref": "v1", "path": "x.txt"}),
                         "https://raw.githubusercontent.com/o/r/v1/x.txt")


if __name__ == "__main__":
    unittest.main()
