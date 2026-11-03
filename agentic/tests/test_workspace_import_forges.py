"""Forge metadata and archive URLs, as experiment E2 found them."""
from __future__ import annotations

import unittest

import httpx

from workspace_import import forges
from workspace_import.errors import ImportFailure
from workspace_import.fetch import GuardedFetcher


class Builders(unittest.TestCase):
    def test_metadata_and_archive_urls(self):
        gl = {"project": "group/sub/project"}
        self.assertEqual(forges.metadata_url("gitlab-repo", gl),
                         "https://gitlab.com/api/v4/projects/group%2Fsub%2Fproject")
        self.assertEqual(forges.archive_url("gitlab-repo", gl, {"id": 42}, "main"),
                         "https://gitlab.com/api/v4/projects/42/repository/archive.tar.gz?sha=main")
        bb = {"project": "ws/repo"}
        self.assertEqual(forges.metadata_url("bitbucket-repo", bb), "https://api.bitbucket.org/2.0/repositories/ws/repo")
        self.assertEqual(forges.archive_url("bitbucket-repo", bb, {}, "master"), "https://bitbucket.org/ws/repo/get/master.tar.gz")
        cb = {"project": "o/r"}
        self.assertEqual(forges.metadata_url("codeberg-repo", cb), "https://codeberg.org/api/v1/repos/o/r")
        self.assertEqual(forges.archive_url("codeberg-repo", cb, {}, "release/1"),
                         "https://codeberg.org/o/r/archive/release%2F1.tar.gz")
        self.assertEqual(forges.default_branch("bitbucket-repo", {"mainbranch": {"name": "master"}}), "master")
        self.assertEqual(forges.default_branch("gitlab-repo", {"default_branch": "main"}), "main")


class Resolve(unittest.IsolatedAsyncioTestCase):
    async def resolve(self, kind, parts, resp):
        f = GuardedFetcher(transport=httpx.MockTransport(lambda _r: resp), assert_safe=lambda _u: None)
        async with f:
            return await forges.resolve_forge(f, kind, parts)

    async def test_resolves_each_forge(self):
        info = await self.resolve("gitlab-repo", {"project": "g/p"},
                                  httpx.Response(200, json={"id": 7, "default_branch": "main", "visibility": "public"}))
        self.assertEqual((info.ref, info.private, info.host), ("main", False, "gitlab.com"))
        self.assertIn("/projects/7/repository/archive.tar.gz", info.archive_url)
        info = await self.resolve("bitbucket-repo", {"project": "ws/r"},
                                  httpx.Response(200, json={"mainbranch": {"name": "master"}, "is_private": False}))
        self.assertEqual((info.ref, info.host), ("master", "bitbucket.org"))
        info = await self.resolve("codeberg-repo", {"project": "o/r"},
                                  httpx.Response(200, json={"default_branch": "main", "private": False}))
        self.assertEqual(info.archive_url, "https://codeberg.org/o/r/archive/main.tar.gz")

    async def test_failures_are_codes(self):
        for resp, code in ((httpx.Response(404), "not_found"), (httpx.Response(403), "not_found"),
                           (httpx.Response(429), "rate_limited"), (httpx.Response(500), "upstream_status"),
                           (httpx.Response(200, json={"id": 1}), "ref_not_found")):
            with self.assertRaises(ImportFailure) as ctx:
                await self.resolve("gitlab-repo", {"project": "g/p"}, resp)
            self.assertEqual(ctx.exception.code, code)


if __name__ == "__main__":
    unittest.main()
