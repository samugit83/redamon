"""URL and probe classification for URL imports."""
from __future__ import annotations

import unittest

import httpx

from workspace_import import detect
from workspace_import.detect import classify_probe, classify_url, mirror_name, suggested_name
from workspace_import.errors import ImportFailure
from workspace_import.fetch import Probe

URL_TABLE = [
    ("https://github.com/o/r", "github-repo", {"owner": "o", "repo": "r", "rest": ""}),
    ("https://github.com/o/r.git", "github-repo", {"owner": "o", "repo": "r", "rest": ""}),
    ("https://www.github.com/o/r/", "github-repo", {"owner": "o", "repo": "r", "rest": ""}),
    ("https://github.com/o/r/tree/main", "github-repo", {"owner": "o", "repo": "r", "rest": "main"}),
    ("https://github.com/o/r/tree/main/docs/api", "github-repo", {"owner": "o", "repo": "r", "rest": "main/docs/api"}),
    ("https://github.com/o/r/tree/feature/x/src", "github-repo", {"owner": "o", "repo": "r", "rest": "feature/x/src"}),
    ("https://github.com/o/r/blob/main/README.md", "github-file", {"owner": "o", "repo": "r", "rest": "main/README.md"}),
    ("https://raw.githubusercontent.com/o/r/main/a/b.txt", "github-file",
     {"owner": "o", "repo": "r", "ref": "main", "path": "a/b.txt"}),
    ("https://gist.github.com/0123456789abcdef", "github-gist", {"id": "0123456789abcdef"}),
    ("https://gist.github.com/someone/0123ABCD", "github-gist", {"id": "0123abcd"}),
    ("https://github.com/o/r/archive/refs/heads/main.zip", "archive", None),
    ("https://github.com/o/r/releases/download/v1/tool.tar.gz", "archive", None),
    ("https://github.com/o/r/releases/download/v1/tool.exe", "file", None),
    ("https://gitlab.com/group/project", "gitlab-repo", {"project": "group/project", "owner": "group", "repo": "project"}),
    ("https://gitlab.com/group/sub/project.git", "gitlab-repo", {"project": "group/sub/project", "owner": "group", "repo": "project"}),
    ("https://gitlab.com/group/project/-/tree/main/docs", "gitlab-repo", {"project": "group/project", "owner": "group", "repo": "project"}),
    ("https://bitbucket.org/ws/repo", "bitbucket-repo", {"project": "ws/repo", "owner": "ws", "repo": "repo"}),
    ("https://bitbucket.org/ws/repo/src/main/", "bitbucket-repo", {"project": "ws/repo", "owner": "ws", "repo": "repo"}),
    ("https://codeberg.org/o/r", "codeberg-repo", {"project": "o/r", "owner": "o", "repo": "r"}),
    ("https://git.example.test/team/tool.git", "git", {"repo": "tool"}),
    ("https://files.example.test/pack.tar.gz", "archive", {}),
    ("https://files.example.test/pack.TGZ", "archive", {}),
    ("https://files.example.test/a/b.zip?x=1", "archive", {}),
    ("https://files.example.test/paper.pdf", None, {}),
    ("https://docs.example.test/guide/", None, {}),
    ("https://example.test", None, {}),
]


class ClassifyUrl(unittest.TestCase):
    def test_url_table(self):
        self.assertGreaterEqual(len(URL_TABLE), 25)
        for url, kind, parts in URL_TABLE:
            with self.subTest(url=url):
                got = classify_url(url)
                self.assertEqual(got.kind, kind)
                if parts is not None:
                    self.assertEqual(got.parts, parts)

    def test_github_pages_that_are_not_importable(self):
        for url in ("https://github.com/o/r/issues/1", "https://github.com/o/r/pull/2",
                    "https://github.com/o/r/wiki", "https://github.com/o", "https://github.com/",
                    "https://gist.github.com/", "https://gitlab.com/group"):
            with self.subTest(url=url):
                with self.assertRaises(ImportFailure) as ctx:
                    classify_url(url)
                self.assertEqual(ctx.exception.code, "kind_not_supported")

    def test_credentials_in_url_refused(self):
        for url in ("https://user:pass@example.test/a.zip", "https://token@github.com/o/r"):
            with self.assertRaises(ImportFailure) as ctx:
                classify_url(url)
            self.assertEqual(ctx.exception.code, "credentials_in_url")

    def test_non_http_scheme_refused(self):
        for url in ("ftp://example.test/a", "file:///etc/passwd", "git@github.com:o/r.git", "javascript:alert(1)"):
            with self.assertRaises(ImportFailure) as ctx:
                classify_url(url)
            self.assertIn(ctx.exception.code, ("unsupported_scheme", "invalid_url"))
        with self.assertRaises(ImportFailure) as ctx:
            classify_url("https:///nohost")
        self.assertEqual(ctx.exception.code, "invalid_url")

    def test_forge_fallback_to_git_when_configured(self):
        orig = detect.FORGE_FALLBACK_TO_GIT
        detect.FORGE_FALLBACK_TO_GIT = frozenset({"bitbucket-repo"})
        try:
            self.assertEqual(classify_url("https://bitbucket.org/ws/repo").kind, "git")
            self.assertEqual(classify_url("https://codeberg.org/o/r").kind, "codeberg-repo")
        finally:
            detect.FORGE_FALLBACK_TO_GIT = orig


def probe(headers=None, head=b"", url="https://x.example.test/dl"):
    return Probe(final_url=url, status=200, headers=httpx.Headers(headers or {}), head=head)


class ClassifyProbe(unittest.TestCase):
    def test_probe_table(self):
        tar = b"\0" * 257 + b"ustar" + b"\0" * 250
        table = [
            ({"content-disposition": 'attachment; filename="x.tar.gz"', "content-type": "text/html"}, b"", "archive"),
            ({"content-disposition": "attachment; filename=paper.pdf"}, b"", "file"),
            ({"content-type": "application/zip"}, b"", "archive"),
            ({"content-type": "application/x-gzip"}, b"", "archive"),
            ({"content-type": "application/pdf"}, b"", "file"),
            ({"content-type": "application/octet-stream"}, b"PK\x03\x04rest", "archive"),
            ({"content-type": "application/octet-stream"}, b"\x1f\x8b\x08", "archive"),
            ({}, b"BZh91AY", "archive"),
            ({}, b"\xfd7zXZ\x00\x00", "archive"),
            ({}, tar, "archive"),
            ({}, b"%PDF-1.7 ...", "file"),
            ({"content-type": "application/octet-stream"}, b"\x00\x01binary", "file"),
            ({"content-type": "text/plain"}, b"just text", "file"),
        ]
        for headers, head, kind in table:
            with self.subTest(headers=headers, head=head[:8]):
                self.assertEqual(classify_probe("https://x.example.test/dl", probe(headers, head)), kind)

    def test_html_signatures_split_docs_site_from_website(self):
        mkdocs = b'<!doctype html><html><head><meta name="generator" content="mkdocs-1.5"></head></html>'
        sphinx = b'<html><head><script src="_static/searchindex.js"></script></head></html>'
        plain = b"<!DOCTYPE html><html><body>Welcome</body></html>"
        self.assertEqual(classify_probe("https://docs.example.test/", probe({"content-type": "text/html"}, mkdocs)), "docs-site")
        self.assertEqual(classify_probe("https://docs.example.test/", probe({}, sphinx)), "docs-site")
        self.assertEqual(classify_probe("https://www.example.test/", probe({"content-type": "text/html; charset=utf-8"}, plain)), "website")

    def test_suggested_names_sanitized(self):
        self.assertEqual(suggested_name("github-repo", {"repo": "r"}), "r")
        self.assertEqual(suggested_name("github-repo", {"repo": "r"}, subpath="Discovery/Web-Content"), "Web-Content")
        self.assertEqual(suggested_name("github-file", {"rest": "main/docs/a.md"}), "a.md")
        self.assertEqual(suggested_name("github-gist", {"id": "0123456789abcdef"}), "gist-01234567")
        self.assertEqual(suggested_name("archive", {}, url="https://f.example.test/pack.tar.gz"), "pack")
        self.assertEqual(suggested_name("archive", {}, disposition="release-1.2.zip"), "release-1.2")
        self.assertEqual(suggested_name("file", {}, url="https://f.example.test/a%2Fb%0A.pdf"), "a_b_.pdf")
        self.assertEqual(suggested_name("file", {}, url="https://f.example.test/"), "download")
        self.assertEqual(mirror_name("https://docs.example.test/"), "docs.example.test")
        self.assertEqual(mirror_name("https://example.test/docs/intro"), "example.test-docs")


if __name__ == "__main__":
    unittest.main()
