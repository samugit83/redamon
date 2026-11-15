"""AI Navigator citations (plan §8.7): only sections read, unknown ids stripped, the public link
only for a published page, the GitHub mirror always, Home, and the allowlist."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from navigator.citations import CitationRegistry, build_links, url_allowed  # noqa: E402


class CitationsTest(unittest.TestCase):
    def test_published_page_links_to_the_docs_site_and_github(self):
        url, mirror = build_links("Scan-Timeline", "creating-a-schedule", "https://www.redamon.org/docs/scan-timeline")
        self.assertEqual(url, "https://www.redamon.org/docs/scan-timeline#creating-a-schedule")
        self.assertEqual(mirror, "https://github.com/samugit83/redamon/wiki/Scan-Timeline#creating-a-schedule")

    def test_unpublished_page_is_cited_on_github_only(self):
        url, mirror = build_links("AI-Navigator", "intro", None)
        self.assertEqual(url, mirror)
        self.assertTrue(url.startswith("https://github.com/samugit83/redamon/wiki/AI-Navigator"))

    def test_home(self):
        self.assertEqual(build_links("Home", None, "https://www.redamon.org/docs"),
                         ("https://www.redamon.org/docs", "https://github.com/samugit83/redamon/wiki"))

    def test_a_forged_public_url_is_ignored(self):
        url, _ = build_links("X", "a", "https://evil.example/docs/x")
        self.assertTrue(url.startswith("https://github.com/"))
        url, _ = build_links("X", "a", "https://www.redamon.org/docs/x?y=1")
        self.assertTrue(url.startswith("https://github.com/"))

    def test_an_anchor_outside_the_allowlist_falls_back_to_the_page(self):
        url, mirror = build_links("Page", "café", "https://www.redamon.org/docs/page")
        self.assertEqual(url, "https://www.redamon.org/docs/page")
        self.assertEqual(mirror, "https://github.com/samugit83/redamon/wiki/Page")

    def test_allocation_reuses_ids_and_finalize_strips_unknown_markers(self):
        reg = CitationRegistry()
        a = reg.allocate("Scan-Timeline", "scans", "Scan Timeline", "Scans", None)
        b = reg.allocate("Home", "", "RedAmon Wiki", "RedAmon Wiki", "https://www.redamon.org/docs")
        again = reg.allocate("Scan-Timeline", "scans", "Scan Timeline", "Scans", None)
        self.assertEqual((a.id, b.id, again.id), ("S1", "S2", "S1"))
        text, used = reg.finalize("See [S2] and [S1], not [S9]. Again [S2].")
        self.assertEqual(text, "See [S2] and [S1], not . Again [S2].")
        self.assertEqual([c.id for c in used], ["S2", "S1"])

    def test_allowlist(self):
        self.assertTrue(url_allowed("https://www.redamon.org/docs/scan-timeline#scans"))
        self.assertTrue(url_allowed("https://github.com/samugit83/redamon/wiki/Scan-Timeline"))
        for bad in ("http://www.redamon.org/docs", "https://www.redamon.org.evil/docs",
                    "https://github.com/other/redamon/wiki", "javascript:alert(1)"):
            self.assertFalse(url_allowed(bad), bad)


if __name__ == "__main__":
    unittest.main()
