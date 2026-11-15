"""AI Navigator's wiki index (plan §8.6): sections, the github-slugger port, exclusions, the banner,
the rebuild on change, an empty checkout, and no path traversal."""
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from navigator import wiki_index as wi  # noqa: E402
from navigator_fakes import write_wiki  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


class SluggerTest(unittest.TestCase):
    def test_github_rules(self):
        self.assertEqual(wi.github_slug("Files Tab — Walkthrough"), "files-tab--walkthrough")
        self.assertEqual(wi.github_slug("Step 2: Configure (optional)"), "step-2-configure-optional")
        self.assertEqual(wi.github_slug("Café & Crème"), "café--crème")
        self.assertEqual(wi.github_slug("snake_case and-dash"), "snake_case-and-dash")
        self.assertEqual(wi.github_slug("🚀 Launch"), "-launch")

    def test_duplicates_get_a_counter(self):
        s = wi.Slugger()
        self.assertEqual([s.slug("Scans"), s.slug("Scans"), s.slug("Scans")], ["scans", "scans-1", "scans-2"])

    def test_inline_markdown_is_stripped_before_slugging(self):
        self.assertEqual(wi.github_slug(wi.strip_inline_markdown("The `ai_*` [link](X) **bold**")), "the-ai_-link-bold")


class IndexTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        write_wiki(self.tmp.name)
        self.idx = wi.build_index(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_pages_and_exclusions(self):
        self.assertEqual(sorted(self.idx.pages), ["Home", "Scan-Timeline", "Unpublished-Page"])
        self.assertIn("Scan Timeline", self.idx.sidebar)
        self.assertNotIn("Footer", " ".join(self.idx.pages))

    def test_sections_anchors_and_paths(self):
        page = self.idx.resolve_page("Scan-Timeline")
        self.assertEqual(page.title, "Scan Timeline")
        self.assertEqual([s.anchor for s in page.sections], ["scan-timeline", "scans", "creating-a-schedule", "scans-1"])
        sched = self.idx.section(page, "creating-a-schedule")
        self.assertEqual(sched.heading_path, "Scan Timeline › Scans › Creating a schedule")
        self.assertIn("Creating a schedule", self.idx.section(page, "scans").full_text)

    def test_banner_is_read_then_stripped_and_badges_go(self):
        page = self.idx.resolve_page("Scan-Timeline")
        self.assertEqual(page.public_url, "https://www.redamon.org/docs/scan-timeline")
        text = " ".join(s.full_text for s in page.sections)
        self.assertNotIn("canonical", text)
        self.assertNotIn("badge.svg", text)
        self.assertEqual(page.summary, "The timeline lists every scan.")
        self.assertIsNone(self.idx.resolve_page("Unpublished-Page").public_url)

    def test_a_banner_url_outside_the_allowlist_is_ignored(self):
        with open(os.path.join(self.tmp.name, "Forged.md"), "w") as fh:
            fh.write("<!-- canonical-banner -->\n[x](https://evil.example/docs/x)\n<!-- canonical-banner -->\n# Forged\n")
        self.assertIsNone(wi.build_index(self.tmp.name).resolve_page("Forged").public_url)

    def test_unicode_heading_anchor(self):
        page = self.idx.resolve_page("Unpublished-Page")
        self.assertIn("café--crème--notes", [s.anchor for s in page.sections])

    def test_search_ranks_the_matching_section(self):
        hits = self.idx.search("schedule weekly scan", 3)
        self.assertEqual((hits[0][0].page, hits[0][0].anchor), ("Scan-Timeline", "creating-a-schedule"))

    def test_lookups_never_follow_a_path(self):
        for name in ("../etc/passwd", "/etc/passwd", "hacklab/Secret", "..%2Fetc", "Scan-Timeline/../Home",
                     "Scan Timeline\\..", "", None, 42):
            self.assertIsNone(self.idx.resolve_page(name), name)
        self.assertEqual(self.idx.resolve_page("scan timeline").name, "Scan-Timeline")
        self.assertEqual(self.idx.resolve_page("Scan-Timeline.md").name, "Scan-Timeline")

    def test_rebuild_on_modification(self):
        holder = wi.WikiIndexHolder(self.tmp.name)
        first = holder.get()
        path = os.path.join(self.tmp.name, "New-Page.md")
        with open(path, "w") as fh:
            fh.write("# New Page\n\nfresh\n")
        future = time.time() + 5
        os.utime(path, (future, future))
        self.assertIs(holder.get(), first)  # within the recheck window
        holder.force_stale()
        second = holder.get()
        self.assertIsNot(second, first)
        self.assertIsNotNone(second.resolve_page("New-Page"))

    def test_empty_checkout(self):
        with tempfile.TemporaryDirectory() as empty:
            idx = wi.WikiIndexHolder(empty).get()
            self.assertFalse(idx.present)
            self.assertEqual(idx.search("anything", 3), [])
        self.assertFalse(wi.WikiIndexHolder("/nonexistent/wiki").get().present)


class RealWikiTest(unittest.TestCase):
    def setUp(self):
        from tooling.scripts.wiki_checkout import SKIP_REASON, wiki_checkout_present
        if not wiki_checkout_present(REPO / "redamon.wiki"):
            self.skipTest(SKIP_REASON)
        self.idx = wi.build_index(str(REPO / "redamon.wiki"))

    def test_every_anchor_of_the_ui_wiki_links_resolves(self):
        src = (REPO / "webapp/src/components/ui/WikiInfoButton/wiki-links.ts").read_text(encoding="utf-8")
        pairs = re.findall(r"page:\s*'([^']+)'(?:,\s*anchor:\s*'([^']*)')?", src)
        self.assertGreater(len(pairs), 20)
        missing = []
        for page_name, anchor in pairs:
            page = self.idx.resolve_page(page_name)
            if page is None or (anchor and self.idx.section(page, anchor) is None):
                missing.append(f"{page_name}#{anchor}")
        self.assertEqual(missing, [])

    def test_sub_directories_are_never_indexed(self):
        for name in self.idx.pages:
            self.assertNotIn("/", name)
        self.assertNotIn("_Footer", self.idx.pages)


if __name__ == "__main__":
    unittest.main()
