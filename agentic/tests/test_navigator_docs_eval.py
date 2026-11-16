"""AI Navigator's documentation retrieval, measured (plan §11 Phase 3): hit@3 of wiki_search on a
synthetic set of questions, each naming the wiki sections a good answer reads
(fixtures/navigator_eval/docs_questions.json). A hit is a top-3 result on an expected section or
one of its sub-sections; the page rate counts any section of an expected page.

The floors sit a little under the measured baseline (page 61/67, section 54/67 on the wiki of
this release), so a wiki edit does not fail it but a retrieval regression does. A question whose
section no longer exists fails on its own: update the set with the wiki.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from navigator import wiki_index as wi  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
QUESTIONS = Path(__file__).resolve().parent / "fixtures" / "navigator_eval" / "docs_questions.json"
PAGE_FLOOR = 0.88
SECTION_FLOOR = 0.75


class DocsRetrievalEvalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tooling.scripts.wiki_checkout import SKIP_REASON, wiki_checkout_present
        if not wiki_checkout_present(REPO / "redamon.wiki"):
            raise unittest.SkipTest(SKIP_REASON)
        cls.idx = wi.build_index(str(REPO / "redamon.wiki"))
        cls.questions = json.loads(QUESTIONS.read_text(encoding="utf-8"))["questions"]

    def _targets(self, q):
        out = []
        for ref in q["expect"]:
            name, anchor = ref.split("#", 1)
            page = self.idx.resolve_page(name)
            sec = self.idx.section(page, anchor) if page else None
            if sec is not None:
                out.append((page.name, sec.path))
        return out

    def test_every_expected_section_exists(self):
        gone = [ref for q in self.questions for ref in q["expect"] if not self._targets({"expect": [ref]})]
        self.assertEqual(gone, [], "the wiki moved these sections: update docs_questions.json")

    def test_hit_at_3(self):
        self.assertGreaterEqual(len(self.questions), 60)
        page_hits = section_hits = 0
        misses = []
        for q in self.questions:
            targets = self._targets(q)
            results = [sec for sec, _ in self.idx.search(q["question"], 3)]
            page_hits += any(r.page == t[0] for r in results for t in targets)
            hit = any(r.page == t[0] and r.path[:len(t[1])] == t[1] for r in results for t in targets)
            section_hits += hit
            if not hit:
                misses.append(f"{q['id']}: {[f'{r.page}#{r.anchor}' for r in results]}")
        n = len(self.questions)
        report = f"page hit@3 {page_hits}/{n}, section hit@3 {section_hits}/{n}; misses:\n" + "\n".join(misses)
        self.assertGreaterEqual(page_hits / n, PAGE_FLOOR, report)
        self.assertGreaterEqual(section_hits / n, SECTION_FLOOR, report)


if __name__ == "__main__":
    unittest.main()
