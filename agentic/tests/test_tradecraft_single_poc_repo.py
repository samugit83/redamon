"""Single-PoC GitHub repos are typed as repositories, never as CVE archives.

Regression for the "PoC not found" loop of the "agent stuck" incident: a repo built around one
PoC (two CVE ids repeated across its README) was auto-typed cve-poc-db. That type only probes
archive paths ({year}/{CVE}.md), which such a repo does not have, so every lookup answered
"PoC not found". Since the cut-over (T9.2) the detection is 2.0's (``tradecraft.ingest.detect``,
1.x's signature kept). The rest of 1.x's checks are 2.0's own: a CVE-named repository without
year folders is retyped github-repo (test_tradecraft_ingest_builders.py::
test_cve_without_year_folders_is_retyped), an archive miss reads the README that names the CVE
and a GitHub limit is an error, not a miss (test_tradecraft_cve_patterns.py).

Run: ./agentic/run_tests.sh tests/test_tradecraft_single_poc_repo.py
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tradecraft.ingest.detect import detect_type  # noqa: E402

CVE_A, CVE_B = "CVE-2026-109618", "CVE-2026-109619"
POC_README = (
    f"# php2shell PoC\n\nProof of concept for {CVE_A} and {CVE_B}.\n\n"
    + "\n".join(f"## Chain {c}: {CVE_A} / {CVE_B} exploitation step" for c in "ABCDE") * 6
    + "\n```python\nprint('pwn')\n```\n"
)


class DetectType(unittest.TestCase):
    def test_single_poc_readme_is_not_an_archive(self):
        # Two ids repeated well over 20 times: the old count rule said cve-poc-db.
        self.assertGreater(POC_README.count("CVE-"), 20)
        self.assertEqual(detect_type("https://github.com/example-owner/php2shell-poc", POC_README),
                         "github-repo")

    def test_repo_named_for_one_cve_is_not_an_archive(self):
        self.assertEqual(detect_type("https://github.com/example-owner/CVE-2026-109618-poc", ""),
                         "github-repo")

    def test_archives_are_still_detected(self):
        self.assertEqual(detect_type("https://github.com/trickest/cve", ""), "cve-poc-db")
        self.assertEqual(detect_type("https://github.com/example-owner/cvelist", ""), "cve-poc-db")
        many = "\n".join(f"CVE-2024-{i:05d}" for i in range(25))
        self.assertEqual(detect_type("https://github.com/example-owner/poc-collection", many),
                         "cve-poc-db")

    def test_case_insensitive_ids_count_once(self):
        body = " ".join([f"cve-2024-{i:05d} CVE-2024-{i:05d}" for i in range(15)])
        self.assertEqual(detect_type("https://github.com/example-owner/notes", body), "github-repo")


if __name__ == "__main__":
    unittest.main()
