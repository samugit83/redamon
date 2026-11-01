"""R6: TruffleHog changes no regex finding's id.

A js_recon Secret's id (rule name, matched text, file) is what mutes, Priority
Board verdicts, fix items and node-filter rules attach to. The TruffleHog
merge keeps a regex finding's identity whole, so the ids the regex engine
produces on the false-positive lab's bundles must be the ones recorded before
TruffleHog was wired in (`fixtures/js_recon_secret_ids_golden.json`, ids
only). The bundles are the lab's committed files; their keys are invented.

    python recon/tests/test_regression_js_recon_secret_ids_stable.py --regen
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "js_recon_secret_ids_golden.json"
LAB_JS = PROJECT_ROOT / "testing" / "guinea_pigs" / "fp_regression_target" / "static" / "js"


def ids() -> dict:
    out = {}
    for path in sorted(LAB_JS.glob("*.js")):
        findings, _ = patterns.scan_js_content(path.read_text(encoding="utf-8"), f"http://lab.test/js/{path.name}")
        out[path.name] = sorted([f["name"], f["id"]] for f in findings)
    return out


class SecretIdsStable(unittest.TestCase):
    def setUp(self):
        if not LAB_JS.is_dir():
            self.skipTest("the fp regression lab is not in this checkout")

    def test_the_regex_ids_are_the_recorded_ones(self):
        self.assertEqual(ids(), json.loads(GOLDEN.read_text()))


if __name__ == "__main__":
    if "--regen" in sys.argv:
        GOLDEN.write_text(json.dumps(ids(), indent=1, sort_keys=True) + "\n")
        print(f"wrote {GOLDEN}")
    else:
        unittest.main()
