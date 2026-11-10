"""graph_db/display_only.py: the display-only secret fields and the strip the
agent's generic graph output applies to them."""
import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.display_only import DISPLAY_ONLY_PROPS, strip_display_only  # noqa: E402


class TestStrip(unittest.TestCase):
    def test_removes_every_display_key_at_any_depth(self):
        node = {"id": "s1", "secret_value": "AKIA-REAL", "masked_url": "https://a.test/?k=***",
                "nested": [{"unmasked_url": "https://a.test/?k=v", "name": "x"}],
                "pair": ({"paired_secret": "s3cr3t", "keep": 1},)}
        out = strip_display_only(node)
        self.assertEqual(out, {"id": "s1", "masked_url": "https://a.test/?k=***",
                               "nested": [{"name": "x"}], "pair": ({"keep": 1},)})
        self.assertEqual(node["secret_value"], "AKIA-REAL")

    def test_scalars_pass_through(self):
        self.assertEqual(strip_display_only("text"), "text")
        self.assertIsNone(strip_display_only(None))


class TestWebappMirror(unittest.TestCase):
    """webapp/src/lib/secrets/secretProps.ts lists the same keys."""

    def test_the_typescript_list_matches(self):
        path = os.path.join(_REPO, "webapp", "src", "lib", "secrets", "secretProps.ts")
        if not os.path.exists(path):
            self.skipTest("webapp source not mounted")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        block = re.search(r"DISPLAY_ONLY_PROPS[^=]*=\s*new Set\(\[(.*?)\]\)", text, re.S)
        self.assertIsNotNone(block, "DISPLAY_ONLY_PROPS not found in secretProps.ts")
        keys = set(re.findall(r"'([a-z_]+)'", block.group(1)))
        self.assertEqual(keys, set(DISPLAY_ONLY_PROPS))


if __name__ == "__main__":
    unittest.main()
