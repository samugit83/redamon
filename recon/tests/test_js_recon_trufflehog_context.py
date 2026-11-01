"""Locating a TruffleHog key in its file (rule M1) and the context it carries.

TruffleHog reports `line: 1` for every key in a minified bundle, so the key is
found here by searching its Raw. The context masks every secret of the file,
from either engine, whole; a decoded hit (base64 in `atob()`) is not in the
file literally and gets no context. Every value is synthetic.
"""

from __future__ import annotations

import random
import string
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns
from recon.helpers.js_recon import trufflehog_bridge as th

ALNUM = string.ascii_letters + string.digits


def _rnd(label, n):
    rng = random.Random(f"ctx:{label}")
    return "".join(rng.choice(ALNUM) for _ in range(n))


class Locate(unittest.TestCase):
    def test_a_one_line_megabyte_bundle(self):
        key = "gh" + "p_" + _rnd("k", 36)
        filler = "var a=function(b){return b+1};" * 34000
        content = filler + f'e.t="{key}";' + filler
        self.assertGreater(len(content), 1_000_000)
        line, start, end = th.locate(key, content)
        self.assertEqual(line, 1)
        self.assertEqual(content[start:end], key)

    def test_the_line_of_a_multi_line_file(self):
        key = "gh" + "p_" + _rnd("m", 36)
        self.assertEqual(th.locate(key, f"a\nb\nconst t = '{key}';\n")[0], 3)

    def test_a_decoded_hit_is_not_found(self):
        self.assertIsNone(th.locate("sk" + "_live_" + _rnd("d", 24), 'atob("c2tfbGl2ZV8=")'))


class MaskedContext(unittest.TestCase):
    def test_no_raw_value_from_either_engine(self):
        th_key = "gh" + "p_" + _rnd("th", 36)
        regex_key = "AK" + "IA" + _rnd("rx", 16).upper()
        pair = _rnd("pair", 40)
        content = (f'x({{a:"{regex_key}",s:"{pair}"}});var g="{th_key}";'
                   + "q=1;" * 10)
        line, start, end = th.locate(th_key, content)
        ctx = th.masked_context(content, start, end, {th_key, regex_key, pair})
        for value in (th_key, regex_key, pair):
            self.assertNotIn(value, ctx)
        self.assertIn(patterns.redact(th_key), ctx)
        self.assertLessEqual(len(ctx), patterns.CONTEXT_MAX_CHARS)

    def test_a_secret_cut_by_the_window_edge_is_masked_whole(self):
        th_key = "gh" + "p_" + _rnd("edge", 36)
        far = _rnd("far", 60)
        content = far + "x" * 120 + f'"{th_key}"'
        _, start, end = th.locate(th_key, content)
        ctx = th.masked_context(content, start, end, {th_key, far})
        self.assertNotIn(far[-20:], ctx)

    def test_a_decoded_hit_gets_no_context(self):
        key = "sk" + "_live_" + _rnd("dec", 24)
        manifest = {"f_00001.js": {"url": "https://a.example.com/x.js", "content": 'k=atob("Zm9v")'}}
        r = th.ThResult(detector="Stripe", verified=False, error="", raw=key, file="f_00001.js",
                        line=1, extra={})
        finding = th.map_result(r, manifest, verify=False)
        self.assertEqual(finding["context"], "")
        self.assertEqual(finding["line_number"], 1)


if __name__ == "__main__":
    unittest.main()
