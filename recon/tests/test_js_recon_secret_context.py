"""The text stored around each JS secret (plan 05.1).

The context is what the Priority Board and a reader see next to a Secret, so it
must show where the match sits and must never carry a raw key: not the match
itself, and not a neighbour key on the same minified line. Every key here is
synthetic (right format, random characters).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns

AWS_KEY = "AKIA" + "Q7R2M9X4K1T8B3V6"
GH_TOKEN = "ghp_" + "r8Tq2LmZ7xKp4Wn9Yc3Vb6Hd1Jf5Gs0Ae2Ui"
STRIPE_KEY = "sk_live_" + "4fT9qZ2mX7cV1bN8kL3pR6sW"
URL = "https://app.example.com/static/main.js"


def _filler(length: int) -> str:
    """Minified-looking code with no secret and no long base64 run."""
    unit = "var q=function(a,b){return a+b};"
    return (unit * (length // len(unit) + 1))[:length]


def _by_name(findings: list) -> dict:
    return {f["name"]: f for f in findings}


class TestContextOnALongMinifiedLine(unittest.TestCase):
    """A 20,000-character line holding two keys 100 characters apart."""

    def setUp(self):
        gap = _filler(100)
        line = _filler(9000) + "k1=\"" + AWS_KEY + "\";" + gap + "k2=\"" + GH_TOKEN + "\";"
        line += _filler(20000 - len(line))
        self.assertEqual(len(line), 20000)
        findings, _ = patterns.scan_js_content("/*! license */\n" + line + "\n", URL)
        self.found = _by_name(findings)

    def test_both_keys_are_found(self):
        self.assertIn("AWS Access Key ID", self.found)
        self.assertIn("GitHub Token Classic", self.found)

    def test_the_context_shows_the_match_position(self):
        for name in ("AWS Access Key ID", "GitHub Token Classic"):
            finding = self.found[name]
            with self.subTest(name=name):
                self.assertIn(finding["redacted_value"], finding["context"])
                self.assertIn("var q=function", finding["context"])

    def test_neither_raw_key_is_in_any_context(self):
        for name in ("AWS Access Key ID", "GitHub Token Classic"):
            context = self.found[name]["context"]
            with self.subTest(name=name):
                self.assertNotIn(AWS_KEY, context)
                self.assertNotIn(GH_TOKEN, context)

    def test_the_neighbour_shows_as_its_redacted_form(self):
        aws = self.found["AWS Access Key ID"]
        gh = self.found["GitHub Token Classic"]
        self.assertIn(gh["redacted_value"], aws["context"])
        self.assertIn(aws["redacted_value"], gh["context"])

    def test_the_context_is_a_character_window(self):
        for finding in self.found.values():
            self.assertLessEqual(len(finding["context"]), patterns.CONTEXT_MAX_CHARS)


class TestContextOnAMultiLineFileWithALongLine(unittest.TestCase):
    """The old code switched to a character window only for files of three
    lines or fewer, and kept the first 500 characters of the surrounding lines
    otherwise: the match was often not in them at all."""

    def test_a_match_deep_in_a_long_line_is_still_in_its_context(self):
        content = "\n".join([
            "// a",
            "// b",
            _filler(5000) + "token=\"" + AWS_KEY + "\";" + _filler(3000),
            "// d",
            "// e",
        ])
        finding = _by_name(patterns.scan_js_content(content, URL)[0])["AWS Access Key ID"]
        self.assertIn(finding["redacted_value"], finding["context"])
        self.assertNotIn(AWS_KEY, finding["context"])
        self.assertLessEqual(len(finding["context"]), patterns.CONTEXT_MAX_CHARS)


class TestLineBasedContextOnShortLines(unittest.TestCase):
    """A 5-line file keeps a line-based context, masked."""

    def setUp(self):
        self.content = "\n".join([
            "// config loader",
            "const region = 'eu-west-1';",
            "const awsKey = '" + AWS_KEY + "';",
            "const stripeKey = '" + STRIPE_KEY + "';",
            "export default { region };",
        ])
        self.found = _by_name(patterns.scan_js_content(self.content, URL)[0])

    def test_the_context_holds_the_surrounding_lines(self):
        context = self.found["AWS Access Key ID"]["context"]
        self.assertIn("const region = 'eu-west-1';", context)
        self.assertIn("const awsKey = '", context)
        self.assertIn("const stripeKey = '", context)
        self.assertEqual(context.count("\n"), 2)

    def test_no_raw_key_is_in_any_context(self):
        for name in ("AWS Access Key ID", "Stripe Secret Key"):
            context = self.found[name]["context"]
            with self.subTest(name=name):
                self.assertNotIn(AWS_KEY, context)
                self.assertNotIn(STRIPE_KEY, context)

    def test_each_key_shows_as_its_redacted_form(self):
        aws = self.found["AWS Access Key ID"]
        stripe = self.found["Stripe Secret Key"]
        self.assertIn(aws["redacted_value"], aws["context"])
        self.assertIn(stripe["redacted_value"], aws["context"])


class TestKeysCutByTheWindowEdgeAreMasked(unittest.TestCase):
    """A neighbour key straddling the window edge would leave a raw fragment
    that no pattern matches on its own."""

    def test_no_fragment_of_a_key_at_the_edge_leaks(self):
        # `=` before the neighbour: a key glued to a letter is no key at all.
        line = (_filler(3000) + "a=\"" + AWS_KEY + "\";" + _filler(139) + "="
                + GH_TOKEN + ";" + _filler(3000))
        finding = _by_name(patterns.scan_js_content(line, URL)[0])["AWS Access Key ID"]
        context = finding["context"]
        self.assertNotIn(GH_TOKEN[:8], context)
        self.assertNotIn(GH_TOKEN[-8:], context)


class TestMaskingHelpers(unittest.TestCase):
    def test_redact_matches_the_redacted_value_rule(self):
        self.assertEqual(patterns.redact(AWS_KEY), AWS_KEY[:6] + "..." + AWS_KEY[-4:])
        self.assertEqual(patterns.redact("abcdefgh"), "abc...")
        self.assertEqual(patterns.redact("abc"), "***")

    def test_prose_around_a_generic_keyword_is_not_masked(self):
        content = "\n".join([
            "label({password: \"Forgot your password?\"});",
            "const awsKey = '" + AWS_KEY + "';",
            "",
        ])
        finding = _by_name(patterns.scan_js_content(content, URL)[0])["AWS Access Key ID"]
        self.assertIn("Forgot your password?", finding["context"])


if __name__ == "__main__":
    unittest.main()
