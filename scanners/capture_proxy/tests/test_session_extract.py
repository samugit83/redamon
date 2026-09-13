"""Unit tests for session_extract: cookie/bearer/CSRF parsing, never-raise."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from session_extract import extract_session  # noqa: E402


class TestExtract(unittest.TestCase):
    def test_set_cookie_overlays_request_cookie(self):
        rec = {
            "host": "app.target.test",
            "reqHeaders": {"Cookie": "sid=old; theme=dark"},
            "respHeaders": {"Set-Cookie": "sid=fresh; Path=/; HttpOnly"},
        }
        out = extract_session(rec)
        self.assertEqual(out["host"], "app.target.test")
        self.assertIn("sid=fresh", out["cookie"])
        self.assertIn("theme=dark", out["cookie"])
        self.assertNotIn("sid=old", out["cookie"])

    def test_multiple_set_cookie_list(self):
        rec = {"host": "h", "respHeaders": {"Set-Cookie": ["a=1; Path=/", "b=2; Secure"]}}
        out = extract_session(rec)
        self.assertIn("a=1", out["cookie"])
        self.assertIn("b=2", out["cookie"])

    def test_authorization_captured(self):
        rec = {"host": "h", "reqHeaders": {"Authorization": "Bearer XYZ"}}
        self.assertEqual(extract_session(rec)["authorization"], "Bearer XYZ")

    def test_csrf_header_captured_with_case(self):
        rec = {"host": "h", "reqHeaders": {"X-CSRF-Token": "tok123"}}
        self.assertEqual(extract_session(rec)["extra"], {"X-CSRF-Token": "tok123"})

    def test_csrf_hidden_field_from_body(self):
        rec = {"host": "h", "respHeaders": {},
               "respBody": '<form><input name="csrf_token" value="hidden-abc"></form>'}
        self.assertEqual(extract_session(rec)["extra"], {"csrf_token": "hidden-abc"})

    def test_nothing_useful_returns_empty(self):
        self.assertEqual(extract_session({"host": "h", "reqHeaders": {"User-Agent": "x"}}), {})
        self.assertEqual(extract_session({}), {})

    def test_never_raises_on_garbage(self):
        for bad in (None, {"reqHeaders": 42}, {"respHeaders": ["not", "a", "dict"]},
                    {"respBody": 123}, {"reqHeaders": {"Cookie": None}}):
            self.assertIsInstance(extract_session(bad if isinstance(bad, dict) else {}), dict)

    def test_no_host_key_when_empty(self):
        self.assertNotIn("host", extract_session({"reqHeaders": {}}))

    def test_oversized_cookie_is_dropped_not_truncated(self):
        # Truncating produced a corrupt cookie that still passed the downstream
        # length check (which rejects only > cap), so it was stored and then
        # failed every authenticated request silently.
        big = "sid=" + ("a" * 9000)
        out = extract_session({"host": "h", "reqHeaders": {"Cookie": big}})
        self.assertNotIn("cookie", out)

    def test_cookie_at_the_cap_is_kept_intact(self):
        exact = "sid=" + ("a" * (8192 - 4))
        out = extract_session({"host": "h", "reqHeaders": {"Cookie": exact}})
        self.assertEqual(out["cookie"], exact)

    def test_oversized_authorization_is_dropped(self):
        out = extract_session({"host": "h", "reqHeaders": {"Authorization": "Bearer " + "x" * 9000}})
        self.assertNotIn("authorization", out)


if __name__ == "__main__":
    unittest.main()
