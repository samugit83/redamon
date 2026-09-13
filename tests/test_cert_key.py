"""build_cert_key: the deterministic Certificate identity used by every writer.

Two writers observing the SAME certificate must produce the SAME key, or the
re-key (Phase 0.2) degrades back to the subject_cn collision it exists to fix.

Run: python -m unittest tests.test_cert_key
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.cert_key import build_cert_key  # noqa: E402


class TestBuildCertKey(unittest.TestCase):
    def test_fingerprint_wins_and_is_lowercased(self):
        self.assertEqual(build_cert_key(fingerprint_sha256="A1B2C3"), "sha256:a1b2c3")

    def test_two_sources_same_fingerprint_converge(self):
        # tlsx (upper) and GVM (lower) seeing one cert -> one node.
        self.assertEqual(
            build_cert_key(fingerprint_sha256="FF00", subject_cn="a.com"),
            build_cert_key(fingerprint_sha256="ff00", subject_cn="a.com"),
        )

    def test_surrogate_when_no_fingerprint(self):
        key = build_cert_key(subject_cn="a.com", issuer="LE", not_before="x", not_after="y")
        self.assertTrue(key.startswith("surrogate:"))
        # deterministic across calls
        self.assertEqual(
            key, build_cert_key(subject_cn="a.com", issuer="LE", not_before="x", not_after="y"))

    def test_surrogate_httpx_and_fofa_converge_on_same_fields(self):
        # httpx and FOFA have no fingerprint; same CN+issuer -> same surrogate.
        self.assertEqual(
            build_cert_key(subject_cn="a.com", issuer="DigiCert"),
            build_cert_key(subject_cn="a.com", issuer="DigiCert"),
        )

    def test_empty_cn_still_produces_a_key(self):
        # SAN-only cert (empty CN) must not collapse to a null key.
        key = build_cert_key(subject_cn="", issuer="LE", not_before="a", not_after="b")
        self.assertTrue(key.startswith("surrogate:"))
        self.assertNotEqual(key, build_cert_key())  # differs from the all-empty key

    def test_blank_fingerprint_falls_through_to_surrogate(self):
        key = build_cert_key(fingerprint_sha256="   ", subject_cn="a.com")
        self.assertTrue(key.startswith("surrogate:"))

    def test_different_certs_get_different_keys(self):
        self.assertNotEqual(
            build_cert_key(subject_cn="a.com", issuer="LE"),
            build_cert_key(subject_cn="b.com", issuer="LE"),
        )


if __name__ == "__main__":
    unittest.main()
