"""Item 7: the origin writer keeps the own-file check and the urlscan date.

The writer copies a fixed list of finding keys; file_match, own_file and
urlscan_seen_at must be on it or the evidence is dropped. Names are
example.test; the address is the lab subnet.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


FINDING = {"type": "waf_bypass", "severity": "high", "name": "Origin Server Exposed (CDN Bypass)",
           "subdomain": "shop.example.test", "matched_ip": "192.88.97.7", "url": "https://192.88.97.7:443",
           "origin_discovery_method": "ip_history", "origin_source": "urlscan_history",
           "confidence_score": 91.0, "port": 443, "match_method": "host-header", "status_code": 200,
           "file_match": True, "own_file": "/assets/app.8f3a91c2.js", "urlscan_seen_at": "2025-12-20",
           "evidence": "shop.example.test → 192.88.97.7:443 (urlscan_history, seen 2025-12-20)",
           "source": "origin_discovery"}


class TestOriginWriter(unittest.TestCase):
    def test_the_new_keys_and_source_values_are_stored(self):
        w = _Writer()
        w.update_graph_from_origin_discovery(
            {"domain": "example.test", "domains": ["example.test"],
             "origin_discovery": {"confirmed": [FINDING]}}, "u1", "p1")
        vuln = next(p for q, p in w.session.calls if "MERGE (v:Vulnerability" in q)
        props = vuln["props"]
        self.assertEqual((props["file_match"], props["own_file"], props["urlscan_seen_at"]),
                         (True, "/assets/app.8f3a91c2.js", "2025-12-20"))
        self.assertEqual((props["origin_source"], props["origin_discovery_method"]),
                         ("urlscan_history", "ip_history"))

    def test_a_finding_without_an_own_file_writes_no_file_keys(self):
        w = _Writer()
        bare = {k: v for k, v in FINDING.items() if k not in ("file_match", "own_file", "urlscan_seen_at")}
        w.update_graph_from_origin_discovery(
            {"domain": "example.test", "domains": ["example.test"],
             "origin_discovery": {"confirmed": [bare]}}, "u1", "p1")
        props = next(p for q, p in w.session.calls if "MERGE (v:Vulnerability" in q)["props"]
        self.assertNotIn("file_match", props)


if __name__ == "__main__":
    unittest.main()
