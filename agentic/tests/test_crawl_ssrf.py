"""
STRIDE I18 — the tradecraft crawl must not be usable as an SSRF probe.

Part A: assert_safe_fetch_url blocks metadata / RFC-1918 / loopback / CGNAT /
link-local (incl. IPv4-mapped) and non-http(s), allows public + unresolvable.

Parts B and C (1.x's crawl: a redirect into 169.254.169.254 refused hop by hop, and a
refusal never retried in the browser) left with the 1.x crawl at the cut-over (T9.2). The 2.0
crawl holds both: ``test_tradecraft_fetcher_contract_integration.py`` (the real fetcher's
``test_redirect_to_private_address_refused``) and
``test_tradecraft_ingest_crawl.py::test_crawl_fetch_never_sends_a_refused_address_to_the_browser``.

Run inside the agent container:
    python -m unittest tests.test_crawl_ssrf
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.fetch_guard import assert_safe_fetch_url, UnsafeFetchURLError  # noqa: E402

PUBLIC = "http://93.184.216.34/"


class GuardPolicy(unittest.TestCase):
    def test_allows_public(self):
        assert_safe_fetch_url(PUBLIC)  # no raise

    def test_allows_unresolvable(self):
        # Stub the resolver: some home and ISP resolvers answer every unknown name
        # (through their search domain) with 127.0.0.1, which a live lookup would
        # turn into a refusal on those networks.
        with patch("orchestrator_helpers.fetch_guard._resolve_ips", return_value=[]):
            assert_safe_fetch_url("http://nonexistent.invalid.example/")  # DNS fails → allowed

    def test_blocks_metadata_and_private(self):
        for bad in [
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/",
            "http://127.0.0.1/",
            "http://192.168.1.10/",
            "http://172.16.0.1/",
            "http://100.100.100.200/",          # CGNAT (Alibaba metadata)
            "http://[::ffff:169.254.169.254]/",  # IPv4-mapped IPv6
        ]:
            with self.assertRaises(UnsafeFetchURLError, msg=bad):
                assert_safe_fetch_url(bad)

    def test_blocks_bad_scheme_and_no_host(self):
        for bad in ["file:///etc/passwd", "gopher://x/", "http://"]:
            with self.assertRaises(UnsafeFetchURLError, msg=bad):
                assert_safe_fetch_url(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
