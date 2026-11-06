"""The urlscan lab's two recon-side hooks are inert unless set.

URLSCAN_API_BASE points the urlscan module at the lab's fake urlscan, and
REDAMON_LAB_CDN_PREFIXES adds the lab's edge subnet to the CDN edge list. In a
deployment both are unset (the orchestrator forwards them only to lab projects),
and the module must then talk to the real urlscan and know only the published
CDN prefixes.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import cdn_ranges as cr  # noqa: E402

_MODULE = PROJECT_ROOT / "recon" / "main_recon_modules" / "urlscan_enrich.py"
LAB_EDGE = "192.88.97.40"


def _load_urlscan(env: dict):
    spec = importlib.util.spec_from_file_location("urlscan_enrich_base_probe", _MODULE)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, env, clear=True):
        spec.loader.exec_module(module)
    return module


def _env_without(*names) -> dict:
    return {k: v for k, v in os.environ.items() if k not in names}


class TestUrlscanApiBase(unittest.TestCase):
    def test_unset_or_blank_is_the_real_api(self):
        for extra in ({}, {"URLSCAN_API_BASE": ""}, {"URLSCAN_API_BASE": "  "}):
            m = _load_urlscan({**_env_without("URLSCAN_API_BASE"), **extra})
            self.assertEqual(m.URLSCAN_API_BASE, "https://urlscan.io/api/v1")

    def test_set_points_the_search_at_the_fake(self):
        m = _load_urlscan({**_env_without("URLSCAN_API_BASE"),
                           "URLSCAN_API_BASE": "http://192.88.97.30/api/v1"})
        self.assertEqual(m.URLSCAN_API_BASE, "http://192.88.97.30/api/v1")


class TestLabCdnPrefixes(unittest.TestCase):
    def test_unset_or_blank_adds_no_edge_network(self):
        for extra in ({}, {"REDAMON_LAB_CDN_PREFIXES": ""}, {"REDAMON_LAB_CDN_PREFIXES": " , "}):
            with patch.dict(os.environ, {**_env_without("REDAMON_LAB_CDN_PREFIXES"), **extra},
                            clear=True):
                self.assertEqual(cr._lab_edge_networks(), [])
                self.assertIsNone(cr.edge_cdn_for_ip(LAB_EDGE))

    def test_set_makes_the_lab_edge_a_cdn(self):
        with patch.dict(os.environ, {**_env_without("REDAMON_LAB_CDN_PREFIXES"),
                                     "REDAMON_LAB_CDN_PREFIXES": f"{LAB_EDGE}/32, bogus"},
                        clear=True):
            self.assertEqual(cr.edge_cdn_for_ip(LAB_EDGE), "cloudflare")
            # The neighbour on the same subnet (the hidden origin) stays an origin.
            self.assertIsNone(cr.edge_cdn_for_ip("192.88.97.41"))


if __name__ == "__main__":
    unittest.main()
