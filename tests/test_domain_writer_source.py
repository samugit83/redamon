"""F1/F2: a name another source added keeps it on its Subdomain.

The domain writer now creates the Subdomain of a urlscan, certificate-SAN,
uncover or JS Recon name (resolved with the rest), so it carries the DNS
entry's `source`, first writer only. Fixture names are example.test.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402


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


class _Writer(DomainMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _subdomain_writes(entries):
    w = _Writer()
    recon = {"domain": "example.test", "metadata": {"root_domain": "example.test", "org_domain": "example.test"},
             "subdomains": sorted(entries), "dns": {"domain": {}, "subdomains": entries}, "whois": {}}
    w.update_graph_from_domain_discovery(recon, "u1", "p1")
    return {p["name"]: (q, p) for q, p in w.session.calls if "MERGE (s:Subdomain {name: $name" in q}


class TestSubdomainSource(unittest.TestCase):
    def test_the_entry_source_is_kept_first_writer_only(self):
        writes = _subdomain_writes({
            "new.example.test": {"has_records": True, "source": "urlscan",
                                 "ips": {"ipv4": ["192.88.97.11"], "ipv6": []}},
            "www.example.test": {"has_records": True, "ips": {"ipv4": ["192.88.97.10"], "ipv6": []}},
        })
        q, p = writes["new.example.test"]
        self.assertIn("s.source = coalesce(s.source, $source)", q)
        self.assertEqual(p["source"], "urlscan")
        self.assertIsNone(writes["www.example.test"][1]["source"])


if __name__ == "__main__":
    unittest.main()
