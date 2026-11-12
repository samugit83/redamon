"""Under the RoE ceiling httpx collects no JARM or favicon hash (R-8, B-R8c):
the graph keeps the ones an earlier run stored.

recon/main_recon_modules/http_probe.py drops -jarm and -favicon from the httpx
command while a rate ceiling is in force, since their requests take no token
of httpx's limiter, and records the gap (sources httpx_jarm, httpx_favicon).
A URL entry from such a run has no ``favicon_hash`` and no ``jarm``. The
writer MERGEs with ``SET n += $props``, where a key set to null would erase
the stored value: so neither key may reach the props when the run did not
collect it. Pinned for the Endpoint (favicon_hash, and the AI frontend guess
a favicon match makes) and the Certificate (jarm).

Hermetic: a fake driver records every query; no Neo4j. Names are under
example.com, addresses RFC 5737.
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

from graph_db.mixins.recon.http_mixin import HttpMixin  # noqa: E402

URL = "https://www.example.com"
CERT = {"subject_cn": "www.example.com", "issuer": ["Example CA"],
        "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
        "fingerprint_sha256": "ab" * 32, "san": ["www.example.com"]}


class _Result:
    def single(self):
        return None

    def __iter__(self):
        return iter([])


class _Session:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((" ".join(query.split()), kwargs))
        return _Result()


class _Driver:
    def __init__(self, queries):
        self.queries = queries

    def session(self):
        return _Session(self.queries)


class _Client(HttpMixin):
    def __init__(self):
        self.queries = []
        self.driver = _Driver(self.queries)

    def props(self, merge_prefix):
        return [kw["props"] for q, kw in self.queries if q.startswith(merge_prefix) and "props" in kw]


def _write(**extra):
    entry = {"url": URL, "host": "www.example.com", "status_code": 200, "ip": "192.0.2.10",
             "title": "Shop", "tls": {"cipher": "TLS_AES_128_GCM_SHA256", "version": "tls13",
                                      "certificate": dict(CERT)}, **extra}
    client = _Client()
    client.update_graph_from_http_probe({
        "domain": "example.com", "subdomains": [], "metadata": {},
        "http_probe": {"scan_metadata": {}, "by_url": {URL: entry}, "by_host": {}},
    }, "u1", "p1")
    return client


class TestARunWithoutFingerprintsKeepsTheStoredOnes(unittest.TestCase):
    def test_the_endpoint_props_carry_no_favicon_key(self):
        endpoints = _write().props("MERGE (e:Endpoint")
        self.assertEqual(len(endpoints), 1)
        self.assertNotIn("favicon_hash", endpoints[0])
        self.assertNotIn("ai_frontend_product_guess", endpoints[0])
        self.assertEqual(endpoints[0]["title"], "Shop")

    def test_the_certificate_props_carry_no_jarm_key(self):
        certs = _write().props("MERGE (c:Certificate")
        self.assertEqual(len(certs), 1)
        self.assertNotIn("jarm", certs[0])
        self.assertEqual(certs[0]["subject_cn"], "www.example.com")

    def test_every_write_merges_its_props_never_replaces_them(self):
        for query, kw in _write().queries:
            if "props" in kw:
                self.assertNotRegex(query, r"SET \w+ = \$props", query)


class TestARunWithFingerprintsStillWritesThem(unittest.TestCase):
    def test_collected_hashes_are_written(self):
        client = _write(favicon_hash="-1137612213", jarm="2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5")
        self.assertEqual(client.props("MERGE (e:Endpoint")[0]["favicon_hash"], "-1137612213")
        self.assertEqual(client.props("MERGE (c:Certificate")[0]["jarm"],
                         "2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5")


if __name__ == "__main__":
    unittest.main()
