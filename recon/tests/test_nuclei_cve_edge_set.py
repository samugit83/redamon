"""A nuclei finding's INCLUDES_CVE edges are exactly the CVEs it cites now.

R-35 links a nuclei Vulnerability to the CVEs its template cites, and drops the
edge to a CVE the template no longer cites, but only while the finding still
cites at least one: a template that dropped every CVE kept all its old edges.

These tests run the real nuclei parser and the real writer over a fake session
and follow the INCLUDES_CVE statement the writer sends; the live test
(tests/test_nuclei_cve_edge_set_graph_live.py) runs it against Neo4j.

Fixture hosts are example.com names and RFC 5737 addresses.
"""
import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.vuln_mixin import VulnMixin  # noqa: E402
from recon.helpers.nuclei_helpers import parse_nuclei_finding  # noqa: E402

U, P = "u1", "p1"
HOST = "www.example.com"


class _Result:
    def single(self):
        return {"matched": 0, "linked": 0, "count": 0, "c": 0}

    def __iter__(self):
        return iter([])


class _Session:
    def __init__(self, writes):
        self.writes = writes

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.writes.append((query, kwargs))
        return _Result()


class _Client(VulnMixin):
    def __init__(self):
        self.writes = []
        self.driver = MagicMock()
        self.driver.session.side_effect = lambda: _Session(self.writes)


def _recon(cve_ids):
    parsed = parse_nuclei_finding({
        "template-id": "apache-path-traversal",
        "template": "http/vulnerabilities/apache/apache-path-traversal.yaml",
        "info": {
            "name": "Apache Path Traversal",
            "severity": "high",
            "tags": ["apache", "lfi"],
            "classification": {"cve-id": list(cve_ids), "cvss-score": 7.5},
        },
        "type": "http",
        "host": HOST,
        "matched-at": f"http://{HOST}/cgi-bin/.%2e/etc/passwd",
        "ip": "192.0.2.10",
        "timestamp": "2026-11-11T08:00:00Z",
    })
    return {
        "domain": "example.com",
        "subdomains": [HOST],
        "vuln_scan": {"scan_metadata": {}, "discovered_urls": {},
                      "by_target": {HOST: {"findings": [parsed]}},
                      "all_cves": [dict(c) for c in parsed["cves"]]},
    }


def _write(cve_ids):
    client = _Client()
    stats = client.update_graph_from_vuln_scan(_recon(cve_ids), U, P)
    [vuln_id] = [kw["id"] for q, kw in client.writes if "MERGE (v:Vulnerability" in q]
    edge_writes = [(q, kw) for q, kw in client.writes if "INCLUDES_CVE" in q]
    return stats, vuln_id, edge_writes


class TestTheEdgeSetFollowsTheCurrentFinding(unittest.TestCase):

    def test_a_finding_that_cites_no_cve_drops_every_old_edge(self):
        stats, vuln_id, edge_writes = _write(())

        self.assertEqual(stats["errors"], [])
        [(query, kw)] = edge_writes
        self.assertEqual(kw["vuln_id"], vuln_id)
        self.assertEqual(kw["cve_ids"], [], "every INCLUDES_CVE edge of the finding is stale")
        self.assertEqual(kw["cves"], [], "and no CVE is merged")
        self.assertRegex(query, r"OPTIONAL MATCH \(v\)-\[stale:INCLUDES_CVE\]->\(old:CVE\)\s+"
                                r"WHERE NOT old\.id IN \$cve_ids\s+DELETE stale")

    def test_a_finding_that_cites_only_malformed_ids_drops_every_old_edge(self):
        _, _, edge_writes = _write(("CVE-21-1", "cve-2021-41773'}) DETACH DELETE c //"))
        [(_, kw)] = edge_writes
        self.assertEqual((kw["cve_ids"], kw["cves"]), ([], []))

    def test_a_finding_that_cites_fewer_cves_keeps_only_those(self):
        _, _, edge_writes = _write(("cve-2021-42013",))
        [(_, kw)] = edge_writes
        self.assertEqual(kw["cve_ids"], ["CVE-2021-42013"])
        self.assertEqual([row["id"] for row in kw["cves"]], ["CVE-2021-42013"])

    def test_the_delete_is_scoped_to_one_tenant_finding_and_spares_the_shared_nodes(self):
        _, _, edge_writes = _write(())
        [(query, kw)] = edge_writes

        self.assertIn("MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})",
                      query)
        self.assertEqual((kw["user_id"], kw["project_id"]), (U, P))
        # Only the edge goes: CVE, MitreData and Capec are reference nodes every
        # project shares.
        self.assertEqual(re.findall(r"\bDELETE\s+\w+", query), ["DELETE stale"])
        self.assertNotIn("DETACH", query)
        self.assertNotIn("MitreData", query)
        self.assertNotIn("Capec", query)


if __name__ == "__main__":
    unittest.main()
