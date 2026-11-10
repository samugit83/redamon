"""R-35: the MITRE enrichment of nuclei CVEs reaches the graph.

add_mitre.enrich_recon_data adds the CWE / CAPEC chain to `vuln_scan.all_cves`
(the CVEs nuclei findings cite), and Group 6 Phase B re-runs the vuln write for
it. The writer read only `technology_cves`, so a nuclei CVE finding never linked
its CVE, and the CWE / CAPEC of a nuclei CVE never reached the graph.

These tests run the real nuclei parser, the real MITRE enrichment (over an
in-memory CVE2CAPEC database: only its files are replaced) and the real writer,
and follow the chain through the writes the writer sends:
(:Vulnerability)-[:INCLUDES_CVE]->(:CVE)-[:HAS_CWE]->(:MitreData)-[:HAS_CAPEC]->(:Capec).

Fixture hosts are example.com names and RFC 5737 addresses.
"""
import copy
import os
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.vuln_mixin import VulnMixin  # noqa: E402
from recon.helpers.nuclei_helpers import parse_nuclei_finding  # noqa: E402
from recon.main_recon_modules.add_mitre import MITREDatabase, enrich_recon_data  # noqa: E402

U, P = "u1", "p1"
HOST = "www.example.com"
OTHER_HOST = "elsewhere.example.org"
CVE = "CVE-2021-41773"
MITRE_ID = f"{CVE}-CWE-22"


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


def _mitre_db():
    """A CVE2CAPEC database held in memory: CVE-2021-41773 -> CWE-22 -> CAPEC-126."""
    db = MITREDatabase(db_path=Path("/nonexistent-mitre-db"))
    db.cwe_db = {"22": {"ChildOf": ["706"], "RelatedAttackPatterns": ["126"]}}
    db.cwe_metadata = {"22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory",
        "abstraction": "Base", "mapping": "ALLOWED", "description": "Path traversal.",
    }}
    db.capec_db = {"126": {"name": "Path Traversal"}}
    db.capec_metadata = {"126": {"description": "Reach files outside the web root.",
                                 "severity": "High", "likelihood": "High"}}
    db.get_cve_data = lambda cve_id: {"CWE": ["22"]} if cve_id.upper() == CVE else None
    return db


def _nuclei_line(host=HOST, template="CVE-2021-41773", cve_ids=("cve-2021-41773",), path="/cgi-bin/.%2e/etc/passwd"):
    return {
        "template-id": template,
        "template": f"http/cves/2021/{template}.yaml",
        "info": {
            "name": "Apache 2.4.49 - Path Traversal",
            "severity": "high",
            "tags": ["cve", "apache", "lfi"],
            "classification": {"cve-id": list(cve_ids), "cvss-score": 7.5},
        },
        "type": "http",
        "host": host,
        "matched-at": f"http://{host}{path}",
        "ip": "192.0.2.10",
        "timestamp": "2026-11-10T08:00:00Z",
    }


def _recon(*parsed_findings, scope=(HOST,)):
    """vuln_scan as run_vuln_scan leaves it: findings by target, and every cited
    CVE once in all_cves."""
    by_target, all_cves, seen = {}, [], set()
    for parsed in parsed_findings:
        host = parsed["matched_at"].split("/")[2]
        by_target.setdefault(host, {"findings": []})["findings"].append(parsed)
        for cve in parsed["cves"]:
            if cve["id"] not in seen:
                seen.add(cve["id"])
                all_cves.append(dict(cve))
    return {
        "domain": "example.com",
        "subdomains": list(scope),
        "vuln_scan": {"scan_metadata": {}, "discovered_urls": {},
                      "by_target": by_target, "all_cves": all_cves},
    }


def _enriched(recon):
    return enrich_recon_data(copy.deepcopy(recon), _mitre_db())


def _writes_with(client, needle):
    return [(q, kw) for q, kw in client.writes if needle in q]


def _vuln_ids(client):
    return [kw["id"] for q, kw in _writes_with(client, "MERGE (v:Vulnerability")]


def _includes_cve(client):
    """(vulnerability id, CVE id) for every INCLUDES_CVE edge the writer merged."""
    pairs = []
    for q, kw in _writes_with(client, "[:INCLUDES_CVE]"):
        if "MERGE (v)-[:INCLUDES_CVE]->(c)" not in q:
            continue
        rows = kw.get("cves")
        ids = [r["id"] for r in rows] if rows is not None else [kw["cve_id"]]
        pairs += [(kw["vuln_id"], cid) for cid in ids]
    return pairs


def _has_cwe(client):
    return [(kw["cve_id"], kw["mitre_id"]) for q, kw in _writes_with(client, "MERGE (c)-[:HAS_CWE]->(m)")]


def _has_capec(client):
    return [(kw["mitre_id"], kw["capec_id"]) for q, kw in _writes_with(client, "MERGE (m)-[:HAS_CAPEC]->(cap)")]


class TestNucleiCveReachesTheMitreChain(unittest.TestCase):

    def test_enriched_nuclei_cve_links_finding_cve_cwe_and_capec(self):
        recon = _enriched(_recon(parse_nuclei_finding(_nuclei_line())))
        self.assertTrue(recon["vuln_scan"]["all_cves"][0]["mitre_attack"]["enriched"],
                        "the enrichment this test feeds the writer")

        client = _Client()
        stats = client.update_graph_from_vuln_scan(recon, U, P)

        self.assertEqual(stats["errors"], [])
        [vuln_id] = _vuln_ids(client)
        self.assertEqual(_includes_cve(client), [(vuln_id, CVE)])
        self.assertEqual(_has_cwe(client), [(CVE, MITRE_ID)])
        self.assertEqual(_has_capec(client), [(MITRE_ID, "CAPEC-126")])

        [(_, mitre)] = _writes_with(client, "MERGE (m:MitreData {id: $id})")
        self.assertEqual(mitre["props"]["cwe_id"], "CWE-22")
        self.assertEqual(mitre["props"]["cve_id"], CVE)
        [(_, capec)] = _writes_with(client, "MERGE (cap:Capec {capec_id: $capec_id})")
        self.assertEqual(capec["props"]["name"], "Path Traversal")

    def test_the_cve_reference_node_carries_no_tenant_key_and_the_finding_does(self):
        client = _Client()
        client.update_graph_from_vuln_scan(_enriched(_recon(parse_nuclei_finding(_nuclei_line()))), U, P)

        [(query, kw)] = [(q, k) for q, k in _writes_with(client, "MERGE (c:CVE")]
        self.assertRegex(query, r"MERGE \(c:CVE \{id: [\w.$]+\}\)")
        cve_merge = re.search(r"MERGE \(c:CVE \{[^}]*\}\)", query).group(0)
        self.assertNotIn("user_id", cve_merge)
        self.assertNotIn("project_id", cve_merge)
        self.assertIn("MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})",
                      query)
        self.assertEqual((kw["user_id"], kw["project_id"]), (U, P))
        for needle in ("MERGE (m:MitreData", "MERGE (cap:Capec"):
            for q, k in _writes_with(client, needle):
                self.assertNotIn("user_id", q)
                self.assertNotIn("user_id", k.get("props", {}))

    def test_phase_a_write_before_the_enrichment_links_the_cve_only(self):
        client = _Client()
        stats = client.update_graph_from_vuln_scan(_recon(parse_nuclei_finding(_nuclei_line())), U, P)

        self.assertEqual(stats["errors"], [])
        [vuln_id] = _vuln_ids(client)
        self.assertEqual(_includes_cve(client), [(vuln_id, CVE)])
        self.assertEqual(_has_cwe(client), [])
        self.assertEqual(_writes_with(client, "MitreData"), [])

    def test_phase_b_rerun_merges_the_same_edges_and_creates_nothing(self):
        plain = _recon(parse_nuclei_finding(_nuclei_line()))
        client = _Client()
        client.update_graph_from_vuln_scan(plain, U, P)
        client.update_graph_from_vuln_scan(_enriched(plain), U, P)
        client.update_graph_from_vuln_scan(_enriched(plain), U, P)

        self.assertEqual(len(set(_includes_cve(client))), 1)
        self.assertEqual(set(_has_cwe(client)), {(CVE, MITRE_ID)})
        self.assertEqual(set(_has_capec(client)), {(MITRE_ID, "CAPEC-126")})
        for query, _ in client.writes:
            for rel in ("INCLUDES_CVE", "HAS_CWE", "HAS_CAPEC"):
                self.assertNotRegex(query, rf"CREATE\s*\([^)]*\)-\[:{rel}\]")

    def test_two_findings_citing_one_cve_each_link_it_and_the_chain_is_written_once(self):
        first = parse_nuclei_finding(_nuclei_line())
        second = parse_nuclei_finding(_nuclei_line(template="apache-path-traversal", path="/icons/.%2e/etc/hosts"))
        client = _Client()
        client.update_graph_from_vuln_scan(_enriched(_recon(first, second)), U, P)

        ids = _vuln_ids(client)
        self.assertEqual(len(set(ids)), 2)
        self.assertEqual(sorted(_includes_cve(client)), sorted((v, CVE) for v in ids))
        self.assertEqual(_has_cwe(client), [(CVE, MITRE_ID)])

    def test_a_malformed_cve_id_never_becomes_a_reference_node(self):
        parsed = parse_nuclei_finding(_nuclei_line(
            cve_ids=("cve-2021-41773", "CVE-2021-41773'}) DETACH DELETE c //", "CVE-21-1")))
        client = _Client()
        stats = client.update_graph_from_vuln_scan(_enriched(_recon(parsed)), U, P)

        self.assertEqual(stats["errors"], [])
        [vuln_id] = _vuln_ids(client)
        self.assertEqual(_includes_cve(client), [(vuln_id, CVE)])
        [(_, props)] = [(q, kw["props"]) for q, kw in _writes_with(client, "MERGE (v:Vulnerability")]
        self.assertIn("CVE-21-1", props["cves"], "the finding still records what nuclei cited")

    def test_an_out_of_scope_finding_brings_no_cve_and_no_chain(self):
        parsed = parse_nuclei_finding(_nuclei_line(host=OTHER_HOST))
        client = _Client()
        client.update_graph_from_vuln_scan(_enriched(_recon(parsed, scope=(HOST,))), U, P)

        self.assertEqual(_vuln_ids(client), [])
        self.assertEqual(_writes_with(client, "MERGE (c:CVE"), [])
        self.assertEqual(_writes_with(client, "MitreData"), [])

    def test_a_finding_without_cves_writes_no_reference_node(self):
        parsed = parse_nuclei_finding(_nuclei_line(cve_ids=()))
        client = _Client()
        stats = client.update_graph_from_vuln_scan(_recon(parsed), U, P)

        self.assertEqual(stats["errors"], [])
        self.assertEqual(len(_vuln_ids(client)), 1)
        self.assertEqual(_includes_cve(client), [])
        self.assertEqual(_writes_with(client, "MitreData"), [])


class TestTechnologyCvesKeepTheirChain(unittest.TestCase):
    """The MITRE writes are shared with the technology CVE lookup now."""

    def test_technology_cve_chain_and_its_additional_hierarchies(self):
        cwe = {"id": "CWE-22", "name": "Path Traversal", "mapping": "ALLOWED",
               "related_capec": [{"id": "CAPEC-126", "name": "Path Traversal"}]}
        extra = {"id": "CWE-23", "name": "Relative Path Traversal", "mapping": "ALLOWED",
                 "related_capec": [{"id": "CAPEC-139", "name": "Relative Path Traversal"}]}
        recon = {
            "vuln_scan": {"scan_metadata": {}},
            "technology_cves": {"by_technology": {"Apache:2.4.49": {
                "product": "apache", "version": "2.4.49",
                "cves": [{"id": CVE, "cvss": 7.5, "severity": "HIGH", "mitre_attack": {
                    "enriched": True, "cwe_hierarchy": cwe,
                    "additional_cwe_hierarchies": [extra]}}],
            }}},
        }
        client = _Client()
        stats = client.update_graph_from_vuln_scan(recon, U, P)

        self.assertEqual(stats["errors"], [])
        self.assertEqual(_has_cwe(client), [(CVE, MITRE_ID), (CVE, f"{CVE}-CWE-23")])
        self.assertEqual(_has_capec(client), [(MITRE_ID, "CAPEC-126"), (f"{CVE}-CWE-23", "CAPEC-139")])

    def test_an_unenriched_technology_cve_writes_no_chain(self):
        recon = {
            "vuln_scan": {"scan_metadata": {}},
            "technology_cves": {"by_technology": {"Apache:2.4.49": {
                "product": "apache", "version": "2.4.49",
                "cves": [{"id": CVE, "mitre_attack": {"enriched": False}}],
            }}},
        }
        client = _Client()
        client.update_graph_from_vuln_scan(recon, U, P)
        self.assertEqual(_writes_with(client, "MitreData"), [])


if __name__ == "__main__":
    unittest.main()
