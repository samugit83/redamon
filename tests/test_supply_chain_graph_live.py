"""LIVE-Neo4j integration tests for the supply-chain graph writer.

Everything else in the supply-chain suite writes into a fake session and asserts
on the Cypher parameters. That proves the writer INTENDED to store a value; it
cannot prove Neo4j accepted it. Property-type rejections (a list property, a
coalesce against a non-existent property, a datetime round-trip) only surface
against a real database, and they surface as a silently missing column in the
Supply-Chain SCA table.

Skipped unless the neo4j driver is importable AND a database answers. To run it
inside a container that has the driver, with this checkout mounted over /app:

  docker run --rm --network host -v "$PWD:/app" -w /app \\
    -e NEO4J_URI -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_supply_chain_graph_live -v

Every node it creates is scoped to a throwaway project id and deleted in
tearDownClass, so it is safe against a populated database.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")

if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    """True when a database actually answers (not just importable driver)."""
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_LIVE = _probe()

USER_ID = "sc-live-user"
PROJECT_ID = "sc-live-" + uuid.uuid4().hex[:12]
OTHER_PROJECT_ID = "sc-live-other-" + uuid.uuid4().hex[:12]

BASE_URL = "https://sc-live-target.invalid"

ARTIFACT = {
    "schema_version": 1,
    "mode": "dir",
    "packages": [
        {"purl": "pkg:npm/axios@1.14.1", "name": "axios", "version": "1.14.1",
         "ecosystem": "npm", "source": "retirejs",
         "source_path": "web/package-lock.json"},
        # Versionless: harvested but NOT verdictable. The table must be able to
        # tell this apart from a checked-and-clean package.
        {"purl": "pkg:npm/lodash", "name": "lodash", "version": None,
         "ecosystem": "npm", "source": "sourcemap"},
    ],
    "malicious": [
        {"purl": "pkg:npm/axios@1.14.1", "name": "axios", "version": "1.14.1",
         "ecosystem": "npm", "advisory_id": "MAL-2026-9999", "severity": "high",
         "confidence": "malicious", "title": "planted malware",
         "aliases": ["GHSA-live-0001", "CVE-2026-0001"]},
    ],
    "vulnerable": [
        {"purl": "pkg:npm/axios@1.14.1", "name": "axios", "version": "1.14.1",
         "ecosystem": "npm", "advisory_id": "GHSA-live-cve", "severity": "high",
         "confidence": "suspicious", "title": "SSRF",
         "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    ],
    "suspicious": [
        {"purl": "pkg:npm/axios@1.14.1", "name": "axios", "version": "1.14.1",
         "ecosystem": "npm", "rule": "guarddog-not-run", "severity": "low",
         "confidence": "suspicious", "message": "registry unreachable",
         "soft_error": True},
        {"purl": "pkg:npm/axios@1.14.1", "name": "axios", "version": "1.14.1",
         "ecosystem": "npm", "rule": "npm-install-script", "severity": "high",
         "confidence": "suspicious", "message": "postinstall runs curl",
         "soft_error": False},
    ],
    "errors": [],
}


@unittest.skipUnless(_LIVE, _SKIP_REASON or "no Neo4j reachable at {}".format(_URI))
class TestSupplyChainGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db import Neo4jClient
        from supply_chain_common.security import validate_artifact

        cls.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        cls._purge()

        # The anchor must pre-exist: the writer MATCHes it and never invents a
        # target node.
        with cls.driver.session() as s:
            s.run("""CREATE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})""",
                  url=BASE_URL, uid=USER_ID, pid=PROJECT_ID)

        artifact = validate_artifact(ARTIFACT)
        with Neo4jClient(uri=_URI, user=_USER, password=_PASSWORD) as client:
            cls.stats = client.update_graph_from_supply_chain(
                artifact, USER_ID, PROJECT_ID,
                anchor_label="BaseURL", anchor_key="url", anchor_value=BASE_URL)
            # Second identical write: every MERGE must be idempotent.
            cls.stats2 = client.update_graph_from_supply_chain(
                artifact, USER_ID, PROJECT_ID,
                anchor_label="BaseURL", anchor_key="url", anchor_value=BASE_URL)
            # A different tenant writing the same purls must not collide.
            client.update_graph_from_supply_chain(
                artifact, USER_ID, OTHER_PROJECT_ID)

    @classmethod
    def tearDownClass(cls):
        cls._purge()
        cls.driver.close()

    @classmethod
    def _purge(cls):
        with cls.driver.session() as s:
            for pid in (PROJECT_ID, OTHER_PROJECT_ID):
                s.run("MATCH (n) WHERE n.project_id = $pid DETACH DELETE n", pid=pid)

    def q(self, cypher, **params):
        params.setdefault("pid", PROJECT_ID)
        with self.driver.session() as s:
            return [r.data() for r in s.run(cypher, **params)]

    # -- the writer reported success -------------------------------------
    def test_write_reported_expected_counts(self):
        self.assertEqual(self.stats["packages_merged"], 2)
        self.assertEqual(self.stats["malicious_merged"], 1)
        self.assertEqual(self.stats["suspicious_merged"], 2)
        self.assertEqual(self.stats["vulnerabilities_merged"], 1)
        self.assertEqual(self.stats["errors"], [])

    # -- properties Neo4j actually accepted -------------------------------
    def test_package_properties_round_trip(self):
        rows = self.q("""MATCH (p:Package {project_id: $pid, purl: 'pkg:npm/axios@1.14.1'})
                         RETURN p.name AS name, p.version AS version,
                                p.ecosystem AS eco, p.source AS source,
                                p.source_path AS sourcePath,
                                p.first_seen IS NOT NULL AS hasFirstSeen,
                                p.last_seen IS NOT NULL AS hasLastSeen""")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "axios")
        self.assertEqual(rows[0]["version"], "1.14.1")
        self.assertEqual(rows[0]["sourcePath"], "web/package-lock.json")
        self.assertTrue(rows[0]["hasFirstSeen"])
        self.assertTrue(rows[0]["hasLastSeen"])

    def test_versionless_package_stores_a_null_version(self):
        # The "unverdictable" status in the table is derived from exactly this.
        rows = self.q("""MATCH (p:Package {project_id: $pid, purl: 'pkg:npm/lodash'})
                         RETURN p.version AS version""")
        self.assertEqual(rows, [{"version": None}])

    def test_aliases_persist_as_a_list_property(self):
        # A list property is the one type Neo4j can refuse outright.
        rows = self.q("""MATCH (:Package {project_id: $pid})-[:FLAGGED_AS]->(f:MalPackageFinding)
                         WHERE f.verdict = 'malicious'
                         RETURN f.aliases AS aliases, f.advisory_id AS advisoryId""")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["advisoryId"], "MAL-2026-9999")
        self.assertEqual(sorted(rows[0]["aliases"]), ["CVE-2026-0001", "GHSA-live-0001"])

    def test_soft_error_persists_as_a_boolean(self):
        rows = self.q("""MATCH (:Package {project_id: $pid})-[:FLAGGED_AS]->(f:MalPackageFinding)
                         RETURN f.advisory_id AS advisoryId, f.soft_error AS softError
                         ORDER BY advisoryId""")
        by_id = {r["advisoryId"]: r["softError"] for r in rows}
        self.assertIs(by_id["guarddog-not-run"], True)
        self.assertIs(by_id["npm-install-script"], False)
        self.assertIs(by_id["MAL-2026-9999"], False)

    def test_cvss_vector_persists_on_the_vulnerability(self):
        rows = self.q("""MATCH (:Package {project_id: $pid})-[:HAS_VULNERABILITY]->(v:Vulnerability)
                         RETURN v.id AS id, v.cvss_metrics AS cvss,
                                v.severity AS severity, v.source AS source""")
        self.assertEqual(len(rows), 1)
        # One node per (package, advisory): the id carries both, so the same
        # advisory on two packages is two findings with their own facts.
        self.assertTrue(rows[0]["id"].startswith("osv:pkg:npm/axios@1.14.1:"), rows[0]["id"])
        self.assertTrue(rows[0]["id"].endswith(":GHSA-live-cve"), rows[0]["id"])
        self.assertTrue(rows[0]["cvss"].startswith("CVSS:3.1/"))
        self.assertEqual(rows[0]["severity"], "high")
        # The SCA advisories sheet filters on this; without it the sheet would
        # pull in GVM/nuclei/GraphQL vulnerabilities too.
        self.assertEqual(rows[0]["source"], "osv")

    # -- relationships -----------------------------------------------------
    def test_depends_on_anchors_to_the_existing_baseurl(self):
        rows = self.q("""MATCH (b:BaseURL {project_id: $pid})-[:DEPENDS_ON]->(p:Package)
                         RETURN p.purl AS purl ORDER BY purl""")
        self.assertEqual([r["purl"] for r in rows],
                         ["pkg:npm/axios@1.14.1", "pkg:npm/lodash"])

    def test_no_orphan_findings(self):
        rows = self.q("""MATCH (f:MalPackageFinding {project_id: $pid})
                         WHERE NOT (:Package)-[:FLAGGED_AS]->(f)
                         RETURN count(f) AS c""")
        self.assertEqual(rows[0]["c"], 0)

    # -- idempotency -------------------------------------------------------
    def test_writing_twice_does_not_duplicate_nodes(self):
        counts = self.q("""MATCH (p:Package {project_id: $pid})
                           WITH count(p) AS packages
                           MATCH (f:MalPackageFinding {project_id: $pid})
                           WITH packages, count(f) AS findings
                           MATCH (v:Vulnerability {project_id: $pid})
                           RETURN packages, findings, count(v) AS vulns""")
        self.assertEqual(counts[0]["packages"], 2)
        self.assertEqual(counts[0]["findings"], 3)
        self.assertEqual(counts[0]["vulns"], 1)

    def test_second_write_reports_the_same_counts(self):
        self.assertEqual(self.stats2["packages_merged"], self.stats["packages_merged"])
        self.assertEqual(self.stats2["malicious_merged"], self.stats["malicious_merged"])

    def test_depends_on_edge_is_not_duplicated(self):
        rows = self.q("""MATCH (:BaseURL {project_id: $pid})-[r:DEPENDS_ON]->(:Package)
                         RETURN count(r) AS c""")
        self.assertEqual(rows[0]["c"], 2)

    # -- tenant isolation --------------------------------------------------
    def test_same_purl_in_another_project_is_a_separate_node(self):
        rows = self.q("""MATCH (p:Package {purl: 'pkg:npm/axios@1.14.1'})
                         WHERE p.project_id IN [$pid, $other]
                         RETURN p.project_id AS pid ORDER BY pid""",
                      other=OTHER_PROJECT_ID)
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["pid"] for r in rows}, {PROJECT_ID, OTHER_PROJECT_ID})

    def test_the_other_tenant_has_no_depends_on_edge(self):
        # It was written with no anchor, so its packages float - and it must not
        # have stolen this project's BaseURL.
        rows = self.q("""MATCH (:BaseURL)-[:DEPENDS_ON]->(p:Package {project_id: $other})
                         RETURN count(p) AS c""", other=OTHER_PROJECT_ID)
        self.assertEqual(rows[0]["c"], 0)


if __name__ == "__main__":
    unittest.main()
