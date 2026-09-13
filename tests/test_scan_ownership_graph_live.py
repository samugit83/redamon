"""LIVE-Neo4j proof that one scan's clear cannot destroy another's data.

The fake-session tests assert the SHAPE of the Cypher. They cannot prove Neo4j
agrees: that the unique constraint really rejects a tenant-keyed CVE merge, that
a shared reference node really survives one project's wipe while its other
project keeps the link, or that a re-parented relationship really lands on the
surviving node. Each of those was a real defect, so each is proved here against
a real database.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://localhost:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_scan_ownership_graph_live -v

Everything it creates is scoped to throwaway project ids and a reserved CVE id,
and is deleted in tearDown, so it is safe against a populated database.
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


_ALIVE = _probe()


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveGraphCase(unittest.TestCase):
    """Shared fixture: a client, two throwaway projects, and a reserved CVE."""

    def setUp(self):
        from graph_db import Neo4jClient
        run = uuid.uuid4().hex[:8]
        self.uid = f"ownership-{run}"
        self.p1 = f"OWNERSHIP_A_{run}"
        self.p2 = f"OWNERSHIP_B_{run}"
        self.cve = f"CVE-9999-{run.upper()}"
        self.cwe = f"CWE-LIVE-{run}"
        self.client = Neo4jClient(uri=_URI, user=_USER, password=_PASSWORD)
        self.session = self.client.driver.session()

    def tearDown(self):
        try:
            self.session.run(
                "MATCH (n) WHERE n.project_id IN [$a, $b] DETACH DELETE n",
                a=self.p1, b=self.p2)
            self.session.run("MATCH (c:CVE {id: $c}) DETACH DELETE c", c=self.cve)
            self.session.run("MATCH (m:MitreData {id: $m}) DETACH DELETE m", m=self.cwe)
        finally:
            self.session.close()
            self.client.close()

    def count(self, cypher, **params):
        return self.session.run(cypher, **params).single()["n"]


class TestNmapNseCveMerge(LiveGraphCase):
    """The nmap NSE path keyed CVE on {id, user_id, project_id} while
    `cve_unique` requires id alone, so it threw ConstraintValidationFailed
    against any CVE another scan had already created — swallowed into a stats
    list, losing the CVE and both of its links."""

    def test_the_old_tenant_keyed_merge_really_does_violate_the_constraint(self):
        self.session.run("CREATE (c:CVE {id: $c, source: 'nuclei'})", c=self.cve)
        with self.assertRaises(Exception) as ctx:
            self.session.run(
                "MERGE (c:CVE {id: $c, user_id: 'x', project_id: 'y'}) RETURN c",
                c=self.cve).consume()
        self.assertIn("already exists", str(ctx.exception).lower())

    def test_merging_on_the_id_alone_succeeds_and_keeps_one_node(self):
        self.session.run("CREATE (c:CVE {id: $c, source: 'nuclei'})", c=self.cve)
        self.session.run(
            """MERGE (c:CVE {id: $c})
               ON CREATE SET c.cve_id = $c, c.name = $c, c.source = 'nmap_nse'
               SET c.updated_at = datetime()""", c=self.cve)
        self.assertEqual(self.count("MATCH (c:CVE {id:$c}) RETURN count(c) AS n", c=self.cve), 1)

    def test_on_create_set_does_not_steal_provenance_from_the_first_writer(self):
        self.session.run("CREATE (c:CVE {id: $c, source: 'nuclei'})", c=self.cve)
        self.session.run(
            """MERGE (c:CVE {id: $c})
               ON CREATE SET c.source = 'nmap_nse'
               SET c.updated_at = datetime()""", c=self.cve)
        source = self.session.run(
            "MATCH (c:CVE {id:$c}) RETURN c.source AS s", c=self.cve).single()["s"]
        self.assertEqual(source, "nuclei")


class TestSharedReferenceNodesSurviveAProjectWipe(LiveGraphCase):
    def _two_projects_sharing_one_cve(self):
        self.session.run(
            """
            CREATE (d1:Domain {user_id:$u, project_id:$p1, domain:'a.tld'})
            CREATE (d2:Domain {user_id:$u, project_id:$p2, domain:'b.tld'})
            CREATE (c:CVE {id:$c, source:'nuclei'})
            CREATE (m:MitreData {id:$m})
            CREATE (d1)-[:HAS_CVE]->(c)
            CREATE (d2)-[:HAS_CVE]->(c)
            CREATE (c)-[:HAS_CWE]->(m)
            """, u=self.uid, p1=self.p1, p2=self.p2, c=self.cve, m=self.cwe)

    def test_wiping_one_project_leaves_the_other_projects_cve_link_intact(self):
        self._two_projects_sharing_one_cve()
        self.client.clear_project_data(self.uid, self.p1)
        self.assertEqual(
            self.count("MATCH (c:CVE {id:$c}) RETURN count(c) AS n", c=self.cve), 1,
            "the shared CVE was destroyed by another project's wipe")
        self.assertEqual(
            self.count("MATCH (:Domain {project_id:$p})-[:HAS_CVE]->(:CVE {id:$c}) "
                       "RETURN count(*) AS n", p=self.p2, c=self.cve), 1,
            "the other project lost its link to the shared CVE")

    def test_the_wiped_projects_own_nodes_are_still_gone(self):
        self._two_projects_sharing_one_cve()
        self.client.clear_project_data(self.uid, self.p1)
        self.assertEqual(
            self.count("MATCH (d:Domain {project_id:$p}) RETURN count(d) AS n", p=self.p1), 0)

    def test_the_sweep_collects_the_cve_once_no_project_references_it(self):
        self._two_projects_sharing_one_cve()
        self.client.clear_project_data(self.uid, self.p1)
        self.client.clear_project_data(self.uid, self.p2)
        self.assertEqual(
            self.count("MATCH (c:CVE {id:$c}) RETURN count(c) AS n", c=self.cve), 0,
            "an unreferenced reference node must not accumulate forever")
        self.assertEqual(
            self.count("MATCH (m:MitreData {id:$m}) RETURN count(m) AS n", m=self.cwe), 0)


class TestReconClearOwnership(LiveGraphCase):
    def setUp(self):
        super().setUp()
        self.session.run(
            """
            CREATE (:Domain            {user_id:$u, project_id:$p, domain:'a.tld'})
            CREATE (:Subdomain         {user_id:$u, project_id:$p, name:'w.a.tld'})
            CREATE (:GithubSecret      {user_id:$u, project_id:$p, id:'gs1'})
            CREATE (:MultiscannerFinding {user_id:$u, project_id:$p, id:'tf1'})
            CREATE (:Package           {user_id:$u, project_id:$p, id:'pkg1'})
            CREATE (:ChainFinding      {user_id:$u, project_id:$p, finding_id:'cf1'})
            CREATE (:ExploitGvm        {user_id:$u, project_id:$p, id:'eg1'})
            CREATE (:Vulnerability     {user_id:$u, project_id:$p, id:'v-gvm',    source:'gvm'})
            CREATE (:Vulnerability     {user_id:$u, project_id:$p, id:'v-osv',    source:'osv'})
            CREATE (:Vulnerability     {user_id:$u, project_id:$p, id:'v-garak',  source:'garak'})
            CREATE (:Vulnerability     {user_id:$u, project_id:$p, id:'v-nuclei', source:'nuclei'})
            CREATE (:Technology        {user_id:$u, project_id:$p, name:'nginx', version:'1.0',
                                        detected_by:'httpx,gvm'})
            CREATE (:Technology        {user_id:$u, project_id:$p, name:'react', version:'18',
                                        detected_by:'httpx'})
            CREATE (:BaseURL           {user_id:$u, project_id:$p, url:'http://ai',
                                        ai_attack_synthetic:true})
            """, u=self.uid, p=self.p1)
        self.client.clear_recon_data(self.uid, self.p1)
        self.survivors = {r["l"]: r["c"] for r in self.session.run(
            "MATCH (n {project_id:$p}) RETURN labels(n)[0] AS l, count(*) AS c", p=self.p1)}

    def test_every_other_scanners_findings_survive(self):
        for label in ("GithubSecret", "MultiscannerFinding", "Package",
                      "ChainFinding", "ExploitGvm"):
            self.assertEqual(self.survivors.get(label), 1,
                             f"a recon re-run deleted {label}: {self.survivors}")

    def test_recon_still_clears_its_own_nodes(self):
        self.assertNotIn("Domain", self.survivors)
        self.assertNotIn("Subdomain", self.survivors)

    def test_a_shared_label_is_split_by_source(self):
        kept = sorted(r["id"] for r in self.session.run(
            "MATCH (v:Vulnerability {project_id:$p}) RETURN v.id AS id", p=self.p1))
        # X7 (ingest-then-prune): recon's OWN findings are no longer deleted
        # by the clear either. They are pruned after a successful ingest, so a
        # rescan cannot delete the operator's mutes and verdicts with them.
        self.assertEqual(kept, ["v-garak", "v-gvm", "v-nuclei", "v-osv"],
                         "Vulnerability is written by four subsystems; the "
                         "clear may delete none of them")

    def test_a_technology_gvm_also_detected_is_kept(self):
        techs = sorted(r["n"] for r in self.session.run(
            "MATCH (t:Technology {project_id:$p}) RETURN t.name AS n", p=self.p1))
        self.assertEqual(techs, ["nginx"])

    def test_the_ai_scans_synthetic_target_survives(self):
        self.assertEqual(self.survivors.get("BaseURL"), 1,
                         "deleting it orphans the AI attack-surface findings")


class TestTechnologyTwinAbsorption(LiveGraphCase):
    """A versioned detection absorbing a versionless twin must carry EVERY
    relationship over. The original moved USES_TECHNOLOGY and DETACH DELETEd."""

    def test_all_four_relationship_types_land_on_the_surviving_node(self):
        from graph_db.mixins.recon.http_mixin import resolve_tech_version
        self.session.run(
            """
            CREATE (old:Technology {user_id:$u, project_id:$p, name:'nginx', version:''})
            CREATE (port:Port      {user_id:$u, project_id:$p, id:'port1'})
            CREATE (ep:Endpoint    {user_id:$u, project_id:$p, id:'ep1'})
            CREATE (cve:CVE        {id:$c})
            CREATE (gv:Vulnerability {user_id:$u, project_id:$p, id:'gv1', source:'gvm'})
            CREATE (port)-[:HAS_TECHNOLOGY]->(old)
            CREATE (ep)-[:USES_TECHNOLOGY]->(old)
            CREATE (old)-[:HAS_KNOWN_CVE]->(cve)
            CREATE (old)-[:HAS_VULNERABILITY]->(gv)
            """, u=self.uid, p=self.p1, c=self.cve)

        resolve_tech_version(self.session, "nginx", "1.24.0", self.uid, self.p1)

        row = self.session.run(
            """MATCH (t:Technology {name:'nginx', version:'1.24.0', project_id:$p})
               RETURN size([(t)<-[:HAS_TECHNOLOGY]-()   | 1]) AS has_tech,
                      size([(t)<-[:USES_TECHNOLOGY]-()  | 1]) AS uses,
                      size([(t)-[:HAS_KNOWN_CVE]->()    | 1]) AS cve,
                      size([(t)-[:HAS_VULNERABILITY]->() | 1]) AS vuln""",
            p=self.p1).single()
        self.assertEqual(row["has_tech"], 1, "Port -[:HAS_TECHNOLOGY]-> was dropped")
        self.assertEqual(row["uses"], 1, "Endpoint -[:USES_TECHNOLOGY]-> was dropped")
        self.assertEqual(row["cve"], 1, "-[:HAS_KNOWN_CVE]-> was dropped")
        self.assertEqual(row["vuln"], 1, "GVM's -[:HAS_VULNERABILITY]-> was dropped")

    def test_the_absorbed_twin_is_removed(self):
        from graph_db.mixins.recon.http_mixin import resolve_tech_version
        self.session.run(
            """CREATE (old:Technology {user_id:$u, project_id:$p, name:'nginx', version:''})
               CREATE (ep:Endpoint {user_id:$u, project_id:$p, id:'ep1'})
               CREATE (ep)-[:USES_TECHNOLOGY]->(old)""",
            u=self.uid, p=self.p1)
        resolve_tech_version(self.session, "nginx", "1.24.0", self.uid, self.p1)
        self.assertEqual(
            self.count("MATCH (t:Technology {name:'nginx', version:'', project_id:$p}) "
                       "RETURN count(t) AS n", p=self.p1), 0)


class TestReferenceTenantStripMigration(LiveGraphCase):
    def test_it_removes_a_stamp_left_by_an_older_build(self):
        from graph_db.schema import strip_reference_node_tenant
        self.session.run(
            "CREATE (c:CVE {id:$c, user_id:'legacy', project_id:'legacy'})", c=self.cve)
        # The marker is written once per database; drop it so the step runs here.
        self.session.run(
            "MATCH (m:RedamonSchemaMigration {id:'strip-reference-node-tenant-v1'}) DELETE m")
        strip_reference_node_tenant(self.session)
        row = self.session.run(
            "MATCH (c:CVE {id:$c}) RETURN c.user_id AS u, c.project_id AS p",
            c=self.cve).single()
        self.assertIsNone(row["u"])
        self.assertIsNone(row["p"])


if __name__ == "__main__":
    unittest.main()


class TestCrossSourceCertificateOwnership(LiveGraphCase):
    """Strategy row 9: a certificate two scanners observed must survive EITHER
    scanner's clear.

    `source` is a single mutable scalar and whoever wrote last owns it, so the
    old predicates destroyed data in both directions:

      * clear_gvm_data deleted `c.source = 'gvm'`. If GVM wrote last to a
        certificate httpx had also seen, the recon certificate went with it --
        under a comment claiming it preserved them.
      * clear_recon_data kept a node only when `source` was a non-recon source.
        If httpx wrote last to a certificate GVM had also seen, GVM's
        certificate was deleted by a recon re-run.

    Neither logged anything. The fix is `observed_by`: an append-only list of
    every writer, with each clear scoped to SOLE observership.
    """

    def _cert(self, key, observed_by, source):
        # .consume() is load-bearing: session.run() is LAZY. clear_gvm_data /
        # clear_recon_data open their OWN session, so without forcing this write
        # to commit first the code under test can run before the fixture exists
        # -- which makes a "the certificate survived" assertion pass for the
        # wrong reason, and flakes the "it was deleted" one.
        self.session.run(
            """
            CREATE (c:Certificate {cert_key: $key, user_id: $uid, project_id: $pid,
                                   subject_cn: 'mail.acme.test', source: $source,
                                   observed_by: $observed})
            """,
            key=key, uid=self.uid, pid=self.p1, source=source,
            observed=observed_by).consume()

    def _alive(self, key):
        return self.count(
            "MATCH (c:Certificate {cert_key: $k, project_id: $pid}) RETURN count(c) AS n",
            k=key, pid=self.p1)

    def _observers(self, key):
        rec = self.session.run(
            "MATCH (c:Certificate {cert_key: $k, project_id: $pid}) RETURN c.observed_by AS o",
            k=key, pid=self.p1).single()
        return list(rec["o"]) if rec else []

    # -- direction 1: GVM's clear must not take httpx's certificate ----------
    def test_gvm_clear_keeps_a_certificate_httpx_also_observed(self):
        # GVM wrote last, so `source` says gvm -- the old predicate's trap.
        self._cert("sha256:shared1", ["http_probe", "gvm"], "gvm")
        self.client.clear_gvm_data(self.uid, self.p1)
        self.assertEqual(self._alive("sha256:shared1"), 1,
                         "GVM's clear destroyed a certificate httpx also observed")

    def test_the_surviving_certificate_keeps_its_other_observer(self):
        self._cert("sha256:shared1", ["http_probe", "gvm"], "gvm")
        self.client.clear_gvm_data(self.uid, self.p1)
        self.assertIn("http_probe", self._observers("sha256:shared1"))

    def test_gvm_clear_still_removes_a_certificate_only_gvm_saw(self):
        # Control: without this the fix would just be "never delete anything".
        self._cert("sha256:gvmonly", ["gvm"], "gvm")
        self.client.clear_gvm_data(self.uid, self.p1)
        self.assertEqual(self._alive("sha256:gvmonly"), 0)

    def test_gvm_clear_removes_a_legacy_certificate_with_no_observed_by(self):
        # Rows written before observed_by existed still have to be collectable.
        self.session.run(
            """CREATE (c:Certificate {cert_key: 'sha256:legacygvm', user_id: $uid,
                                      project_id: $pid, source: 'gvm'})""",
            uid=self.uid, pid=self.p1).consume()
        self.client.clear_gvm_data(self.uid, self.p1)
        self.assertEqual(self._alive("sha256:legacygvm"), 0)

    # -- direction 2: recon's clear must not take GVM's certificate ----------
    def test_recon_clear_keeps_a_certificate_gvm_also_observed(self):
        # httpx wrote last, so `source` says http_probe -- the mirror-image trap.
        self._cert("sha256:shared2", ["gvm", "http_probe"], "http_probe")
        self.client.clear_recon_data(self.uid, self.p1)
        self.assertEqual(self._alive("sha256:shared2"), 1,
                         "a recon re-run destroyed a certificate GVM also observed")

    def test_recon_clear_still_removes_a_certificate_only_recon_saw(self):
        # Control: recon rebuilds what it can re-observe, so its own must go.
        self._cert("sha256:recononly", ["http_probe", "tlsx"], "http_probe")
        self.client.clear_recon_data(self.uid, self.p1)
        self.assertEqual(self._alive("sha256:recononly"), 0)
