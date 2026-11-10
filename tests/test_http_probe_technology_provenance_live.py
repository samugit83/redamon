"""LIVE-Neo4j proof that an httpx or Wappalyzer sighting keeps GVM's claim on a
Technology node, so the next full recon does not delete it (R-25).

clear_recon_data spares a Technology only while its `detected_by` holds `gvm`,
and clear_gvm_data deletes one whose `detected_by` is exactly `gvm` and strips a
`,gvm` suffix. update_graph_from_http_probe used to overwrite `detected_by`, so:

  * GVM `httpx,gvm` -> recon run 1 keeps it -> http_probe resets it to `httpx`
    -> recon run 2 deletes the node with its HAS_VULNERABILITY edges;
  * a GVM-only versionless node httpx re-saw stayed `gvm`, so a GVM rescan
    deleted it with the Endpoint edge httpx had just written.

Self-skips unless the neo4j driver imports AND a database answers. Everything it
writes is under a random tenant and is deleted afterwards. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_http_probe_technology_provenance_live.py -v
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
_URL = "https://app.example.test"


def _probe_data(technologies=(), wappalyzer=()):
    return {"http_probe": {
        "scan_metadata": {},
        "by_host": {},
        "by_url": {_URL: {"url": _URL, "host": "app.example.test", "status_code": 200,
                          "technologies": list(technologies)}},
        "wappalyzer": {"by_url": {_URL: list(wappalyzer)}, "all_technologies": {}},
    }}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestHttpProbeKeepsGvmProvenanceLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"r25-{run}", f"R25_{run}"

    def tearDown(self):
        self._q("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)

    def _q(self, cypher, **params):
        with self.client.driver.session() as s:
            return [r.data() for r in s.run(cypher, **params)]

    def _seed_gvm_tech(self, name, version, detected_by):
        """A Technology GVM tagged, with one GVM vulnerability hanging off it."""
        self._q(
            """
            CREATE (t:Technology {name: $name, version: $version, user_id: $u, project_id: $p,
                                  detected_by: $detected_by, cpe: 'cpe:/a:example:product'})
            CREATE (v:Vulnerability {id: $u + '-' + $name, source: 'gvm', severity: 'high',
                                     user_id: $u, project_id: $p})
            CREATE (t)-[:HAS_VULNERABILITY]->(v)
            """,
            name=name, version=version, detected_by=detected_by, u=self.uid, p=self.pid)

    def _tech(self, name):
        rows = self._q(
            """
            MATCH (t:Technology {name: $name, user_id: $u, project_id: $p})
            RETURN t.version AS version, t.detected_by AS detected_by,
                   [(t)-[:HAS_VULNERABILITY]->(v) | v.id] AS gvm_vulns,
                   [(e:Endpoint)-[r:USES_TECHNOLOGY]->(t) | r.detected_by] AS endpoint_edges
            """,
            name=name, u=self.uid, p=self.pid)
        return rows[0] if rows else None

    def _write(self, **probe):
        stats = self.client.update_graph_from_http_probe(_probe_data(**probe), self.uid, self.pid)
        self.assertEqual(stats["errors"], [])

    def test_httpx_keeps_the_gvm_tag_and_the_next_clear_spares_the_node(self):
        self._seed_gvm_tech("nginx", "1.19.0", "httpx,gvm")
        self._write(technologies=["nginx:1.19.0"])
        self.assertEqual(self._tech("nginx")["detected_by"], "httpx,gvm")

        self.client.clear_recon_data(self.uid, self.pid)
        tech = self._tech("nginx")
        self.assertIsNotNone(tech, "the next full recon deleted a GVM-tagged Technology")
        self.assertEqual(tech["gvm_vulns"], [f"{self.uid}-nginx"])

    def test_a_gvm_only_node_gains_httpx_ahead_of_gvm(self):
        self._seed_gvm_tech("nginx", "1.19.0", "gvm")
        self._write(technologies=["nginx:1.19.0"])
        self.assertEqual(self._tech("nginx")["detected_by"], "httpx,gvm")

    def test_wappalyzer_keeps_the_gvm_tag_too(self):
        self._seed_gvm_tech("jQuery", "3.5.1", "gvm")
        self._write(wappalyzer=[{"name": "jQuery", "version": "3.5.1"}])
        self.assertEqual(self._tech("jQuery")["detected_by"], "wappalyzer,gvm")

        self.client.clear_recon_data(self.uid, self.pid)
        self.assertIsNotNone(self._tech("jQuery"))

    def test_a_gvm_rescan_strips_only_gvm_from_a_versionless_node_httpx_saw(self):
        self._seed_gvm_tech("Ubuntu", "", "gvm")
        self._write(technologies=["Ubuntu"])
        self.assertEqual(self._tech("Ubuntu")["detected_by"], "httpx,gvm")

        self.client.clear_gvm_data(self.uid, self.pid)
        tech = self._tech("Ubuntu")
        self.assertIsNotNone(tech, "a GVM rescan deleted a Technology httpx also saw")
        self.assertEqual(tech["detected_by"], "httpx")
        self.assertEqual(tech["endpoint_edges"], ["httpx"])

    def test_detectors_are_listed_once_and_gvm_stays_last(self):
        self._seed_gvm_tech("nginx", "1.19.0", "gvm")
        self._write(technologies=["nginx:1.19.0"])
        self._write(technologies=["nginx:1.19.0"])
        self._write(wappalyzer=[{"name": "nginx", "version": "1.19.0"}])
        self.assertEqual(self._tech("nginx")["detected_by"], "httpx,wappalyzer,gvm")

    def test_a_new_node_and_an_older_untagged_one_name_only_the_detector(self):
        self._q("CREATE (:Technology {name: 'PHP', version: '8.1', user_id: $u, project_id: $p})",
                u=self.uid, p=self.pid)
        self._write(technologies=["PHP:8.1", "Express"])
        self.assertEqual(self._tech("PHP")["detected_by"], "httpx")
        self.assertEqual(self._tech("Express")["detected_by"], "httpx")
        self.assertEqual(self._tech("Express")["version"], "")


if __name__ == "__main__":
    unittest.main()
