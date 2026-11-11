"""LIVE-Neo4j proof that an Uncover URL mints no Subdomain for a host the
payload does not name (D2).

merge_uncover_into_pipeline removes every name its gates refuse (RoE included)
from the payload's hosts, but keeps the URLs. update_graph_from_uncover MERGEd a
Subdomain for every URL host, so an RoE-excluded host became a Subdomain that
partial Naabu, httpx and Nuclei then read as a target. The mocked test
(recon/tests/test_uncover_url_host_roe.py) pins which statements run; only a
real database proves the lookup creates nothing, stays in its tenant, and falls
back to the Domain.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_uncover_graph_url_hosts_live.py -v
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
_ORG = "uncover-roe-itest.test"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestUncoverUrlHostsLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"unc-roe-{run}"
        self.pid = f"UNCROE_{run}"
        # Another tenant holding the excluded name as a Subdomain: the lookup
        # must never reach it.
        self.other_uid = f"unc-roe-other-{run}"
        with self.client.driver.session() as s:
            s.run(
                """
                CREATE (:Domain {name: $org, user_id: $u, project_id: $p})
                CREATE (:Subdomain {name: 'www.' + $org, user_id: $u, project_id: $p})
                CREATE (:Subdomain {name: 'shop.' + $org, user_id: $ou, project_id: $p})
                """, org=_ORG, u=self.uid, p=self.pid, ou=self.other_uid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id IN [$u, $ou] DETACH DELETE n",
                  u=self.uid, ou=self.other_uid)

    def _count(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, **params).single()[0]

    def _uncover(self, hosts, urls):
        return self.client.update_graph_from_uncover({
            "domain": _ORG,
            "uncover": {"hosts": hosts, "ips": [], "ip_ports": {}, "urls": urls,
                        "sources": ["shodan"], "source_counts": {}, "total_raw": 1,
                        "total_deduped": 1},
        }, self.uid, self.pid)

    def _owner_of(self, base_url):
        with self.client.driver.session() as s:
            rows = s.run(
                """MATCH (o)-[:HAS_BASE_URL]->(:BaseURL {url: $b, user_id: $u, project_id: $p})
                   RETURN labels(o)[0] AS label, o.name AS name""",
                b=base_url, u=self.uid, p=self.pid)
            return sorted((r["label"], r["name"]) for r in rows)

    def test_a_url_host_the_merge_refused_gets_no_subdomain(self):
        # The merge dropped shop (RoE) from hosts; its URL is still in the payload.
        stats = self._uncover([f"api.{_ORG}"], [f"https://api.{_ORG}/login", f"https://shop.{_ORG}/cart"])

        self.assertEqual(stats["errors"], [])
        self.assertEqual(self._count(
            "MATCH (s:Subdomain {name: $n, user_id: $u, project_id: $p}) RETURN count(s)",
            n=f"shop.{_ORG}", u=self.uid, p=self.pid), 0)
        self.assertEqual(self._owner_of(f"https://shop.{_ORG}"), [("Domain", _ORG)])
        # The other tenant's node is neither linked nor changed.
        self.assertEqual(self._count(
            "MATCH (s:Subdomain {name: $n, user_id: $ou})-[r]-() RETURN count(r)",
            n=f"shop.{_ORG}", ou=self.other_uid), 0)
        # The name the payload does carry is still a Subdomain owning its URL.
        self.assertEqual(self._owner_of(f"https://api.{_ORG}"), [("Subdomain", f"api.{_ORG}")])

    def test_a_url_host_already_in_the_graph_joins_its_subdomain(self):
        self._uncover([], [f"https://www.{_ORG}/page"])

        self.assertEqual(self._owner_of(f"https://www.{_ORG}"), [("Subdomain", f"www.{_ORG}")])
        self.assertEqual(self._count(
            "MATCH (s:Subdomain {user_id: $u, project_id: $p}) RETURN count(s)",
            u=self.uid, p=self.pid), 1)


if __name__ == "__main__":
    unittest.main()
