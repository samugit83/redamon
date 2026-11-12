"""LIVE-Neo4j proof that a crawler's link mints no Subdomain (D2, R-2).

update_graph_from_external_domains MERGEd a Subdomain, with BELONGS_TO and
HAS_SUBDOMAIN, for every aggregated "external" host under a project root: a
link Hakrawler, Katana, GAU or a redirect saw. A name the run refused (the RoE,
an EXACT group's list) became a Subdomain with the crawler as its source, and
partial Naabu, httpx and Nuclei read it back as a target. The writer now only
joins a Subdomain the tenant's graph already holds. The mocked test
(recon/tests/test_crawler_link_host_subdomain.py) pins the statements; only a
real database proves the lookup creates nothing, joins what exists without
touching its provenance, and stays in its tenant.

Skipped unless the neo4j driver is importable AND a database answers:

  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://localhost:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest -q tests/test_external_domains_subdomain_live.py

Every node is scoped to throwaway user and project ids and deleted in tearDown.
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

ROOT = "example.com"
KEPT = "www.example.com"
EXCLUDED = "shop.example.com"
FOREIGN = "cdn.example.org"


def _recon(*entries, **extra):
    """The end of a domain run: the aggregate the writer reads."""
    recon = {"domain": ROOT, "subdomains": [KEPT],
             "metadata": {"root_domain": ROOT, "org_domain": ROOT, "scope_mode": "enumerate"},
             "external_domains_aggregated": [
                 {"domain": d, "sources": [src], "redirect_to_urls": [f"https://{d}/"], "times_seen": 1}
                 for d, src in entries]}
    recon.update(extra)
    return recon


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class CrawlerLinksMintNoSubdomain(unittest.TestCase):
    def setUp(self):
        from graph_db import Neo4jClient
        run = uuid.uuid4().hex[:8]
        self.uid = f"crawllink-{run}"
        self.pid = f"CRAWLLINK_{run}"
        self.other_pid = f"CRAWLLINK_OTHER_{run}"
        self.client = Neo4jClient(uri=_URI, user=_USER, password=_PASSWORD)
        self._domain(self.pid)

    def tearDown(self):
        try:
            with self.client.driver.session() as s:
                s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid).consume()
        finally:
            self.client.close()

    def _domain(self, pid):
        with self.client.driver.session() as s:
            s.run("MERGE (:Domain {name: $root, user_id: $uid, project_id: $pid})",
                  root=ROOT, uid=self.uid, pid=pid).consume()

    def _subdomain(self, name, pid=None, linked=True, source="crt.sh"):
        """A name a discovery step wrote (linked) or another writer left unlinked."""
        with self.client.driver.session() as s:
            s.run(
                """
                MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                  ON CREATE SET s.source = $source
                WITH s
                MATCH (d:Domain {name: $root, user_id: $uid, project_id: $pid})
                FOREACH (_ IN CASE WHEN $linked THEN [1] ELSE [] END |
                    MERGE (s)-[:BELONGS_TO]->(d)
                    MERGE (d)-[:HAS_SUBDOMAIN]->(s))
                """,
                name=name, root=ROOT, uid=self.uid, pid=pid or self.pid,
                linked=linked, source=source).consume()

    def _rows(self, cypher, **params):
        with self.client.driver.session() as s:
            return [r.values() for r in s.run(cypher, uid=self.uid, **params)]

    def _subdomains(self, pid=None):
        return sorted(r[0] for r in self._rows(
            "MATCH (s:Subdomain {user_id: $uid, project_id: $pid}) RETURN s.name",
            pid=pid or self.pid))

    def _externals(self):
        return sorted(r[0] for r in self._rows(
            "MATCH (e:ExternalDomain {user_id: $uid, project_id: $pid}) RETURN e.domain",
            pid=self.pid))

    def _edges(self, name):
        (row,) = self._rows(
            """
            MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
            OPTIONAL MATCH (s)-[b:BELONGS_TO]->(:Domain {name: $root, user_id: $uid, project_id: $pid})
            WITH s, count(b) AS belongs
            OPTIONAL MATCH (:Domain {name: $root, user_id: $uid, project_id: $pid})-[h:HAS_SUBDOMAIN]->(s)
            RETURN belongs, count(h), s.source
            """, name=name, root=ROOT, pid=self.pid)
        return row

    def test_an_empty_graph_gets_no_subdomain_for_a_crawled_link(self):
        self.client.update_graph_from_external_domains(
            _recon((EXCLUDED, "hakrawler"), (FOREIGN, "hakrawler")), self.uid, self.pid)

        self.assertEqual(self._subdomains(), [],
                         "a crawler's link minted a Subdomain the run never admitted")
        self.assertEqual(self._externals(), [FOREIGN])

    def test_a_link_joins_an_existing_subdomain_once_and_keeps_its_source(self):
        self._subdomain(KEPT)
        for _ in range(2):
            self.client.update_graph_from_external_domains(
                _recon((KEPT, "katana")), self.uid, self.pid)

        self.assertEqual(self._subdomains(), [KEPT])
        self.assertEqual(self._edges(KEPT), [1, 1, "crt.sh"])

    def test_an_unlinked_subdomain_joins_its_org_domain(self):
        self._subdomain(KEPT, linked=False, source="vhost_sni_enum")
        self.client.update_graph_from_external_domains(
            _recon((KEPT, "http_probe_redirect")), self.uid, self.pid)

        self.assertEqual(self._edges(KEPT), [1, 1, "vhost_sni_enum"])

    def test_the_lookup_never_crosses_into_another_project(self):
        self._domain(self.other_pid)
        self._subdomain(EXCLUDED, pid=self.other_pid)
        self.client.update_graph_from_external_domains(
            _recon((EXCLUDED, "gau")), self.uid, self.pid)

        self.assertEqual(self._subdomains(), [])
        self.assertEqual(self._rows(
            "MATCH (:Domain {user_id: $uid, project_id: $pid})-[r:HAS_SUBDOMAIN]->"
            "(:Subdomain {user_id: $uid, project_id: $other}) RETURN count(r)",
            pid=self.pid, other=self.other_pid), [[0]])

    def test_ip_mode_still_writes_a_selected_name(self):
        mock_root = f"ip-targets.{self.pid.lower()}"
        recon = {"domain": mock_root, "subdomains": ["192-0-2-10", KEPT],
                 "metadata": {"ip_mode": True, "root_domain": mock_root,
                              "expanded_ips": ["192.0.2.10"], "ip_mode_hosts": {KEPT: ROOT}},
                 "external_domains_aggregated": [
                     {"domain": KEPT, "sources": ["http_probe_redirect"], "times_seen": 1}]}
        self.client.update_graph_from_external_domains(recon, self.uid, self.pid)

        self.assertEqual(self._subdomains(), [KEPT])
        self.assertEqual(self._edges(KEPT), [1, 1, "http_probe_redirect"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
