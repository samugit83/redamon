"""LIVE-Neo4j proof of the positive-coverage prune (design decision D1).

With `only_hosts`, the prune deletes a source's stale findings only when one of
its host fields names a host the source re-checked, however the writer stores
it (a bare host, host:port, a URL with a port, userinfo or a path, a bracketed
IPv6 address, a passive CVE's `target_ip`). Every other finding of the source
is left as it is; a kept host still wins; `types` limits it to one check's
findings, `exclude_types` leaves a check's findings out of the source-level
rule; an empty `only_hosts` prunes nothing; a DNS finding's org (`domain`) is
one of the host fields. Hosts are example.com names and
RFC 5737 / 3849 addresses.

Self-skips unless the neo4j driver imports AND a database answers. To run it
against the dev stack, with NEO4J_PASSWORD exported from the repo .env:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_positive_prune_graph_live.py -v
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

CHECKED = ["a.example.com", "198.51.100.7", "2001:db8::1"]

#: id -> the host fields a finding carries; the first group names a checked
#: host, the second does not.
ON_CHECKED = {
    "bare-host": {"host": "a.example.com"},
    "host-port": {"host": "A.Example.com:8443"},
    "url-path": {"url": "https://a.example.com/login?next=/"},
    "url-userinfo": {"matched_at": "https://user:pw@a.example.com:8443/x"},
    "ipv6-url": {"base_url": "http://[2001:db8::1]:8080/app"},
    "bare-ipv6": {"ip": "2001:db8::1"},
    "passive-cve": {"target_ip": "198.51.100.7"},
    "two-fields-one-checked": {"hostname": "z.example.com", "matched_ip": "198.51.100.7"},
    "dns-org": {"domain": "A.example.com", "url": "", "matched_at": ""},
}
ON_UNCHECKED = {
    "other-host": {"host": "b.example.com"},
    "suffix-host": {"host": "a.example.com.evil.test"},
    "sub-host": {"url": "https://x.a.example.com/"},
    "host-in-query": {"url": "https://b.example.com/?h=a.example.com"},
    "userinfo-without-scheme": {"host": "user@a.example.com"},
    "no-host-field": {"name": "SPF missing"},
    "other-ip": {"target_ip": "198.51.100.8"},
    "dns-parent-org": {"domain": "example.com", "url": "", "matched_at": ""},
}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestPositivePruneGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"d1-{run}", f"D1_{run}"
        rows = [{"id": fid, "props": props, "type": "missing_hsts" if fid == "bare-host" else "x"}
                for fid, props in {**ON_CHECKED, **ON_UNCHECKED}.items()]
        with self.client.driver.session() as s:
            s.run(
                """
                UNWIND $rows AS r
                CREATE (v:Vulnerability {id: r.id, user_id: $u, project_id: $p, source: 'nuclei',
                                         type: r.type, updated_at: datetime() - duration('PT1H')})
                SET v += r.props
                """, rows=rows, u=self.uid, p=self.pid)
        from graph_db.mixins.base_mixin import run_timestamp
        self.since = run_timestamp()

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)

    def _left(self):
        with self.client.driver.session() as s:
            return {r["id"] for r in s.run(
                "MATCH (v:Vulnerability {user_id: $u, project_id: $p}) RETURN v.id AS id",
                u=self.uid, p=self.pid)}

    def _prune(self, **kwargs):
        return self.client.prune_unseen_findings(self.uid, self.pid, ["nuclei"], self.since,
                                                 **kwargs)

    def test_only_findings_on_a_re_checked_host_are_pruned(self):
        stats = self._prune(only_hosts=CHECKED)
        self.assertEqual(self._left(), set(ON_UNCHECKED))
        self.assertEqual(stats["pruned"], len(ON_CHECKED))

    def test_a_kept_host_wins_over_a_checked_one(self):
        self._prune(only_hosts=CHECKED, keep_hosts=["198.51.100.7"])
        self.assertEqual(self._left(), set(ON_UNCHECKED) | {"passive-cve", "two-fields-one-checked"})

    def test_types_limit_the_prune_to_one_check(self):
        self._prune(only_hosts=CHECKED, types=["missing_hsts"])
        self.assertEqual(self._left(), set(ON_CHECKED) - {"bare-host"} | set(ON_UNCHECKED))

    def test_no_re_checked_host_prunes_nothing(self):
        stats = self._prune(only_hosts=[])
        self.assertEqual(self._left(), set(ON_CHECKED) | set(ON_UNCHECKED))
        self.assertEqual(stats["pruned"], 0)

    def test_a_muted_finding_on_a_checked_host_is_stamped_stale(self):
        with self.client.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id: 'bare-host', user_id: $u, project_id: $p}) "
                  "SET v:Muted, v.muted_by = 'user-1'", u=self.uid, p=self.pid)
        stats = self._prune(only_hosts=CHECKED)
        self.assertIn("bare-host", self._left())
        self.assertEqual(stats["stale"], 1)

    def test_without_only_hosts_every_stale_finding_is_pruned_as_before(self):
        self._prune()
        self.assertEqual(self._left(), set())

    def test_excluded_types_are_left_alone_and_the_rest_pruned_as_before(self):
        self._prune(exclude_types=["missing_hsts"])
        self.assertEqual(self._left(), {"bare-host"})

    def test_a_kept_org_keeps_only_the_finding_that_names_it(self):
        self._prune(keep_hosts=["example.com"])
        self.assertEqual(self._left(), {"dns-parent-org"})


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestSecurityCheckDomainBackfillLive(unittest.TestCase):
    """Older SPF/DMARC/DNSSEC/zone-transfer findings get their org from the
    Domain they hang off, so the per-org prune can match them."""

    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"d1dns-{run}", f"D1DNS_{run}"
        with self.client.driver.session() as s:
            s.run(
                """
                CREATE (d:Domain {name: 'Example.com', user_id: $u, project_id: $p})
                CREATE (d)-[:HAS_VULNERABILITY]->(:Vulnerability {id: 'spf', user_id: $u,
                    project_id: $p, source: 'security_check', type: 'spf_missing',
                    url: '', matched_at: '', updated_at: datetime('2026-01-01T00:00:00Z')})
                CREATE (d)-[:HAS_VULNERABILITY]->(:Vulnerability {id: 'url', user_id: $u,
                    project_id: $p, source: 'security_check', type: 'missing_coop',
                    url: 'https://example.com', updated_at: datetime('2026-01-01T00:00:00Z')})
                CREATE (d)-[:HAS_VULNERABILITY]->(:Vulnerability {id: 'nuclei', user_id: $u,
                    project_id: $p, source: 'nuclei', url: ''})
                """, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)

    def _domains(self):
        with self.client.driver.session() as s:
            return {r["id"]: (r["domain"], r["at"]) for r in s.run(
                "MATCH (v:Vulnerability {user_id: $u, project_id: $p}) "
                "RETURN v.id AS id, v.domain AS domain, toString(v.updated_at) AS at",
                u=self.uid, p=self.pid)}

    def test_only_domain_level_security_findings_get_the_org(self):
        self.assertEqual(self.client.backfill_security_check_domains(self.uid, self.pid), 1)
        found = self._domains()
        self.assertEqual(found["spf"], ("example.com", "2026-01-01T00:00:00Z"))
        self.assertIsNone(found["url"][0])
        self.assertIsNone(found["nuclei"][0])
        self.assertEqual(self.client.backfill_security_check_domains(self.uid, self.pid), 0)


if __name__ == "__main__":
    unittest.main()
