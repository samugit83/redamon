"""LIVE-Neo4j: passive CVEs are pruned only on the IPs a lookup decided (D1, option b).

An earlier run left Shodan and CriminalIP CVEs on four IPs. This run's real
enrichers (their HTTP calls mocked) ask about one IP and get an answer with no
CVE, ask about another and get none, see a third dropped by their CDN filter,
and never see the fourth, which left the run. The real end-of-run prune then
runs against Neo4j: the CVEs of the answered and the filtered IP are deleted,
those of the unanswered IP and of the IP that left the run are kept. The
legacy rows carry no `target_ip`, so this also proves the backfill gives them
the IP their id names before the positive prune matches on it. Addresses are
RFC 5737.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/recon \\
    -e PYTHONPATH=/repo/recon:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD -e HOME=/tmp --entrypoint sh \\
    redamon-recon -c 'python -m pytest -q tests/test_passive_cve_positive_prune_live.py'

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

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

CLEAN, CDN, UNANSWERED, GONE = "198.51.100.31", "198.51.100.34", "198.51.100.35", "198.51.100.39"
TARGETS = [CLEAN, CDN, UNANSWERED]


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.text = ""
        self.headers = {}

    def json(self):
        return self._body


def _provider(url, params=None, **_kw):
    if url.endswith("/" + CLEAN) or CLEAN in str(params or {}):
        return _Resp(200, {})
    if url.endswith("/" + UNANSWERED) or UNANSWERED in str(params or {}):
        raise ConnectionError("refused")
    raise AssertionError("looked up an IP the run must not ask about")


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LivePassiveCvePositivePrune(unittest.TestCase):
    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"fd1p-{run}", f"FD1P_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        rows = [{"id": f"{prefix}-CVE-2018-15473-{ip}", "source": source}
                for prefix, source in (("shodan", "internetdb"), ("criminalip", "criminalip"))
                for ip in (CLEAN, CDN, UNANSWERED, GONE)]
        with self.driver.session() as s:
            s.run("""
                UNWIND $rows AS row
                CREATE (v:Vulnerability {id: row.id, source: row.source, name: row.id,
                        user_id: $u, project_id: $p,
                        updated_at: datetime('2020-01-01T00:00:00Z')})
                """, rows=rows, u=self.uid, p=self.pid).consume()

        from recon.helpers import circuit_breaker
        circuit_breaker.reset_registry()
        stub = {
            'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True,
            'TARGET_IPS': list(TARGETS), 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
            'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': [],
            'UPDATE_GRAPH_DB': True, 'USER_ID': self.uid, 'PROJECT_ID': self.pid,
            'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
            'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
        }
        with mock.patch('recon.project_settings.get_settings', return_value=stub):
            for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
                del sys.modules[mod]
            import recon.main as rm
        from graph_db.mixins.base_mixin import run_timestamp
        rm._RUN_STARTED_AT = run_timestamp()
        rm._COVERAGE_WRITE_FAILED = False
        rm.SCAN_MODULES = []
        self.rm = rm

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid).consume()
        self.driver.close()
        from recon.helpers import circuit_breaker
        circuit_breaker.reset_registry()

    def _surviving(self) -> set:
        with self.driver.session() as s:
            rows = s.run("MATCH (v:Vulnerability {user_id: $u, project_id: $p}) "
                         "RETURN v.source AS source, v.target_ip AS ip",
                         u=self.uid, p=self.pid)
            return {(r["source"], r["ip"]) for r in rows}

    def test_only_the_decided_ips_lose_their_cves(self):
        from recon.main_recon_modules import criminalip_enrich as cip
        from recon.main_recon_modules import shodan_enrich as se

        def drop_cdn(ips, *_a, **_k):
            return [ip for ip in ips if ip != CDN]

        recon = {"domain": "", "metadata": {"ip_mode": True, "expanded_ips": list(TARGETS)},
                 "dns": {"domain": {}, "subdomains": {}}}
        with mock.patch.object(se, "filter_ips_for_enrichment", drop_cdn), \
                mock.patch.object(cip, "filter_ips_for_enrichment", drop_cdn), \
                mock.patch.object(se.time, "sleep", lambda *_: None), \
                mock.patch.object(se.requests, "get", side_effect=_provider), \
                mock.patch.object(cip.requests, "get", side_effect=_provider):
            se.run_shodan_enrichment(dict(recon), {
                "SHODAN_HOST_LOOKUP": True, "SHODAN_PASSIVE_CVES": True,
                "SHODAN_API_KEY": "", "SHODAN_WORKERS": 1})
            cip.run_criminalip_enrichment(dict(recon), {
                "CRIMINALIP_ENABLED": True, "CRIMINALIP_API_KEY": "synthetic-key-0000",
                "CRIMINALIP_WORKERS": 1})

        self.rm._prune_recon_findings()
        self.assertEqual(self._surviving(), {
            ("internetdb", UNANSWERED), ("internetdb", GONE),
            ("criminalip", UNANSWERED), ("criminalip", GONE)})


if __name__ == "__main__":
    unittest.main()
