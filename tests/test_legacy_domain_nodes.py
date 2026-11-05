"""Old-model Domain detection: legacy_domain_nodes (plan 4.11.6, GDB-09).

A partial run that attaches to a Domain an older scope model left behind
(`Domain(co.uk)` after the batch regrouped to `acme.co.uk`) writes the new
results under a node the next full recon deletes. The helper finds those nodes
so partial recon can refuse until a full recon.

The hermetic half checks the query the helper sends against a mocked driver,
and a reference reading of its WHERE clause against the shared vectors. The
live half seeds each vector into a real Neo4j and runs the real query, which is
what keeps that reference reading honest. It self-skips without a database:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_legacy_domain_nodes.py -v
"""
import json
import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402

CASES = json.loads(
    (_REPO / 'tests' / 'fixtures' / 'legacy_domain_vectors.json').read_text())['cases']


def _is_legacy(d: dict, expected: list, related: list) -> bool:
    """The WHERE clause of legacy_domain_nodes, read as Python."""
    n = d['name'].lower()
    expected = {e.lower() for e in expected}
    related = {r.lower() for r in related}
    return (n not in expected and not d.get('ip_mode', False)
            and any(n == r or n.endswith('.' + r) or r.endswith('.' + n) for r in related)
            and (d.get('has_subdomain', False) or d.get('coverage', False)))


class _Client(DomainMixin):
    def __init__(self, driver):
        self.driver = driver


def _mock_client(legacy):
    driver = MagicMock()
    session = driver.session.return_value.__enter__.return_value
    session.run.return_value.single.return_value = {'legacy': legacy}
    return _Client(driver), session


class TestQuery(unittest.TestCase):
    def test_the_query_and_its_parameters(self):
        client, session = _mock_client(['co.uk'])
        out = client.legacy_domain_nodes('u1', 'p1', ['ACME.co.uk', ' acme.co.uk '], ['Acme.CO.uk'])
        self.assertEqual(out, ['co.uk'])
        cypher = session.run.call_args.args[0]
        kwargs = session.run.call_args.kwargs
        for clause in (
            'MATCH (d:Domain {user_id: $uid, project_id: $pid})',
            'toLower(d.name) AS n',
            'NOT n IN $expected',
            'coalesce(d.ip_mode, false) = false',
            "n = r OR n ENDS WITH '.' + r OR r ENDS WITH '.' + n",
            'EXISTS { (d)-[:HAS_SUBDOMAIN]->() } OR d.recon_coverage_at IS NOT NULL',
        ):
            self.assertIn(clause, cypher)
        # tenant-scoped, and the names lower-cased and deduplicated
        self.assertEqual((kwargs['uid'], kwargs['pid']), ('u1', 'p1'))
        self.assertEqual(kwargs['expected'], ['acme.co.uk'])
        self.assertEqual(kwargs['related'], ['acme.co.uk'])

    def test_the_partial_container_reaches_it_on_the_client(self):
        # recon/partial_recon.py calls it as Neo4jClient().legacy_domain_nodes(...)
        from graph_db import Neo4jClient
        self.assertIs(Neo4jClient.legacy_domain_nodes, DomainMixin.legacy_domain_nodes)

    def test_the_absent_ip_mode_key_logs_no_warning(self):
        # A database that never ran an IP-mode scan has no `ip_mode` key, and
        # Neo4j's 01N52 notification otherwise floods every partial-recon log.
        from neo4j import NotificationDisabledClassification
        client, _ = _mock_client([])
        client.legacy_domain_nodes('u', 'p', [], ['acme.test'])
        self.assertEqual(
            client.driver.session.call_args.kwargs['notifications_disabled_classifications'],
            [NotificationDisabledClassification.UNRECOGNIZED])

    def test_no_related_name_sends_no_query(self):
        client, session = _mock_client(['x'])
        self.assertEqual(client.legacy_domain_nodes('u', 'p', ['a.test'], []), [])
        session.run.assert_not_called()

    def test_the_vectors_under_the_reference_reading(self):
        for case in CASES:
            got = sorted(d['name'] for d in case['domains']
                         if _is_legacy(d, case['expected'], case['related']))
            self.assertEqual(got, sorted(case['legacy']), case['name'])


_SKIP = None
try:
    import neo4j as _neo4j
except ImportError:
    _SKIP = 'neo4j driver not installed'
_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
_USER = os.getenv('NEO4J_USER', 'neo4j')
_PASSWORD = os.getenv('NEO4J_PASSWORD')
if _SKIP is None and not _PASSWORD:
    _SKIP = 'NEO4J_PASSWORD not set'


def _alive() -> bool:
    if _SKIP:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run('RETURN 1').single()
        drv.close()
        return True
    except Exception:
        return False


@unittest.skipUnless(_alive(), _SKIP or 'no Neo4j reachable')
class TestLiveVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)
        cls.uid = 'legacy-itest-user'
        cls.pids = []

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.client.driver.session() as s:
                for pid in cls.pids:
                    s.run('MATCH (n) WHERE n.project_id = $pid DETACH DELETE n', pid=pid)
        finally:
            cls.client.close()

    def test_each_vector(self):
        for case in CASES:
            pid = f'legacy-itest-{uuid.uuid4().hex[:10]}'
            self.pids.append(pid)
            with self.client.driver.session() as s:
                for d in case['domains']:
                    s.run(
                        """
                        CREATE (dom:Domain {name: $name, user_id: $uid, project_id: $pid})
                        SET dom.ip_mode = $ip_mode,
                            dom.recon_coverage_at = CASE WHEN $coverage THEN datetime() END
                        FOREACH (_ IN CASE WHEN $sub THEN [1] ELSE [] END |
                          CREATE (dom)-[:HAS_SUBDOMAIN]->(:Subdomain {name: 'www.' + $name,
                                                                     user_id: $uid, project_id: $pid}))
                        """,
                        name=d['name'], uid=self.uid, pid=pid, ip_mode=d.get('ip_mode', False),
                        coverage=d.get('coverage', False), sub=d.get('has_subdomain', False))
            got = self.client.legacy_domain_nodes(self.uid, pid, case['expected'], case['related'])
            self.assertEqual(got, sorted(case['legacy']), case['name'])


if __name__ == '__main__':
    unittest.main()
