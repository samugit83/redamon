"""The graph side of the security-check outcomes (R-24), without Neo4j.

A DNS finding (SPF, DMARC, DNSSEC, zone transfer) names no url, host or IP, so
the prune could neither keep it for an org whose check timed out nor delete it
on an org whose check came back clean. The writer now stores the org as
`domain`, one of the prune's host fields, without changing the finding's id;
`backfill_security_check_domains` gives older findings the same field from the
Domain they hang off. `prune_unseen_findings(exclude_types=)` prunes every
other type of a source by the source-level rule, so the checks that record
their coverage per type do not stop the rest of security_check from pruning.
The Cypher is proven against a real graph in tests/test_positive_prune_graph_live.py.

Roots are alpha.test / beta.test only.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins import base_mixin  # noqa: E402
from graph_db.mixins.base_mixin import BaseMixin  # noqa: E402
from graph_db.mixins.recon.vuln_mixin import VulnMixin, stable_vuln_id  # noqa: E402

SINCE = "2026-01-01T00:00:00+00:00"


class _Session:
    def __init__(self, single=None):
        self.calls = []
        self._single = single or {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = {"matched": 1, "removed": 0, "created": 0, "linked": 0,
                                      "pruned": 0, "stale": 0, "revived": 0, **self._single}
        return result


def _client(cls, session):
    client = cls.__new__(cls)
    client.driver = MagicMock()
    client.driver.session.side_effect = lambda: session
    return client


def _written(findings, **recon):
    session = _Session()
    data = {"domain": "alpha.test", "subdomains": [], "metadata": {},
            "vuln_scan": {"security_checks": {"findings": findings}}, **recon}
    _client(VulnMixin, session).update_graph_from_vuln_scan(data, "u1", "p1")
    return [p["props"] for q, p in session.calls if "MERGE (v:Vulnerability {id: $id" in q]


class TestTheWriterStoresTheOrg(unittest.TestCase):
    def test_a_dns_finding_stores_its_org_and_keeps_its_id(self):
        (props,) = _written([{"type": "spf_missing", "domain": "Alpha.Test"}])
        self.assertEqual(props["domain"], "alpha.test")
        self.assertEqual(props["id"], stable_vuln_id("spf_missing", "", "", "u1", "p1"))

    def test_a_batch_stores_the_org_of_the_scan_root(self):
        (props,) = _written(
            [{"type": "dmarc_missing", "domain": "api.beta.test"}],
            domain="api.beta.test", domains=["api.beta.test"],
            metadata={"domain_batch": True},
            scope_groups=[{"scan_root": "api.beta.test", "org_domain": "beta.test"}])
        self.assertEqual(props["domain"], "beta.test")
        self.assertEqual(props["id"], stable_vuln_id("dmarc_missing", "", "beta.test", "u1", "p1"))

    def test_a_finding_with_a_url_or_an_ip_stores_no_domain(self):
        findings = _written([
            {"type": "missing_coop", "url": "https://www.alpha.test", "domain": "alpha.test"},
            {"type": "redis_no_auth", "ip": "198.51.100.10", "port": 6379},
        ])
        self.assertEqual([p.get("domain") for p in findings], [None, None])


class TestTheBackfill(unittest.TestCase):
    def _backfill(self, count):
        session = _Session({"backfilled": count})
        n = _client(VulnMixin, session).backfill_security_check_domains("u1", "p1")
        return n, session.calls

    def test_older_domain_level_findings_get_the_org_they_hang_off(self):
        n, calls = self._backfill(2)
        self.assertEqual(n, 2)
        ((query, params),) = calls
        self.assertIn("(d:Domain {user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->", query)
        self.assertIn("source: 'security_check'", query)
        self.assertIn("v.domain IS NULL", query)
        self.assertIn("coalesce(v.url, '') = ''", query)
        self.assertIn("SET v.domain = org", query)
        self.assertEqual(params, {"uid": "u1", "pid": "p1"})

    def test_it_never_writes_updated_at(self):
        _, calls = self._backfill(0)
        self.assertNotIn("updated_at", calls[0][0])


def _prune(**kwargs):
    session = _Session({"pruned": 2, "stale": 1, "revived": 3})
    stats = _client(BaseMixin, session).prune_unseen_findings(
        "u1", "p1", ["security_check"], SINCE, **kwargs)
    return stats, session.calls


class TestExcludeTypes(unittest.TestCase):
    def test_none_is_the_older_query_byte_for_byte(self):
        _, plain = _prune(keep_hosts=["a.example.com"])
        _, explicit = _prune(keep_hosts=["a.example.com"], exclude_types=None)
        self.assertEqual(plain, explicit)
        self.assertNotIn("$exclude_types", plain[1][0])

    def test_the_listed_types_are_left_out(self):
        _, calls = _prune(exclude_types=("spf_missing", "dmarc_missing", "spf_missing", ""))
        prune_query, params = calls[1]
        self.assertIn("AND NOT coalesce(n.type, '') IN $exclude_types", prune_query)
        self.assertLess(prune_query.index("$exclude_types"), prune_query.index("SET n._prune_lock"))
        self.assertEqual(params["exclude_types"], ["dmarc_missing", "spf_missing"])
        self.assertNotIn("only_hosts", params)

    def test_excluding_nothing_changes_nothing(self):
        _, plain = _prune()
        _, empty = _prune(exclude_types=())
        self.assertEqual(plain, empty)


class TestTheOrgIsAHostField(unittest.TestCase):
    def test_domain_is_read_by_the_keep_and_the_positive_rule(self):
        self.assertIn("domain", base_mixin._KEEP_HOST_FIELDS)
        self.assertIn("toLower(toStringOrNull(n.domain))", base_mixin._ONLY_HOSTS_CLAUSE)
        _, calls = _prune(keep_hosts=["alpha.test"])
        self.assertIn("coalesce(toLower(toStringOrNull(n.domain)), '') =~ rx", calls[1][0])


if __name__ == "__main__":
    unittest.main()
