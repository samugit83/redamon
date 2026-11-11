"""LIVE-Neo4j proof that the prune reads a finding's list host fields (R-49).

A dependency-confusion finding's scalar host fields name the first file that
imports its package; `source_urls` names every one, on up to five hosts. A
host only the list names must keep the finding when the run cut it, and count
as one of its hosts when the run re-checked it, the way a scalar field does.
Another project's identical finding is never touched, a restored finding
(ISO-string `updated_at`, R-38) is read the same, and a list field holding a
scalar or non-strings does not fail the prune. Hosts are example.com names.

Self-skips unless the neo4j driver imports AND a database answers. To run it
against the dev stack, with NEO4J_PASSWORD exported from the repo .env:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_prune_list_host_fields_graph_live.py -v

Everything is written under a throwaway user id and DETACH DELETEd in teardown.
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

A, B, C = "app.example.com", "admin.example.com", "cdn.example.com"
UNDERSCORE = "dev_api.example.com"
A_JS = f"https://{A}/static/main.js"
B_JS = f"https://{B}:8443/assets/admin.js"
U_JS = f"https://{UNDERSCORE}/bundle.js"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestListHostFieldsLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"listhost-{run}"
        self.pid, self.other = f"LH_{run}", f"LH_{run}_other"
        from graph_db.mixins.base_mixin import run_timestamp
        self.since = run_timestamp()

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)

    def _write(self, source_urls, *, fid="dep-1", restored=False, project=None):
        """One stale dependency finding as the writer stores it: the first file
        is its source_url, that file's origin its base_url."""
        listed = source_urls if isinstance(source_urls, list) else []
        first = next((u for u in listed if isinstance(u, str)), "")
        base = first.split("/", 3)[0] + "//" + first.split("/", 3)[2] if "://" in first else ""
        with self.client.driver.session() as s:
            s.run(
                """
                CREATE (f:JsReconFinding {id: $id, user_id: $u, project_id: $p, source: 'js_recon',
                                          finding_type: 'dependency_confusion',
                                          source_url: $first, base_url: $base,
                                          source_urls: $urls})
                SET f.updated_at = CASE WHEN $restored
                    THEN toString(datetime() - duration('PT1H'))
                    ELSE datetime() - duration('PT1H') END
                """, id=fid, u=self.uid, p=project or self.pid, first=first, base=base,
                urls=source_urls, restored=restored)

    def _write_both_tenants(self, source_urls, **kw):
        self._write(source_urls, **kw)
        self._write(source_urls, project=self.other, **kw)

    def _left(self, project=None):
        with self.client.driver.session() as s:
            return {r["id"] for r in s.run(
                "MATCH (f:JsReconFinding {user_id: $u, project_id: $p}) RETURN f.id AS id",
                u=self.uid, p=project or self.pid)}

    def _prune(self, **kw):
        return self.client.prune_unseen_findings(self.uid, self.pid, ["js_recon"], self.since, **kw)

    # -- keep_hosts: a host the run cut -----------------------------------

    def test_a_cut_host_only_the_list_names_keeps_the_finding(self):
        self._write_both_tenants([A_JS, B_JS])
        stats = self._prune(keep_hosts=[B])
        self.assertEqual(self._left(), {"dep-1"})
        self.assertEqual(stats["pruned"], 0)

    def test_a_cut_host_the_finding_does_not_name_keeps_nothing(self):
        self._write_both_tenants([A_JS, B_JS])
        self._prune(keep_hosts=[C])
        self.assertEqual(self._left(), set())
        self.assertEqual(self._left(self.other), {"dep-1"}, "another project's finding is untouched")

    def test_an_underscore_host_in_the_list_keeps_it(self):
        self._write([A_JS, U_JS])
        self._prune(keep_hosts=[UNDERSCORE])
        self.assertEqual(self._left(), {"dep-1"})

    # -- only_hosts: the hosts a positive source re-checked ----------------

    def test_a_degraded_second_host_keeps_it_though_the_first_was_checked(self):
        """What main.py sends for a positive source: the cut host is out of
        the checked set and in the keep set."""
        self._write_both_tenants([A_JS, B_JS])
        self._prune(only_hosts=[A], keep_hosts=[B])
        self.assertEqual(self._left(), {"dep-1"})

    def test_every_host_checked_prunes_it_in_its_own_project_only(self):
        self._write_both_tenants([A_JS, B_JS])
        stats = self._prune(only_hosts=[A, B])
        self.assertEqual(self._left(), set())
        self.assertEqual(stats["pruned"], 1)
        self.assertEqual(self._left(self.other), {"dep-1"})

    def test_a_re_checked_host_only_the_list_names_counts(self):
        self._write([A_JS, B_JS])
        self._prune(only_hosts=[B])
        self.assertEqual(self._left(), set())

    def test_a_host_the_finding_does_not_name_prunes_nothing(self):
        self._write([A_JS, B_JS])
        self._prune(only_hosts=[C])
        self.assertEqual(self._left(), {"dep-1"})

    # -- older and odd nodes -------------------------------------------------

    def test_a_restored_finding_is_kept_and_pruned_the_same_way(self):
        self._write([A_JS, B_JS], restored=True)
        self._prune(keep_hosts=[B])
        self.assertEqual(self._left(), {"dep-1"})
        self._prune(only_hosts=[A, B])
        self.assertEqual(self._left(), set())

    def test_a_scalar_in_the_list_field_is_read_as_one_host(self):
        self._write(B_JS, fid="dep-scalar")
        self._prune(keep_hosts=[B])
        self.assertEqual(self._left(), {"dep-scalar"})
        self._prune(only_hosts=[B])
        self.assertEqual(self._left(), set())

    def test_non_string_elements_do_not_fail_the_prune(self):
        self._write([7, 8], fid="dep-ints")
        self._write([A_JS, B_JS], fid="dep-1")
        self._prune(keep_hosts=[B])
        self.assertEqual(self._left(), {"dep-1"})

    def test_a_finding_written_before_the_list_existed_is_unchanged(self):
        with self.client.driver.session() as s:
            s.run("""CREATE (f:JsReconFinding {id: 'dep-old', user_id: $u, project_id: $p,
                       source: 'js_recon', finding_type: 'dependency_confusion',
                       source_url: $url, base_url: 'upload',
                       updated_at: datetime() - duration('PT1H')})""",
                  u=self.uid, p=self.pid, url=A_JS)
        self._prune(keep_hosts=[A])
        self.assertEqual(self._left(), {"dep-old"})
        self._prune(only_hosts=[A])
        self.assertEqual(self._left(), set())


if __name__ == "__main__":
    unittest.main()
