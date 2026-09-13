"""LIVE-Neo4j proof that the Certificate re-key really applied (strategy row 11).

`init_schema` swallows every DDL exception, so a constraint that fails to create
is INVISIBLE. That matters here more than usual:

  * `CREATE CONSTRAINT certificate_unique IF NOT EXISTS` against a database that
    already has a constraint of that name is a silent no-op -- the old
    subject_cn key survives and the new key is never applied. That is why the
    new constraint had to be given a DIFFERENT name.
  * Without the uniqueness actually in force, two scanners observing one
    certificate produce two nodes, and a snapshot restore has nothing to MERGE on.

So the only honest test is to ask the running database what it enforces.

Run:
  docker run --rm --network host -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://localhost:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_cert_constraint_live -v
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
class CertificateConstraintLive(unittest.TestCase):
    def setUp(self):
        from graph_db import Neo4jClient
        # Constructing the client runs init_schema, which is the code under test.
        self.client = Neo4jClient(uri=_URI, user=_USER, password=_PASSWORD)
        self.session = self.client.driver.session()
        run = uuid.uuid4().hex[:8]
        self.uid = f"certc-{run}"
        self.pid = f"CERTC_{run}"

    def tearDown(self):
        try:
            self.session.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid)
        finally:
            self.session.close()
            self.client.close()

    def _cert_constraints(self):
        rows = self.session.run(
            "SHOW CONSTRAINTS YIELD name, labelsOrTypes, properties, type "
            "WHERE type = 'UNIQUENESS' AND 'Certificate' IN labelsOrTypes "
            "RETURN name, properties").data()
        return {r["name"]: r["properties"] for r in rows}

    def test_the_new_constraint_exists_and_keys_on_cert_key(self):
        cons = self._cert_constraints()
        self.assertIn("certificate_key_unique", cons,
                      f"re-key never applied; Certificate constraints = {cons}")
        self.assertEqual(cons["certificate_key_unique"],
                         ["cert_key", "user_id", "project_id"])

    def test_the_old_subject_cn_constraint_is_gone(self):
        cons = self._cert_constraints()
        self.assertNotIn("certificate_unique", cons,
                         "the old subject_cn constraint survived the rename")
        for name, props in cons.items():
            self.assertNotIn("subject_cn", props,
                             f"{name} still keys Certificate on subject_cn")

    def test_the_constraint_is_actually_enforced(self):
        """A constraint that exists but does not bite is worth nothing."""
        self.session.run(
            "CREATE (c:Certificate {cert_key: 'sha256:dup', user_id: $uid, project_id: $pid})",
            uid=self.uid, pid=self.pid)
        with self.assertRaises(Exception) as ctx:
            self.session.run(
                "CREATE (c:Certificate {cert_key: 'sha256:dup', user_id: $uid, project_id: $pid})",
                uid=self.uid, pid=self.pid).consume()
        self.assertIn("already exists", str(ctx.exception).lower())

    def test_two_certificates_sharing_a_subject_cn_are_now_legal(self):
        """The whole point of the re-key: a CN is not a certificate identity.
        Under the old constraint the second CREATE threw."""
        for key in ("sha256:aaa", "sha256:bbb"):
            self.session.run(
                "CREATE (c:Certificate {cert_key: $k, subject_cn: 'mail.acme.test', "
                "user_id: $uid, project_id: $pid})", k=key, uid=self.uid, pid=self.pid)
        n = self.session.run(
            "MATCH (c:Certificate {user_id: $uid, project_id: $pid}) RETURN count(c) AS n",
            uid=self.uid, pid=self.pid).single()["n"]
        self.assertEqual(n, 2)

    def test_the_tenant_index_backing_certificate_reads_exists(self):
        """Re-keying moved the index that backed project-scoped certificate
        reads; readers filtering on project_id alone would lose index support."""
        names = [r["name"] for r in self.session.run(
            "SHOW INDEXES YIELD name, labelsOrTypes "
            "WHERE 'Certificate' IN labelsOrTypes RETURN name").data()]
        self.assertIn("idx_certificate_tenant", names, f"indexes = {names}")

    def test_the_backfill_marker_was_recorded_so_it_does_not_rescan_forever(self):
        from graph_db.schema import CERT_KEY_BACKFILL_MARKER
        n = self.session.run(
            "MATCH (m:RedamonSchemaMigration {id: $id}) RETURN count(m) AS n",
            id=CERT_KEY_BACKFILL_MARKER).single()["n"]
        self.assertEqual(n, 1, "cert_key backfill marker missing: it will re-scan "
                               "every Certificate on every client construction")

    def test_no_certificate_in_the_database_is_left_without_a_key(self):
        """A node missing the key property escapes the uniqueness constraint
        entirely, which is how duplicates come back."""
        n = self.session.run(
            "MATCH (c:Certificate) WHERE c.cert_key IS NULL RETURN count(c) AS n"
        ).single()["n"]
        self.assertEqual(n, 0)


if __name__ == "__main__":
    unittest.main()
