"""Phase 0 certificate plumbing: re-key + cross-source deletion safety.

Query-structure regressions (a live-DB survival test lives in the graph-live
tier). These guard the exact defects Phase 0 fixed:
  - the constraint moved to cert_key under a NEW name (a same-name recreate is a
    silent no-op);
  - clear_gvm_data no longer deletes a cert httpx/tlsx also observed;
  - clear_recon_data no longer deletes a cert GVM also observed.

Run: python -m unittest tests.test_certificate_rekey
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db import schema  # noqa: E402


class FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class FakeSession:
    def __init__(self):
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        for key in ("deleted_count", "deleted", "cleaned", "kept"):
            if f"as {key}" in query or f"AS {key}" in query:
                return FakeResult({key: 0})
        return FakeResult()


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


def _client(session):
    from graph_db.mixins.base_mixin import BaseMixin
    client = BaseMixin.__new__(BaseMixin)
    client.driver = FakeDriver(session)
    return client


def _run(method, *args):
    session = FakeSession()
    getattr(_client(session), method)(*args)
    return [q for q, _ in session.queries]


class TestConstraintRekey(unittest.TestCase):
    def test_old_constraint_dropped_by_its_old_name(self):
        self.assertIn("DROP CONSTRAINT certificate_unique IF EXISTS",
                      schema.DROP_LEGACY_CONSTRAINTS)

    def test_new_constraint_has_a_new_name_on_cert_key(self):
        joined = "\n".join(schema.CONSTRAINTS)
        self.assertIn("certificate_key_unique", joined)
        self.assertIn("(c.cert_key, c.user_id, c.project_id)", joined)

    def test_no_constraint_still_keys_certificate_on_subject_cn(self):
        for c in schema.CONSTRAINTS:
            if "Certificate" in c:
                self.assertNotIn("c.subject_cn", c,
                                 "subject_cn is not a certificate identity")

    def test_certificate_has_a_backing_tenant_index(self):
        self.assertTrue(any("idx_certificate_tenant" in i for i in schema.TENANT_INDEXES))

    def test_backfill_is_guarded_and_wired(self):
        self.assertTrue(hasattr(schema, "backfill_cert_key"))
        self.assertTrue(hasattr(schema, "CERT_KEY_BACKFILL_MARKER"))

    def test_backfill_does_not_touch_updated_at(self):
        import inspect
        src = inspect.getsource(schema.backfill_cert_key)
        self.assertNotIn(".updated_at", src,
                         "bumping updated_at lights the unseen badge for every cert")


class TestCrossSourceDeletion(unittest.TestCase):
    def test_gvm_clear_scopes_certs_to_sole_gvm_observership(self):
        queries = _run("clear_gvm_data", "u1", "p1")
        cert_delete = next(q for q in queries
                           if ":Certificate" in q and "DELETE" in q and "observed_by" in q)
        self.assertIn("observed_by, []) = ['gvm']", cert_delete)

    def test_gvm_clear_no_longer_deletes_certs_by_source_alone(self):
        queries = _run("clear_gvm_data", "u1", "p1")
        cert_delete = next(q for q in queries if ":Certificate" in q and "DELETE" in q)
        # the sole 'c.source = gvm' predicate must be gated by empty observed_by
        self.assertNotIn("WHERE c.source = 'gvm'\n", cert_delete)

    def test_recon_clear_preserves_certs_with_a_non_recon_observer(self):
        queries = _run("clear_recon_data", "u1", "p1")
        wipe = next(q for q in queries if "MATCH (n)" in q and "AS deleted" in q)
        self.assertIn("n:Certificate AND any(o IN coalesce(n.observed_by, [])", wipe)


if __name__ == "__main__":
    unittest.main()
