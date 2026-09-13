"""Unit tests for the GitHub Secret Hunt graph writer's pre-clear.

Uses a fake Neo4j session (no live DB), mirroring test_supply_chain_mixin.

Guards two regressions:
- the pre-clear used to `DETACH DELETE` every GithubRepository in the project,
  destroying the supply-chain scan's DEPENDS_ON edges on the node both features
  share by design (supply_chain_mixin.ensure_github_repository).
- node ids used the builtin hash(), randomised per process, so the same file
  got a different GithubPath id on every scan.

Run: python -m unittest tests.test_github_hunt_graph_clear
"""

import hashlib
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.base_mixin import BaseMixin
from graph_db.mixins.secret_mixin import SecretMixin


class FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class FakeSession:
    """Records every query; answers the counting reads with 0."""

    def __init__(self, domain_exists=True):
        self.queries = []
        self.domain_exists = domain_exists

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if "HAS_GITHUB_HUNT" in query:
            return FakeResult({"linked": 1 if self.domain_exists else 0})
        for key in ("deleted", "kept"):
            if f"as {key}" in query or f"AS {key}" in query:
                return FakeResult({key: 0})
        return FakeResult()


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class Client(SecretMixin, BaseMixin):
    """The real client mixes in both, and the hunt ingest now calls across:
    it prunes through `BaseMixin.prune_unseen_findings` after a successful run.
    `BaseMixin.__init__` is deliberately not called - it would open a real
    Neo4j connection - and is not needed, since the driver is supplied here."""

    def __init__(self, session):
        self.driver = FakeDriver(session)


def _cleared(**kwargs):
    session = FakeSession(**kwargs)
    Client(session).clear_github_hunt_data("u1", "p1")
    return [q for q, _ in session.queries]


class TestClearPreservesSharedRepository(unittest.TestCase):
    def test_repository_sweep_is_guarded_by_zero_degree(self):
        repo_queries = [q for q in _cleared() if "GithubRepository" in q and "DELETE" in q]
        self.assertEqual(len(repo_queries), 1, "expected exactly one repository delete")
        self.assertIn("WHERE NOT (gr)--()", repo_queries[0])

    def test_repository_sweep_never_detaches(self):
        for query in _cleared():
            if "GithubRepository" in query and "DELETE" in query:
                self.assertNotIn(
                    "DETACH DELETE", query,
                    "DETACH DELETE on GithubRepository drops the supply-chain "
                    "scan's DEPENDS_ON edges on the shared node")

    def test_hunt_is_deleted_before_the_repository_sweep(self):
        queries = _cleared()
        hunt = next(i for i, q in enumerate(queries)
                    if "GithubHunt" in q and "DETACH DELETE" in q)
        repo = next(i for i, q in enumerate(queries)
                    if "GithubRepository" in q and "DELETE" in q)
        self.assertLess(hunt, repo,
                        "the hunt's HAS_REPOSITORY edges must be gone before the "
                        "sweep, or every repository still looks referenced")

    def test_leaf_and_path_nodes_are_still_wiped(self):
        queries = _cleared()
        for label in ("GithubSecret", "GithubSensitiveFile", "GithubPath"):
            self.assertTrue(
                any(label in q and "DETACH DELETE" in q for q in queries),
                f"{label} must still be cleared")

    def test_every_delete_is_tenant_scoped(self):
        session = FakeSession()
        Client(session).clear_github_hunt_data("u1", "p1")
        for query, params in session.queries:
            if "DELETE" not in query:
                continue
            self.assertIn("user_id: $uid", query)
            self.assertIn("project_id: $pid", query)
            self.assertEqual(params, {"uid": "u1", "pid": "p1"})


class TestStableNodeIds(unittest.TestCase):
    def test_digest_matches_sha1_and_is_process_stable(self):
        expected = hashlib.sha1(b"acme/app\x1fsrc/.env").hexdigest()[:12]
        self.assertEqual(SecretMixin._github_digest("acme/app", "src/.env"), expected)
        self.assertEqual(len(expected), 12)

    def test_ingested_ids_use_the_digest(self):
        session = FakeSession()
        payload = {
            "target": "acme",
            "statistics": {},
            "findings": [
                {"type": "SECRET", "repository": "acme/app", "path": "src/.env (commit: abc1234)",
                 "secret_type": "AWS Key", "details": {"matches": 1, "sample": "AKIA..."}},
                {"type": "SENSITIVE_FILE", "repository": "acme/app", "path": "src/.env",
                 "secret_type": "Sensitive Filename", "details": {}},
                {"type": "HIGH_ENTROPY", "repository": "acme/app", "path": "src/.env",
                 "secret_type": "High Entropy (5.1)", "details": {}},
            ],
        }
        stats = Client(session).update_graph_from_github_hunt(payload, "u1", "p1")

        self.assertEqual(stats["errors"], [])
        self.assertEqual(stats["findings_skipped_high_entropy"], 1)
        self.assertEqual(stats["secrets_created"], 1)
        self.assertEqual(stats["sensitive_files_created"], 1)
        self.assertEqual(stats["paths_created"], 1, "the commit suffix must be stripped")

        ids = [p["id"] for _, p in session.queries if "id" in p]
        path_digest = SecretMixin._github_digest("acme/app", "src/.env")
        self.assertIn(f"github-path-u1-p1-{path_digest}", ids)

        secret_digest = SecretMixin._github_digest("acme/app:src/.env:AWS Key")
        self.assertIn(f"github-secret-u1-p1-{secret_digest}", ids)

    def test_secret_node_carries_its_details(self):
        session = FakeSession()
        payload = {
            "target": "acme",
            "statistics": {},
            "findings": [
                {"type": "SECRET", "repository": "acme/app", "path": "src/.env",
                 "secret_type": "AWS Key", "details": {"matches": 3, "sample": "AKIAX"}},
            ],
        }
        Client(session).update_graph_from_github_hunt(payload, "u1", "p1")
        props = next(p["props"] for _, p in session.queries
                     if "props" in p and p["props"].get("secret_type") == "AWS Key")
        self.assertEqual(props["matches"], 3)
        self.assertEqual(props["sample"], "AKIAX")
        self.assertEqual(props["user_id"], "u1")
        self.assertEqual(props["project_id"], "p1")
        self.assertEqual(props["path"], "src/.env")


if __name__ == "__main__":
    unittest.main()
