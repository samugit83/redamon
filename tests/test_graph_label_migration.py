"""The Trufflehog -> Multiscanner graph migration.

A rename does not leave old data stale, it leaves it INVISIBLE: every read is by
label, so an un-migrated finding vanishes from the Red Zone and from every report
while still sitting in the database. That makes this migration the highest-risk
part of the rename, and these tests pin the properties that make it safe to run
on every connection.

Run: docker run --rm -v "$PWD:/repo" -w /repo -e PYTHONPATH=/repo:/repo/graph_db \
       redamon-agent python -m pytest tests/test_graph_label_migration.py -q
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from graph_db import schema  # noqa: E402


def fake_session(counts=None, applied=False):
    """A session whose queries return `counts` in order, then zero.

    `applied` decides whether the marker lookup reports the migration as done.
    """
    counts = list(counts or [])
    session = MagicMock()

    def run(query, **params):
        row = MagicMock()
        if "RedamonSchemaMigration" in query and "MATCH" in query:
            row.single.return_value = {"c": 1 if applied else 0}
            return row
        value = counts.pop(0) if counts else 0
        row.single.return_value = {"c": value}
        return row

    session.run.side_effect = run
    return session


def queries(session):
    return [c.args[0] for c in session.run.call_args_list if c.args]


class TestMigrationCost(unittest.TestCase):
    """Regression: F1 - unguarded label scans on every connection."""

    def test_an_applied_migration_costs_one_lookup(self):
        """init_schema runs from BaseMixin.__init__, so this is paid on EVERY
        scan container spawn and every agent graph call. Before the marker it was
        21 unguarded label scans, forever, at a cost that grew with the graph."""
        session = fake_session(applied=True)
        schema.migrate_legacy_labels(session)
        qs = queries(session)
        self.assertEqual(len(qs), 1, f"expected a single marker lookup, got {qs}")
        self.assertIn("RedamonSchemaMigration", qs[0])
        self.assertFalse([q for q in qs if "STARTS WITH" in q],
                         "an applied migration must not scan any label")

    def test_an_unapplied_migration_does_the_work(self):
        session = fake_session(applied=False)
        schema.migrate_legacy_labels(session)
        qs = queries(session)
        for old, new in schema.LEGACY_LABEL_RENAMES:
            self.assertTrue([q for q in qs if f"`{old}`" in q and f"`{new}`" in q],
                            f"{old} -> {new} was never attempted")
        self.assertTrue([q for q in qs if "HAS_TRUFFLEHOG_SCAN" in q])
        self.assertTrue([q for q in qs if "STARTS WITH 'trufflehog-'" in q])


class TestMigrationBatching(unittest.TestCase):
    """Regression: F3 - one unbounded transaction over the caller's data."""

    def test_every_write_is_batched(self):
        """A single MATCH ... SET over the whole graph is one transaction whose
        size is the user's data; exceeding the heap left the rest un-migrated,
        which is invisible data rather than merely stale data."""
        session = fake_session(applied=False)
        schema.migrate_legacy_labels(session)
        writes = [q for q in queries(session)
                  if ("SET n" in q or "DELETE r" in q) and "RedamonSchemaMigration" not in q]
        self.assertTrue(writes, "no write statements ran")
        for q in writes:
            self.assertIn("LIMIT", q, f"unbatched write: {q[:90]}")

    def test_a_batched_write_drains_until_empty(self):
        # Two full batches then a short one; the loop must keep going until 0.
        session = fake_session(counts=[10_000, 10_000, 7] + [0] * 200)
        moved = schema._run_batched(session, "MATCH (n) RETURN count(n) AS c")
        self.assertEqual(moved, 20_007)


class TestMigrationMarker(unittest.TestCase):
    def test_a_clean_run_records_the_marker(self):
        session = fake_session(applied=False)
        schema.migrate_legacy_labels(session)
        self.assertTrue([q for q in queries(session)
                         if "MERGE" in q and "RedamonSchemaMigration" in q])

    def test_a_failed_step_leaves_no_marker_so_it_retries(self):
        """A half-migrated graph must be retried, not silently accepted."""
        session = MagicMock()

        def run(query, **params):
            row = MagicMock()
            if "RedamonSchemaMigration" in query and "MATCH" in query:
                row.single.return_value = {"c": 0}
                return row
            if "`TrufflehogFinding`" in query:
                raise RuntimeError("out of memory")
            row.single.return_value = {"c": 0}
            return row

        session.run.side_effect = run
        schema.migrate_legacy_labels(session)
        self.assertFalse(
            [q for q in queries(session) if "MERGE" in q and "RedamonSchemaMigration" in q],
            "a failed migration must NOT record the marker")

    def test_running_twice_is_a_no_op_the_second_time(self):
        """Idempotency, and the property that makes it safe on every connect."""
        first = fake_session(applied=False)
        schema.migrate_legacy_labels(first)
        second = fake_session(applied=True)
        schema.migrate_legacy_labels(second)
        self.assertGreater(len(queries(first)), len(queries(second)))
        self.assertEqual(len(queries(second)), 1)

    def test_an_unreadable_marker_falls_towards_doing_the_work(self):
        """Unknown state: re-running is idempotent, skipping is unrecoverable."""
        session = MagicMock()
        session.run.side_effect = RuntimeError("connection reset")
        self.assertFalse(schema._migration_applied(session))


class TestMigrationOrdering(unittest.TestCase):
    def test_labels_move_before_constraints_are_created(self):
        """A uniqueness constraint on the new label cannot be satisfied while
        data still carries the old one."""
        session = fake_session(applied=False)
        schema.init_schema(session)
        qs = queries(session)
        first_migration = next(i for i, q in enumerate(qs) if "TrufflehogFinding" in q)
        first_constraint = next(i for i, q in enumerate(qs) if q.startswith("CREATE CONSTRAINT"))
        self.assertLess(first_migration, first_constraint)


class TestResolvesToIdentityMigration(unittest.TestCase):
    def test_dedupe_is_marker_guarded_and_tenant_scoped(self):
        session = fake_session(applied=False)
        schema.dedupe_resolves_to(session)
        qs = queries(session)
        dedupe = [q for q in qs if "RESOLVES_TO" in q]
        self.assertTrue(dedupe)
        query = dedupe[0]
        self.assertIn("s.user_id = i.user_id", query)
        self.assertIn("s.project_id = i.project_id", query)
        self.assertIn("SET keep += properties(r)", query)
        self.assertIn("DELETE r", query)
        self.assertIn("LIMIT", query)
        self.assertTrue([q for q in qs if "MERGE" in q and "RedamonSchemaMigration" in q])

    def test_applied_dedupe_does_one_marker_lookup(self):
        session = fake_session(applied=True)
        schema.dedupe_resolves_to(session)
        qs = queries(session)
        self.assertEqual(len(qs), 1)
        self.assertIn("RedamonSchemaMigration", qs[0])


class TestMigrationSchemaNames(unittest.TestCase):
    def test_old_constraints_are_dropped_by_their_old_names(self):
        """A constraint is identified by NAME. Recreating it under the new name
        leaves the old one behind, still guarding a label nothing writes - and,
        worse, makes CREATE ... IF NOT EXISTS skip the new label entirely."""
        drops = " ".join(schema.DROP_LEGACY_CONSTRAINTS)
        for suffix in ("scan", "repository", "finding", "image", "model", "bucket", "endpoint"):
            self.assertIn(f"trufflehog{suffix}_unique", drops)

    def test_no_constraint_still_targets_a_legacy_label(self):
        ddl = " ".join(schema.CONSTRAINTS + schema.TENANT_INDEXES + schema.ADDITIONAL_INDEXES)
        for old, _new in schema.LEGACY_LABEL_RENAMES:
            self.assertNotIn(f":{old})", ddl)

    def test_every_migrated_label_keeps_a_tenant_scoped_constraint(self):
        """The tenant triple is the isolation guarantee; losing it on the rename
        would merge one project's findings into another's."""
        ddl = " ".join(schema.CONSTRAINTS)
        for _old, new in schema.LEGACY_LABEL_RENAMES:
            match = [c for c in schema.CONSTRAINTS if f":{new})" in c]
            self.assertTrue(match, f"{new} has no uniqueness constraint")
            self.assertIn("user_id", match[0])
            self.assertIn("project_id", match[0])


class TestMigrationTenantSafety(unittest.TestCase):
    """The rename must not touch the tenant triple.

    Every read is scoped by {id, user_id, project_id}. A migration that dropped
    or rewrote user_id/project_id would not lose data - it would hand one
    tenant's findings to another, which is worse.
    """

    def test_no_migration_statement_writes_a_tenant_key(self):
        session = fake_session(applied=False)
        schema.migrate_legacy_labels(session)
        for q in queries(session):
            if "RedamonSchemaMigration" in q:
                continue
            self.assertNotIn("n.user_id =", q, f"migration writes user_id: {q[:90]}")
            self.assertNotIn("n.project_id =", q, f"migration writes project_id: {q[:90]}")

    def test_no_migration_statement_is_scoped_to_one_tenant(self):
        """The reverse hazard: a tenant-filtered migration would silently leave
        every OTHER tenant's nodes on the old label, i.e. invisible."""
        session = fake_session(applied=False)
        schema.migrate_legacy_labels(session)
        for q in queries(session):
            if "RedamonSchemaMigration" in q:
                continue
            self.assertNotIn("user_id:", q, f"migration is tenant-scoped: {q[:90]}")

    def test_the_marker_is_a_global_reference_node(self):
        """It describes the DATABASE, not a project, so it must carry no tenant
        key - adding one would fragment it per tenant and re-run the migration
        for every project forever."""
        session = fake_session(applied=False)
        schema.migrate_legacy_labels(session)
        merge = [q for q in queries(session)
                 if "MERGE" in q and "RedamonSchemaMigration" in q]
        self.assertTrue(merge)
        self.assertNotIn("user_id", merge[0])
        self.assertNotIn("project_id", merge[0])


if __name__ == "__main__":
    unittest.main()
