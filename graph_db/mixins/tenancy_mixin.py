"""
TenancyMixin: move one project's graph from one tenant user to another.

An ownership transfer (RBAC step 5.12) sets Project.userId to the new owner.
Every entity node is keyed on (natural key, user_id, project_id) and every read
filters on both, so the project's nodes must follow or the new owner sees an
empty graph while the old owner keeps a hidden copy.

Only `user_id` changes, on the project's nodes and on any relationship stamped
with the tenant:
- no node is recreated, so relationships and element ids survive;
- `updated_at` stays: a re-tenant is not a scan observation, and the prune and
  the Recon Delta read it;
- node `id` values keep the user id they were minted with (github-hunt-<uid>-…,
  jsrf-<uid>-…, the hashed Vulnerability ids): Postgres references them
  (remediation finding_ids, traffic finding_id) and the hashed ones cannot be
  recomputed from the node;
- attribution such as `muted_by` keeps naming the person who acted;
- the global reference labels are never touched, even when an old writer left
  a tenant stamp on one.
"""

import re
import time

from graph_db.schema import ADDITIONAL_INDEXES, GLOBAL_REFERENCE_LABELS, TENANT_INDEXES
from graph_db.schema_keys import KEY_CONSTRAINTS

RETENANT_BATCH = 5000

_TENANT_TAIL = ["user_id", "project_id"]
_TENANT_INDEX = re.compile(r"FOR \((\w+):(\w+)\) ON \(\1\.user_id, \1\.project_id\)")


def _tenant_keyed():
    """label -> its identifying properties before the tenant pair, for every
    label whose uniqueness key ends in (user_id, project_id)."""
    return {k["label"]: tuple(k["key_properties"][:-2]) for k in KEY_CONSTRAINTS
            if k["key_properties"][-2:] == _TENANT_TAIL}


def _tenant_indexed():
    """Labels with a (user_id, project_id) index: the keyed ones plus those keyed
    on a global id that still carry the tenant (the attack-chain labels)."""
    return {m.group(2) for stmt in TENANT_INDEXES + ADDITIONAL_INDEXES
            for m in [_TENANT_INDEX.search(stmt)] if m}


#: Label -> the key properties a twin under the new owner would collide on.
TENANT_KEYS = _tenant_keyed()

#: Every label that holds per-project data, moved one label at a time through
#: its tenant index. Sorted: the Cypher is built from it.
TENANT_LABELS = tuple(sorted(
    (set(TENANT_KEYS) | _tenant_indexed()) - set(GLOBAL_REFERENCE_LABELS)))

_NOT_REFERENCE = " OR ".join(f"n:`{label}`" for label in GLOBAL_REFERENCE_LABELS)

_PREFLIGHT_NODES = f"""
MATCH (n)
WHERE n.user_id = $uid AND n.project_id = $pid
  AND NOT ({_NOT_REFERENCE})
RETURN elementId(n) AS id, labels(n) AS labels
"""

_PREFLIGHT_RELS = """
MATCH ()-[r]->()
WHERE r.user_id = $uid AND r.project_id = $pid
RETURN elementId(r) AS id
"""

_MOVE_LABEL = """
MATCH (n:`{label}` {{user_id: $src, project_id: $pid}})
WHERE NOT elementId(n) IN $keep
WITH n LIMIT $batch
SET n.user_id = $dst
RETURN count(n) AS c
"""

# The label-free sweep catches what the schema does not list: a label an older
# release wrote (GithubFinding, the pre-rename Trufflehog* nodes) or one added
# later without its schema entries. It runs after the per-label moves, so it
# normally scans once and finds nothing.
_MOVE_ANY = f"""
MATCH (n)
WHERE n.user_id = $src AND n.project_id = $pid
  AND NOT ({_NOT_REFERENCE}) AND NOT elementId(n) IN $keep
WITH n LIMIT $batch
SET n.user_id = $dst
RETURN count(n) AS c, collect(labels(n)) AS labels
"""

# No writer stamps a relationship with the tenant today; a restored snapshot or
# an older writer may have, and a stamp left behind would still name the old owner.
_MOVE_RELS = """
MATCH ()-[r]->()
WHERE r.user_id = $src AND r.project_id = $pid AND NOT elementId(r) IN $keep_rels
WITH r LIMIT $batch
SET r.user_id = $dst
RETURN count(r) AS c
"""


def _conflict_query(label, keys):
    twin = "".join(f"{k}: a.{k}, " for k in keys)
    return f"""
MATCH (a:`{label}` {{user_id: $src, project_id: $pid}})
MATCH (b:`{label}` {{{twin}user_id: $dst, project_id: $pid}})
RETURN count(a) AS c
"""


def _label_name(labels):
    """A node's functional label: Muted is added beside a finding's own label."""
    own = sorted(label for label in labels if label != "Muted")
    return ":".join(own or sorted(labels)) or "(no label)"


class RetenantError(RuntimeError):
    """A re-tenant that did not complete.

    code:
      retenant_invalid         bad arguments; nothing ran
      retenant_conflict        a node under the new owner shares a key with one
                               being moved; nothing was written (`conflicts`)
      retenant_failed          a write failed and the move was run back: the
                               graph is as it was before the call
      retenant_rollback_failed the run back failed too: the project is split
                               between the two tenants (`moved` says how far the
                               move got); calling the same transfer again
                               completes it, the reverse call undoes it
    """

    def __init__(self, code, message, moved=None, conflicts=None):
        super().__init__(message)
        self.code = code
        self.moved = moved or {}
        self.conflicts = conflicts or {}


def _empty_tally():
    return {"nodes": {}, "unlisted": {}, "relationships": 0}


def _require_id(name, value):
    if not isinstance(value, str) or not value.strip():
        raise RetenantError("retenant_invalid", f"{name} must be a non-empty string")


class TenancyMixin:
    def retenant_project(self, project_id: str, from_user_id: str, to_user_id: str,
                         batch_size: int = RETENANT_BATCH) -> dict:
        """Move every node of `project_id` held by `from_user_id` to `to_user_id`.

        Idempotent: a second call finds nothing left to move, and a call after an
        interrupted one moves the rest. Refused before any write when a node
        already under the new owner would collide on its uniqueness key. A write
        that fails runs the move back, so the graph either moves completely or
        stays as it was; the nodes already under the new owner before the call
        (an interrupted earlier attempt) stay where they were.

        Runs alone on the project: the caller holds the project lock that every
        graph writer asks first.
        """
        for name, value in (("project_id", project_id), ("from_user_id", from_user_id),
                            ("to_user_id", to_user_id)):
            _require_id(name, value)
        if from_user_id == to_user_id:
            raise RetenantError("retenant_invalid", "from_user_id and to_user_id are the same user")
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
            raise RetenantError("retenant_invalid", "batch_size must be a positive integer")

        started = time.monotonic()
        moved = _empty_tally()
        with self.driver.session() as session:
            keep, keep_rels, already = self._retenant_preflight(
                session, project_id, from_user_id, to_user_id)
            try:
                self._retenant_pass(session, project_id, from_user_id, to_user_id,
                                    batch_size, [], [], moved)
            except Exception as exc:
                failure = exc
            else:
                failure = None
        if failure is not None:
            self._retenant_run_back(project_id, from_user_id, to_user_id, batch_size,
                                    keep, keep_rels, moved, failure)

        total = sum(moved["nodes"].values()) + sum(moved["unlisted"].values())
        elapsed_ms = int((time.monotonic() - started) * 1000)
        print(f"[rbac] retenant project={project_id}: moved {total} node(s) and "
              f"{moved['relationships']} relationship(s) to the new owner in {elapsed_ms} ms")
        if moved["unlisted"]:
            print(f"[rbac] retenant project={project_id}: moved nodes of labels the schema "
                  f"does not list: {moved['unlisted']}")
        return {
            "project_id": project_id,
            "from_user_id": from_user_id,
            "to_user_id": to_user_id,
            "nodes": moved["nodes"],
            "unlisted": moved["unlisted"],
            "relationships": moved["relationships"],
            "total_nodes": total,
            "already_at_target": already,
            "elapsed_ms": elapsed_ms,
        }

    def _retenant_preflight(self, session, project_id, src, dst):
        """What the new owner already holds in the project, and whether any of it
        collides with a node about to move. Raises before anything is written."""
        keep, already = [], {}
        for row in session.run(_PREFLIGHT_NODES, uid=dst, pid=project_id):
            keep.append(row["id"])
            name = _label_name(row["labels"])
            already[name] = already.get(name, 0) + 1
        keep_rels = [row["id"] for row in session.run(_PREFLIGHT_RELS, uid=dst, pid=project_id)]

        conflicts = {}
        for label in TENANT_LABELS:
            keys = TENANT_KEYS.get(label)
            if not keys or not already.get(label):
                continue  # keyed on a global id, or nothing of it under the new owner
            row = session.run(_conflict_query(label, keys),
                              src=src, dst=dst, pid=project_id).single()
            count = int(row["c"] if row else 0)
            if count:
                conflicts[label] = count
        if conflicts:
            print(f"[rbac] retenant refused project={project_id}: the new owner already "
                  f"holds nodes with the same keys: {conflicts}")
            raise RetenantError(
                "retenant_conflict",
                f"nodes under the new owner collide with the project's: {conflicts}",
                conflicts=conflicts)
        return keep, keep_rels, already

    def _retenant_pass(self, session, project_id, src, dst, batch_size, keep, keep_rels, tally):
        """Move every node and stamped relationship of the project from `src` to
        `dst`, leaving the element ids in `keep` / `keep_rels`. Counts into
        `tally` as each batch commits, so a failure still reports how far it got."""
        params = {"pid": project_id, "src": src, "dst": dst, "batch": batch_size,
                  "keep": keep}
        for label in TENANT_LABELS:
            query = _MOVE_LABEL.format(label=label)
            while True:
                row = session.run(query, **params).single()
                count = int(row["c"] if row else 0)
                if count:
                    tally["nodes"][label] = tally["nodes"].get(label, 0) + count
                if count < batch_size:
                    break
        while True:
            row = session.run(_MOVE_ANY, **params).single()
            count = int(row["c"] if row else 0)
            for labels in (row["labels"] if row else []):
                name = _label_name(labels)
                # A listed label here was written after its own loop ran.
                bucket = tally["nodes"] if name in TENANT_LABELS else tally["unlisted"]
                bucket[name] = bucket.get(name, 0) + 1
            if count < batch_size:
                break
        rel_params = {"pid": project_id, "src": src, "dst": dst, "batch": batch_size,
                      "keep_rels": keep_rels}
        while True:
            row = session.run(_MOVE_RELS, **rel_params).single()
            count = int(row["c"] if row else 0)
            tally["relationships"] += count
            if count < batch_size:
                break

    def _retenant_run_back(self, project_id, src, dst, batch_size, keep, keep_rels,
                           moved, failure):
        """Put back under `src` what the failed pass moved; always raises."""
        print(f"[rbac] retenant failed project={project_id} after moving "
              f"{sum(moved['nodes'].values()) + sum(moved['unlisted'].values())} node(s): "
              f"{failure}; running the move back")
        try:
            # A fresh session: the failure may have been the connection itself.
            with self.driver.session() as session:
                self._retenant_pass(session, project_id, dst, src, batch_size,
                                    keep, keep_rels, _empty_tally())
        except Exception as exc:
            print(f"[rbac] retenant rollback failed project={project_id}: {exc}; the project "
                  f"is split between the two owners until the transfer is retried")
            raise RetenantError(
                "retenant_rollback_failed",
                f"re-tenant failed ({failure}) and its run back failed ({exc})",
                moved=moved) from exc
        raise RetenantError("retenant_failed", f"re-tenant failed and was run back: {failure}",
                            moved=moved) from failure
