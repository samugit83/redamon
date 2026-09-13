#!/usr/bin/env python3
"""One-shot data migration for the graph-identity fixes. DRY RUN BY DEFAULT.

WHAT NEEDS MIGRATING, AND WHAT DOES NOT

The uniqueness constraints went from `id` to `(id, user_id, project_id)`, which
is strictly WEAKER: anything valid under the old constraint is valid under the
new one. So the constraint swap itself needs no migration and no downtime, and
`init_schema` does it on its own.

What does need a migration is data that is already wrong:

1. **Duplicate nuclei findings.** The old id ended in `hash(matched_at) % 10000`,
   and Python's builtin hash() is randomised per process unless PYTHONHASHSEED
   is pinned, which it was not. So every scan produced a NEW id for the same
   finding: a new node each time, while the operator's mute, their verdict and
   the AI's cached review stayed behind on the old one. This collapses each
   natural key down to one node and carries that state forward.

2. **`HAS_BASEURL` relationships** left over from before the spelling was
   unified on `HAS_BASE_URL`.

WHAT IT REFUSES TO DO
Nothing, while anything else might be writing. It checks that the agent, the
webapp and the recon orchestrator are all unreachable first, and stops if any of
them answers. A rescan running through this would re-create exactly what it just
merged.

  # see what it would do, change nothing (the default)
  python tooling/scripts/triage_graph_migrate.py

  # after a Neo4j backup, with the services stopped
  docker compose stop agent webapp recon-orchestrator
  python tooling/scripts/triage_graph_migrate.py --apply
  docker compose start agent webapp recon-orchestrator

Every step is idempotent: running it twice changes nothing the second time.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

#: Services that must be DOWN. Each is (name, url) and is probed with a short
#: timeout; anything that answers stops the migration.
GUARDED_SERVICES = [
    ("agent", os.environ.get("AGENT_URL", "http://localhost:8090") + "/health"),
    ("webapp", os.environ.get("WEBAPP_API_URL", "http://localhost:3000") + "/api/health"),
    ("recon-orchestrator",
     os.environ.get("RECON_ORCHESTRATOR_URL", "http://localhost:8010") + "/health"),
]

#: Triage state that must survive a merge. A person's decision is the whole
#: reason this migration is careful rather than a DELETE.
CARRIED_PROPS = (
    "triage_status", "triage_reason", "triage_source", "triage_confidence",
    "triage_priority_score", "triage_signals", "triage_tier", "triage_factors",
    "triage_state", "triage_group_key", "triage_run_id", "triage_ai_verdict",
    "triage_ai_quote", "triage_ai_model", "triage_evidence_hash",
    "triage_proof", "triaged_at", "muted_at", "muted_by", "muted_reason",
)


def services_are_up() -> list[str]:
    """The guarded services that answered. Empty means it is safe to proceed."""
    import urllib.error
    import urllib.request

    up = []
    for name, url in GUARDED_SERVICES:
        try:
            with urllib.request.urlopen(url, timeout=2):
                up.append(name)
        except urllib.error.HTTPError:
            # It answered, even if with an error status. That is "running".
            up.append(name)
        except Exception:
            pass
    return up


# ---------------------------------------------------------------------------
# Step 1: collapse duplicate nuclei findings
# ---------------------------------------------------------------------------
#: The natural key: what actually identifies one nuclei finding. Matches the
#: id `vuln_mixin` now builds.
NUCLEI_GROUPS = """
MATCH (v:Vulnerability {source: 'nuclei'})
WITH v.user_id AS uid, v.project_id AS pid,
     coalesce(v.template_id, '') AS template,
     coalesce(v.target_host, v.host, '') AS host,
     coalesce(v.fuzzing_parameter, '') AS param,
     coalesce(v.matched_at, '') AS matched,
     collect(v) AS nodes
WHERE size(nodes) > 1
RETURN uid, pid, template, host, param, matched, size(nodes) AS count,
       [n IN nodes | coalesce(n.id, '')] AS ids
ORDER BY count DESC
"""

def migrate_nuclei(session, apply: bool) -> dict:
    """Collapse each duplicated nuclei finding to one node."""
    groups = list(session.run(NUCLEI_GROUPS))
    total_dupes = sum(row["count"] - 1 for row in groups)
    print(f"  nuclei findings with duplicates: {len(groups)} natural keys, "
          f"{total_dupes} surplus nodes")

    if not apply or not groups:
        for row in groups[:10]:
            print(f"    {row['count']}x  template={row['template'] or '-'} "
                  f"param={row['param'] or '-'}")
        if len(groups) > 10:
            print(f"    ... and {len(groups) - 10} more")
        return {"groups": len(groups), "dropped": 0}

    dropped = 0
    for row in groups:
        # Read the group, decide what to keep, and merge the state in PYTHON.
        # Doing it in Cypher needs either APOC or a contortion that is hard to
        # read and harder to be sure of, and this runs once.
        nodes = list(session.run(
            """
            MATCH (v:Vulnerability {source: 'nuclei', user_id: $uid,
                                    project_id: $pid})
            WHERE coalesce(v.template_id, '') = $template
              AND coalesce(v.target_host, v.host, '') = $host
              AND coalesce(v.fuzzing_parameter, '') = $param
              AND coalesce(v.matched_at, '') = $matched
            RETURN v.id AS id, v:Muted AS muted,
                   coalesce(v.triage_source, '') AS triage_source,
                   toString(v.updated_at) AS updated_at,
                   properties(v) AS props
            """,
            uid=row["uid"], pid=row["pid"], template=row["template"],
            host=row["host"], param=row["param"], matched=row["matched"],
        ))
        if len(nodes) < 2:
            continue

        # Keep the one a PERSON touched, then the newest. Never the other way
        # round: the whole point is that a mute or a verdict is not what gets
        # thrown away.
        def rank(node):
            return (0 if node["muted"] else
                    1 if node["triage_source"] == "human" else 2,
                    "" if node["updated_at"] is None else node["updated_at"])

        keep = min(nodes, key=lambda n: (rank(n)[0],
                                         _negate(n["updated_at"] or "")))
        surplus = [n for n in nodes if n["id"] != keep["id"]]

        # Anything the kept node is missing but a surplus node has, it inherits.
        carried = {}
        for node in surplus:
            for prop in CARRIED_PROPS:
                value = (node["props"] or {}).get(prop)
                if value is not None and (keep["props"] or {}).get(prop) is None \
                        and prop not in carried:
                    carried[prop] = value
        inherits_mute = any(n["muted"] for n in surplus) and not keep["muted"]

        session.run(
            """
            MATCH (keep:Vulnerability {id: $keep_id, user_id: $uid,
                                       project_id: $pid})
            SET keep += $carried
            WITH keep
            FOREACH (_ IN CASE WHEN $mute THEN [1] ELSE [] END | SET keep:Muted)
            WITH keep
            UNWIND $surplus AS dead_id
            MATCH (dead:Vulnerability {id: dead_id, user_id: $uid,
                                       project_id: $pid})
            DETACH DELETE dead
            """,
            keep_id=keep["id"], uid=row["uid"], pid=row["pid"],
            carried=carried, mute=inherits_mute,
            surplus=[n["id"] for n in surplus],
        )
        dropped += len(surplus)
    print(f"    merged: {dropped} surplus nodes removed")
    return {"groups": len(groups), "dropped": dropped}


def _negate(text: str):
    """Sort an ISO timestamp DESCENDING inside an ascending `min()` key."""
    return [-ord(c) for c in text]


# ---------------------------------------------------------------------------
# Step 2: unify the base-URL relationship spelling
# ---------------------------------------------------------------------------
COUNT_OLD_BASEURL = """
MATCH ()-[r:HAS_BASEURL]->()
RETURN count(r) AS total
"""

RENAME_BASEURL = """
MATCH (a)-[r:HAS_BASEURL]->(b)
MERGE (a)-[:HAS_BASE_URL]->(b)
DELETE r
RETURN count(*) AS renamed
"""


def migrate_baseurl(session, apply: bool) -> dict:
    record = session.run(COUNT_OLD_BASEURL).single()
    total = int((record["total"] if record else 0) or 0)
    print(f"  HAS_BASEURL relationships to rename: {total}")
    if not apply or not total:
        return {"renamed": 0, "pending": total}
    result = session.run(RENAME_BASEURL).single()
    renamed = int((result["renamed"] if result else 0) or 0)
    print(f"    renamed: {renamed}")
    return {"renamed": renamed, "pending": 0}


# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true",
                        help="actually change the graph (default: dry run)")
    parser.add_argument("--force", action="store_true",
                        help="skip the services-are-down check. Do not.")
    args = parser.parse_args(argv)

    if args.apply:
        up = [] if args.force else services_are_up()
        if up:
            print("REFUSING: these services are still running: "
                  + ", ".join(up), file=sys.stderr)
            print("A scan or an agent writing during this migration would "
                  "re-create exactly what it just merged.", file=sys.stderr)
            print("\n  docker compose stop agent webapp recon-orchestrator",
                  file=sys.stderr)
            return 2
        print("Applying. Make sure you have a Neo4j backup.\n")
    else:
        print("DRY RUN. Nothing will be changed. Re-run with --apply.\n")

    from graph_db.neo4j_client import Neo4jClient

    with Neo4jClient() as client:
        with client.driver.session() as session:
            print("Step 1: duplicate nuclei findings (G1)")
            nuclei = migrate_nuclei(session, args.apply)
            print("\nStep 2: HAS_BASEURL -> HAS_BASE_URL (K8)")
            baseurl = migrate_baseurl(session, args.apply)

    print("\nSummary:", {"nuclei": nuclei, "baseurl": baseurl})
    if not args.apply:
        print("\nNothing was changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
