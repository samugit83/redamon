#!/usr/bin/env python3
"""Seed N recorded hostnames on one lab project's target IP (row E24, volume).

    python3 -I seed_recorded_names.py --project-id <pid> [--ip 192.88.98.10] [--count 5000] [--zone example-a.test]
    python3 -I seed_recorded_names.py --project-id <pid> --status
    python3 -I seed_recorded_names.py --project-id <pid> --undo

It writes what the product's writer writes for a recorded name
(graph_db/mixins/recon/ip_hostnames_mixin.py: _RECORDED, _LINKED, _SEEN_ON), in
the same 200-name transactions, every node keyed on its natural key plus
user_id and project_id:

    ExternalDomain {domain: vol-00001.<zone>, user_id, project_id}
    (Domain ip-targets.<pid>, the IP-mode root)-[:HAS_EXTERNAL_DOMAIN]->(ed)
    (ed)-[:SEEN_ON {sources, cert_covers, reason}]->(IP {address: <ip>})

plus one lab-only property, `iphn_lab_seed`, set on create only: --undo deletes
the nodes that carry it AND have a seeded name, nothing else (DETACH, so their
SEEN_ON and HAS_EXTERNAL_DOMAIN edges go with them), then checks that the
project's counts are back to the ones kept when it seeded.

The reason follows the last run's mode, as the writer would have judged a name
with no DNS record: record_only -> record_only; record_filter / scan_all ->
no_current_resolution. An ip_only project records nothing, so it is refused.

Refused before any write: an IP outside 192.88.98.0/24 or not a node of this
project, a project without its IP-mode root, a zone that is not a lab zone, a
seeded name that already exists, or an earlier seed not undone. Cypher only,
over Neo4j's HTTP endpoint (127.0.0.1:7474, NEO4J_HTTP_URL overrides) with
NEO4J_PASSWORD from the environment or the repository's .env, never printed.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import iphn_lab as lab  # noqa: E402

TAG = "iphn-e24"
LAB_NET = ipaddress.ip_network(f"{lab.NET}.0/24")
LAB_ZONES = ("example-a.test", "example-b.test", "lab-c.example")
#: Per transaction, as the product's writer (_BATCH).
BATCH = 200
REASON_BY_MODE = {"record_only": "record_only", "record_filter": "no_current_resolution",
                  "scan_all": "no_current_resolution"}

_RECORDED = """
UNWIND $rows AS row
MERGE (ed:ExternalDomain {domain: row.name, user_id: $uid, project_id: $pid})
  ON CREATE SET ed.first_seen_at = datetime(), ed.iphn_lab_seed = $tag
SET ed.sources = coalesce(ed.sources, []) + [x IN row.sources WHERE NOT x IN coalesce(ed.sources, [])],
    ed.ips_seen = coalesce(ed.ips_seen, []) + [x IN row.ips WHERE NOT x IN coalesce(ed.ips_seen, [])],
    ed.ip_hostname_reason = row.reason,
    ed.ip_hostname_org = row.org,
    ed.ip_hostname_evaluated_at = datetime(),
    ed.updated_at = datetime()
RETURN count(ed) AS n
"""

_LINKED = """
MATCH (d:Domain {name: $mock, user_id: $uid, project_id: $pid})
UNWIND $names AS name
MATCH (ed:ExternalDomain {domain: name, user_id: $uid, project_id: $pid})
MERGE (d)-[:HAS_EXTERNAL_DOMAIN]->(ed)
RETURN count(ed) AS n
"""

_SEEN_ON = """
UNWIND $seen AS s
MATCH (ed:ExternalDomain {domain: s.name, user_id: $uid, project_id: $pid})
MATCH (i:IP {address: s.ip, user_id: $uid, project_id: $pid})
MERGE (ed)-[r:SEEN_ON]->(i)
SET r.sources = s.sources, r.first_seen = s.first, r.last_seen = s.last,
    r.resolves_here = s.resolves_here, r.cert_covers = s.cert_covers, r.reason = s.reason
RETURN count(r) AS n
"""

# The one read keyed by project only: it finds the owner every later statement
# is keyed by, and refuses unless exactly one IP-mode root answers.
_ROOT = """
MATCH (d:Domain {name: $mock, project_id: $pid})
WHERE d.is_mock = true AND d.ip_mode = true
RETURN d.user_id AS uid, d.ip_hostname_mode AS mode
"""

_IP = "MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid}) RETURN count(i) AS n"

_EXISTING = """
MATCH (ed:ExternalDomain {user_id: $uid, project_id: $pid})
WHERE ed.domain IN $names OR ed.iphn_lab_seed IS NOT NULL
RETURN count(ed) AS n
"""

_COUNTS = """
CALL { MATCH (ed:ExternalDomain {user_id: $uid, project_id: $pid}) RETURN count(ed) AS external_domains }
CALL { MATCH (:ExternalDomain {user_id: $uid, project_id: $pid})-[r:SEEN_ON]->(:IP {user_id: $uid, project_id: $pid})
       RETURN count(r) AS seen_on }
CALL { MATCH (:Domain {name: $mock, user_id: $uid, project_id: $pid})-[r:HAS_EXTERNAL_DOMAIN]->
             (:ExternalDomain {user_id: $uid, project_id: $pid})
       RETURN count(r) AS root_links }
CALL { MATCH (ed:ExternalDomain {user_id: $uid, project_id: $pid}) WHERE ed.iphn_lab_seed = $tag
       RETURN count(ed) AS seeded }
RETURN external_domains, seen_on, root_links, seeded
"""

_UNDO = """
MATCH (ed:ExternalDomain {user_id: $uid, project_id: $pid})
WHERE ed.iphn_lab_seed = $tag AND ed.domain =~ $pattern
WITH ed LIMIT 1000
DETACH DELETE ed
RETURN count(*) AS n
"""


def log(sym: str, msg: str) -> None:
    print(f"[{sym}][Seed] {msg}", flush=True)


def cypher(statements: list[tuple[str, dict]]) -> list[list[dict]]:
    """Run the statements in ONE transaction; one row list per statement."""
    password = lab.env_value("NEO4J_PASSWORD")
    if not password:
        raise SystemExit("[!][Seed] NEO4J_PASSWORD is not set and not in .env")
    url = os.environ.get("NEO4J_HTTP_URL", "http://127.0.0.1:7474") + "/db/neo4j/tx/commit"
    body = json.dumps({"statements": [{"statement": s, "parameters": p} for s, p in statements]}).encode()
    token = base64.b64encode(f"neo4j:{password}".encode()).decode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Basic {token}"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            out = json.load(resp)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"[!][Seed] Neo4j answered HTTP {e.code}")
    if out.get("errors"):
        raise SystemExit(f"[!][Seed] Cypher error: {out['errors'][0].get('message', '?')[:300]}")
    return [[dict(zip(r["columns"], row["row"])) for row in r["data"]] for r in out["results"]]


def one(statement: str, params: dict) -> dict:
    rows = cypher([(statement, params)])[0]
    return rows[0] if rows else {}


def state_path(pid: str) -> Path:
    return lab.GEN / f"seed_recorded_names-{pid}.json"


def names_for(count: int, zone: str) -> list[str]:
    return [f"vol-{i:05d}.{zone}" for i in range(1, count + 1)]


def owner(pid: str) -> tuple[str, str | None, str]:
    """(user_id, last run's mode, root name) of an IP-mode project, or exit."""
    mock = f"ip-targets.{pid}"
    rows = cypher([(_ROOT, {"mock": mock, "pid": pid})])[0]
    uids = {r["uid"] for r in rows if r.get("uid")}
    if len(rows) != 1 or len(uids) != 1:
        raise SystemExit(f"[!][Seed] project {pid}: {len(rows)} IP-mode root(s) named {mock}, need exactly one "
                         "(an IP-mode project that has run)")
    return rows[0]["uid"], rows[0].get("mode"), mock


def counts(uid: str, pid: str, mock: str) -> dict:
    return one(_COUNTS, {"uid": uid, "pid": pid, "mock": mock, "tag": TAG})


def seed(args) -> int:
    ip = str(ipaddress.ip_address(args.ip))
    if ipaddress.ip_address(ip) not in LAB_NET:
        raise SystemExit(f"[!][Seed] {ip} is not in the lab range {LAB_NET}")
    if args.zone not in LAB_ZONES:
        raise SystemExit(f"[!][Seed] {args.zone} is not a lab zone ({', '.join(LAB_ZONES)})")
    if not 1 <= args.count <= 99999:
        raise SystemExit("[!][Seed] --count must be 1..99999")
    uid, mode, mock = owner(args.project_id)
    reason = args.reason or REASON_BY_MODE.get(mode or "")
    if not reason:
        raise SystemExit(f"[!][Seed] the last run's mode is {mode!r}: an IP-only run records no name, "
                         "so there is nothing realistic to seed (or pass --reason)")
    params = {"uid": uid, "pid": args.project_id}
    if one(_IP, {**params, "ip": ip}).get("n") != 1:
        raise SystemExit(f"[!][Seed] {ip} is not an IP node of project {args.project_id}")
    names = names_for(args.count, args.zone)
    if state_path(args.project_id).is_file():
        raise SystemExit(f"[!][Seed] {state_path(args.project_id).name} exists: undo the earlier seed first")
    clash = one(_EXISTING, {**params, "names": names}).get("n")
    if clash:
        raise SystemExit(f"[!][Seed] {clash} seeded name(s) or marked node(s) already exist in this project: "
                         "refusing, so that --undo deletes exactly what this seed wrote")

    before = counts(uid, args.project_id, mock)
    state_path(args.project_id).write_text(json.dumps({
        "project_id": args.project_id, "ip": ip, "zone": args.zone, "count": args.count, "reason": reason,
        "mode": mode, "tag": TAG, "before": before, "seeded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=1))
    log("*", f"project {args.project_id} (mode {mode}): before {before}; seeding {args.count} name(s) "
             f"vol-NNNNN.{args.zone} on {ip}, reason {reason}")

    # The record_only writer stores no forward answer (resolves_here null); the
    # filtering modes looked the name up and found none.
    resolves_here = None if reason == "record_only" else False
    t0 = time.time()
    recorded = edges = 0
    for start in range(0, len(names), BATCH):
        batch = names[start:start + BATCH]
        rows = [{"name": n, "sources": ["tlsx_san"], "ips": [ip], "reason": reason, "org": args.zone} for n in batch]
        seen = [{"name": n, "ip": ip, "sources": ["tlsx_san"], "first": None, "last": None,
                 "resolves_here": resolves_here, "cert_covers": True, "reason": reason} for n in batch]
        out = cypher([(_RECORDED, {**params, "rows": rows, "tag": TAG}),
                      (_LINKED, {**params, "mock": mock, "names": batch}),
                      (_SEEN_ON, {**params, "seen": seen})])
        recorded += out[0][0]["n"]
        edges += out[2][0]["n"]
    after = counts(uid, args.project_id, mock)
    log("+", f"{recorded} ExternalDomain(s), {edges} SEEN_ON edge(s) in {time.time() - t0:.1f}s; after {after}")
    want = {k: before[k] + args.count for k in ("external_domains", "seen_on", "root_links")}
    bad = {k: (after[k], v) for k, v in want.items() if after[k] != v}
    if bad or after["seeded"] != args.count:
        log("!", f"counts off (got, want): {bad or {'seeded': (after['seeded'], args.count)}}")
        return 1
    return 0


def undo(args) -> int:
    path = state_path(args.project_id)
    if not path.is_file():
        raise SystemExit(f"[!][Seed] no {path.name}: nothing seeded on {args.project_id} by this script")
    state = json.loads(path.read_text())
    uid, _, mock = owner(args.project_id)
    params = {"uid": uid, "pid": args.project_id, "tag": TAG,
              "pattern": r"vol-\d{5}\." + re.escape(state["zone"])}
    deleted = 0
    while True:
        n = one(_UNDO, params).get("n") or 0
        deleted += n
        if n == 0:
            break
    after = counts(uid, args.project_id, mock)
    before = state["before"]
    same = all(after[k] == before[k] for k in ("external_domains", "seen_on", "root_links")) and after["seeded"] == 0
    log("+" if same else "!", f"deleted {deleted} seeded name(s); now {after}; before the seed {before}: "
                              f"{'back to the same counts' if same else 'COUNTS DIFFER'}")
    if same:
        path.unlink()
    return 0 if same else 1


def status(args) -> int:
    uid, mode, mock = owner(args.project_id)
    log("*", f"project {args.project_id} (mode {mode}): {counts(uid, args.project_id, mock)}"
             f"{'; seed state kept in ' + state_path(args.project_id).name if state_path(args.project_id).is_file() else ''}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--ip", default=f"{lab.NET}.10")
    ap.add_argument("--count", type=int, default=5000)
    ap.add_argument("--zone", default="example-a.test")
    ap.add_argument("--reason", choices=("record_only", "no_current_resolution", "filter_no_match"),
                    help="override the reason the last run's mode implies")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--undo", action="store_true")
    mode.add_argument("--status", action="store_true")
    args = ap.parse_args()
    if args.undo:
        return undo(args)
    if args.status:
        return status(args)
    return seed(args)


if __name__ == "__main__":
    sys.exit(main())
