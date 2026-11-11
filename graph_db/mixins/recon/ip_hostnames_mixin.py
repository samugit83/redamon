"""Hostnames seen on IP-mode target addresses: the graph write (design §6).

The hook (recon/helpers/ip_hostnames.py) collects every name a source saw on a
target IP and gives each the selection rule's reason. This writer records the
names that are not scanned, the only place an IP-mode run writes a hostname:

  - `ExternalDomain {domain, user_id, project_id}` (the `externaldomain_unique`
    key). `sources` and `ips_seen` grow additively, because the external-domains
    aggregator MERGEs the same node for a redirect name; the `ip_hostname_*`
    evidence is this run's and is plain SET.
  - `(mock Domain)-[:HAS_EXTERNAL_DOMAIN]->(ed)`, the aggregator's edge.
  - `(ed)-[:SEEN_ON]->(ip)` per target IP, with what was seen there.

Never a Subdomain (a recorded name is no target, invariant I-4). The
candidate's name-level first/last dates and cert_covers are the SEEN_ON
values aggregated, and on_shared_edge is the IP's own `ownership`, so neither
is stored twice.

Every run, IP only included, stamps its hostname mode on the mock root
(`ip_hostname_mode`), which tells "no record run yet" from "a record run found
no name". The root is MATCHed: only update_graph_from_ip_recon creates it.
"""

#: Names per transaction: a /24 of shared hosting can carry thousands.
_BATCH = 200

_RECORDED = """
UNWIND $rows AS row
MERGE (ed:ExternalDomain {domain: row.name, user_id: $uid, project_id: $pid})
  ON CREATE SET ed.first_seen_at = datetime()
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

_RUN_MODE = """
MATCH (d:Domain {name: $mock, user_id: $uid, project_id: $pid})
WHERE d.is_mock = true
SET d.ip_hostname_mode = $mode
"""


def _recorded_rows(candidates: dict) -> list:
    """(node row, SEEN_ON rows) per recorded candidate, in name order."""
    out = []
    for name in sorted(candidates):
        cand = candidates[name]
        reason = cand.get("reason") if isinstance(cand, dict) else None
        if not isinstance(reason, str) or reason == "scanned":
            continue
        ips = list(cand.get("ips_seen") or [])
        resolved = cand.get("resolves_to_now")
        seen_on = cand.get("seen_on") or {}
        seen = []
        for ip in ips:
            ev = seen_on.get(ip) if isinstance(seen_on.get(ip), dict) else {}
            seen.append({
                "name": name, "ip": ip,
                "sources": list(ev.get("sources") or cand.get("sources") or []),
                "first": ev.get("first_seen"), "last": ev.get("last_seen"),
                "resolves_here": (ip in resolved) if isinstance(resolved, list) else None,
                "cert_covers": bool(ev.get("cert_covers")),
                "reason": reason,
            })
        row = {"name": name, "sources": list(cand.get("sources") or []), "ips": ips,
               "reason": reason, "org": cand.get("org_domain")}
        out.append((row, seen))
    return out


class IpHostnamesMixin:
    def update_graph_from_ip_hostnames(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {"mode_stamped": False, "names_recorded": 0, "seen_on": 0, "errors": []}
        metadata = (recon_data or {}).get("metadata") or {}
        block = (recon_data or {}).get("ip_hostnames")
        if not metadata.get("ip_mode") or not isinstance(block, dict):
            return stats
        mock = metadata.get("root_domain") or recon_data.get("domain") or ""

        mode = block.get("mode")
        if isinstance(mode, str) and mode:
            try:
                with self.driver.session() as session:
                    session.run(_RUN_MODE, mock=mock, uid=user_id, pid=project_id, mode=mode)
                stats["mode_stamped"] = True
            except Exception as e:
                stats["errors"].append(f"ip_hostname_mode on {mock}: {e}")

        rows = _recorded_rows(block.get("candidates") or {})
        for start in range(0, len(rows), _BATCH):
            batch = rows[start:start + _BATCH]
            names = [row["name"] for row, _ in batch]
            seen = [s for _, per_ip in batch for s in per_ip]

            def work(tx, batch=batch, names=names, seen=seen):
                recorded = tx.run(_RECORDED, rows=[row for row, _ in batch],
                                  uid=user_id, pid=project_id).single()["n"]
                tx.run(_LINKED, mock=mock, names=names, uid=user_id, pid=project_id)
                edges = tx.run(_SEEN_ON, seen=seen, uid=user_id, pid=project_id).single()["n"]
                return recorded, edges

            try:
                with self.driver.session() as session:
                    recorded, edges = session.execute_write(work)
                stats["names_recorded"] += recorded
                stats["seen_on"] += edges
            except Exception as e:
                stats["errors"].append(f"ip_hostnames {names[0]} (+{len(names) - 1}): {e}")

        print(f"[+][graph-db] IP hostnames: {stats['names_recorded']} recorded name(s), "
              f"{stats['seen_on']} SEEN_ON edge(s), mode {mode}")
        if stats["errors"]:
            print(f"[!][graph-db] IP hostnames: {len(stats['errors'])} write(s) failed, "
                  f"first: {stats['errors'][0]}")
        return stats
