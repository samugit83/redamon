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

A name the selection rule scanned (record_filter, scan_all) is a target:

  - its org Domain comes from the one allowed site, `ensure_root_domains`
    (tests/test_no_stray_domain_merge.py), and is then MATCHed and marked
    `ip_hostname_org = true`; it carries no `ip_mode` and no `is_mock`, which
    only the synthetic root has, so every Domain.ip_mode reader treats it as
    any org Domain (design §6.1);
  - `Subdomain {name}` (source `ip_hostname_selection` on create) under it;
  - `RESOLVES_TO` each address of the pinned answer, as current forward DNS
    (no `source`); `HISTORICALLY_RESOLVED_TO` per dated source that saw it on a
    target IP, the existing history convention (design §6.2);
  - `COVERS_HOST` from each target IP's tlsx certificate (by cert_key) whose
    CN or SAN covers it.

Every run, IP only included, stamps its hostname mode on the mock root
(`ip_hostname_mode`), which tells "no record run yet" from "a record run found
no name". The root is MATCHed: only update_graph_from_ip_recon creates it.
"""
from graph_db.mixins.recon.tlsx_mixin import _entry_cert_key

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

_ORG_MARK = """
UNWIND $orgs AS org
MATCH (d:Domain {name: org, user_id: $uid, project_id: $pid})
SET d.ip_hostname_org = true, d.updated_at = datetime()
RETURN count(d) AS n
"""

_SCANNED = """
UNWIND $rows AS row
MERGE (s:Subdomain {name: row.name, user_id: $uid, project_id: $pid})
  ON CREATE SET s.source = 'ip_hostname_selection', s.discovered_at = datetime(), s.status = 'resolved'
SET s.ip_mode = true,
    s.has_records = true,
    s.ip_hostname_reason = 'scanned',
    s.ip_hostname_sources = row.sources,
    s.ip_hostname_evaluated_at = datetime(),
    s.updated_at = datetime()
RETURN count(s) AS n
"""

_ATTACHED = """
UNWIND $rows AS row
MATCH (d:Domain {name: row.org, user_id: $uid, project_id: $pid})
MATCH (s:Subdomain {name: row.name, user_id: $uid, project_id: $pid})
MERGE (d)-[:HAS_SUBDOMAIN]->(s)
MERGE (s)-[:BELONGS_TO]->(d)
RETURN count(s) AS n
"""

_RESOLVES = """
UNWIND $edges AS e
MATCH (s:Subdomain {name: e.name, user_id: $uid, project_id: $pid})
MATCH (i:IP {address: e.ip, user_id: $uid, project_id: $pid})
MERGE (s)-[r:RESOLVES_TO]->(i)
SET r.record_type = e.record_type, r.last_seen_at = datetime()
REMOVE r.source
RETURN count(r) AS n
"""

_HISTORY = """
UNWIND $history AS h
MATCH (s:Subdomain {name: h.name, user_id: $uid, project_id: $pid})
MATCH (i:IP {address: h.ip, user_id: $uid, project_id: $pid})
MERGE (s)-[r:HISTORICALLY_RESOLVED_TO {source: h.source}]->(i)
ON CREATE SET r.first_seen = h.first, r.last_seen = h.last
ON MATCH SET r.first_seen = CASE WHEN h.first IS NOT NULL AND (r.first_seen IS NULL OR h.first < r.first_seen)
                                 THEN h.first ELSE r.first_seen END,
             r.last_seen = CASE WHEN h.last IS NOT NULL AND (r.last_seen IS NULL OR h.last > r.last_seen)
                                THEN h.last ELSE r.last_seen END
RETURN count(r) AS n
"""

_COVERS = """
UNWIND $covers AS v
MATCH (c:Certificate {cert_key: v.cert_key, user_id: $uid, project_id: $pid})
MATCH (s:Subdomain {name: v.name, user_id: $uid, project_id: $pid})
MERGE (c)-[:COVERS_HOST]->(s)
RETURN count(s) AS n
"""

#: The collector's sources that date what they saw (OTX first/last; Censys,
#: FOFA and ZoomEye last update), in recon/helpers/ip_hostnames.py. Only they
#: may claim a history edge's dates.
_DATED_SOURCES = frozenset({
    "otx_passive_dns", "censys_rdns", "censys_cert", "fofa_host", "fofa_domain", "fofa_cname",
    "fofa_cert", "zoomeye_hostname", "zoomeye_rdns",
})


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


def _covers(name: str, cert_names) -> bool:
    """TLS name matching: exact, or one wildcard label (`*.x` covers `a.x`,
    never `b.a.x` nor `x`)."""
    for raw in cert_names:
        entry = str(raw or "").strip().lower().rstrip(".")
        if entry == name:
            return True
        if entry.startswith("*.") and name.endswith(entry[1:]) and "." not in name[: -len(entry) + 1]:
            return True
    return False


def _scanned_rows(recon_data: dict, candidates: dict) -> dict:
    """The scanned part's statement parameters: rows (name, org, sources),
    RESOLVES_TO edges, history edges and COVERS_HOST pairs, in name order."""
    hosts = (recon_data.get("metadata") or {}).get("ip_mode_hosts") or {}
    dns_subs = ((recon_data.get("dns") or {}).get("subdomains")) or {}
    out = {"rows": [], "edges": [], "history": [], "covers": []}
    for name in sorted(candidates):
        cand = candidates[name]
        if not isinstance(cand, dict) or cand.get("reason") != "scanned":
            continue
        org = hosts.get(name) or cand.get("org_domain")
        if not isinstance(org, str) or not org:
            continue
        out["rows"].append({"name": name, "org": org, "sources": list(cand.get("sources") or [])})
        pinned = cand.get("resolves_to_now")
        if not isinstance(pinned, list):
            ips = (dns_subs.get(name) or {}).get("ips") or {}
            pinned = list(ips.get("ipv4") or []) + list(ips.get("ipv6") or [])
        for ip in pinned:
            out["edges"].append({"name": name, "ip": ip, "record_type": "AAAA" if ":" in str(ip) else "A"})
        for ip, ev in (cand.get("seen_on") or {}).items():
            if not isinstance(ev, dict) or not (ev.get("first_seen") or ev.get("last_seen")):
                continue
            for source in sorted(set(ev.get("sources") or ()) & _DATED_SOURCES):
                out["history"].append({"name": name, "ip": ip, "source": source,
                                       "first": ev.get("first_seen"), "last": ev.get("last_seen")})
    names = [row["name"] for row in out["rows"]]
    targets = {str(ip) for ip in (recon_data.get("metadata") or {}).get("expanded_ips") or ()}
    for entry in (((recon_data.get("tlsx") or {}).get("by_target")) or {}).values():
        # The certificates the tlsx writer stores: an entry without a
        # fingerprint or CN made no node to link.
        if not isinstance(entry, dict) or not (entry.get("fingerprint_sha256") or entry.get("subject_cn")):
            continue
        if str(entry.get("scanned_ip") or entry.get("ip") or "") not in targets:
            continue
        sans = entry.get("san_raw") if entry.get("san_raw") is not None else entry.get("san")
        cert_names = [entry.get("subject_cn"), *(sans or [])]
        key = _entry_cert_key(entry)
        for name in names:
            pair = {"cert_key": key, "name": name}
            if _covers(name, cert_names) and pair not in out["covers"]:
                out["covers"].append(pair)
    return out


class IpHostnamesMixin:
    def _write_scanned(self, recon_data: dict, candidates: dict, user_id: str, project_id: str,
                       stats: dict) -> None:
        params = _scanned_rows(recon_data, candidates)
        if not params["rows"]:
            return
        orgs = sorted({row["org"] for row in params["rows"]})
        try:
            self.ensure_root_domains(orgs, user_id, project_id)
            with self.driver.session() as session:
                session.run(_ORG_MARK, orgs=orgs, uid=user_id, pid=project_id)
        except Exception as e:
            stats["errors"].append(f"ip_hostnames org Domain(s) {', '.join(orgs)}: {e}")
        for start in range(0, len(params["rows"]), _BATCH):
            rows = params["rows"][start:start + _BATCH]
            names = {row["name"] for row in rows}
            part = {key: [p for p in params[key] if p["name"] in names]
                    for key in ("edges", "history", "covers")}

            def work(tx, rows=rows, part=part):
                written = tx.run(_SCANNED, rows=rows, uid=user_id, pid=project_id).single()["n"]
                tx.run(_ATTACHED, rows=rows, uid=user_id, pid=project_id)
                tx.run(_RESOLVES, edges=part["edges"], uid=user_id, pid=project_id)
                tx.run(_HISTORY, history=part["history"], uid=user_id, pid=project_id)
                tx.run(_COVERS, covers=part["covers"], uid=user_id, pid=project_id)
                return written

            try:
                with self.driver.session() as session:
                    stats["names_scanned"] += session.execute_write(work)
            except Exception as e:
                stats["errors"].append(f"ip_hostnames scanned {rows[0]['name']} (+{len(rows) - 1}): {e}")

    def update_graph_from_ip_hostnames(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {"mode_stamped": False, "names_recorded": 0, "names_scanned": 0, "seen_on": 0, "errors": []}
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

        self._write_scanned(recon_data, block.get("candidates") or {}, user_id, project_id, stats)

        print(f"[+][graph-db] IP hostnames: {stats['names_recorded']} recorded name(s), "
              f"{stats['names_scanned']} scanned name(s), {stats['seen_on']} SEEN_ON edge(s), mode {mode}")
        if stats["errors"]:
            print(f"[!][graph-db] IP hostnames: {len(stats['errors'])} write(s) failed, "
                  f"first: {stats['errors'][0]}")
        return stats
