"""
Subdomain takeover graph updates.

Writes Vulnerability nodes with source="takeover_scan" that reuse the existing
Vulnerability label (no new node type). Connected to existing Subdomain nodes
via the standard (:Subdomain)-[:HAS_VULNERABILITY]->(:Vulnerability)
relationship. Falls back to (:Domain) for the apex when the hostname matches
the project's root domain and no Subdomain node exists.

Properties written on each Vulnerability:
    id                     deterministic hash (hostname+provider+method)
    user_id, project_id    tenant isolation
    source                 "takeover_scan"
    type                   "subdomain_takeover"
    name                   human-readable
    severity               high | medium | info (driven by scorer + verdict)
    description            short summary
    hostname               e.g. "promo.acme.com"
    cname_target           e.g. "acme.herokuapp.com"  (when available)
    takeover_provider      github-pages | heroku | aws-s3 | ...
    takeover_method        cname | dns | ns | mx | stale_a
    confidence             0..100 integer
    sources                list[str] of confirming tool names
    confirmation_count     len(sources)
    verdict                confirmed | likely | manual_review
    evidence               raw response / fingerprint hit excerpt
    tool_raw               JSON-encoded raw output per tool
    first_seen, last_seen  ISO timestamps
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


class TakeoverMixin:
    def update_graph_from_subdomain_takeover(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
    ) -> dict:
        """Persist scored takeover findings as Vulnerability nodes."""
        stats = {
            "vulnerabilities_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        takeover_data = recon_data.get("subdomain_takeover") or {}
        findings = takeover_data.get("findings") or []
        if not findings:
            return stats

        target_domain = (
            recon_data.get("domain")
            or recon_data.get("metadata", {}).get("target", "")
            or ""
        ).strip().lower()

        with self.driver.session() as session:
            for finding in findings:
                try:
                    vuln_id = finding.get("id")
                    hostname = (finding.get("hostname") or "").strip().lower()
                    if not vuln_id or not hostname:
                        continue

                    provider = finding.get("takeover_provider") or "unknown"
                    method = finding.get("takeover_method") or "cname"
                    verdict = finding.get("verdict") or "manual_review"
                    severity = finding.get("severity") or "info"
                    sources = finding.get("sources") or []
                    evidence_txt = finding.get("evidence") or ""
                    cname_target = finding.get("cname_target")
                    detected_at = finding.get("detected_at") or datetime.now(timezone.utc).isoformat()

                    name = _finding_name(provider, method)
                    description = _finding_description(finding)

                    # JSON-encode the raw per-source payload so Neo4j can store
                    # it safely (arbitrary nested structures can't go on a
                    # scalar property).
                    raw_by_source = finding.get("raw_by_source") or {}
                    try:
                        tool_raw = json.dumps(raw_by_source, default=str)[:50000]
                    except (TypeError, ValueError):
                        tool_raw = ""

                    vuln_props = {
                        "id": vuln_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "source": "takeover_scan",
                        "type": "subdomain_takeover",
                        "name": name,
                        "severity": severity,
                        "description": description,
                        "hostname": hostname,
                        "cname_target": cname_target,
                        "takeover_provider": provider,
                        "takeover_method": method,
                        "confidence": int(finding.get("confidence") or 0),
                        "sources": sources,
                        "confirmation_count": int(finding.get("confirmation_count") or len(sources)),
                        "verdict": verdict,
                        "evidence": evidence_txt[:2000] if evidence_txt else "",
                        "matched_at": f"https://{hostname}",
                        "host": hostname,
                        "is_dast_finding": False,
                        "tool_raw": tool_raw,
                        "last_seen": detected_at,
                    }
                    # Remove None values so MERGE's SET += doesn't wipe existing props
                    vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                    # Merge the Vulnerability node (set last_seen on every run,
                    # first_seen only on create).
                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id})
                        ON CREATE SET v.first_seen = $detected_at
                        SET v += $props,
                            v.updated_at = datetime()
                        """,
                        id=vuln_id, props=vuln_props, detected_at=detected_at,
                    )
                    stats["vulnerabilities_created"] += 1

                    # Attach to Subdomain if it exists; otherwise Domain (apex).
                    attached = False
                    rel = session.run(
                        """
                        MATCH (s:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                        MATCH (v:Vulnerability {id: $id})
                        MERGE (s)-[:HAS_VULNERABILITY]->(v)
                        RETURN count(*) AS matched
                        """,
                        hostname=hostname, uid=user_id, pid=project_id, id=vuln_id,
                    )
                    if rel.single()["matched"] > 0:
                        stats["relationships_created"] += 1
                        attached = True

                    if not attached and target_domain and hostname == target_domain:
                        rel = session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                            MATCH (v:Vulnerability {id: $id})
                            MERGE (d)-[:HAS_VULNERABILITY]->(v)
                            RETURN count(*) AS matched
                            """,
                            domain=target_domain, uid=user_id, pid=project_id, id=vuln_id,
                        )
                        if rel.single()["matched"] > 0:
                            stats["relationships_created"] += 1
                            attached = True

                    if not attached:
                        # No host anchor exists in the graph yet — create the
                        # Subdomain node defensively so the vulnerability is
                        # reachable from the graph page. This mirrors how
                        # vuln_mixin treats orphan discoveries.
                        session.run(
                            """
                            MERGE (s:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                            ON CREATE SET s.source = 'takeover_scan',
                                          s.created_at = datetime()
                            SET s.updated_at = datetime()
                            WITH s
                            MATCH (v:Vulnerability {id: $id})
                            MERGE (s)-[:HAS_VULNERABILITY]->(v)
                            """,
                            hostname=hostname, uid=user_id, pid=project_id, id=vuln_id,
                        )
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"takeover finding {finding.get('id', '?')} failed: {e}")

        if stats["vulnerabilities_created"] > 0:
            print(
                f"[+][graph-db] Created/updated {stats['vulnerabilities_created']} takeover Vulnerability node(s), "
                f"{stats['relationships_created']} relationship(s)"
            )
        if stats["errors"]:
            print(f"[!][graph-db] takeover: {len(stats['errors'])} error(s) during graph update")

        return stats


def _finding_name(provider: str, method: str) -> str:
    prov = provider.replace("-", " ").title() if provider and provider != "unknown" else "Unknown service"
    return f"Subdomain Takeover — {prov} ({method.upper()})"


def _finding_description(finding: dict) -> str:
    hostname = finding.get("hostname", "")
    provider = finding.get("takeover_provider") or "unknown"
    verdict = finding.get("verdict") or "manual_review"
    confidence = finding.get("confidence", 0)
    sources = ", ".join(finding.get("sources") or []) or "unknown"
    cname = finding.get("cname_target") or ""
    parts = [
        f"{hostname} appears takeover-prone on {provider}.",
        f"Verdict: {verdict} (confidence {confidence}).",
        f"Confirmed by: {sources}.",
    ]
    if cname:
        parts.append(f"CNAME target: {cname}.")
    return " ".join(parts)
