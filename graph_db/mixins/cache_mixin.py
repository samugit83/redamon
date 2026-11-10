"""
Cache Poisoning Scan Graph DB Mixin.

Persists web-cache-poisoning findings from recon/cache_scan into Neo4j. Reuses
the shared Vulnerability node (source="cache_poisoning") attached to the affected
Endpoint/BaseURL via HAS_VULNERABILITY, matching the Nuclei / GVM / GraphQL /
SecurityChecks convention. No new node label is introduced.
"""

import json
from datetime import datetime, timezone
from urllib.parse import urlparse


# Schema contract: every key a cache_scan finding can emit. Must stay in sync with
# recon/cache_scan/normalizers.py build_finding(). If the scanner adds a key, the
# _check_unknown_keys log flags it at ingest so we never silently drop data.
KNOWN_FINDING_KEYS = frozenset({
    "endpoint_url", "technique", "vector_type", "cache_header", "cache_param",
    "impact", "confidence", "confidence_tier", "severity", "cvss_score",
    "cache_signals", "cache_buster", "source_engine", "evidence", "cross_vantage",
    "detection_mode",
})

KNOWN_EVIDENCE_KEYS = frozenset({
    "baseline_hash", "poisoned_hash", "clean_validation_hash", "poc_link",
    "curl_verify", "canary", "differential_change", "clean_cache_state",
    "baseline_stable", "control_check", "xss_context",
})

# Only the Confirmed tier is a confirmation; the description must not say more than
# the tier does.
_TIER_VERDICT = {"Confirmed": "confirmed", "Strong": "likely", "Tentative": "possible"}


def cache_vuln_id(user_id: str, project_id: str, technique: str, endpoint_url: str,
                  vector: str) -> str:
    """The Vulnerability id of one cache finding: tenant, technique, URL path and vector.

    Vulnerability.id is globally unique, so the tenant is part of it. Every input
    must be the same on every run that finds the same problem: the MERGE dedupes
    re-scans on it, and a person's mute, verdict and fix item hang off it. A
    per-run token (a cache buster, the deception plant's marker) belongs in the
    evidence, never in `endpoint_url` or the vector. The query string is ignored.
    """
    parsed = urlparse(endpoint_url)
    path = parsed.path or "/"
    baseurl = f"{parsed.scheme}://{parsed.netloc}"
    return (
        f"cache_{user_id}_{project_id}_{technique}_{baseurl}_{path}_{vector}"
        .replace(":", "_").replace("/", "_").replace(".", "_").replace(" ", "_")
    )


def _check_unknown_keys(obj: dict, known: frozenset, surface: str, identifier: str) -> None:
    if not isinstance(obj, dict):
        return
    unknown = set(obj.keys()) - known
    if unknown:
        print(
            f"[!][graph-db] cache_scan unknown {surface} key(s) {sorted(unknown)!r} "
            f"on {identifier!r} — update KNOWN_{surface.upper()}_KEYS + persistence logic"
        )


class CacheMixin:
    """Mixin for updating the graph with web cache poisoning scan results."""

    def update_graph_from_cache_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """Create Vulnerability(source="cache_poisoning") nodes for confirmed findings.

        Args:
            recon_data: combined recon data containing recon_data["cache_scan"]
            user_id / project_id: tenant scope

        Returns:
            Stats dict with counts.
        """
        stats = {
            "vulnerabilities_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        cache_data = recon_data.get("cache_scan", {})
        if not cache_data:
            stats["errors"].append("No cache_scan data found in recon_data")
            return stats

        findings = cache_data.get("findings", []) or []
        if not findings:
            print("[*][graph-db] cache_scan: no findings to persist")
            return stats

        with self.driver.session() as session:
            for finding in findings:
                _check_unknown_keys(finding, KNOWN_FINDING_KEYS, "finding",
                                    finding.get("endpoint_url", "?"))
                try:
                    endpoint_url = finding.get("endpoint_url", "")
                    technique = finding.get("technique", "unknown")
                    if not endpoint_url:
                        continue

                    parsed = urlparse(endpoint_url)
                    path = parsed.path or "/"
                    baseurl = f"{parsed.scheme}://{parsed.netloc}"
                    vector = finding.get("cache_header") or finding.get("cache_param") or "vector"

                    vuln_id = cache_vuln_id(user_id, project_id, technique, endpoint_url, vector)

                    evidence = finding.get("evidence", {}) or {}
                    _check_unknown_keys(evidence, KNOWN_EVIDENCE_KEYS, "evidence", endpoint_url)

                    impact = finding.get("impact", "unknown")
                    tier = finding.get("confidence_tier", "Tentative")
                    mode = finding.get("detection_mode", "reflected")
                    vuln_props = {
                        "id": vuln_id,
                        "vulnerability_id": vuln_id,
                        "vulnerability_type": "web_cache_poisoning",
                        "source": "cache_poisoning",
                        "name": f"Web Cache Poisoning via {vector}",
                        "description": (
                            f"{technique} cache poisoning {_TIER_VERDICT.get(tier, 'possible')} "
                            f"on {endpoint_url} using {vector} (impact: {impact}, {tier}, "
                            f"detected by {mode})."
                        ),
                        "severity": finding.get("severity", "medium"),
                        "cvss_score": finding.get("cvss_score", 5.0),
                        "confidence": finding.get("confidence", 0.0),
                        "confidence_tier": finding.get("confidence_tier", "Tentative"),
                        "cache_header": finding.get("cache_header", ""),
                        "cache_param": finding.get("cache_param", ""),
                        "cache_vector_type": finding.get("vector_type", ""),
                        "cache_impact": impact,
                        "cache_technique": technique,
                        "cache_buster": finding.get("cache_buster", ""),
                        "cache_signals": finding.get("cache_signals", []) or [],
                        "source_engine": finding.get("source_engine", "hypothesis"),
                        "detection_mode": finding.get("detection_mode", "reflected"),
                        "cross_vantage": bool(finding.get("cross_vantage", False)),
                        "endpoint": endpoint_url,
                        "user_id": user_id,
                        "project_id": project_id,
                        "evidence": json.dumps(evidence, default=str),
                        "matched_at": endpoint_url,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    }
                    # Hoist queryable evidence subkeys to first-class props.
                    if evidence.get("poc_link"):
                        vuln_props["poc_link"] = evidence["poc_link"]
                    if evidence.get("curl_verify"):
                        vuln_props["curl_verify"] = evidence["curl_verify"]

                    session.run(
                        """
                        MERGE (v:Vulnerability {
                            id: $id,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                        SET v += $props
                        SET v.updated_at = datetime()
                        """,
                        id=vuln_id, user_id=user_id, project_id=project_id, props=vuln_props,
                    )
                    stats["vulnerabilities_created"] += 1

                    # Wire BaseURL -> Endpoint -> Vulnerability. MERGE (not MATCH)
                    # so a finding whose endpoint wasn't created upstream still
                    # lands in a connected subgraph. GET is the cache-relevant method.
                    session.run(
                        """
                        MATCH (v:Vulnerability {
                            id: $vuln_id, user_id: $user_id, project_id: $project_id
                        })
                        MERGE (bu:BaseURL {
                            url: $baseurl, user_id: $user_id, project_id: $project_id
                        })
                          ON CREATE SET bu.source = 'cache_poisoning',
                                        bu.updated_at = datetime()
                        MERGE (e:Endpoint {
                            path: $path, method: 'GET', baseurl: $baseurl,
                            user_id: $user_id, project_id: $project_id
                        })
                          ON CREATE SET e.source = 'cache_poisoning',
                                        e.created_at = datetime()
                        SET e.updated_at = datetime()
                        SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        MERGE (e)-[:HAS_VULNERABILITY]->(v)
                        MERGE (bu)-[:HAS_VULNERABILITY]->(v)
                        """,
                        vuln_id=vuln_id, baseurl=baseurl, path=path,
                        user_id=user_id, project_id=project_id,
                    )
                    stats["relationships_created"] += 2

                except Exception as e:
                    stats["errors"].append(
                        f"Failed to persist cache finding {finding.get('endpoint_url', '?')}: {e}"
                    )

            print(f"[+][graph-db] cache_scan: {stats['vulnerabilities_created']} vulnerabilities created")
            print(f"[+][graph-db] cache_scan: {stats['relationships_created']} relationships created")
            if stats["errors"]:
                print(f"[!][graph-db] cache_scan: {len(stats['errors'])} error(s)")
                for err in stats["errors"][:5]:
                    print(f"[!][graph-db] {err}")

        return stats
