"""
GraphQL Scan Graph DB Mixin

Contains methods for updating Neo4j graph with GraphQL security scan results.
Separated from recon_mixin.py for better organization.
"""

from typing import Dict, List, Optional
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Schema contract: every key the GraphQL scanner can emit, per surface.
# Must be kept in sync with:
#   recon/graphql_scan/normalizers.py (native `normalize_finding`)
#   recon/graphql_scan/misconfig.py   (graphql-cop `normalize_graphql_cop_findings`)
#   recon/graphql_scan/scanner.py     (endpoint_info construction)
# If a scanner adds a new key, the _check_unknown_keys log will flag it at
# ingest time so we can decide whether to persist, drop, or reshape it.
# ---------------------------------------------------------------------------
KNOWN_VULN_KEYS = frozenset({
    # Native (normalize_finding)
    "endpoint", "vulnerability_type", "severity", "title", "description",
    "source", "discovered_at", "evidence", "remediation",
    # graphql-cop (normalize_graphql_cop_findings)
    "impact", "timestamp",
})

KNOWN_ENDPOINT_INFO_KEYS = frozenset({
    # scanner.py initialization + introspection test
    "tested", "introspection_enabled", "schema_extracted",
    "mutations_count", "queries_count", "subscriptions_count",
    "schema_hash", "error", "operations",
    # graphql-cop integration
    "graphql_cop_ran",
    "graphql_graphiql_exposed",
    "graphql_tracing_enabled",
    "graphql_get_allowed",
    "graphql_field_suggestions_enabled",
    "graphql_batching_enabled",
})


def _check_unknown_keys(obj: dict, known: frozenset, surface: str, identifier: str) -> None:
    """Warn loudly if the scanner emitted a key the mixin doesn't know about.

    This is the 100%-coverage guarantee: if this warning ever fires, the
    scanner has added a field and the mixin needs updating — don't silently
    drop data.
    """
    if not isinstance(obj, dict):
        return
    unknown = set(obj.keys()) - known
    if unknown:
        print(
            f"[!][graph-db] graphql_scan unknown {surface} key(s) {sorted(unknown)!r} "
            f"on {identifier!r} — update KNOWN_{surface.upper()}_KEYS + persistence logic"
        )


class GraphQLMixin:
    """Mixin for updating graph with GraphQL scan results."""

    def update_graph_from_graphql_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update Neo4j graph with results from GraphQL security scan.

        Enriches existing Endpoint nodes with GraphQL properties and creates
        Vulnerability nodes for discovered GraphQL-specific vulnerabilities.

        Args:
            recon_data: GraphQL scan result dict from run_graphql_scan()
            user_id: Tenant user ID
            project_id: Tenant project ID

        Returns:
            Stats dict with counts of nodes/relationships created/updated
        """
        stats = {
            "endpoints_enriched": 0,
            "vulnerabilities_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        # Extract GraphQL scan data
        graphql_data = recon_data.get("graphql_scan", {})
        if not graphql_data:
            stats["errors"].append("No graphql_scan data found in recon_data")
            return stats

        endpoints_data = graphql_data.get("endpoints", {})
        vulnerabilities = graphql_data.get("vulnerabilities", [])

        # graphql-cop capability flags produced by misconfig.derive_endpoint_flags.
        cop_capability_flags = (
            "graphql_graphiql_exposed",
            "graphql_tracing_enabled",
            "graphql_get_allowed",
            "graphql_field_suggestions_enabled",
            "graphql_batching_enabled",
        )

        def _is_confirmed_graphql(info: dict) -> bool:
            if not info.get("tested"):
                return False
            if info.get("introspection_enabled") or info.get("schema_extracted"):
                return True
            if any(info.get(flag) for flag in cop_capability_flags):
                return True
            return False

        with self.driver.session() as session:
            # Process endpoints - enrich existing Endpoint nodes with GraphQL properties
            for endpoint_url, endpoint_info in endpoints_data.items():
                # Flag any keys the scanner added that this mixin doesn't map.
                _check_unknown_keys(endpoint_info, KNOWN_ENDPOINT_INFO_KEYS,
                                    "endpoint_info", endpoint_url)

                # Skip URL-pattern candidates that didn't turn out to be GraphQL
                # (e.g. 301/404 probes). Only persist when we have positive evidence.
                if not _is_confirmed_graphql(endpoint_info):
                    continue

                try:
                    # Parse endpoint URL to get path and baseurl
                    from urllib.parse import urlparse
                    parsed = urlparse(endpoint_url)
                    path = parsed.path or "/"
                    baseurl = f"{parsed.scheme}://{parsed.netloc}"

                    # Build GraphQL enrichment properties
                    graphql_props = {
                        "is_graphql": True,
                        "graphql_introspection_enabled": endpoint_info.get("introspection_enabled", False),
                        "graphql_schema_extracted": endpoint_info.get("schema_extracted", False),
                        "source": "graphql_scan",
                        "updated_at": datetime.now().isoformat()
                    }

                    # Operation-name arrays + explicit counts (closes subscriptions data-loss gap)
                    operations = endpoint_info.get("operations", {}) or {}
                    mutations = operations.get("mutations", []) or []
                    queries = operations.get("queries", []) or []
                    subscriptions = operations.get("subscriptions", []) or []

                    if mutations:
                        graphql_props["graphql_mutations"] = mutations[:50]
                    if queries:
                        graphql_props["graphql_queries"] = queries[:50]
                    if subscriptions:
                        graphql_props["graphql_subscriptions"] = subscriptions[:50]

                    graphql_props["graphql_mutations_count"] = endpoint_info.get("mutations_count", 0)
                    graphql_props["graphql_queries_count"] = endpoint_info.get("queries_count", 0)
                    graphql_props["graphql_subscriptions_count"] = endpoint_info.get("subscriptions_count", 0)

                    if endpoint_info.get("schema_hash"):
                        graphql_props["graphql_schema_hash"] = endpoint_info["schema_hash"]

                    if endpoint_info.get("schema_extracted"):
                        graphql_props["graphql_schema_extracted_at"] = datetime.now(timezone.utc).isoformat()

                    # Preserve last error from introspection attempt for debugging
                    # (e.g. "Non-200 status code: 301", "Timeout after 45s").
                    if endpoint_info.get("error"):
                        graphql_props["graphql_last_error"] = endpoint_info["error"]

                    # graphql-cop capability flags (Phase 2 §17.4). The scanner copies
                    # these booleans onto endpoint_info via misconfig.derive_endpoint_flags.
                    for flag in cop_capability_flags:
                        if flag in endpoint_info:
                            graphql_props[flag] = bool(endpoint_info[flag])
                    if endpoint_info.get("graphql_cop_ran"):
                        graphql_props["graphql_cop_scanned_at"] = datetime.now(timezone.utc).isoformat()

                    # MERGE Endpoint AND wire the (BaseURL)-[:HAS_ENDPOINT]->(Endpoint)
                    # edge. Cannot assume resource_enum created the Endpoint upstream —
                    # Katana/GAU sometimes discover nothing, leaving the graphql mixin
                    # to create these nodes from scratch. Without this MERGE, the
                    # Endpoint is orphaned from the asset graph.
                    result = session.run(
                        """
                        MERGE (bu:BaseURL {
                            url: $baseurl,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                          ON CREATE SET bu.source = 'graphql_scan',
                                        bu.updated_at = datetime()
                        WITH bu
                        MERGE (e:Endpoint {
                            path: $path,
                            method: 'POST',
                            baseurl: $baseurl,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                          ON CREATE SET e.source = 'graphql_scan',
                                        e.created_at = datetime()
                        SET e += $props
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        RETURN e.path as path, e.is_graphql as was_graphql
                        """,
                        path=path,
                        baseurl=baseurl,
                        user_id=user_id,
                        project_id=project_id,
                        props=graphql_props
                    )

                    record = result.single()
                    if record:
                        stats["endpoints_enriched"] += 1
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to enrich endpoint {endpoint_url}: {str(e)}")

            # Process vulnerabilities
            vuln_id_mapping = {}  # Map generated IDs to Neo4j IDs

            for vuln in vulnerabilities:
                # Flag any keys the scanner added that this mixin doesn't map.
                _check_unknown_keys(vuln, KNOWN_VULN_KEYS, "vuln",
                                    vuln.get("vulnerability_type", "?"))

                try:
                    endpoint_url = vuln.get("endpoint", "")
                    vuln_type = vuln.get("vulnerability_type", "")
                    severity = vuln.get("severity", "info")

                    if not endpoint_url or not vuln_type:
                        continue

                    # Parse endpoint URL
                    parsed = urlparse(endpoint_url)
                    path = parsed.path or "/"
                    baseurl = f"{parsed.scheme}://{parsed.netloc}"

                    # Generate unique vulnerability ID.
                    # Scanner source (graphql_scan vs graphql_cop) is part of the ID so
                    # the native scanner and graphql-cop can both report the same
                    # vulnerability_type on the same endpoint without MERGE-stomping
                    # each other's provenance (severity / source / evidence). The UI
                    # can dedupe by {type, endpoint} if it wants a single row per
                    # finding; the graph keeps both records for audit.
                    vuln_source = vuln.get("source", "graphql_scan")
                    vuln_id = (
                        f"graphql_{vuln_type}_{baseurl}_{path}_{vuln_source}"
                        .replace(":", "_").replace("/", "_").replace(".", "_")
                    )

                    # Normalize `discovered_at`: native scanner uses `discovered_at`,
                    # graphql-cop uses `timestamp`. Prefer the scanner's value when set
                    # so the node timestamp reflects scan time, not ingest time.
                    discovered_at = (
                        vuln.get("discovered_at")
                        or vuln.get("timestamp")
                        or datetime.now(timezone.utc).isoformat()
                    )

                    # Create vulnerability properties.
                    # Respect the vuln dict's own `source` when set (graphql-cop uses
                    # 'graphql_cop' so reports can distinguish it from PR's native scan).
                    # All canonical scanner keys are mapped explicitly here so
                    # _check_unknown_keys can flag any future additions.
                    vuln_props = {
                        "id": vuln_id,
                        "vulnerability_id": vuln_id,
                        "vulnerability_type": vuln_type,
                        "severity": severity,
                        "title": vuln.get("title", f"GraphQL {vuln_type}"),
                        "description": vuln.get("description", ""),
                        "source": vuln.get("source", "graphql_scan"),
                        "endpoint": endpoint_url,
                        "user_id": user_id,
                        "project_id": project_id,
                        "discovered_at": discovered_at,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }

                    # Optional native-scanner field: remediation guidance.
                    if vuln.get("remediation"):
                        vuln_props["remediation"] = vuln["remediation"]

                    # Optional graphql-cop field: impact description.
                    if vuln.get("impact"):
                        vuln_props["impact"] = vuln["impact"]

                    # Evidence: store full dict as JSON for fidelity, AND hoist
                    # high-value subkeys to top-level so they're queryable in Cypher
                    # (otherwise they'd require JSON parsing at query time).
                    evidence = vuln.get("evidence", {}) or {}
                    if evidence:
                        import json
                        vuln_props["evidence"] = json.dumps(evidence, default=str)

                        # Hoist queryable subkeys. Neo4j can't index JSON blobs,
                        # so mirror these to first-class props for filter queries.
                        if "curl_verify" in evidence:
                            vuln_props["curl_verify"] = evidence["curl_verify"]
                        if "raw_severity" in evidence:
                            vuln_props["raw_severity"] = evidence["raw_severity"]
                        if "graphql_cop_key" in evidence:
                            vuln_props["graphql_cop_key"] = evidence["graphql_cop_key"]
                        if "operations_count" in evidence:
                            oc = evidence["operations_count"] or {}
                            vuln_props["evidence_queries_count"] = oc.get("queries", 0)
                            vuln_props["evidence_mutations_count"] = oc.get("mutations", 0)
                            vuln_props["evidence_subscriptions_count"] = oc.get("subscriptions", 0)
                        if "sensitive_fields_sample" in evidence:
                            vuln_props["sensitive_fields_sample"] = evidence["sensitive_fields_sample"]

                    # Create Vulnerability node
                    result = session.run(
                        """
                        MERGE (v:Vulnerability {
                            id: $id,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                        SET v += $props
                        RETURN v.id as id
                        """,
                        id=vuln_id,
                        user_id=user_id,
                        project_id=project_id,
                        props=vuln_props
                    )

                    record = result.single()
                    if record:
                        stats["vulnerabilities_created"] += 1
                        vuln_id_mapping[vuln_id] = record["id"]

                    # Create relationship to Endpoint.
                    # Uses (Endpoint)-[:HAS_VULNERABILITY]->(Vulnerability) to match the
                    # rest of the codebase (Nuclei, GVM, SecurityChecks, report queries
                    # in reportData.ts all rely on this direction + label).
                    # MERGE (not MATCH) the BaseURL + Endpoint so a vuln whose endpoint
                    # didn't pass the persistence filter still lands in a wired subgraph.
                    session.run(
                        """
                        MATCH (v:Vulnerability {
                            id: $vuln_id,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                        MERGE (bu:BaseURL {
                            url: $baseurl,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                          ON CREATE SET bu.source = 'graphql_scan',
                                        bu.updated_at = datetime()
                        MERGE (e:Endpoint {
                            path: $path,
                            method: 'POST',
                            baseurl: $baseurl,
                            user_id: $user_id,
                            project_id: $project_id
                        })
                          ON CREATE SET e.source = 'graphql_scan',
                                        e.is_graphql = true,
                                        e.created_at = datetime()
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        MERGE (e)-[:HAS_VULNERABILITY]->(v)
                        """,
                        vuln_id=vuln_id,
                        path=path,
                        baseurl=baseurl,
                        user_id=user_id,
                        project_id=project_id
                    )
                    stats["relationships_created"] += 1

                    # If introspection vulnerability, check for sensitive fields.
                    # Scanner emits `sensitive_fields_sample`; older code read `sensitive_fields`.
                    if vuln_type == "graphql_introspection_enabled":
                        sensitive_fields = (
                            evidence.get("sensitive_fields")
                            or evidence.get("sensitive_fields_sample")
                            or []
                        )
                        if sensitive_fields:
                            # Create additional high severity finding for sensitive data exposure
                            sensitive_vuln_id = f"{vuln_id}_sensitive_data"
                            sensitive_props = vuln_props.copy()
                            sensitive_props.update({
                                "id": sensitive_vuln_id,
                                "vulnerability_id": sensitive_vuln_id,
                                "vulnerability_type": "graphql_sensitive_data_exposure",
                                "severity": "high",
                                "title": "GraphQL Schema Exposes Sensitive Fields",
                                "description": f"Introspection reveals sensitive fields: {', '.join(sensitive_fields[:10])}"
                            })

                            result = session.run(
                                """
                                MERGE (v:Vulnerability {
                                    id: $id,
                                    user_id: $user_id,
                                    project_id: $project_id
                                })
                                SET v += $props
                                RETURN v.id as id
                                """,
                                id=sensitive_vuln_id,
                                user_id=user_id,
                                project_id=project_id,
                                props=sensitive_props
                            )

                            if result.single():
                                stats["vulnerabilities_created"] += 1

                                # Link to endpoint (Endpoint -> Vulnerability, matches codebase convention)
                                session.run(
                                    """
                                    MATCH (v:Vulnerability {
                                        id: $vuln_id,
                                        user_id: $user_id,
                                        project_id: $project_id
                                    })
                                    MERGE (bu:BaseURL {
                                        url: $baseurl,
                                        user_id: $user_id,
                                        project_id: $project_id
                                    })
                                      ON CREATE SET bu.source = 'graphql_scan',
                                                    bu.updated_at = datetime()
                                    MERGE (e:Endpoint {
                                        path: $path,
                                        method: 'POST',
                                        baseurl: $baseurl,
                                        user_id: $user_id,
                                        project_id: $project_id
                                    })
                                      ON CREATE SET e.source = 'graphql_scan',
                                                    e.is_graphql = true,
                                                    e.created_at = datetime()
                                    MERGE (bu)-[:HAS_ENDPOINT]->(e)
                                    MERGE (e)-[:HAS_VULNERABILITY]->(v)
                                    """,
                                    vuln_id=sensitive_vuln_id,
                                    path=path,
                                    baseurl=baseurl,
                                    user_id=user_id,
                                    project_id=project_id
                                )
                                stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to create vulnerability {vuln.get('vulnerability_type', 'unknown')}: {str(e)}")

            # Log results
            print(f"[+][graph-db] GraphQL scan: {stats['endpoints_enriched']} endpoints enriched")
            print(f"[+][graph-db] GraphQL scan: {stats['vulnerabilities_created']} vulnerabilities created")
            print(f"[+][graph-db] GraphQL scan: {stats['relationships_created']} relationships created")

            if stats["errors"]:
                print(f"[!][graph-db] GraphQL scan: {len(stats['errors'])} errors occurred")
                for error in stats["errors"][:5]:  # Show first 5 errors
                    print(f"[!][graph-db] {error}")

        return stats