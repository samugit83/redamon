"""Vulnerability scan graph updates (Vulnerability, CVE, CWE, CAPEC, Exploit, MitreData).

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address

class VulnMixin:
    def _find_cwes_with_capec(self, cwe_node: dict, results: list):
        """
        Recursively traverse CWE hierarchy and collect only CWEs that have non-empty related_capec.

        Args:
            cwe_node: CWE hierarchy node
            results: List to collect CWEs with CAPEC (passed by reference)
        """
        if not cwe_node:
            return

        # Check if this CWE has related_capec
        related_capec = cwe_node.get("related_capec", [])
        if related_capec:
            results.append(cwe_node)

        # Recursively check child
        child = cwe_node.get("child")
        if child:
            self._find_cwes_with_capec(child, results)

    def _process_cwe_with_capec(self, session, cwe_node: dict, cve_id: str, user_id: str,
                                 project_id: str, stats_mitre: dict):
        """
        Create MitreData (CWE) node and its related Capec nodes, directly connected to CVE.

        Args:
            session: Neo4j session
            cwe_node: CWE node that has related_capec
            cve_id: The CVE ID to connect to
            user_id: User identifier
            project_id: Project identifier
            stats_mitre: Dictionary to track created nodes
        """

        # Get CWE ID (support both "cwe_id" and "id" keys)
        cwe_id = cwe_node.get("cwe_id") or cwe_node.get("id")
        if not cwe_id:
            return

        # Generate unique MitreData node ID (per CVE + CWE combination)
        mitre_id = f"{cve_id}-{cwe_id}"

        # Create MitreData node with CWE properties
        mitre_props = {
            "id": mitre_id,
            "user_id": user_id,
            "project_id": project_id,
            "cve_id": cve_id,
            "cwe_id": cwe_id,
            "cwe_name": cwe_node.get("name"),
            "cwe_description": cwe_node.get("description"),
            "cwe_url": cwe_node.get("url"),
            "abstraction": cwe_node.get("abstraction"),
        }

        # Add additional fields if available
        if cwe_node.get("mapping"):
            mitre_props["mapping"] = cwe_node.get("mapping")
        if cwe_node.get("structure"):
            mitre_props["structure"] = cwe_node.get("structure")
        if cwe_node.get("consequences"):
            mitre_props["consequences"] = json.dumps(cwe_node.get("consequences"))
        if cwe_node.get("mitigations"):
            mitre_props["mitigations"] = json.dumps(cwe_node.get("mitigations"))
        if cwe_node.get("detection_methods"):
            mitre_props["detection_methods"] = json.dumps(cwe_node.get("detection_methods"))

        # Remove None values
        mitre_props = {k: v for k, v in mitre_props.items() if v is not None}

        session.run(
            """
            MERGE (m:MitreData {id: $id})
            SET m += $props,
                m.updated_at = datetime()
            """,
            id=mitre_id, props=mitre_props
        )
        stats_mitre["nodes"] += 1

        # Create relationship: CVE -[:HAS_CWE]-> MitreData (directly connected)
        session.run(
            """
            MATCH (c:CVE {id: $cve_id})
            MATCH (m:MitreData {id: $mitre_id})
            MERGE (c)-[:HAS_CWE]->(m)
            """,
            cve_id=cve_id, mitre_id=mitre_id
        )
        stats_mitre["rels"] += 1

        # Process related CAPEC entries
        related_capec = cwe_node.get("related_capec", [])
        for capec in related_capec:
            capec_id_raw = capec.get("id")
            if not capec_id_raw:
                continue

            # Handle both formats: "CAPEC-475" (string) or 475 (numeric)
            if isinstance(capec_id_raw, str) and capec_id_raw.startswith("CAPEC-"):
                capec_node_id = capec_id_raw
                try:
                    numeric_id = int(capec_id_raw.replace("CAPEC-", ""))
                except ValueError:
                    numeric_id = None
            else:
                capec_node_id = f"CAPEC-{capec_id_raw}"
                numeric_id = capec_id_raw if isinstance(capec_id_raw, int) else None

            # Create Capec node with all properties
            capec_props = {
                "capec_id": capec_node_id,
                "user_id": user_id,
                "project_id": project_id,
                "numeric_id": numeric_id,
                "name": capec.get("name"),
                "description": capec.get("description"),
                "url": capec.get("url"),
                "likelihood": capec.get("likelihood"),
                "severity": capec.get("severity"),
                "prerequisites": capec.get("prerequisites"),
                "examples": capec.get("examples"),
            }

            # Add execution flow if available
            execution_flow = capec.get("execution_flow", [])
            if execution_flow:
                capec_props["execution_flow"] = json.dumps(execution_flow)

            # Add related CWEs
            related_cwes = capec.get("related_cwes", [])
            if related_cwes:
                capec_props["related_cwes"] = related_cwes

            # Remove None values
            capec_props = {k: v for k, v in capec_props.items() if v is not None}

            session.run(
                """
                MERGE (cap:Capec {capec_id: $capec_id})
                SET cap += $props,
                    cap.updated_at = datetime()
                """,
                capec_id=capec_node_id, props=capec_props
            )
            stats_mitre["capec"] += 1

            # Create relationship: MitreData -[:HAS_CAPEC]-> Capec
            session.run(
                """
                MATCH (m:MitreData {id: $mitre_id})
                MATCH (cap:Capec {capec_id: $capec_id})
                MERGE (m)-[:HAS_CAPEC]->(cap)
                """,
                mitre_id=mitre_id, capec_id=capec_node_id
            )
            stats_mitre["rels"] += 1

    def update_graph_from_vuln_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with vulnerability scan data.

        This function creates/updates:
        - Endpoint nodes (discovered paths/URLs with parameters from Katana crawling)
        - Parameter nodes (query/body parameters discovered and tested)
        - Vulnerability nodes (DAST findings from Nuclei scanning)
        - Relationships: BaseURL -[:HAS_ENDPOINT]-> Endpoint -[:HAS_PARAMETER]-> Parameter
        - Relationships: Vulnerability -[:AFFECTS_PARAMETER]-> Parameter, Vulnerability -[:FOUND_AT]-> Endpoint
        - Relationships: BaseURL -[:HAS_VULNERABILITY]-> Vulnerability

        Args:
            recon_data: The recon JSON data containing vuln_scan results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "endpoints_created": 0,
            "parameters_created": 0,
            "vulnerabilities_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        vuln_scan_data = recon_data.get("vuln_scan", {})
        if not vuln_scan_data:
            stats["errors"].append("No vuln_scan data found in recon_data")
            return stats

        # Get target subdomains from scan scope - only create nodes for these
        target_subdomains = set(recon_data.get("subdomains", []))
        target_domain = recon_data.get("domain", "")

        # Also include the main domain if no subdomains specified
        if target_domain and not target_subdomains:
            target_subdomains.add(target_domain)

        def is_in_scope(hostname: str) -> bool:
            """Check if a hostname is within the scan scope (target subdomains)."""
            if not target_subdomains:
                return True  # No filter if no subdomains defined
            # Remove port if present
            host_only = hostname.split(":")[0] if ":" in hostname else hostname
            return host_only in target_subdomains

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_metadata = vuln_scan_data.get("scan_metadata", {})
            discovered_urls = vuln_scan_data.get("discovered_urls", {})
            by_target = vuln_scan_data.get("by_target", {})

            # Track created endpoints and parameters for deduplication
            created_endpoints = set()  # (baseurl, path, method)
            created_parameters = set()  # (endpoint_path, param_name, param_position)
            skipped_out_of_scope = 0  # Track skipped URLs

            # Process discovered URLs with parameters (from Katana crawling)
            dast_urls = discovered_urls.get("dast_urls_with_params", [])
            base_urls = discovered_urls.get("base_urls", [])

            for dast_url in dast_urls:
                try:
                    # Parse the URL to extract components
                    parsed = urlparse(dast_url)

                    # Determine scheme, host, path
                    scheme = parsed.scheme or "http"
                    host = parsed.netloc
                    path = parsed.path or "/"
                    query_string = parsed.query

                    # Skip URLs that are not in scan scope (discovered subdomains only)
                    if not is_in_scope(host):
                        skipped_out_of_scope += 1
                        continue

                    # Construct base URL (scheme://host)
                    base_url = f"{scheme}://{host}"

                    # Determine HTTP method (default to GET for URLs with query params)
                    method = "GET"

                    # Create Endpoint node
                    endpoint_key = (base_url, path, method)
                    if endpoint_key not in created_endpoints:
                        has_parameters = bool(query_string)

                        session.run(
                            """
                            MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            SET e.user_id = $user_id,
                                e.project_id = $project_id,
                                e.has_parameters = $has_parameters,
                                e.full_url = $full_url,
                                e.source = 'katana_crawl',
                                e.updated_at = datetime()
                            """,
                            path=path, method=method, baseurl=base_url,
                            user_id=user_id, project_id=project_id,
                            has_parameters=has_parameters,
                            full_url=dast_url.split('?')[0]  # URL without query params
                        )
                        stats["endpoints_created"] += 1
                        created_endpoints.add(endpoint_key)

                        # Create BaseURL node if it doesn't exist and relationship
                        # BaseURL may not exist if endpoint was discovered by crawling a different subdomain
                        session.run(
                            """
                            MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET bu.source = 'resource_enum',
                                          bu.updated_at = datetime()
                            WITH bu
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            MERGE (bu)-[:HAS_ENDPOINT]->(e)
                            """,
                            baseurl=base_url, path=path, method=method,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1


                    # Parse and create Parameter nodes from query string
                    if query_string:
                        params = parse_qs(query_string, keep_blank_values=True)
                        for param_name, param_values in params.items():
                            param_key = (path, param_name, "query")
                            if param_key not in created_parameters:
                                sample_value = param_values[0] if param_values else ""

                                session.run(
                                    """
                                    MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    SET p.user_id = $user_id,
                                        p.project_id = $project_id,
                                        p.sample_value = $sample_value,
                                        p.is_injectable = false,
                                        p.updated_at = datetime()
                                    """,
                                    name=param_name, position="query", endpoint_path=path, baseurl=base_url,
                                    user_id=user_id, project_id=project_id,
                                    sample_value=sample_value
                                )
                                stats["parameters_created"] += 1
                                created_parameters.add(param_key)

                                # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, method=method, baseurl=base_url,
                                    param_name=param_name, position="query",
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"DAST URL {dast_url} processing failed: {e}")

            # Process vulnerability findings by target
            for target_host, target_data in by_target.items():
                # Skip targets that are not in scan scope
                target_host_only = target_host.split(":")[0] if ":" in target_host else target_host
                if not is_in_scope(target_host_only):
                    skipped_out_of_scope += 1
                    continue

                findings = target_data.get("findings", [])

                for finding in findings:
                    try:
                        # Extract raw data for detailed information
                        raw = finding.get("raw", {})
                        raw_info = raw.get("info", {})
                        raw_metadata = raw_info.get("metadata", {})

                        # Generate unique vulnerability ID
                        template_id = finding.get("template_id", "unknown")
                        matched_at = finding.get("matched_at", "")
                        fuzzing_param = raw.get("fuzzing_parameter", "")
                        vuln_id = f"{template_id}-{target_host}-{fuzzing_param}-{hash(matched_at) % 10000}"

                        # Extract path from matched_at URL
                        matched_parsed = urlparse(matched_at)
                        vuln_path = matched_parsed.path or "/"
                        vuln_scheme = matched_parsed.scheme or "http"
                        vuln_host = matched_parsed.netloc or target_host

                        # Also check if matched_at URL host is in scope
                        vuln_host_only = vuln_host.split(":")[0] if ":" in vuln_host else vuln_host
                        if not is_in_scope(vuln_host_only):
                            skipped_out_of_scope += 1
                            continue

                        vuln_base_url = f"{vuln_scheme}://{vuln_host}"

                        # Create Vulnerability node with all fields
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "source": "nuclei",
                            "template_id": template_id,
                            "template_path": finding.get("template_path"),
                            "template_url": raw.get("template-url"),
                            "name": finding.get("name"),
                            "description": finding.get("description"),
                            "severity": finding.get("severity"),
                            "category": finding.get("category"),
                            "tags": finding.get("tags", []),
                            "authors": raw_info.get("author", []),
                            "references": finding.get("reference", []),

                            # Classification
                            "cwe_ids": finding.get("cwe_id", []),
                            "cves": finding.get("cves", []),
                            "cvss_score": finding.get("cvss_score"),
                            "cvss_metrics": finding.get("cvss_metrics"),

                            # Attack details
                            "matched_at": matched_at,
                            "matcher_name": finding.get("matcher_name"),
                            "matcher_status": raw.get("matcher-status", False),
                            "extractor_name": raw.get("extractor-name"),
                            "extracted_results": finding.get("extracted_results", []),

                            # Request/Response details
                            "request_type": raw.get("type"),
                            "scheme": raw.get("scheme"),
                            "host": raw.get("host"),
                            "port": raw.get("port"),
                            "path": vuln_path,
                            "matched_ip": raw.get("ip"),

                            # DAST specific
                            "is_dast_finding": raw.get("is_fuzzing_result", False),
                            "fuzzing_method": raw.get("fuzzing_method"),
                            "fuzzing_parameter": raw.get("fuzzing_parameter"),
                            "fuzzing_position": raw.get("fuzzing_position"),

                            # Template metadata
                            "max_requests": raw_metadata.get("max-request"),

                            # Reproduction
                            "curl_command": finding.get("curl_command"),

                            # Raw request/response (for evidence)
                            "raw_request": finding.get("request"),
                            "raw_response": finding.get("response", "")[:5000] if finding.get("response") else None,  # Truncate long responses

                            # Timestamp
                            "timestamp": finding.get("timestamp"),
                            "discovered_at": finding.get("timestamp")
                        }

                        # Remove None values
                        vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (v:Vulnerability {id: $id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        stats["vulnerabilities_created"] += 1

                        # Note: We don't create BaseURL -[:HAS_VULNERABILITY]-> Vulnerability
                        # because the vulnerability is connected via:
                        # BaseURL -> Endpoint <- Vulnerability (FOUND_AT)
                        # and optionally: Endpoint -> Parameter <- Vulnerability (AFFECTS_PARAMETER)
                        # This avoids redundant connections in the graph.

                        # Create Endpoint node for the vulnerability path if not exists
                        fuzzing_method = raw.get("fuzzing_method", "GET")
                        endpoint_key = (vuln_base_url, vuln_path, fuzzing_method)

                        if endpoint_key not in created_endpoints:
                            session.run(
                                """
                                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET e.user_id = $user_id,
                                    e.project_id = $project_id,
                                    e.has_parameters = true,
                                    e.source = 'vuln_scan',
                                    e.updated_at = datetime()
                                """,
                                path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["endpoints_created"] += 1
                            created_endpoints.add(endpoint_key)

                            # Create BaseURL node if it doesn't exist and relationship
                            session.run(
                                """
                                MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET bu.source = 'vuln_scan',
                                              bu.updated_at = datetime()
                                WITH bu
                                MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (bu)-[:HAS_ENDPOINT]->(e)
                                """,
                                baseurl=vuln_base_url, path=vuln_path, method=fuzzing_method,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create relationship: Vulnerability -[:FOUND_AT]-> Endpoint
                        session.run(
                            """
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            MERGE (v)-[:FOUND_AT]->(e)
                            """,
                            vuln_id=vuln_id, path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                        # Create Parameter node and mark as injectable if this is a DAST finding
                        fuzzing_param = raw.get("fuzzing_parameter")
                        fuzzing_position = raw.get("fuzzing_position", "query")

                        if fuzzing_param:
                            param_key = (vuln_path, fuzzing_param, fuzzing_position)

                            # Create or update Parameter node (mark as injectable)
                            session.run(
                                """
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    p.is_injectable = true,
                                    p.updated_at = datetime()
                                """,
                                name=fuzzing_param, position=fuzzing_position, endpoint_path=vuln_path, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )

                            if param_key not in created_parameters:
                                stats["parameters_created"] += 1
                                created_parameters.add(param_key)

                                # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                    param_name=fuzzing_param, position=fuzzing_position,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                            # Create relationship: Vulnerability -[:AFFECTS_PARAMETER]-> Parameter
                            session.run(
                                """
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (v)-[:AFFECTS_PARAMETER]->(p)
                                """,
                                vuln_id=vuln_id, param_name=fuzzing_param, position=fuzzing_position,
                                path=vuln_path, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Finding {finding.get('template_id', 'unknown')} processing failed: {e}")

            # =========================================================================
            # Process technology_cves - CVE, MitreData, and Capec nodes
            # =========================================================================
            technology_cves = recon_data.get("technology_cves", {})
            by_technology = technology_cves.get("by_technology", {})

            cves_created = 0
            mitre_stats = {"nodes": 0, "capec": 0, "rels": 0}  # Shared stats for MITRE processing
            cve_relationships_created = 0

            for tech_name, tech_data in by_technology.items():
                tech_product = tech_data.get("product", tech_name)
                tech_version = tech_data.get("version")  # Version from CVE lookup
                cves = tech_data.get("cves", [])

                # Extract clean technology name from key by stripping version suffix
                # e.g. "Apache HTTP Server:2.4.49" → "Apache HTTP Server"
                # e.g. "Apache/2.4.49" → "Apache"
                tech_name_clean = tech_name
                if tech_version:
                    for sep in [":", "/"]:
                        suffix = f"{sep}{tech_version}"
                        if tech_name_clean.endswith(suffix):
                            tech_name_clean = tech_name_clean[:-len(suffix)]
                            break

                for cve in cves:
                    try:
                        cve_id = cve.get("id")
                        if not cve_id:
                            continue

                        # Create CVE node with all properties
                        cve_props = {
                            "id": cve_id,
                            "cve_id": cve_id,
                            "name": cve_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "cvss": cve.get("cvss"),
                            "severity": cve.get("severity"),
                            "description": cve.get("description"),
                            "published": cve.get("published"),
                            "source": cve.get("source"),
                            "url": cve.get("url"),
                        }

                        # Handle references (can be a list)
                        references = cve.get("references", [])
                        if references:
                            cve_props["references"] = references

                        # Remove None values
                        cve_props = {k: v for k, v in cve_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (c:CVE {id: $id})
                            SET c += $props,
                                c.updated_at = datetime()
                            """,
                            id=cve_id, props=cve_props
                        )
                        cves_created += 1

                        # Create relationship: Technology -[:HAS_KNOWN_CVE]-> CVE
                        # Match Technology node by name (case-insensitive)
                        # Matching strategies (in order):
                        # 1. Exact match by clean name (key without version suffix)
                        # 2. Exact match by NVD product name or raw key
                        # 3. CONTAINS fallback (product name within technology name)
                        # Version matching:
                        # - First try exact version match
                        # - Then fallback to version-less match (handles httpx detecting
                        #   "Apache Tomcat" without version while NVD uses "Apache-Coyote/1.1")
                        name_where = """
                            (toLower(t.name) = toLower($tech_name_clean)
                             OR toLower(t.name) = toLower($tech_product)
                             OR toLower(t.name) = toLower($tech_key)
                             OR toLower(t.name) CONTAINS toLower($tech_product))
                        """

                        matched = 0

                        if tech_version:
                            # Try 1: exact name + exact version
                            result = session.run(
                                f"""
                                MATCH (t:Technology {{user_id: $user_id, project_id: $project_id}})
                                WHERE {name_where} AND t.version = $tech_version
                                MATCH (c:CVE {{id: $cve_id}})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                user_id=user_id, project_id=project_id, tech_name_clean=tech_name_clean,
                                tech_product=tech_product, tech_key=tech_name,
                                tech_version=tech_version, cve_id=cve_id
                            )
                            matched = result.single()["matched"]

                        if matched == 0:
                            # Try 2: name match ignoring version (fallback for version mismatch)
                            result = session.run(
                                f"""
                                MATCH (t:Technology {{user_id: $user_id, project_id: $project_id}})
                                WHERE {name_where}
                                MATCH (c:CVE {{id: $cve_id}})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                user_id=user_id, project_id=project_id, tech_name_clean=tech_name_clean,
                                tech_product=tech_product, tech_key=tech_name, cve_id=cve_id
                            )
                            matched = result.single()["matched"]

                        if matched > 0:
                            cve_relationships_created += 1

                        # Process MITRE data if available
                        mitre_attack = cve.get("mitre_attack", {})
                        if mitre_attack.get("enriched"):
                            cwe_hierarchy = mitre_attack.get("cwe_hierarchy")

                            if cwe_hierarchy:
                                # Find all CWEs that have related_capec (traverse hierarchy)
                                cwes_with_capec = []
                                self._find_cwes_with_capec(cwe_hierarchy, cwes_with_capec)

                                # Create MitreData and Capec nodes for each CWE with CAPEC
                                for cwe_node in cwes_with_capec:
                                    self._process_cwe_with_capec(
                                        session, cwe_node, cve_id, user_id, project_id,
                                        stats_mitre=mitre_stats
                                    )

                            # Process additional CWE hierarchies if present
                            additional_hierarchies = mitre_attack.get("additional_cwe_hierarchies", [])
                            for add_hierarchy in additional_hierarchies:
                                cwes_with_capec = []
                                self._find_cwes_with_capec(add_hierarchy, cwes_with_capec)

                                for cwe_node in cwes_with_capec:
                                    self._process_cwe_with_capec(
                                        session, cwe_node, cve_id, user_id, project_id,
                                        stats_mitre=mitre_stats
                                    )

                    except Exception as e:
                        stats["errors"].append(f"CVE {cve.get('id', 'unknown')} processing failed: {e}")

            if cves_created > 0:
                print(f"[+][graph-db] Created {cves_created} CVE nodes")
                print(f"[+][graph-db] Created {cve_relationships_created} Technology-CVE relationships")
            if mitre_stats["nodes"] > 0:
                print(f"[+][graph-db] Created {mitre_stats['nodes']} MitreData (CWE) nodes")
            if mitre_stats["capec"] > 0:
                print(f"[+][graph-db] Created {mitre_stats['capec']} Capec nodes")

            # =========================================================================
            # Process security_checks - Direct IP access, WAF bypass, etc.
            # =========================================================================
            security_checks_created = 0
            waf_bypass_rels = 0

            for target_host, target_data in by_target.items():
                security_checks = target_data.get("security_checks", {})

                if not security_checks:
                    continue

                # Process direct_ip_access checks
                direct_ip_access = security_checks.get("direct_ip_access", {})
                ip_address = direct_ip_access.get("ip")
                checks = direct_ip_access.get("checks", [])

                for check in checks:
                    try:
                        check_type = check.get("check_type", "unknown")
                        severity = check.get("severity", "info")
                        url = check.get("url", "")
                        finding = check.get("finding", "")
                        evidence = check.get("evidence")
                        status_code = check.get("status_code")
                        content_length = check.get("content_length")

                        # Generate unique vulnerability ID
                        vuln_id = f"sec_{check_type}_{ip_address}_{hash(url) % 10000}"

                        # Human-readable names for check types
                        check_names = {
                            "direct_ip_http": "HTTP accessible directly via IP",
                            "direct_ip_https": "HTTPS accessible directly via IP",
                            "ip_api_exposed": "API endpoint exposed on IP without TLS",
                            "waf_bypass": "WAF bypass via direct IP access",
                            "tls_mismatch": "TLS certificate mismatch",
                            "http_on_ip": "HTTP service on direct IP",
                        }

                        # Create Vulnerability node (source='security_check')
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "source": "security_check",
                            "type": check_type,
                            "severity": severity,
                            "name": check_names.get(check_type, f"Security check: {check_type}"),
                            "description": finding,
                            "url": url,
                            "matched_at": url,
                            "host": target_host,
                            "matched_ip": ip_address,
                            "template_id": None,
                            "is_dast_finding": False,
                        }

                        if evidence:
                            vuln_props["evidence"] = evidence
                        if status_code:
                            vuln_props["status_code"] = status_code
                        if content_length:
                            vuln_props["content_length"] = content_length

                        vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (v:Vulnerability {id: $id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        security_checks_created += 1
                        stats["vulnerabilities_created"] += 1

                        # Create relationship: IP -[:HAS_VULNERABILITY]-> Vulnerability
                        # These are IP-level findings (direct IP access), so IP relationship is correct
                        if ip_address:
                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i.updated_at = datetime()
                                """,
                                address=ip_address, user_id=user_id, project_id=project_id
                            )

                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                """,
                                ip_addr=ip_address, vuln_id=vuln_id,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # For WAF bypass: create WAF_BYPASS_VIA relationship (not HAS_VULNERABILITY)
                        # The vulnerability is already connected to IP; WAF_BYPASS_VIA shows the bypass path
                        if check_type == "waf_bypass" and target_host:
                            # Subdomain -[:WAF_BYPASS_VIA]-> IP (shows which subdomain can bypass WAF via IP)
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:WAF_BYPASS_VIA {
                                    discovered_at: datetime(),
                                    evidence: $evidence
                                }]->(i)
                                """,
                                subdomain=target_host, ip_addr=ip_address,
                                evidence=evidence or "",
                                user_id=user_id, project_id=project_id
                            )
                            waf_bypass_rels += 1

                    except Exception as e:
                        stats["errors"].append(f"Security check {check_type} failed: {e}")

            if security_checks_created > 0:
                print(f"[+][graph-db] Created {security_checks_created} security check Vulnerability nodes")
            if waf_bypass_rels > 0:
                print(f"[+][graph-db] Created {waf_bypass_rels} WAF_BYPASS_VIA relationships")

            # =========================================================================
            # Process top-level security_checks.findings (new structure)
            # =========================================================================
            top_level_security_checks = vuln_scan_data.get("security_checks", {})
            security_findings = top_level_security_checks.get("findings", [])

            for finding in security_findings:
                try:
                    finding_type = finding.get("type", "unknown")
                    severity = finding.get("severity", "info")
                    name = finding.get("name", f"Security Issue: {finding_type}")
                    description = finding.get("description", "")
                    url = finding.get("url", "")
                    matched_ip = finding.get("matched_ip")
                    hostname = finding.get("hostname")
                    evidence = finding.get("evidence")
                    status_code = finding.get("status_code")
                    server = finding.get("server")
                    recommendation = finding.get("recommendation")
                    missing_header = finding.get("missing_header")
                    port = finding.get("port")

                    # Generate unique vulnerability ID
                    unique_key = f"{finding_type}_{url}_{matched_ip or hostname or ''}"
                    vuln_id = f"seccheck_{finding_type}_{hash(unique_key) % 100000}"

                    # Create Vulnerability node
                    vuln_props = {
                        "id": vuln_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "source": "security_check",
                        "type": finding_type,
                        "severity": severity,
                        "name": name,
                        "description": description,
                        "url": url,
                        "matched_at": url,
                        "is_dast_finding": False,
                    }

                    if matched_ip:
                        vuln_props["matched_ip"] = matched_ip
                    if hostname:
                        vuln_props["hostname"] = hostname
                    if evidence:
                        vuln_props["evidence"] = evidence
                    if status_code:
                        vuln_props["status_code"] = status_code
                    if server:
                        vuln_props["server"] = server
                    if recommendation:
                        vuln_props["recommendation"] = recommendation
                    if missing_header:
                        vuln_props["missing_header"] = missing_header
                    if port:
                        vuln_props["port"] = port

                    vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id})
                        SET v += $props,
                            v.updated_at = datetime()
                        """,
                        id=vuln_id, props=vuln_props
                    )
                    security_checks_created += 1
                    stats["vulnerabilities_created"] += 1

                    # Create relationships based on finding type
                    # Priority: IP (for IP-based URLs) > BaseURL (for hostname URLs) > Subdomain/Domain > IP
                    # Only ONE relationship is created per vulnerability to avoid redundancy
                    # (You can always traverse: BaseURL <- Service <- Port <- IP <- Subdomain <- Domain)
                    
                    relationship_created = False
                    
                    # For URL-based findings
                    if url and (url.startswith("http://") or url.startswith("https://")):
                        parsed = urlparse(url)
                        url_host = parsed.netloc.split(':')[0]  # Remove port if present
                        
                        # If URL host is an IP address, connect to IP node (not BaseURL)
                        # This keeps the vulnerability connected to the existing IP node in the graph
                        if _is_ip_address(url_host):
                            result = session.run(
                                """
                                MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                address=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True
                        else:
                            # URL host is a hostname - connect to existing BaseURL if it exists
                            base_url = f"{parsed.scheme}://{parsed.netloc}"
                            result = session.run(
                                """
                                MATCH (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (bu)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                baseurl=base_url, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True
                            else:
                                # BaseURL doesn't exist, try Subdomain/Domain
                                result = session.run(
                                    """
                                    MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                    MATCH (v:Vulnerability {id: $vuln_id})
                                    MERGE (s)-[:HAS_VULNERABILITY]->(v)
                                    RETURN count(*) as matched
                                    """,
                                    hostname=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                                )
                                if result.single()["matched"] > 0:
                                    stats["relationships_created"] += 1
                                    relationship_created = True
                                else:
                                    # Try Domain
                                    session.run(
                                        """
                                        MATCH (d:Domain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                        MATCH (v:Vulnerability {id: $vuln_id})
                                        MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                        """,
                                        hostname=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                                    )
                                    stats["relationships_created"] += 1
                                    relationship_created = True

                    # For hostname-only findings (no URL): connect to Subdomain/Domain
                    elif hostname and not relationship_created:
                        # Try to link to Subdomain node
                        result = session.run(
                            """
                            MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MERGE (s)-[:HAS_VULNERABILITY]->(v)
                            RETURN count(*) as matched
                            """,
                            hostname=hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                        )
                        if result.single()["matched"] > 0:
                            stats["relationships_created"] += 1
                            relationship_created = True
                        else:
                            # Try Domain node if not a subdomain
                            session.run(
                                """
                                MATCH (d:Domain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                """,
                                hostname=hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            stats["relationships_created"] += 1
                            relationship_created = True

                    # For IP-only findings (no URL, no hostname): connect to IP
                    elif matched_ip and not relationship_created:
                        session.run(
                            """
                            MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MERGE (i)-[:HAS_VULNERABILITY]->(v)
                            """,
                            address=matched_ip, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                        )
                        stats["relationships_created"] += 1
                        relationship_created = True

                    # For domain-only findings (e.g., SPF/DMARC missing): connect to Domain
                    if not relationship_created:
                        finding_domain = finding.get("domain")
                        if finding_domain:
                            result = session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                domain=finding_domain, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True

                except Exception as e:
                    stats["errors"].append(f"Security finding {finding.get('type', 'unknown')} failed: {e}")

            if security_checks_created > 0:
                print(f"[+][graph-db] Created {security_checks_created} SecurityCheck Vulnerability nodes")

            # Update Domain node with vuln_scan metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            summary = vuln_scan_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.vuln_scan_timestamp = $scan_timestamp,
                            d.vuln_scan_dast_mode = $dast_mode,
                            d.vuln_scan_total_urls_scanned = $total_urls,
                            d.vuln_scan_dast_urls_discovered = $dast_urls,
                            d.vuln_scan_critical_count = $critical_count,
                            d.vuln_scan_high_count = $high_count,
                            d.vuln_scan_medium_count = $medium_count,
                            d.vuln_scan_low_count = $low_count,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        dast_mode=scan_metadata.get("dast_mode", False),
                        total_urls=scan_metadata.get("total_urls_scanned", 0),
                        dast_urls=scan_metadata.get("dast_urls_discovered", 0),
                        critical_count=summary.get("critical", 0),
                        high_count=summary.get("high", 0),
                        medium_count=summary.get("medium", 0),
                        low_count=summary.get("low", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+][graph-db] Created {stats['endpoints_created']} Endpoint nodes")
            print(f"[+][graph-db] Created {stats['parameters_created']} Parameter nodes")
            print(f"[+][graph-db] Created {stats['vulnerabilities_created']} Vulnerability nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            if skipped_out_of_scope > 0:
                print(f"[*][graph-db] Skipped {skipped_out_of_scope} items out of scan scope")
                stats["skipped_out_of_scope"] = skipped_out_of_scope

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats
