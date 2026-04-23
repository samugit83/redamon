"""User-supplied input nodes and partial discovery graph updates.

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address

class UserInputMixin:
    def create_user_input_node(self, domain: str, user_input_data: dict, user_id: str, project_id: str) -> str:
        """
        Create a UserInput node for partial recon user-provided values.

        Args:
            domain: Root domain to attach the UserInput to
            user_input_data: Dict with keys: id, input_type, values, tool_id
            user_id: Tenant user ID
            project_id: Tenant project ID

        Returns:
            The UserInput node ID
        """
        node_id = user_input_data["id"]

        with self.driver.session() as session:
            # Create UserInput node
            session.run(
                """
                MERGE (ui:UserInput {id: $id})
                SET ui.input_type = $input_type,
                    ui.values = $values,
                    ui.tool_id = $tool_id,
                    ui.source = 'user',
                    ui.status = 'running',
                    ui.created_at = datetime(),
                    ui.user_id = $user_id,
                    ui.project_id = $project_id
                """,
                id=node_id,
                input_type=user_input_data.get("input_type", "subdomains"),
                values=user_input_data.get("values", []),
                tool_id=user_input_data.get("tool_id", ""),
                user_id=user_id,
                project_id=project_id,
            )

            # Connect to Domain node (create Domain if needed via MERGE)
            session.run(
                """
                MERGE (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                ON CREATE SET d.updated_at = datetime()
                WITH d
                MATCH (ui:UserInput {id: $ui_id})
                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                """,
                domain=domain, user_id=user_id, project_id=project_id, ui_id=node_id,
            )

            print(f"[+][graph-db] Created UserInput node {node_id} for {domain}")

        return node_id

    def update_user_input_status(self, user_input_id: str, status: str, stats: dict = None) -> None:
        """Update the status and stats of a UserInput node."""
        with self.driver.session() as session:
            props = {"status": status, "updated_at": datetime.now().isoformat()}
            if status == "completed":
                props["completed_at"] = datetime.now().isoformat()
            if stats:
                props["stats"] = json.dumps(stats)

            session.run(
                """
                MATCH (ui:UserInput {id: $id})
                SET ui += $props
                """,
                id=user_input_id, props=props,
            )

    def update_graph_from_partial_discovery(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
        user_input_id: str = None,
    ) -> dict:
        """
        Update Neo4j graph with results from a partial subdomain discovery run.

        Creates Subdomain, IP, DNSRecord nodes and relationships using the same
        MERGE patterns as update_graph_from_domain_discovery(). Optionally links
        all produced nodes to a UserInput node via PRODUCED relationships.

        Args:
            recon_data: Discovery result dict (same format as domain_recon output)
            user_id: Tenant user ID
            project_id: Tenant project ID
            user_input_id: Optional UserInput node ID to link produced nodes

        Returns:
            Stats dict with counts
        """

        stats = {
            "subdomains_total": 0,
            "subdomains_new": 0,
            "subdomains_existing": 0,
            "ips_total": 0,
            "ips_new": 0,
            "dns_records_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        subdomains = recon_data.get("subdomains", [])
        dns_data = recon_data.get("dns") or {}
        domain = recon_data.get("domain", "")

        if not domain:
            stats["errors"].append("No domain found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure Domain node exists
            session.run(
                """
                MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                ON CREATE SET d.updated_at = datetime()
                ON MATCH SET d.updated_at = datetime()
                """,
                name=domain, user_id=user_id, project_id=project_id,
            )

            subdomain_dns = dns_data.get("subdomains", {}) if dns_data else {}
            domain_dns = dns_data.get("domain", {}) if dns_data else {}
            subdomain_status_map = recon_data.get("subdomain_status_map", {})

            for subdomain in subdomains:
                try:
                    # Get DNS info
                    if subdomain == domain:
                        subdomain_info = domain_dns
                    else:
                        subdomain_info = subdomain_dns.get(subdomain, {})
                    has_records = subdomain_info.get("has_records", False)
                    sub_status = subdomain_status_map.get(subdomain)

                    # Check if subdomain already exists (for stats tracking)
                    result = session.run(
                        """
                        OPTIONAL MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        RETURN s IS NOT NULL AS exists
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                    )
                    existed = result.single()["exists"]

                    # MERGE subdomain node (same pattern as full recon)
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        SET s.has_dns_records = $has_records,
                            s.status = coalesce(s.status, $status),
                            s.discovered_at = coalesce(s.discovered_at, datetime()),
                            s.updated_at = datetime()
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                        has_records=has_records, status=sub_status,
                    )
                    stats["subdomains_total"] += 1
                    if existed:
                        stats["subdomains_existing"] += 1
                    else:
                        stats["subdomains_new"] += 1

                    # Relationships: Subdomain <-> Domain
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                        """,
                        domain=domain, sub=subdomain, uid=user_id, pid=project_id,
                    )
                    stats["relationships_created"] += 1

                    # Link to UserInput via PRODUCED
                    if user_input_id:
                        session.run(
                            """
                            MATCH (ui:UserInput {id: $ui_id})
                            MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                            MERGE (ui)-[:PRODUCED]->(s)
                            """,
                            ui_id=user_input_id, name=subdomain, uid=user_id, pid=project_id,
                        )

                    # Create IP nodes from resolved IPs
                    records = subdomain_info.get("records", {})
                    ips_data = subdomain_info.get("ips", {})

                    for ip_version in ["ipv4", "ipv6"]:
                        for ip_addr in ips_data.get(ip_version, []):
                            if not ip_addr:
                                continue
                            try:
                                # Check if IP already exists
                                ip_exists = session.run(
                                    """
                                    OPTIONAL MATCH (i:IP {address: $address, user_id: $uid, project_id: $pid})
                                    RETURN i IS NOT NULL AS exists
                                    """,
                                    address=ip_addr, uid=user_id, pid=project_id,
                                ).single()["exists"]

                                session.run(
                                    """
                                    MERGE (i:IP {address: $address, user_id: $uid, project_id: $pid})
                                    SET i.version = $version,
                                        i.updated_at = datetime()
                                    """,
                                    address=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version,
                                )
                                stats["ips_total"] += 1
                                if not ip_exists:
                                    stats["ips_new"] += 1

                                # Subdomain -[:RESOLVES_TO]-> IP
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:RESOLVES_TO {record_type: $rt}]->(i)
                                    """,
                                    sub=subdomain, ip=ip_addr, rt=record_type,
                                    uid=user_id, pid=project_id,
                                )
                                stats["relationships_created"] += 1

                                # Link IP to UserInput
                                if user_input_id:
                                    session.run(
                                        """
                                        MATCH (ui:UserInput {id: $ui_id})
                                        MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        MERGE (ui)-[:PRODUCED]->(i)
                                        """,
                                        ui_id=user_input_id, addr=ip_addr,
                                        uid=user_id, pid=project_id,
                                    )
                            except Exception as e:
                                stats["errors"].append(f"IP {ip_addr} failed: {e}")

                    # Create DNSRecord nodes (non-A/AAAA)
                    for record_type, record_values in records.items():
                        if not record_values or record_type in ["A", "AAAA"]:
                            continue
                        if not isinstance(record_values, list):
                            record_values = [record_values]
                        for value in record_values:
                            if not value:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $sub, user_id: $uid, project_id: $pid})
                                    SET dns.updated_at = datetime()
                                    """,
                                    type=record_type, value=str(value), sub=subdomain,
                                    uid=user_id, pid=project_id,
                                )
                                stats["dns_records_created"] += 1

                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MATCH (dns:DNSRecord {type: $type, value: $value, subdomain: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:HAS_DNS_RECORD]->(dns)
                                    """,
                                    sub=subdomain, type=record_type, value=str(value),
                                    uid=user_id, pid=project_id,
                                )
                                stats["relationships_created"] += 1
                            except Exception as e:
                                stats["errors"].append(f"DNSRecord {record_type}={value} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain} processing failed: {e}")
                    print(f"[!][graph-db] Partial discovery: {subdomain} failed: {e}")

            # Count new IPs (approximate -- count those without prior discovered_at)
            # For simplicity, ips_new tracking is done at MERGE time above

            print(f"[+][graph-db] Partial discovery: {stats['subdomains_total']} subdomains "
                  f"({stats['subdomains_new']} new, {stats['subdomains_existing']} existing)")
            print(f"[+][graph-db] Partial discovery: {stats['ips_total']} IPs, "
                  f"{stats['dns_records_created']} DNS records")
            if stats["errors"]:
                print(f"[!][graph-db] Partial discovery: {len(stats['errors'])} errors")

        return stats

    def get_graph_inputs_for_tool(self, tool_id: str, user_id: str, project_id: str) -> dict:
        """
        Query existing graph data to provide inputs for a partial recon tool.

        Args:
            tool_id: Tool identifier (e.g., "SubdomainDiscovery")
            user_id: Tenant user ID
            project_id: Tenant project ID

        Returns:
            Dict with tool-specific inputs from the existing graph
        """
        with self.driver.session() as session:
            if tool_id == "SubdomainDiscovery":
                # Get the domain and count existing subdomains
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    RETURN d.name AS domain, count(s) AS subdomain_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["subdomain_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id in ("Naabu", "Masscan"):
                # Get domain, subdomain count, and IP count for port scanning
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
                    WITH d, count(DISTINCT s) AS sub_count,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count
                    RETURN d.name AS domain, sub_count, ip_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Nmap":
                # Get domain, IPs with ports, and port count for Nmap service detection
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
                    WITH d, count(DISTINCT s) AS sub_count,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count,
                         count(DISTINCT p) + count(DISTINCT dp) AS port_count
                    RETURN d.name AS domain, sub_count, ip_count, port_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "existing_ports_count": record["port_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Httpx":
                # Get domain, subdomains, IPs, ports, and existing BaseURLs for HTTP probing
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)-[:HAS_PORT]->(p:Port)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)-[:HAS_PORT]->(dp:Port)
                    OPTIONAL MATCH (p)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(bu:BaseURL)
                    OPTIONAL MATCH (dp)-[:HAS_SERVICE]->(:Service)-[:SERVES_URL]->(dbu:BaseURL)
                    WITH d, count(DISTINCT s) AS sub_count,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count,
                         count(DISTINCT p) + count(DISTINCT dp) AS port_count,
                         count(DISTINCT bu) + count(DISTINCT dbu) AS baseurl_count
                    RETURN d.name AS domain, sub_count, ip_count, port_count, baseurl_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "existing_ports_count": record["port_count"] or 0,
                    "existing_baseurls_count": record["baseurl_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id in ("Gau", "ParamSpider"):
                # Get domain and subdomain count for passive URL discovery tools
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    WITH d, collect(DISTINCT s.name) AS subdomains
                    RETURN d.name AS domain, subdomains, size(subdomains) AS sub_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains": record["subdomains"] or [],
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "JsRecon":
                # Get domain, BaseURL count/list, and Endpoint count for JS Recon
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    WITH d
                    OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                    WITH d, collect(DISTINCT b.url) AS baseurls
                    OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                    WITH d, baseurls, count(DISTINCT e) AS endpoint_count
                    RETURN d.name AS domain, baseurls, size(baseurls) AS baseurl_count, endpoint_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": 0,
                    "existing_baseurls": record["baseurls"] or [],
                    "existing_baseurls_count": record["baseurl_count"] or 0,
                    "existing_endpoints_count": record["endpoint_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Nuclei":
                # Get domain, BaseURL count/list, and Endpoint count for Nuclei vuln scanning
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    WITH d
                    OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                    WITH d, collect(DISTINCT b.url) AS baseurls
                    OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                    WITH d, baseurls, count(DISTINCT e) AS endpoint_count
                    RETURN d.name AS domain, baseurls, size(baseurls) AS baseurl_count, endpoint_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": 0,
                    "existing_baseurls": record["baseurls"] or [],
                    "existing_baseurls_count": record["baseurl_count"] or 0,
                    "existing_endpoints_count": record["endpoint_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "GraphqlScan":
                # GraphQL scan consumes BaseURLs + Endpoints (graph-only, no user textareas)
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    WITH d
                    OPTIONAL MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                    WITH d, collect(DISTINCT b.url) AS baseurls
                    OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                    WITH d, baseurls, count(DISTINCT e) AS endpoint_count,
                         count(DISTINCT CASE WHEN e.is_graphql = true THEN e END) AS graphql_endpoint_count
                    RETURN d.name AS domain, baseurls, size(baseurls) AS baseurl_count,
                           endpoint_count, graphql_endpoint_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": 0,
                    "existing_baseurls": record["baseurls"] or [],
                    "existing_baseurls_count": record["baseurl_count"] or 0,
                    "existing_endpoints_count": record["endpoint_count"] or 0,
                    "existing_graphql_endpoints_count": record["graphql_endpoint_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Shodan":
                # Get domain, subdomain names (for IP attach-to dropdown), and IP count
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
                    WITH d, collect(DISTINCT s.name) AS subdomains,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count
                    RETURN d.name AS domain, subdomains, size(subdomains) AS sub_count, ip_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains": record["subdomains"] or [],
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Urlscan":
                # Get domain and subdomain count for URLScan passive enrichment
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    RETURN d.name AS domain, count(s) AS subdomain_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["subdomain_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "Uncover":
                # Get domain and subdomain count for Uncover multi-engine expansion
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    RETURN d.name AS domain, count(s) AS subdomain_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains_count": record["subdomain_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "SubdomainTakeover":
                # Subdomain list + domain for the takeover scanner. Matches the
                # SubdomainDiscovery input shape because takeover operates on
                # the same input class (subdomains). BaseURL count is also
                # returned so the UI can show whether Nuclei-takeover templates
                # will have anything to scan.
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    OPTIONAL MATCH (s)-[:HAS_BASEURL]->(bu:BaseURL)
                    WITH d, collect(DISTINCT s.name) AS subdomains,
                         count(DISTINCT bu) AS baseurl_count
                    RETURN d.name AS domain, subdomains,
                           size(subdomains) AS sub_count, baseurl_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains": record["subdomains"] or [],
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_baseurls_count": record["baseurl_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            elif tool_id == "OsintEnrichment":
                # Get domain, subdomain names (for dropdown), and IP count for OSINT enrichment
                result = session.run(
                    """
                    OPTIONAL MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                    OPTIONAL MATCH (d)-[:RESOLVES_TO]->(di:IP)
                    WITH d, collect(DISTINCT s.name) AS subdomains,
                         count(DISTINCT i) + count(DISTINCT di) AS ip_count
                    RETURN d.name AS domain, subdomains, size(subdomains) AS sub_count, ip_count
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return {
                    "domain": record["domain"] if record["domain"] else None,
                    "existing_subdomains": record["subdomains"] or [],
                    "existing_subdomains_count": record["sub_count"] or 0,
                    "existing_ips_count": record["ip_count"] or 0,
                    "source": "graph" if record["domain"] else "settings",
                }

            return {"error": f"Unknown tool_id: {tool_id}"}
