"""Port and service scan graph updates.

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address

class PortMixin:
    def update_graph_from_port_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with port scan data.

        This function creates/updates:
        - Port nodes with open ports
        - Service nodes for detected services
        - Updates IP nodes with CDN information
        - Relationships: IP -[:HAS_PORT]-> Port, Port -[:RUNS_SERVICE]-> Service

        Args:
            recon_data: The recon JSON data containing port_scan results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "ports_created": 0,
            "services_created": 0,
            "ips_updated": 0,
            "relationships_created": 0,
            "errors": []
        }

        port_scan_data = recon_data.get("port_scan", {})
        if not port_scan_data:
            stats["errors"].append("No port_scan data found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_metadata = port_scan_data.get("scan_metadata", {})
            by_ip = port_scan_data.get("by_ip", {})
            by_host = port_scan_data.get("by_host", {})

            # Process by_ip data - this gives us IP -> ports mapping
            # Only update IPs that already exist in the graph (from DNS) or have open ports.
            # Skip IPs with no ports and no hostnames to avoid orphaned nodes.
            for ip_addr, ip_info in by_ip.items():
                try:
                    ports = ip_info.get("ports", [])
                    hostnames = ip_info.get("hostnames", [])

                    # Skip IPs that have no open ports and no hostname associations
                    if not ports and not hostnames:
                        continue

                    # Update IP node with CDN info if available
                    cdn_name = ip_info.get("cdn")
                    is_cdn = ip_info.get("is_cdn", False)

                    session.run(
                        """
                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        SET i.is_cdn = $is_cdn,
                            i.cdn_name = $cdn_name,
                            i.updated_at = datetime(),
                            i.first_seen = coalesce(i.first_seen, datetime($recon_job_started_at)),
                            i.first_seen_job_id = coalesce(i.first_seen_job_id, $recon_job_id),
                            i.last_seen = datetime($recon_job_started_at),
                            i.last_seen_job_id = $recon_job_id
                        """,
                        address=ip_addr, user_id=user_id, project_id=project_id,
                        is_cdn=is_cdn, cdn_name=cdn_name,
                        **self._recon_job_params(),
                    )
                    stats["ips_updated"] += 1

                except Exception as e:
                    stats["errors"].append(f"IP {ip_addr} update failed: {e}")

            # Process by_host data - this gives us hostname -> port details with services
            for hostname, host_info in by_host.items():
                ip_addr = host_info.get("ip")
                port_details = host_info.get("port_details", [])
                cdn_name = host_info.get("cdn")
                is_cdn = host_info.get("is_cdn", False)

                # Update IP node with CDN info (if not already done)
                if ip_addr:
                    try:
                        session.run(
                            """
                            MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            SET i.is_cdn = $is_cdn,
                                i.cdn_name = $cdn_name,
                                i.updated_at = datetime(),
                                i.first_seen = coalesce(i.first_seen, datetime($recon_job_started_at)),
                                i.first_seen_job_id = coalesce(i.first_seen_job_id, $recon_job_id),
                                i.last_seen = datetime($recon_job_started_at),
                                i.last_seen_job_id = $recon_job_id
                            """,
                            address=ip_addr, user_id=user_id, project_id=project_id,
                            is_cdn=is_cdn, cdn_name=cdn_name,
                            **self._recon_job_params(),
                        )
                    except Exception as e:
                        stats["errors"].append(f"IP {ip_addr} update failed: {e}")

                # Create Port and Service nodes
                for port_info in port_details:
                    port_number = port_info.get("port")
                    protocol = port_info.get("protocol", "tcp")
                    service_name = port_info.get("service")

                    if not port_number:
                        continue

                    try:
                        # Create Port node linked to IP
                        # Port uniqueness is per IP + port + protocol + tenant
                        session.run(
                            """
                            MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            SET p.state = 'open',
                                p.updated_at = datetime(),
                                p.first_seen = coalesce(p.first_seen, datetime($recon_job_started_at)),
                                p.first_seen_job_id = coalesce(p.first_seen_job_id, $recon_job_id),
                                p.last_seen = datetime($recon_job_started_at),
                                p.last_seen_job_id = $recon_job_id
                            """,
                            port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                            user_id=user_id, project_id=project_id,
                            **self._recon_job_params(),
                        )
                        stats["ports_created"] += 1

                        # Create relationship: IP -[:HAS_PORT]-> Port
                        if ip_addr:
                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                ip_addr=ip_addr, port_number=port_number, protocol=protocol,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create Service node if service detected
                        if service_name:
                            session.run(
                                """
                                MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET svc.updated_at = datetime(),
                                    svc.first_seen = coalesce(svc.first_seen, datetime($recon_job_started_at)),
                                    svc.first_seen_job_id = coalesce(svc.first_seen_job_id, $recon_job_id),
                                    svc.last_seen = datetime($recon_job_started_at),
                                    svc.last_seen_job_id = $recon_job_id
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=ip_addr,
                                user_id=user_id, project_id=project_id,
                                **self._recon_job_params(),
                            )
                            stats["services_created"] += 1

                            # Create relationship: Port -[:RUNS_SERVICE]-> Service
                            session.run(
                                """
                                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                                service_name=service_name, user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # AI surface recon: MERGE Technology(category=ai-*) when the
                        # port matched the AI port catalogue. Reuses the existing
                        # USES_TECHNOLOGY (on Service) + HAS_TECHNOLOGY (on Port)
                        # edges; new annotations are distinguished by the
                        # detected_by relationship property.
                        ai_service = port_info.get("ai_service") or {}
                        ai_name = ai_service.get("name")
                        ai_category = ai_service.get("category")
                        ai_detected_by = ai_service.get("detected_by", "naabu-ai-port")
                        if ai_name and ai_category and ip_addr:
                            try:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, user_id: $user_id, project_id: $project_id})
                                    SET t.category = $category,
                                        t.source = 'ai-port-catalog',
                                        t.updated_at = datetime(),
                                        t.first_seen = coalesce(t.first_seen, datetime($recon_job_started_at)),
                                        t.first_seen_job_id = coalesce(t.first_seen_job_id, $recon_job_id),
                                        t.last_seen = datetime($recon_job_started_at),
                                        t.last_seen_job_id = $recon_job_id
                                    """,
                                    name=ai_name, category=ai_category,
                                    user_id=user_id, project_id=project_id,
                                    **self._recon_job_params(),
                                )
                                stats.setdefault("ai_technologies_created", 0)
                                stats["ai_technologies_created"] += 1

                                # Link Port -> Technology
                                session.run(
                                    """
                                    MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $name, user_id: $user_id, project_id: $project_id})
                                    MERGE (p)-[r:HAS_TECHNOLOGY]->(t)
                                    SET r.detected_by = $detected_by
                                    """,
                                    port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                                    name=ai_name, detected_by=ai_detected_by,
                                    user_id=user_id, project_id=project_id,
                                )
                                # Link Service -> Technology when we have a Service
                                if service_name:
                                    session.run(
                                        """
                                        MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                        MATCH (t:Technology {name: $name, user_id: $user_id, project_id: $project_id})
                                        MERGE (svc)-[r:USES_TECHNOLOGY]->(t)
                                        SET r.detected_by = $detected_by
                                        """,
                                        service_name=service_name, port_number=port_number, ip_addr=ip_addr,
                                        name=ai_name, detected_by=ai_detected_by,
                                        user_id=user_id, project_id=project_id,
                                    )
                                stats["relationships_created"] += 1
                            except Exception as e:
                                stats["errors"].append(f"AI Technology {ai_name!r} on port {port_number} failed: {e}")

                    except Exception as e:
                        stats["errors"].append(f"Port {port_number}/{protocol} on {ip_addr} failed: {e}")

            # Update Domain node with port scan metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.port_scan_timestamp = $scan_timestamp,
                            d.port_scan_type = $scan_type,
                            d.port_scan_ports_config = $ports_config,
                            d.port_scan_total_open_ports = $total_open_ports,
                            d.updated_at = datetime(),
                            d.first_seen = coalesce(d.first_seen, datetime($recon_job_started_at)),
                            d.first_seen_job_id = coalesce(d.first_seen_job_id, $recon_job_id),
                            d.last_seen = datetime($recon_job_started_at),
                            d.last_seen_job_id = $recon_job_id
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        scan_type=scan_metadata.get("scan_type"),
                        ports_config=scan_metadata.get("ports_config"),
                        total_open_ports=port_scan_data.get("summary", {}).get("total_open_ports", 0),
                        **self._recon_job_params(),
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+][graph-db] Updated {stats['ips_updated']} IP nodes with CDN info")
            print(f"[+][graph-db] Created {stats['ports_created']} Port nodes")
            print(f"[+][graph-db] Created {stats['services_created']} Service nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_nmap(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with Nmap service detection and NSE vuln data.

        This function:
        - Enriches existing Port nodes with product, version, CPE from Nmap -sV
        - Updates existing Service nodes with version info
        - Creates Vulnerability nodes from NSE script findings
        - Creates CVE nodes if NSE scripts report specific CVEs
        - Creates Technology nodes for detected services (for CVE lookup linkage)
        """
        import re

        stats = {
            "ports_enriched": 0,
            "services_enriched": 0,
            "technologies_created": 0,
            "nse_vulns_created": 0,
            "cves_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        nmap_data = recon_data.get("nmap_scan", {})
        if not nmap_data:
            return stats

        with self.driver.session() as session:

            # 1. Enrich Port and Service nodes with Nmap version data
            for host, host_info in nmap_data.get("by_host", {}).items():
                ip_addr = host_info.get("ip", "")
                for pd in host_info.get("port_details", []):
                    port_number = pd.get("port")
                    product = pd.get("product")
                    version = pd.get("version")
                    cpe = pd.get("cpe")
                    # AI surface recon: set by parse_nmap_xml when product/version
                    # matches the AI runtime catalogue (Ollama, vLLM, LiteLLM, …)
                    ai_runtime_version = pd.get("ai_runtime_version")

                    if not port_number or not ip_addr:
                        continue

                    try:
                        # Enrich Port node
                        session.run(
                            """
                            MATCH (p:Port {number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            SET p.product = $product,
                                p.version = $version,
                                p.cpe = $cpe,
                                p.nmap_scanned = true,
                                p.updated_at = datetime(),
                                p.first_seen = coalesce(p.first_seen, datetime($recon_job_started_at)),
                                p.first_seen_job_id = coalesce(p.first_seen_job_id, $recon_job_id),
                                p.last_seen = datetime($recon_job_started_at),
                                p.last_seen_job_id = $recon_job_id
                            """,
                            port_number=port_number, ip_addr=ip_addr,
                            product=product, version=version, cpe=cpe,
                            user_id=user_id, project_id=project_id,
                            **self._recon_job_params(),
                        )
                        stats["ports_enriched"] += 1

                        # Enrich Service node
                        if product:
                            session.run(
                                """
                                MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET svc.product = $product,
                                    svc.version = $version,
                                    svc.cpe = $cpe,
                                    svc.updated_at = datetime(),
                                    svc.first_seen = coalesce(svc.first_seen, datetime($recon_job_started_at)),
                                    svc.first_seen_job_id = coalesce(svc.first_seen_job_id, $recon_job_id),
                                    svc.last_seen = datetime($recon_job_started_at),
                                    svc.last_seen_job_id = $recon_job_id
                                """,
                                port_number=port_number, ip_addr=ip_addr,
                                product=product, version=version, cpe=cpe,
                                user_id=user_id, project_id=project_id,
                                **self._recon_job_params(),
                            )
                            stats["services_enriched"] += 1

                        # AI surface recon: promote ai_runtime_version onto the Service
                        # so downstream CVE lookups can join against AI library CVE clusters.
                        if ai_runtime_version:
                            session.run(
                                """
                                MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET svc.ai_runtime_version = $ai_runtime_version,
                                    svc.updated_at = datetime(),
                                    svc.first_seen = coalesce(svc.first_seen, datetime($recon_job_started_at)),
                                    svc.first_seen_job_id = coalesce(svc.first_seen_job_id, $recon_job_id),
                                    svc.last_seen = datetime($recon_job_started_at),
                                    svc.last_seen_job_id = $recon_job_id
                                """,
                                port_number=port_number, ip_addr=ip_addr,
                                ai_runtime_version=ai_runtime_version,
                                user_id=user_id, project_id=project_id,
                                **self._recon_job_params(),
                            )
                            stats.setdefault("ai_runtime_versions_set", 0)
                            stats["ai_runtime_versions_set"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Port {port_number} enrich failed: {e}")

            # 2. Create Technology nodes for Nmap-detected services (for CVE lookup linkage)
            #    Link: (Service)-[:USES_TECHNOLOGY]->(Technology)
            #    Link: (Port)-[:HAS_TECHNOLOGY]->(Technology)
            for svc in nmap_data.get("services_detected", []):
                product = svc.get("product", "")
                version = svc.get("version", "")
                port_number = svc.get("port")
                if not product:
                    continue
                tech_name = f"{product}/{version}" if version else product

                # Find the IP for this service from by_host data
                svc_ip = ""
                for host_info in nmap_data.get("by_host", {}).values():
                    if any(pd.get("port") == port_number for pd in host_info.get("port_details", [])):
                        svc_ip = host_info.get("ip", "")
                        break

                try:
                    session.run(
                        """
                        MERGE (t:Technology {name: $name, user_id: $user_id, project_id: $project_id})
                        SET t.version = $version,
                            t.source = 'nmap',
                            t.cpe = $cpe,
                            t.updated_at = datetime(),
                            t.first_seen = coalesce(t.first_seen, datetime($recon_job_started_at)),
                            t.first_seen_job_id = coalesce(t.first_seen_job_id, $recon_job_id),
                            t.last_seen = datetime($recon_job_started_at),
                            t.last_seen_job_id = $recon_job_id
                        """,
                        name=tech_name, version=version or "",
                        cpe=svc.get("cpe", ""),
                        user_id=user_id, project_id=project_id,
                        **self._recon_job_params(),
                    )
                    stats["technologies_created"] += 1

                    # Link Service -> Technology
                    if svc_ip and port_number:
                        session.run(
                            """
                            MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                            MERGE (svc)-[:USES_TECHNOLOGY]->(t)
                            """,
                            port_number=port_number, ip_addr=svc_ip,
                            tech_name=tech_name,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                        # Link Port -> Technology
                        session.run(
                            """
                            MATCH (p:Port {number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                            MERGE (p)-[:HAS_TECHNOLOGY]->(t)
                            """,
                            port_number=port_number, ip_addr=svc_ip,
                            tech_name=tech_name,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Technology {tech_name} failed: {e}")

            # 3. Create Vulnerability nodes from NSE script findings
            for vuln in nmap_data.get("nse_vulns", []):
                script_id = vuln.get("script_id", "")
                ip_addr = vuln.get("host", "")
                port_number = vuln.get("port")
                output = vuln.get("output", "")
                state = vuln.get("state", "")
                cve_id = vuln.get("cve")

                if not script_id or not ip_addr:
                    continue

                try:
                    # Determine severity from NSE state
                    severity = "high" if "VULNERABLE" in state.upper() else "medium"

                    # Create Vulnerability node
                    session.run(
                        """
                        MERGE (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                        SET v.severity = $severity,
                            v.type = 'nmap_nse',
                            v.source = 'nmap_nse',
                            v.output = $output,
                            v.state = $state,
                            v.cve_id = $cve_id,
                            v.updated_at = datetime(),
                            v.first_seen = coalesce(v.first_seen, datetime($recon_job_started_at)),
                            v.first_seen_job_id = coalesce(v.first_seen_job_id, $recon_job_id),
                            v.last_seen = datetime($recon_job_started_at),
                            v.last_seen_job_id = $recon_job_id
                        """,
                        name=script_id, ip_addr=ip_addr, port_number=port_number,
                        severity=severity, output=output[:2000], state=state,
                        cve_id=cve_id,
                        user_id=user_id, project_id=project_id,
                        **self._recon_job_params(),
                    )
                    stats["nse_vulns_created"] += 1

                    # Link Vulnerability to Port
                    if port_number:
                        session.run(
                            """
                            MATCH (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                            MATCH (p:Port {number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            MERGE (v)-[:AFFECTS]->(p)
                            """,
                            name=script_id, ip_addr=ip_addr, port_number=port_number,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                    # Link Vulnerability to the Technology on that port
                    if port_number:
                        # Find the technology name for this port from services_detected
                        for svc in nmap_data.get("services_detected", []):
                            if svc.get("port") == port_number and svc.get("product"):
                                svc_product = svc["product"]
                                svc_version = svc.get("version", "")
                                svc_tech_name = f"{svc_product}/{svc_version}" if svc_version else svc_product
                                session.run(
                                    """
                                    MATCH (v:Vulnerability {name: $vuln_name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                                    MERGE (v)-[:FOUND_ON]->(t)
                                    """,
                                    vuln_name=script_id, ip_addr=ip_addr, port_number=port_number,
                                    tech_name=svc_tech_name,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1
                                break

                    # Create CVE node if NSE reported a specific CVE
                    if cve_id:
                        session.run(
                            """
                            MERGE (c:CVE {id: $cve_id, user_id: $user_id, project_id: $project_id})
                            SET c.cve_id = $cve_id,
                                c.name = $cve_id,
                                c.source = 'nmap_nse',
                                c.updated_at = datetime()
                            """,
                            cve_id=cve_id, user_id=user_id, project_id=project_id
                        )
                        stats["cves_created"] += 1

                        # Link CVE to Vulnerability
                        session.run(
                            """
                            MATCH (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                            MATCH (c:CVE {id: $cve_id, user_id: $user_id, project_id: $project_id})
                            MERGE (v)-[:HAS_CVE]->(c)
                            """,
                            name=script_id, ip_addr=ip_addr, port_number=port_number,
                            cve_id=cve_id, user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                        # Link Technology to CVE (so agent can traverse Service -> Tech -> CVE)
                        if port_number:
                            for svc in nmap_data.get("services_detected", []):
                                if svc.get("port") == port_number and svc.get("product"):
                                    svc_product = svc["product"]
                                    svc_version = svc.get("version", "")
                                    svc_tech_name = f"{svc_product}/{svc_version}" if svc_version else svc_product
                                    session.run(
                                        """
                                        MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                                        MATCH (c:CVE {id: $cve_id, user_id: $user_id, project_id: $project_id})
                                        MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                        """,
                                        tech_name=svc_tech_name, cve_id=cve_id,
                                        user_id=user_id, project_id=project_id
                                    )
                                    stats["relationships_created"] += 1
                                    break

                except Exception as e:
                    stats["errors"].append(f"NSE vuln {script_id} failed: {e}")

        print(f"[+][graph-db] Nmap Graph Update Summary:")
        print(f"[+][graph-db] Enriched {stats['ports_enriched']} Port nodes with version data")
        print(f"[+][graph-db] Enriched {stats['services_enriched']} Service nodes")
        print(f"[+][graph-db] Created {stats['technologies_created']} Technology nodes")
        print(f"[+][graph-db] Created {stats['nse_vulns_created']} NSE Vulnerability nodes")
        print(f"[+][graph-db] Created {stats['cves_created']} CVE nodes")
        print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

        if stats["errors"]:
            print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats
