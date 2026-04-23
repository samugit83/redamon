"""
GvmMixin: GVM (Greenbone Vulnerability Manager) scan data graph operations.

Provides methods to ingest GVM scan results:
- _extract_gvm_technologies: parse CPE/technology data from GVM hosts
- _merge_gvm_technology: upsert Technology nodes from GVM CPE data
- _parse_traceroute: static helper to parse traceroute hop data
- update_graph_from_gvm_scan: main GVM scan ingestion pipeline
"""

import re
from datetime import datetime

from graph_db.cpe_resolver import _resolve_cpe_to_display_name, _parse_cpe_string, _CPE_SKIP_LIST


class GvmMixin:
    def _extract_gvm_technologies(self, raw_data: dict, scan: dict) -> list:
        """
        Extract technology detections from GVM host details.

        Parses 'App', 'OS', 'OS-Detection', and 'best_os_cpe' entries from
        raw_data.report.host.detail, resolves CPE strings to display names,
        and maps CPEs to ports.

        Returns list of dicts with keys: name, version, cpe, cpe_vendor,
        cpe_product, port, protocol, categories, target_ip.
        """
        technologies = []

        report = raw_data.get("report", {})
        host_data = report.get("host", {})

        # Handle both single host (dict) and multiple hosts (list)
        hosts = [host_data] if isinstance(host_data, dict) else (
            host_data if isinstance(host_data, list) else []
        )

        for host in hosts:
            host_ip = host.get("ip", "") or scan.get("target_ip", "")
            details = host.get("detail", [])
            if isinstance(details, dict):
                details = [details]
            if not details:
                continue

            # Pass 1: Build CPE-to-port map
            cpe_port_map = {}
            for detail in details:
                name = detail.get("name", "")
                value = detail.get("value", "")
                if name.startswith("cpe:/") or name.startswith("cpe:2.3:"):
                    cpe_port_map[name] = value

            # Pass 2: Extract App and OS CPE entries
            seen_cpes = set()
            capture_names = {"App", "OS", "OS-Detection", "best_os_cpe"}

            for detail in details:
                name = detail.get("name", "")
                value = detail.get("value", "")

                if name not in capture_names:
                    continue
                if not value.startswith("cpe:/") and not value.startswith("cpe:2.3:"):
                    continue
                if value in seen_cpes:
                    continue
                seen_cpes.add(value)

                parsed = _parse_cpe_string(value)
                if not parsed:
                    continue

                vendor = parsed["vendor"]
                product = parsed["product"]
                cpe_version = parsed["version"]
                part = parsed["part"]  # "a" for app, "o" for OS

                # Skip protocol-level CPEs
                if (vendor, product) in _CPE_SKIP_LIST:
                    continue

                # Resolve to display name
                display_name = _resolve_cpe_to_display_name(vendor, product)

                # Look up port from CPE-to-port map
                port_str = cpe_port_map.get(value, "")
                port_number = None
                port_protocol = None
                if "/" in port_str:
                    port_part, proto_part = port_str.split("/", 1)
                    if port_part.isdigit():
                        port_number = int(port_part)
                        port_protocol = proto_part

                # Categorize
                categories = ["Operating systems"] if part == "o" else []

                technologies.append({
                    "name": display_name,
                    "version": cpe_version,
                    "cpe": value,
                    "cpe_vendor": vendor,
                    "cpe_product": product,
                    "port": port_number,
                    "protocol": port_protocol,
                    "categories": categories,
                    "target_ip": host_ip,
                })

        return technologies

    def _merge_gvm_technology(self, session, tech: dict, user_id: str, project_id: str, stats: dict):
        """
        Merge a GVM-detected technology into the graph.

        Uses the same MERGE key as the recon pipeline ({name, version} or {name})
        to avoid duplicates. Enriches existing nodes with CPE data.

        Port-specific technologies (e.g. Apache on 8080, OpenSSH on 22):
            Port -[:USES_TECHNOLOGY {detected_by: 'gvm'}]-> Technology
        OS / general technologies (e.g. Ubuntu, Linux — no specific port):
            IP -[:USES_TECHNOLOGY {detected_by: 'gvm'}]-> Technology
        """
        name = tech["name"]
        version = tech["version"]
        cpe = tech["cpe"]
        target_ip = tech["target_ip"]
        port = tech.get("port")          # int or None
        protocol = tech.get("protocol")  # str or None

        tech_props = {
            "name": name,
            "user_id": user_id,
            "project_id": project_id,
            "cpe": cpe,
            "cpe_vendor": tech.get("cpe_vendor"),
            "cpe_product": tech.get("cpe_product"),
        }
        if tech.get("categories"):
            tech_props["categories"] = tech["categories"]

        # Remove None values
        tech_props = {k: v for k, v in tech_props.items() if v is not None}

        # Step 1: MERGE the Technology node (tenant-scoped)
        if version:
            session.run(
                """
                MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                ON CREATE SET t += $props,
                              t.detected_by = 'gvm',
                              t.confidence = 100,
                              t.updated_at = datetime()
                ON MATCH SET  t.cpe = $cpe,
                              t.cpe_vendor = $cpe_vendor,
                              t.cpe_product = $cpe_product,
                              t.detected_by = CASE
                                  WHEN t.detected_by IS NULL THEN 'gvm'
                                  WHEN t.detected_by CONTAINS 'gvm' THEN t.detected_by
                                  ELSE t.detected_by + ',gvm'
                              END,
                              t.updated_at = datetime()
                """,
                name=name, version=version, props=tech_props,
                cpe=cpe,
                cpe_vendor=tech.get("cpe_vendor"),
                cpe_product=tech.get("cpe_product"),
                user_id=user_id, project_id=project_id,
            )
        else:
            session.run(
                """
                MERGE (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                ON CREATE SET t += $props,
                              t.detected_by = 'gvm',
                              t.confidence = 100,
                              t.updated_at = datetime()
                ON MATCH SET  t.cpe = COALESCE($cpe, t.cpe),
                              t.cpe_vendor = COALESCE($cpe_vendor, t.cpe_vendor),
                              t.cpe_product = COALESCE($cpe_product, t.cpe_product),
                              t.detected_by = CASE
                                  WHEN t.detected_by IS NULL THEN 'gvm'
                                  WHEN t.detected_by CONTAINS 'gvm' THEN t.detected_by
                                  ELSE t.detected_by + ',gvm'
                              END,
                              t.updated_at = datetime()
                """,
                name=name, props=tech_props,
                cpe=cpe,
                cpe_vendor=tech.get("cpe_vendor"),
                cpe_product=tech.get("cpe_product"),
                user_id=user_id, project_id=project_id,
            )
        stats["technologies_created"] += 1

        # Step 2: Create relationship based on whether we have a port
        if not target_ip:
            return

        is_os = "Operating systems" in (tech.get("categories") or [])

        if port is not None and not is_os:
            # PORT-SPECIFIC technology: chain through Port node
            effective_protocol = protocol or "tcp"

            # MERGE Port node (may already exist from recon port_scan)
            session.run(
                """
                MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                SET p.state = 'open',
                    p.updated_at = datetime()
                """,
                port_number=port, protocol=effective_protocol, ip_addr=target_ip,
                user_id=user_id, project_id=project_id,
            )
            stats["ports_created"] += 1

            # MERGE IP -[:HAS_PORT]-> Port (in case recon didn't create it)
            session.run(
                """
                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                MERGE (i)-[:HAS_PORT]->(p)
                """,
                ip=target_ip, user_id=user_id, project_id=project_id,
                port_number=port, protocol=effective_protocol,
            )

            # MERGE Port -[:USES_TECHNOLOGY]-> Technology
            if version:
                session.run(
                    """
                    MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                    MATCH (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                    MERGE (p)-[r:USES_TECHNOLOGY]->(t)
                    SET r.detected_by = 'gvm'
                    """,
                    port_number=port, protocol=effective_protocol, ip=target_ip,
                    name=name, version=version,
                    user_id=user_id, project_id=project_id,
                )
            else:
                session.run(
                    """
                    MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                    MATCH (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                    MERGE (p)-[r:USES_TECHNOLOGY]->(t)
                    SET r.detected_by = 'gvm'
                    """,
                    port_number=port, protocol=effective_protocol, ip=target_ip,
                    name=name,
                    user_id=user_id, project_id=project_id,
                )
            stats["relationships_created"] += 1
        else:
            # OS / GENERAL technology (no port, or OS category): link to IP directly
            rel_props = {"detected_by": "gvm"}

            if version:
                session.run(
                    """
                    MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                    MATCH (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                    MERGE (i)-[r:USES_TECHNOLOGY]->(t)
                    SET r += $rel_props
                    """,
                    ip=target_ip, user_id=user_id, project_id=project_id,
                    name=name, version=version, rel_props=rel_props,
                )
            else:
                session.run(
                    """
                    MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                    MATCH (t:Technology {name: $name, version: '', user_id: $user_id, project_id: $project_id})
                    MERGE (i)-[r:USES_TECHNOLOGY]->(t)
                    SET r += $rel_props
                    """,
                    ip=target_ip, user_id=user_id, project_id=project_id,
                    name=name, rel_props=rel_props,
                )
            stats["relationships_created"] += 1

    @staticmethod
    def _parse_traceroute(description: str) -> dict:
        """
        Parse a GVM Traceroute description into structured data.

        Expected format:
            Network route from scanner (172.20.0.4) to target (15.160.68.117):

            172.20.0.4
            192.168.1.1
            ...
            15.160.68.117

            Network distance between scanner and target: 7
        """

        result = {"scanner_ip": "", "target_ip": "", "hops": [], "distance": 0}

        # Extract scanner and target IPs from header line
        header_match = re.search(
            r"Network route from scanner \(([^)]+)\) to target \(([^)]+)\)", description
        )
        if header_match:
            result["scanner_ip"] = header_match.group(1)
            result["target_ip"] = header_match.group(2)

        # Extract distance from footer line
        dist_match = re.search(r"Network distance between scanner and target:\s*(\d+)", description)
        if dist_match:
            result["distance"] = int(dist_match.group(1))

        # Extract hop IPs (lines that look like IP addresses)
        ip_pattern = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$", re.MULTILINE)
        result["hops"] = ip_pattern.findall(description)

        return result

    def update_graph_from_gvm_scan(self, gvm_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with GVM/OpenVAS vulnerability scan data.

        This function creates/updates:
        - Technology nodes (from GVM product/service/OS detections via CPE)
        - Port nodes (MERGE'd for port-specific technologies)
        - Vulnerability nodes (from GVM findings with source="gvm")
        - Traceroute nodes (from log-level Traceroute findings)

        Relationships (preferred chain):
        - Port -[:USES_TECHNOLOGY {detected_by: 'gvm'}]-> Technology
        - Technology -[:HAS_VULNERABILITY]-> Vulnerability

        Fallback relationships:
        - IP -[:USES_TECHNOLOGY]-> Technology (for OS-level tech with no port)
        - Port -[:HAS_VULNERABILITY]-> Vulnerability (port with no tech detected)
        - IP -[:HAS_VULNERABILITY]-> Vulnerability (no port, no tech)
        - Subdomain -[:HAS_VULNERABILITY]-> Vulnerability (always, for subdomain context)

        Args:
            gvm_data: The GVM scan JSON data
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "vulnerabilities_created": 0,
            "cves_linked": 0,
            "ips_linked": 0,
            "subdomains_linked": 0,
            "technologies_linked": 0,
            "ports_created": 0,
            "mitre_nodes": 0,
            "capec_nodes": 0,
            "technologies_created": 0,
            "traceroutes_created": 0,
            "exploits_gvm_created": 0,
            "cisa_kev_count": 0,
            "closed_cves_processed": 0,
            "certificates_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        metadata = gvm_data.get("metadata", {})
        scans = gvm_data.get("scans", [])

        if not scans:
            stats["errors"].append("No scans found in GVM data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_timestamp = metadata.get("scan_timestamp", "")
            target_domain = metadata.get("target_domain", "")

            # Process each scan
            for scan in scans:
                # Extract and merge technology detections FIRST
                # (so vulnerability linking can find Technology nodes)
                raw_data = scan.get("raw_data", {})
                gvm_technologies = self._extract_gvm_technologies(raw_data, scan)
                for tech in gvm_technologies:
                    try:
                        self._merge_gvm_technology(session, tech, user_id, project_id, stats)
                    except Exception as e:
                        stats["errors"].append(f"GVM technology {tech.get('name')} failed: {e}")

                vulnerabilities = scan.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    try:
                        # Skip log-level findings (informational only)
                        severity_class = vuln.get("severity_class", "log")
                        if severity_class == "log":
                            continue

                        # Extract data from vulnerability
                        nvt = vuln.get("nvt", {})
                        host_data = vuln.get("host", {})
                        qod_data = vuln.get("qod", {})

                        # Get target IP and hostname
                        target_ip = host_data.get("#text", "")
                        target_hostname = host_data.get("hostname", "")

                        # Parse port info (format: "80/tcp" or "general/tcp")
                        port_str = vuln.get("port", "")
                        target_port = None
                        port_protocol = None
                        if "/" in port_str:
                            port_part, protocol_part = port_str.split("/", 1)
                            if port_part.isdigit():
                                target_port = int(port_part)
                            port_protocol = protocol_part

                        # Get OID for unique identification
                        oid = nvt.get("@oid", "")

                        # Generate unique vulnerability ID
                        vuln_id = f"gvm-{oid}-{target_ip}-{target_port or 'general'}"

                        # Extract severity info
                        severities = nvt.get("severities", {})
                        severity_info = severities.get("severity", {})
                        cvss_vector = severity_info.get("value", "")
                        cvss_score = vuln.get("severity_float", 0.0)

                        # Extract solution info
                        solution_data = nvt.get("solution", {})
                        solution_text = solution_data.get("#text", "") if isinstance(solution_data, dict) else ""
                        solution_type = solution_data.get("@type", "") if isinstance(solution_data, dict) else ""

                        # Extract CVE IDs and CISA KEV flag from refs
                        cve_ids = vuln.get("cves_extracted", [])
                        cisa_kev = False
                        refs = nvt.get("refs", {})
                        if refs:
                            ref_list = refs.get("ref", [])
                            if isinstance(ref_list, dict):
                                ref_list = [ref_list]
                            for ref in ref_list:
                                if ref.get("@type") == "cve":
                                    cve_id = ref.get("@id", "")
                                    if cve_id and cve_id not in cve_ids:
                                        cve_ids.append(cve_id)
                                elif ref.get("@type") == "cisa":
                                    cisa_kev = True

                        # Check QoD — if 100, this is a confirmed active exploit
                        qod_value = int(qod_data.get("value", 0)) if qod_data.get("value") else 0

                        if qod_value == 100:
                            # Confirmed active exploit — create ExploitGvm node instead of Vulnerability
                            exploit_id = f"gvm-exploit-{oid}-{target_ip}-{target_port or 'general'}"

                            exploit_props = {
                                "id": exploit_id,
                                "user_id": user_id,
                                "project_id": project_id,
                                "attack_type": "cve_exploit",
                                "severity": "critical",
                                "name": nvt.get("name", vuln.get("name", "")),
                                "target_ip": target_ip,
                                "target_port": target_port,
                                "target_hostname": target_hostname,
                                "port_protocol": port_protocol,
                                "cve_ids": cve_ids,
                                "cisa_kev": cisa_kev,
                                "description": vuln.get("description", ""),
                                "evidence": vuln.get("description", ""),
                                "solution": solution_text,
                                "oid": oid,
                                "family": nvt.get("family", ""),
                                "qod": qod_value,
                                "cvss_score": cvss_score,
                                "cvss_vector": cvss_vector,
                                "source": "gvm",
                                "scanner": "OpenVAS",
                                "scan_timestamp": scan_timestamp,
                            }
                            exploit_props = {k: v for k, v in exploit_props.items() if v is not None}

                            session.run(
                                """
                                MERGE (e:ExploitGvm {id: $id})
                                SET e += $props, e.updated_at = datetime()
                                """,
                                id=exploit_id, props=exploit_props
                            )
                            stats["exploits_gvm_created"] += 1
                            if cisa_kev:
                                stats["cisa_kev_count"] += 1

                            # Link ExploitGvm → CVE (only connection)
                            # MERGE CVE node — creates it if not found from previous scan
                            for cve_id_link in cve_ids:
                                severity_label = "CRITICAL" if cvss_score >= 9.0 else "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
                                session.run(
                                    """
                                    MATCH (e:ExploitGvm {id: $exploit_id})
                                    MERGE (c:CVE {id: $cve_id})
                                    ON CREATE SET c.severity = $severity,
                                                  c.cvss = $cvss,
                                                  c.source = 'gvm',
                                                  c.user_id = $uid,
                                                  c.project_id = $pid
                                    MERGE (e)-[:EXPLOITED_CVE]->(c)
                                    """,
                                    exploit_id=exploit_id, cve_id=cve_id_link,
                                    severity=severity_label, cvss=cvss_score,
                                    uid=user_id, pid=project_id
                                )
                                stats["cves_linked"] += 1

                            continue  # Skip Vulnerability node creation

                        # Create Vulnerability node (non-exploit findings)
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "oid": oid,
                            "name": nvt.get("name", vuln.get("name", "")),
                            "severity": severity_class,
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "threat": vuln.get("threat", ""),
                            "description": vuln.get("description", ""),
                            "solution": solution_text,
                            "solution_type": solution_type,
                            "target_ip": target_ip,
                            "target_port": target_port,
                            "target_hostname": target_hostname,
                            "port_protocol": port_protocol,
                            "family": nvt.get("family", ""),
                            "qod": qod_value,
                            "qod_type": qod_data.get("type"),
                            "cve_ids": cve_ids,
                            "cisa_kev": cisa_kev,
                            "source": "gvm",
                            "scanner": "OpenVAS",
                            "scan_timestamp": scan_timestamp,
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
                        if cisa_kev:
                            stats["cisa_kev_count"] += 1

                        # Link Vulnerability to Technology (preferred) or fallback
                        vuln_linked = False

                        if target_ip and target_port is not None:
                            # TIER 1: Link via Technology on the same Port
                            effective_protocol = port_protocol or "tcp"
                            result = session.run(
                                """
                                MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                                      -[:USES_TECHNOLOGY]->(t:Technology)
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (t)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(t) as matched
                                """,
                                port=target_port, protocol=effective_protocol,
                                ip=target_ip, vuln_id=vuln_id,
                                user_id=user_id, project_id=project_id,
                            )
                            record = result.single()
                            if record and record["matched"] > 0:
                                stats["technologies_linked"] += record["matched"]
                                stats["relationships_created"] += record["matched"]
                                vuln_linked = True

                        if target_ip and not vuln_linked and target_port is None:
                            # TIER 2: "general/tcp" vuln — link to OS Technology on IP
                            result = session.run(
                                """
                                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                      -[:USES_TECHNOLOGY]->(t:Technology)
                                WHERE 'Operating systems' IN t.categories
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (t)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(t) as matched
                                """,
                                ip=target_ip, user_id=user_id, project_id=project_id,
                                vuln_id=vuln_id,
                            )
                            record = result.single()
                            if record and record["matched"] > 0:
                                stats["technologies_linked"] += record["matched"]
                                stats["relationships_created"] += record["matched"]
                                vuln_linked = True

                        if target_ip and not vuln_linked and target_port is not None:
                            # TIER 3: Port exists but no Technology — link to Port
                            effective_protocol = port_protocol or "tcp"
                            result = session.run(
                                """
                                MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (p)-[:HAS_VULNERABILITY]->(v)
                                RETURN p
                                """,
                                port=target_port, protocol=effective_protocol,
                                ip=target_ip, vuln_id=vuln_id,
                                user_id=user_id, project_id=project_id,
                            )
                            if result.single():
                                stats["relationships_created"] += 1
                                vuln_linked = True

                        if target_ip and not vuln_linked:
                            # TIER 4 (FALLBACK): No Technology, no Port — link to IP
                            result = session.run(
                                """
                                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                RETURN i
                                """,
                                ip=target_ip, user_id=user_id, project_id=project_id,
                                vuln_id=vuln_id,
                            )
                            if result.single():
                                stats["ips_linked"] += 1
                                stats["relationships_created"] += 1

                        # Link to Subdomain node (if hostname matches a subdomain)
                        if target_hostname:
                            result = session.run(
                                """
                                MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MERGE (s)-[:HAS_VULNERABILITY]->(v)
                                RETURN s
                                """,
                                hostname=target_hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single():
                                stats["subdomains_linked"] += 1
                                stats["relationships_created"] += 1

                        # CVE IDs are stored as cve_ids property on the Vulnerability node
                        # No separate CVE nodes created — avoids bare CVE node clutter

                    except Exception as e:
                        stats["errors"].append(f"Vulnerability processing failed: {e}")

                # Process Traceroute from log-level findings
                for vuln in vulnerabilities:
                    try:
                        nvt = vuln.get("nvt", {})
                        if nvt.get("@oid") != "1.3.6.1.4.1.25623.1.0.51662":
                            continue

                        tr_data = self._parse_traceroute(vuln.get("description", ""))
                        if not tr_data["hops"]:
                            continue

                        target_ip = tr_data["target_ip"]

                        # MERGE Traceroute node
                        session.run(
                            """
                            MERGE (tr:Traceroute {target_ip: $target_ip, user_id: $user_id, project_id: $project_id})
                            SET tr.scanner_ip = $scanner_ip,
                                tr.hops = $hops,
                                tr.distance = $distance,
                                tr.source = 'gvm',
                                tr.scan_timestamp = $scan_timestamp,
                                tr.updated_at = datetime()
                            """,
                            target_ip=target_ip, user_id=user_id, project_id=project_id,
                            scanner_ip=tr_data["scanner_ip"],
                            hops=tr_data["hops"],
                            distance=tr_data["distance"],
                            scan_timestamp=scan_timestamp,
                        )
                        stats["traceroutes_created"] += 1

                        # Link Traceroute to IP node
                        result = session.run(
                            """
                            MATCH (i:IP {address: $target_ip, user_id: $user_id, project_id: $project_id})
                            MATCH (tr:Traceroute {target_ip: $target_ip, user_id: $user_id, project_id: $project_id})
                            MERGE (i)-[:HAS_TRACEROUTE]->(tr)
                            RETURN i
                            """,
                            target_ip=target_ip, user_id=user_id, project_id=project_id,
                        )
                        if result.single():
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Traceroute processing failed: {e}")

                # Process Closed CVEs from raw report data
                try:
                    raw_data = scan.get("raw_data", {})
                    report = raw_data.get("report", raw_data)

                    closed_cves_data = report.get("closed_cves", {})
                    closed_count = int(closed_cves_data.get("count", "0")) if closed_cves_data else 0

                    if closed_count > 0:
                        closed_list = closed_cves_data.get("closed_cve", [])
                        if isinstance(closed_list, dict):
                            closed_list = [closed_list]

                        for closed in closed_list:
                            cve_id = closed.get("cve", {}).get("@id", "")
                            if not cve_id:
                                continue

                            # Mark existing Vulnerability node as remediated
                            session.run(
                                """
                                MATCH (v:Vulnerability {user_id: $uid, project_id: $pid, source: 'gvm'})
                                WHERE $cve_id IN v.cve_ids
                                SET v.remediated = true, v.updated_at = datetime()
                                """,
                                uid=user_id, pid=project_id, cve_id=cve_id
                            )
                            stats["closed_cves_processed"] += 1

                except Exception as e:
                    stats["errors"].append(f"Closed CVEs processing failed: {e}")

                # Process TLS Certificates from raw report data
                try:
                    if not raw_data:
                        raw_data = scan.get("raw_data", {})
                        report = raw_data.get("report", raw_data)

                    tls_certs = report.get("tls_certificates")
                    if tls_certs and tls_certs.get("count", "0") != "0":
                        cert_list = tls_certs.get("tls_certificate", [])
                        if isinstance(cert_list, dict):
                            cert_list = [cert_list]

                        for cert_data in cert_list:
                            cert_name = cert_data.get("name", "")
                            if not cert_name:
                                continue

                            subject_cn = cert_name
                            issuer_dn = cert_data.get("issuer_dn", "")
                            serial = cert_data.get("serial", "")
                            sha256 = cert_data.get("sha256_fingerprint", "")
                            activation = cert_data.get("activation_time", "")
                            expiration = cert_data.get("expiration_time", "")

                            # Extract host:port binding
                            host_info = cert_data.get("host", {})
                            cert_ip = host_info.get("ip", "") if isinstance(host_info, dict) else str(host_info)

                            cert_props = {
                                "subject_cn": subject_cn,
                                "user_id": user_id,
                                "project_id": project_id,
                                "issuer": issuer_dn,
                                "serial": serial,
                                "sha256_fingerprint": sha256,
                                "not_before": activation,
                                "not_after": expiration,
                                "source": "gvm",
                                "scan_timestamp": scan_timestamp,
                            }
                            cert_props = {k: v for k, v in cert_props.items() if v}

                            session.run(
                                """
                                MERGE (c:Certificate {subject_cn: $subject_cn, user_id: $user_id, project_id: $project_id})
                                SET c += $props, c.updated_at = datetime()
                                """,
                                subject_cn=subject_cn, user_id=user_id, project_id=project_id, props=cert_props
                            )

                            # Link to IP node if available
                            if cert_ip:
                                session.run(
                                    """
                                    MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                                    MATCH (c:Certificate {subject_cn: $cn, user_id: $uid, project_id: $pid})
                                    MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                    """,
                                    ip=cert_ip, uid=user_id, pid=project_id, cn=subject_cn
                                )

                            stats["certificates_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"TLS Certificates processing failed: {e}")

            # Update Domain node with GVM scan metadata
            if target_domain:
                try:
                    summary = gvm_data.get("summary", {})
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.gvm_scan_timestamp = $scan_timestamp,
                            d.gvm_total_vulnerabilities = $total_vulns,
                            d.gvm_critical = $critical,
                            d.gvm_high = $high,
                            d.gvm_medium = $medium,
                            d.gvm_low = $low,
                            d.updated_at = datetime()
                        """,
                        root_domain=target_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_timestamp,
                        total_vulns=summary.get("total_vulnerabilities", 0),
                        critical=summary.get("critical", 0),
                        high=summary.get("high", 0),
                        medium=summary.get("medium", 0),
                        low=summary.get("low", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+][graph-db] Created/enriched {stats['technologies_created']} Technology nodes from GVM")
            print(f"[+][graph-db] Created {stats['ports_created']} Port nodes from GVM")
            print(f"[+][graph-db] Created {stats['vulnerabilities_created']} GVM Vulnerability nodes")
            print(f"[+][graph-db] Created {stats['exploits_gvm_created']} ExploitGvm nodes (confirmed active exploits)")
            print(f"[+][graph-db] Created {stats['traceroutes_created']} Traceroute nodes")
            print(f"[+][graph-db] CISA KEV flagged: {stats['cisa_kev_count']} vulnerabilities")
            print(f"[+][graph-db] Closed CVEs processed: {stats['closed_cves_processed']}")
            print(f"[+][graph-db] TLS Certificates created: {stats['certificates_created']}")
            print(f"[+][graph-db] Linked {stats['technologies_linked']} vulnerabilities to technologies")
            print(f"[+][graph-db] Linked {stats['cves_linked']} CVEs")
            print(f"[+][graph-db] Linked {stats['ips_linked']} IPs (fallback)")
            print(f"[+][graph-db] Linked {stats['subdomains_linked']} Subdomains")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats
