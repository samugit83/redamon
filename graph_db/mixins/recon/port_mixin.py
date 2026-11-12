"""Port and service scan graph updates.

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address
from graph_db.mixins.recon.scope import org_for_scan_root
from graph_db.technology_identity import resolve_tech_name, resolve_tech_version


def _matched(result) -> int:
    """The `matched` count a MATCH ... RETURN count(...) AS matched query returned."""
    try:
        record = result.single()
        return int(record["matched"]) if record is not None else 0
    except Exception:  # noqa: BLE001
        return 0


def _nmap_service_on(services: list, ip_addr: str, port_number):
    """The nmap-detected service on this IP's port, or None.

    An entry without an `ip` (written before nmap recorded one) matches on the
    port alone, as it always did.
    """
    for svc in services:
        if svc.get("port") != port_number or not svc.get("product"):
            continue
        if svc.get("ip") and svc["ip"] != ip_addr:
            continue
        return svc
    return None


#: The `source` of a Port a passive provider reported from its own crawl. A
#: Port an active scan found carries no source (naabu, masscan) or `nmap`.
PASSIVE_PORT_SOURCES = ("shodan", "internetdb", "censys", "fofa", "netlas", "zoomeye",
                        "criminalip", "uncover")


class PortMixin:
    def active_open_ports(self, user_id: str, project_id: str, ips) -> dict:
        """{ip: {port, ...}}: the open ports an active scan found on these IPs.

        `passive_only = false` is an active writer's mark; a Port written before
        that mark existed counts as active unless a passive provider created it.
        """
        ips = sorted({ip for ip in ips or () if ip})
        if not ips:
            return {}
        passive = ", ".join(f"'{s}'" for s in PASSIVE_PORT_SOURCES)
        out: dict = {}
        with self.driver.session() as session:
            for record in session.run(
                f"""
                MATCH (i:IP {{user_id: $uid, project_id: $pid}})-[:HAS_PORT]->(p:Port)
                WHERE i.address IN $ips
                  AND toLower(coalesce(p.state, 'open')) = 'open'
                  AND (p.passive_only = false
                       OR (p.passive_only IS NULL
                           AND NOT toLower(coalesce(p.source, '')) IN [{passive}]))
                RETURN i.address AS ip, collect(DISTINCT p.number) AS ports
                """,
                uid=user_id, pid=project_id, ips=ips,
            ):
                out[record["ip"]] = {int(n) for n in record["ports"] or [] if n is not None}
        return out

    def update_graph_from_port_scan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with port scan data.

        This function creates/updates:
        - Port nodes with open ports
        - Service nodes for detected services
        - Updates IP nodes with CDN information
        - Relationships: IP -[:HAS_PORT]-> Port, Port -[:RUNS_SERVICE]-> Service

        It never lowers what it did not measure (D5). A full run clears the
        assets first, so there it sets exactly what the scanner reported; a
        partial run, or a later write in the same run, lands on nodes other
        tools already tagged. So IP.is_cdn only ever goes up and the first
        cdn_name stays, and Port.passive_only goes false only for a port the
        caller saw itself: a port detail that carries a passive_only other
        than false (port data rebuilt from the graph: true, or null on a Port
        from before the mark) is none. A detail's own `ip` names the address
        the port is on, for a host whose addresses have different ports.

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
                    # A bool, never None: `false OR null` is null, which would drop a stored true.
                    is_cdn = bool(ip_info.get("is_cdn"))

                    session.run(
                        """
                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        SET i.is_cdn = coalesce(i.is_cdn, false) OR $is_cdn,
                            i.cdn_name = coalesce(i.cdn_name, $cdn_name),
                            i.updated_at = datetime()
                        """,
                        address=ip_addr, user_id=user_id, project_id=project_id,
                        is_cdn=is_cdn, cdn_name=cdn_name
                    )
                    stats["ips_updated"] += 1

                except Exception as e:
                    stats["errors"].append(f"IP {ip_addr} update failed: {e}")

            # Process by_host data - this gives us hostname -> port details with services
            for hostname, host_info in by_host.items():
                host_ip = host_info.get("ip")
                port_details = host_info.get("port_details", [])
                cdn_name = host_info.get("cdn")
                is_cdn = bool(host_info.get("is_cdn"))

                # Update IP node with CDN info (if not already done)
                if host_ip:
                    try:
                        session.run(
                            """
                            MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            SET i.is_cdn = coalesce(i.is_cdn, false) OR $is_cdn,
                                i.cdn_name = coalesce(i.cdn_name, $cdn_name),
                                i.updated_at = datetime()
                            """,
                            address=host_ip, user_id=user_id, project_id=project_id,
                            is_cdn=is_cdn, cdn_name=cdn_name
                        )
                    except Exception as e:
                        stats["errors"].append(f"IP {host_ip} update failed: {e}")

                # Create Port and Service nodes
                for port_info in port_details:
                    port_number = port_info.get("port")
                    protocol = port_info.get("protocol", "tcp")
                    service_name = port_info.get("service")
                    ip_addr = port_info.get("ip") or host_ip
                    active = port_info.get("passive_only", False) is False

                    if not port_number:
                        continue

                    try:
                        # Create Port node linked to IP
                        # Port uniqueness is per IP + port + protocol + tenant
                        session.run(
                            """
                            MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            SET p.state = 'open',
                                p.updated_at = datetime()
                            WITH p WHERE $active
                            SET p.passive_only = false
                            """,
                            port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                            active=active, user_id=user_id, project_id=project_id
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
                                SET svc.updated_at = datetime()
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=ip_addr,
                                user_id=user_id, project_id=project_id
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
                                # MERGE on the version too: a MERGE without it creates
                                # a NULL-version node the uniqueness constraint ignores.
                                ai_name = resolve_tech_name(session, ai_name, user_id, project_id)
                                ai_version = resolve_tech_version(
                                    session, ai_name, "", user_id, project_id)
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                    SET t.category = $category,
                                        t.source = 'ai-port-catalog',
                                        t.updated_at = datetime()
                                    """,
                                    name=ai_name, version=ai_version, category=ai_category,
                                    user_id=user_id, project_id=project_id,
                                )
                                stats.setdefault("ai_technologies_created", 0)
                                stats["ai_technologies_created"] += 1

                                # Link Port -> Technology
                                session.run(
                                    """
                                    MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                    MATCH (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                    MERGE (p)-[r:HAS_TECHNOLOGY]->(t)
                                    SET r.detected_by = $detected_by
                                    """,
                                    port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                                    name=ai_name, version=ai_version, detected_by=ai_detected_by,
                                    user_id=user_id, project_id=project_id,
                                )
                                # Link Service -> Technology when we have a Service
                                if service_name:
                                    session.run(
                                        """
                                        MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                        MATCH (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                                        MERGE (svc)-[r:USES_TECHNOLOGY]->(t)
                                        SET r.detected_by = $detected_by
                                        """,
                                        service_name=service_name, port_number=port_number, ip_addr=ip_addr,
                                        name=ai_name, version=ai_version, detected_by=ai_detected_by,
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
            # The flat per-tool stamp goes on the org Domain (§4.11.3): a scan
            # root below its org has no Domain node of its own.
            if root_domain:
                root_domain = metadata.get("org_domain") or org_for_scan_root(root_domain, recon_data)

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.port_scan_timestamp = $scan_timestamp,
                            d.port_scan_type = $scan_type,
                            d.port_scan_ports_config = $ports_config,
                            d.port_scan_total_open_ports = $total_open_ports,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        scan_type=scan_metadata.get("scan_type"),
                        ports_config=scan_metadata.get("ports_config"),
                        total_open_ports=port_scan_data.get("summary", {}).get("total_open_ports", 0)
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
        - Creates Port (and Service) nodes for nmap_scan.new_open_ports, the open
          ports nmap confirmed that the port scan did not report
        - Enriches existing Port nodes with product, version, CPE from Nmap -sV,
          and takes passive_only to false on each (nmap found it open)
        - Updates existing Service nodes with version info
        - Creates Vulnerability nodes from NSE script findings: a port script's
          AFFECTS its Port, a host script's (host_level, port 0) hangs off its
          existing IP via HAS_VULNERABILITY
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

            # 0. Open ports nmap confirmed that the port scan missed have no Port
            #    node yet; create them the way update_graph_from_port_scan does,
            #    so step 1 enriches them like every other port.
            for added in nmap_data.get("new_open_ports", []):
                ip_addr = added.get("ip")
                port_number = added.get("port")
                protocol = added.get("protocol") or "tcp"
                service_name = added.get("service")
                if not ip_addr or not port_number:
                    continue
                try:
                    session.run(
                        """
                        MERGE (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                        SET i.updated_at = datetime()
                        MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                        ON CREATE SET p.source = 'nmap'
                        SET p.state = 'open',
                            p.passive_only = false,
                            p.updated_at = datetime()
                        MERGE (i)-[:HAS_PORT]->(p)
                        """,
                        ip_addr=ip_addr, port_number=port_number, protocol=protocol,
                        user_id=user_id, project_id=project_id
                    )
                    stats.setdefault("ports_created", 0)
                    stats["ports_created"] += 1
                    stats["relationships_created"] += 1

                    if service_name:
                        session.run(
                            """
                            MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            SET svc.updated_at = datetime()
                            MERGE (p)-[:RUNS_SERVICE]->(svc)
                            """,
                            port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                            service_name=service_name, user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Port {port_number}/{protocol} on {ip_addr} create failed: {e}")

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
                        # nmap lists only the ports it found open on this
                        # address, so a passive provider's Port here is now an
                        # active hit; a Port of the other protocol is not.
                        port_result = session.run(
                            """
                            MATCH (p:Port {number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            SET p.product = $product,
                                p.version = $version,
                                p.cpe = $cpe,
                                p.nmap_scanned = true,
                                p.passive_only = CASE WHEN p.protocol = $protocol THEN false ELSE p.passive_only END,
                                p.updated_at = datetime()
                            RETURN count(p) AS matched
                            """,
                            port_number=port_number, ip_addr=ip_addr,
                            protocol=pd.get("protocol") or "tcp",
                            product=product, version=version, cpe=cpe,
                            user_id=user_id, project_id=project_id
                        )
                        if _matched(port_result):
                            stats["ports_enriched"] += 1

                        # Enrich Service node
                        if product:
                            service_result = session.run(
                                """
                                MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET svc.product = $product,
                                    svc.version = $version,
                                    svc.cpe = $cpe,
                                    svc.updated_at = datetime()
                                RETURN count(svc) AS matched
                                """,
                                port_number=port_number, ip_addr=ip_addr,
                                product=product, version=version, cpe=cpe,
                                user_id=user_id, project_id=project_id
                            )
                            if _matched(service_result):
                                stats["services_enriched"] += 1

                        # AI surface recon: promote ai_runtime_version onto the Service
                        # so downstream CVE lookups can join against AI library CVE clusters.
                        if ai_runtime_version:
                            session.run(
                                """
                                MATCH (svc:Service {port_number: $port_number, ip_address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                SET svc.ai_runtime_version = $ai_runtime_version,
                                    svc.updated_at = datetime()
                                """,
                                port_number=port_number, ip_addr=ip_addr,
                                ai_runtime_version=ai_runtime_version,
                                user_id=user_id, project_id=project_id,
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

                svc_ip = svc.get("ip") or ""
                if not svc_ip:
                    # An entry without its IP: the first host with this port open.
                    for host_info in nmap_data.get("by_host", {}).values():
                        if any(pd.get("port") == port_number for pd in host_info.get("port_details", [])):
                            svc_ip = host_info.get("ip", "")
                            break

                try:
                    tech_name = resolve_tech_name(session, tech_name, user_id, project_id)
                    session.run(
                        """
                        MERGE (t:Technology {name: $name, version: $version, user_id: $user_id, project_id: $project_id})
                        SET t.source = 'nmap',
                            t.cpe = $cpe,
                            t.updated_at = datetime()
                        """,
                        name=tech_name, version=version or "",
                        cpe=svc.get("cpe", ""),
                        user_id=user_id, project_id=project_id
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
                ip_addr = vuln.get("ip") or vuln.get("host", "")
                # A host-rule script (<hostscript>) is about the host, not a
                # port: 0 is its port key, since a null port_number fails the MERGE.
                host_level = bool(vuln.get("host_level"))
                port_number = 0 if host_level else vuln.get("port")
                output = vuln.get("output", "")
                state = vuln.get("state", "")
                cve_id = vuln.get("cve")

                if not script_id or not ip_addr:
                    continue

                try:
                    # Determine severity from NSE state
                    severity = "high" if "VULNERABLE" in state.upper() else "medium"

                    # K6: nmap_nse findings had NO `id`, so triage could never
                    # address one: it could not be muted, given a verdict, or
                    # linked to a remediation. The natural key is what the MERGE
                    # already uses, hashed so the id is short and stable (port 0
                    # for a host-level finding).
                    nse_id = "nse-" + hashlib.sha1(
                        f"{script_id}|{ip_addr}|{port_number}".encode()
                    ).hexdigest()[:16]

                    # Create Vulnerability node
                    session.run(
                        """
                        MERGE (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                        SET v.id = COALESCE(v.id, $nse_id),
                            v.severity = $severity,
                            v.type = 'nmap_nse',
                            v.source = 'nmap_nse',
                            v.output = $output,
                            v.state = $state,
                            v.cve_id = $cve_id,
                            // C2: the scorer reads `cve_ids`; nmap_nse stored
                            // only `cve_id`, so its CVEs were invisible to it.
                            v.cve_ids = CASE WHEN $cve_id IS NULL OR $cve_id = ''
                                             THEN coalesce(v.cve_ids, [])
                                             ELSE [$cve_id] END,
                            // null on a port finding, so it stays absent there
                            v.host_level = $host_level,
                            v.updated_at = datetime()
                        """,
                        name=script_id, ip_addr=ip_addr, port_number=port_number,
                        severity=severity, output=output[:2000], state=state,
                        cve_id=cve_id, nse_id=nse_id, host_level=True if host_level else None,
                        user_id=user_id, project_id=project_id
                    )
                    stats["nse_vulns_created"] += 1

                    if host_level:
                        # MATCH, never MERGE: nmap scans only IPs the graph
                        # already holds, and its output must not invent one.
                        ip_link = session.run(
                            """
                            MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                            MERGE (i)-[:HAS_VULNERABILITY]->(v)
                            RETURN count(v) AS matched
                            """,
                            name=script_id, ip_addr=ip_addr, port_number=port_number,
                            user_id=user_id, project_id=project_id
                        )
                        if _matched(ip_link):
                            stats["relationships_created"] += 1
                            stats["host_level_links"] = stats.get("host_level_links", 0) + 1

                    # Link Vulnerability to Port
                    elif port_number:
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

                    # The Technology nmap detected on this finding's own IP and port
                    svc = (_nmap_service_on(nmap_data.get("services_detected", []), ip_addr, port_number)
                           if port_number else None)
                    svc_tech_name = ""
                    if svc:
                        svc_version = svc.get("version", "")
                        svc_tech_name = f"{svc['product']}/{svc_version}" if svc_version else svc["product"]

                    # Link Vulnerability to the Technology on that port
                    if svc_tech_name:
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

                    # Create CVE node if NSE reported a specific CVE
                    if cve_id:
                        session.run(
                            """
                            // CVE is a GLOBAL reference node: `cve_unique`
                            // requires id to be unique across the database, so
                            // keying the MERGE on the tenant triple collided
                            // with any CVE another scan had already created and
                            // threw ConstraintValidationFailed. The exception
                            // landed in stats["errors"], so the CVE and both of
                            // its links were dropped with nothing on screen.
                            MERGE (c:CVE {id: $cve_id})
                            ON CREATE SET c.cve_id = $cve_id,
                                          c.name = $cve_id,
                                          c.source = 'nmap_nse'
                            SET c.updated_at = datetime()
                            """,
                            cve_id=cve_id
                        )
                        stats["cves_created"] += 1

                        # Link CVE to Vulnerability
                        session.run(
                            """
                            MATCH (v:Vulnerability {name: $name, ip_address: $ip_addr, port_number: $port_number, user_id: $user_id, project_id: $project_id})
                            MATCH (c:CVE {id: $cve_id})
                            MERGE (v)-[:HAS_CVE]->(c)
                            """,
                            name=script_id, ip_addr=ip_addr, port_number=port_number,
                            cve_id=cve_id, user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                        # Link Technology to CVE (so agent can traverse Service -> Tech -> CVE)
                        if svc_tech_name:
                            session.run(
                                """
                                MATCH (t:Technology {name: $tech_name, user_id: $user_id, project_id: $project_id})
                                MATCH (c:CVE {id: $cve_id})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                """,
                                tech_name=svc_tech_name, cve_id=cve_id,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"NSE vuln {script_id} failed: {e}")

        print(f"[+][graph-db] Nmap Graph Update Summary:")
        if stats.get("ports_created"):
            print(f"[+][graph-db] Created {stats['ports_created']} Port nodes for open ports only nmap found")
        print(f"[+][graph-db] Enriched {stats['ports_enriched']} Port nodes with version data")
        print(f"[+][graph-db] Enriched {stats['services_enriched']} Service nodes")
        print(f"[+][graph-db] Created {stats['technologies_created']} Technology nodes")
        print(f"[+][graph-db] Created {stats['nse_vulns_created']} NSE Vulnerability nodes")
        if stats.get("host_level_links"):
            print(f"[+][graph-db] Linked {stats['host_level_links']} host-level NSE findings to their IP")
        print(f"[+][graph-db] Created {stats['cves_created']} CVE nodes")
        print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

        if stats["errors"]:
            print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats
