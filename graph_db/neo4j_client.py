"""
Neo4j Graph Database Client for RedAmon Reconnaissance Data

This client initializes the graph database with reconnaissance data
after the domain_discovery module completes.

Usage:
    from graph_db import Neo4jClient

    client = Neo4jClient()
    client.update_graph_from_domain_discovery(recon_data, user_id, project_id)
    client.close()
"""

import os
from datetime import datetime
from neo4j import GraphDatabase


class Neo4jClient:
    def __init__(self, uri=None, user=None, password=None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))

    def close(self):
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def verify_connection(self):
        """Verify the connection to Neo4j is working."""
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS test")
                return result.single()["test"] == 1
        except Exception as e:
            print(f"[!] Neo4j connection failed: {e}")
            return False

    def _init_schema(self, session):
        """Initialize constraints and indexes for the graph schema."""
        # Constraints
        constraints = [
            "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE (d.name, d.user_id, d.project_id) IS UNIQUE",
            "CREATE CONSTRAINT subdomain_unique IF NOT EXISTS FOR (s:Subdomain) REQUIRE s.name IS UNIQUE",
            "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT baseurl_unique IF NOT EXISTS FOR (u:BaseURL) REQUIRE u.url IS UNIQUE",
            "CREATE CONSTRAINT cve_unique IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT mitredata_unique IF NOT EXISTS FOR (m:MitreData) REQUIRE m.id IS UNIQUE",
            "CREATE CONSTRAINT capec_unique IF NOT EXISTS FOR (cap:Capec) REQUIRE cap.capec_id IS UNIQUE",
            "CREATE CONSTRAINT vulnerability_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
        ]

        # Tenant composite indexes
        tenant_indexes = [
            "CREATE INDEX idx_domain_tenant IF NOT EXISTS FOR (d:Domain) ON (d.user_id, d.project_id)",
            "CREATE INDEX idx_subdomain_tenant IF NOT EXISTS FOR (s:Subdomain) ON (s.user_id, s.project_id)",
            "CREATE INDEX idx_ip_tenant IF NOT EXISTS FOR (i:IP) ON (i.user_id, i.project_id)",
            "CREATE INDEX idx_port_tenant IF NOT EXISTS FOR (p:Port) ON (p.user_id, p.project_id)",
            "CREATE INDEX idx_dnsrecord_tenant IF NOT EXISTS FOR (dns:DNSRecord) ON (dns.user_id, dns.project_id)",
            "CREATE INDEX idx_baseurl_tenant IF NOT EXISTS FOR (u:BaseURL) ON (u.user_id, u.project_id)",
            "CREATE INDEX idx_technology_tenant IF NOT EXISTS FOR (t:Technology) ON (t.user_id, t.project_id)",
            "CREATE INDEX idx_header_tenant IF NOT EXISTS FOR (h:Header) ON (h.user_id, h.project_id)",
            "CREATE INDEX idx_endpoint_tenant IF NOT EXISTS FOR (e:Endpoint) ON (e.user_id, e.project_id)",
            "CREATE INDEX idx_parameter_tenant IF NOT EXISTS FOR (p:Parameter) ON (p.user_id, p.project_id)",
            "CREATE INDEX idx_vulnerability_tenant IF NOT EXISTS FOR (v:Vulnerability) ON (v.user_id, v.project_id)",
        ]

        # Additional indexes
        additional_indexes = [
            "CREATE INDEX subdomain_name IF NOT EXISTS FOR (s:Subdomain) ON (s.name)",
            "CREATE INDEX ip_address IF NOT EXISTS FOR (i:IP) ON (i.address)",
            "CREATE INDEX idx_service_tenant IF NOT EXISTS FOR (svc:Service) ON (svc.user_id, svc.project_id)",
            "CREATE INDEX tech_name IF NOT EXISTS FOR (t:Technology) ON (t.name)",
            "CREATE INDEX tech_name_version IF NOT EXISTS FOR (t:Technology) ON (t.name, t.version)",
            # Vulnerability indexes
            "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
            "CREATE INDEX vuln_category IF NOT EXISTS FOR (v:Vulnerability) ON (v.category)",
            "CREATE INDEX vuln_template IF NOT EXISTS FOR (v:Vulnerability) ON (v.template_id)",
            # Parameter indexes
            "CREATE INDEX param_injectable IF NOT EXISTS FOR (p:Parameter) ON (p.is_injectable)",
            # CVE indexes
            "CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity)",
            "CREATE INDEX cve_cvss IF NOT EXISTS FOR (c:CVE) ON (c.cvss)",
            "CREATE INDEX idx_cve_tenant IF NOT EXISTS FOR (c:CVE) ON (c.user_id, c.project_id)",
            # MitreData indexes
            "CREATE INDEX idx_mitredata_tenant IF NOT EXISTS FOR (m:MitreData) ON (m.user_id, m.project_id)",
            # Capec indexes
            "CREATE INDEX capec_id IF NOT EXISTS FOR (c:Capec) ON (c.capec_id)",
            "CREATE INDEX idx_capec_tenant IF NOT EXISTS FOR (c:Capec) ON (c.user_id, c.project_id)",
        ]

        for query in constraints + tenant_indexes + additional_indexes:
            try:
                session.run(query)
            except Exception as e:
                # Ignore if constraint/index already exists
                if "already exists" not in str(e).lower():
                    print(f"[!] Schema warning: {e}")

    def update_graph_from_domain_discovery(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Initialize the Neo4j graph database with reconnaissance data after domain_discovery.

        This function creates:
        - Domain node (root) with WHOIS data
        - Subdomain nodes
        - IP nodes
        - DNSRecord nodes
        - All relationships between them

        Args:
            recon_data: The recon JSON data from domain_discovery module
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created nodes/relationships
        """
        stats = {
            "domain_created": False,
            "subdomains_created": 0,
            "ips_created": 0,
            "dns_records_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        with self.driver.session() as session:
            # Initialize schema first
            self._init_schema(session)

            # Extract data from recon_data
            metadata = recon_data.get("metadata", {})
            whois_data = recon_data.get("whois", {})
            subdomains = recon_data.get("subdomains", [])
            dns_data = recon_data.get("dns", {})

            root_domain = metadata.get("root_domain", "")
            target = metadata.get("target", "")
            filtered_mode = metadata.get("filtered_mode", False)
            subdomain_filter = metadata.get("subdomain_filter", [])

            if not root_domain:
                stats["errors"].append("No root_domain found in metadata")
                return stats

            # 1. Create Domain node with WHOIS data
            try:
                domain_props = {
                    "name": root_domain,
                    "user_id": user_id,
                    "project_id": project_id,
                    "scan_timestamp": metadata.get("scan_timestamp"),
                    "scan_type": metadata.get("scan_type"),
                    "target": target,
                    "filtered_mode": filtered_mode,
                    "subdomain_filter": subdomain_filter,
                    "modules_executed": metadata.get("modules_executed", []),
                    "anonymous_mode": metadata.get("anonymous_mode", False),
                    "bruteforce_mode": metadata.get("bruteforce_mode", False),
                    # WHOIS data
                    "registrar": whois_data.get("registrar"),
                    "registrar_url": whois_data.get("registrar_url"),
                    "whois_server": whois_data.get("whois_server"),
                    "dnssec": whois_data.get("dnssec"),
                    "organization": whois_data.get("org"),
                    "country": whois_data.get("country"),
                    "city": whois_data.get("city"),
                    "state": whois_data.get("state"),
                    "address": whois_data.get("address"),
                    "registrant_postal_code": whois_data.get("registrant_postal_code"),
                    "registrant_name": whois_data.get("name"),
                    "admin_name": whois_data.get("admin_name"),
                    "admin_org": whois_data.get("admin_org"),
                    "tech_name": whois_data.get("tech_name"),
                    "tech_org": whois_data.get("tech_org"),
                    "domain_name": whois_data.get("domain_name"),
                    "referral_url": whois_data.get("referral_url"),
                    "reseller": whois_data.get("reseller"),
                    "name_servers": whois_data.get("name_servers", []),
                    "whois_emails": whois_data.get("emails", []),
                    "updated_at": datetime.now().isoformat()
                }

                # Handle date fields (can be list or single value)
                for date_field in ["creation_date", "expiration_date", "updated_date"]:
                    date_val = whois_data.get(date_field)
                    if isinstance(date_val, list) and date_val:
                        domain_props[date_field] = date_val[0]
                    elif date_val:
                        domain_props[date_field] = date_val

                # Handle status (can be list)
                status = whois_data.get("status", [])
                if isinstance(status, list):
                    # Clean status strings (remove URL part)
                    domain_props["status"] = [s.split()[0] if " " in s else s for s in status]
                elif status:
                    domain_props["status"] = [status.split()[0] if " " in status else status]

                # Remove None values
                domain_props = {k: v for k, v in domain_props.items() if v is not None}

                session.run(
                    """
                    MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                    SET d += $props
                    """,
                    name=root_domain, user_id=user_id, project_id=project_id, props=domain_props
                )
                stats["domain_created"] = True
                print(f"[+] Created Domain node: {root_domain}")
            except Exception as e:
                stats["errors"].append(f"Domain creation failed: {e}")
                print(f"[!] Domain creation failed: {e}")

            # 2. Create Subdomain nodes and relationships
            subdomain_dns = dns_data.get("subdomains", {})

            for subdomain in subdomains:
                try:
                    subdomain_info = subdomain_dns.get(subdomain, {})
                    has_records = subdomain_info.get("has_records", False)

                    # Create Subdomain node
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name})
                        SET s.user_id = $user_id,
                            s.project_id = $project_id,
                            s.is_target = $is_target,
                            s.has_dns_records = $has_records,
                            s.discovered_at = datetime(),
                            s.updated_at = datetime()
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                        is_target=(subdomain == target), has_records=has_records
                    )
                    stats["subdomains_created"] += 1

                    # Create relationship: Subdomain -[:BELONGS_TO]-> Domain
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                        MATCH (s:Subdomain {name: $subdomain})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        """,
                        domain=root_domain, subdomain=subdomain,
                        user_id=user_id, project_id=project_id
                    )
                    stats["relationships_created"] += 1

                    # 3. Create DNS records and IP addresses
                    records = subdomain_info.get("records", {})
                    ips_data = subdomain_info.get("ips", {})

                    # Create IP nodes from resolved IPs
                    for ip_version in ["ipv4", "ipv6"]:
                        ip_list = ips_data.get(ip_version, [])
                        for ip_addr in ip_list:
                            if ip_addr:
                                try:
                                    # Create IP node
                                    session.run(
                                        """
                                        MERGE (i:IP {address: $address})
                                        SET i.user_id = $user_id,
                                            i.project_id = $project_id,
                                            i.version = $version,
                                            i.updated_at = datetime()
                                        """,
                                        address=ip_addr, user_id=user_id, project_id=project_id,
                                        version=ip_version
                                    )
                                    stats["ips_created"] += 1

                                    # Create relationship: Subdomain -[:RESOLVES_TO]-> IP
                                    record_type = "A" if ip_version == "ipv4" else "AAAA"
                                    session.run(
                                        """
                                        MATCH (s:Subdomain {name: $subdomain})
                                        MATCH (i:IP {address: $ip})
                                        MERGE (s)-[:RESOLVES_TO {record_type: $record_type}]->(i)
                                        """,
                                        subdomain=subdomain, ip=ip_addr, record_type=record_type
                                    )
                                    stats["relationships_created"] += 1
                                except Exception as e:
                                    stats["errors"].append(f"IP {ip_addr} creation failed: {e}")

                    # Create DNSRecord nodes for other record types
                    for record_type, record_values in records.items():
                        if record_values and record_type not in ["A", "AAAA"]:  # A/AAAA handled via IP nodes
                            if not isinstance(record_values, list):
                                record_values = [record_values]

                            for value in record_values:
                                if value:
                                    try:
                                        # Create DNSRecord node
                                        session.run(
                                            """
                                            MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain})
                                            SET dns.user_id = $user_id,
                                                dns.project_id = $project_id,
                                                dns.updated_at = datetime()
                                            """,
                                            type=record_type, value=str(value), subdomain=subdomain,
                                            user_id=user_id, project_id=project_id
                                        )
                                        stats["dns_records_created"] += 1

                                        # Create relationship: Subdomain -[:HAS_DNS_RECORD]-> DNSRecord
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $subdomain})
                                            MATCH (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain})
                                            MERGE (s)-[:HAS_DNS_RECORD]->(dns)
                                            """,
                                            subdomain=subdomain, type=record_type, value=str(value)
                                        )
                                        stats["relationships_created"] += 1
                                    except Exception as e:
                                        stats["errors"].append(f"DNSRecord {record_type}={value} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain} processing failed: {e}")
                    print(f"[!] Subdomain {subdomain} processing failed: {e}")

            print(f"[+] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+] Created {stats['ips_created']} IP nodes")
            print(f"[+] Created {stats['dns_records_created']} DNSRecord nodes")
            print(f"[+] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!] {len(stats['errors'])} errors occurred")

        return stats

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
            self._init_schema(session)

            scan_metadata = port_scan_data.get("scan_metadata", {})
            by_ip = port_scan_data.get("by_ip", {})
            by_host = port_scan_data.get("by_host", {})

            # Process by_ip data - this gives us IP -> ports mapping
            for ip_addr, ip_info in by_ip.items():
                try:
                    # Update IP node with CDN info if available
                    cdn_name = ip_info.get("cdn")
                    is_cdn = ip_info.get("is_cdn", False)

                    session.run(
                        """
                        MERGE (i:IP {address: $address})
                        SET i.user_id = $user_id,
                            i.project_id = $project_id,
                            i.is_cdn = $is_cdn,
                            i.cdn_name = $cdn_name,
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
                ip_addr = host_info.get("ip")
                port_details = host_info.get("port_details", [])
                cdn_name = host_info.get("cdn")
                is_cdn = host_info.get("is_cdn", False)

                # Update IP node with CDN info (if not already done)
                if ip_addr:
                    try:
                        session.run(
                            """
                            MERGE (i:IP {address: $address})
                            SET i.user_id = $user_id,
                                i.project_id = $project_id,
                                i.is_cdn = $is_cdn,
                                i.cdn_name = $cdn_name,
                                i.updated_at = datetime()
                            """,
                            address=ip_addr, user_id=user_id, project_id=project_id,
                            is_cdn=is_cdn, cdn_name=cdn_name
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
                        # Port uniqueness is per IP + port + protocol
                        session.run(
                            """
                            MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr})
                            SET p.user_id = $user_id,
                                p.project_id = $project_id,
                                p.state = 'open',
                                p.updated_at = datetime()
                            """,
                            port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                            user_id=user_id, project_id=project_id
                        )
                        stats["ports_created"] += 1

                        # Create relationship: IP -[:HAS_PORT]-> Port
                        if ip_addr:
                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr})
                                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                ip_addr=ip_addr, port_number=port_number, protocol=protocol
                            )
                            stats["relationships_created"] += 1

                        # Create Service node if service detected
                        if service_name:
                            session.run(
                                """
                                MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr})
                                SET svc.user_id = $user_id,
                                    svc.project_id = $project_id,
                                    svc.updated_at = datetime()
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=ip_addr,
                                user_id=user_id, project_id=project_id
                            )
                            stats["services_created"] += 1

                            # Create relationship: Port -[:RUNS_SERVICE]-> Service
                            session.run(
                                """
                                MATCH (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr})
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                port_number=port_number, protocol=protocol, ip_addr=ip_addr,
                                service_name=service_name
                            )
                            stats["relationships_created"] += 1

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

            print(f"[+] Updated {stats['ips_updated']} IP nodes with CDN info")
            print(f"[+] Created {stats['ports_created']} Port nodes")
            print(f"[+] Created {stats['services_created']} Service nodes")
            print(f"[+] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_http_probe(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with HTTP probe data.

        This function creates/updates:
        - BaseURL nodes with HTTP response data (root/base URLs discovered by httpx)
        - Technology nodes for detected technologies
        - Header nodes for HTTP response headers
        - Service nodes (if not existing) for the HTTP/HTTPS service
        - Relationships: Service -[:SERVES_URL]-> BaseURL, BaseURL -[:USES_TECHNOLOGY]-> Technology, BaseURL -[:HAS_HEADER]-> Header

        Args:
            recon_data: The recon JSON data containing http_probe results
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created/updated nodes/relationships
        """
        stats = {
            "baseurls_created": 0,
            "services_created": 0,
            "technologies_created": 0,
            "headers_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        http_probe_data = recon_data.get("http_probe", {})
        if not http_probe_data:
            stats["errors"].append("No http_probe data found in recon_data")
            return stats

        with self.driver.session() as session:
            # Ensure schema is initialized
            self._init_schema(session)

            scan_metadata = http_probe_data.get("scan_metadata", {})
            by_url = http_probe_data.get("by_url", {})
            wappalyzer = http_probe_data.get("wappalyzer", {})
            all_technologies = wappalyzer.get("all_technologies", {})

            # Process each URL
            for url, url_info in by_url.items():
                try:
                    # Extract URL components
                    host = url_info.get("host", "")
                    scheme = "https" if url.startswith("https://") else "http"

                    # Create BaseURL node (root/base URL discovered by http_probe)
                    baseurl_props = {
                        "url": url,
                        "user_id": user_id,
                        "project_id": project_id,
                        "scheme": scheme,
                        "host": host,
                        "status_code": url_info.get("status_code"),
                        "content_length": url_info.get("content_length"),
                        "content_type": url_info.get("content_type"),
                        "title": url_info.get("title"),
                        "server": url_info.get("server"),
                        "response_time_ms": url_info.get("response_time_ms"),
                        "word_count": url_info.get("word_count"),
                        "line_count": url_info.get("line_count"),
                        "resolved_ip": url_info.get("ip"),
                        "cname": url_info.get("cname"),
                        "cdn": url_info.get("cdn"),
                        "is_cdn": url_info.get("is_cdn", False),
                        "asn": url_info.get("asn"),
                        "favicon_hash": url_info.get("favicon_hash"),
                        "is_live": url_info.get("status_code") is not None,
                        "source": "http_probe"
                    }

                    # Add body hash info if available
                    body_hash = url_info.get("body_hash", {})
                    if body_hash:
                        baseurl_props["body_sha256"] = body_hash.get("body_sha256")
                        baseurl_props["header_sha256"] = body_hash.get("header_sha256")

                    # Remove None values
                    baseurl_props = {k: v for k, v in baseurl_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (u:BaseURL {url: $url})
                        SET u += $props,
                            u.updated_at = datetime()
                        """,
                        url=url, props=baseurl_props
                    )
                    stats["baseurls_created"] += 1

                    # Create relationship: Service -[:SERVES_URL]-> BaseURL
                    # BaseURLs are served by HTTP/HTTPS services running on ports
                    if host:
                        resolved_ip = url_info.get("ip")
                        # Determine port from scheme (default ports for HTTP/HTTPS)
                        port_number = 443 if scheme == "https" else 80
                        service_name = "https" if scheme == "https" else "http"

                        if resolved_ip:
                            # Ensure the Service node exists for this IP/port combination
                            session.run(
                                """
                                MERGE (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr})
                                SET svc.user_id = $user_id,
                                    svc.project_id = $project_id,
                                    svc.updated_at = datetime()
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=resolved_ip,
                                user_id=user_id, project_id=project_id
                            )

                            stats["services_created"] += 1

                            # Create relationship: Service -[:SERVES_URL]-> BaseURL
                            session.run(
                                """
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr})
                                MATCH (u:BaseURL {url: $url})
                                MERGE (svc)-[:SERVES_URL]->(u)
                                """,
                                service_name=service_name, port_number=port_number, ip_addr=resolved_ip, url=url
                            )
                            stats["relationships_created"] += 1

                            # Also ensure Port node exists and is connected to Service
                            session.run(
                                """
                                MERGE (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr})
                                SET p.user_id = $user_id,
                                    p.project_id = $project_id,
                                    p.state = 'open',
                                    p.updated_at = datetime()
                                WITH p
                                MATCH (svc:Service {name: $service_name, port_number: $port_number, ip_address: $ip_addr})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                port_number=port_number, ip_addr=resolved_ip,
                                service_name=service_name,
                                user_id=user_id, project_id=project_id
                            )

                            # Also ensure IP -[:HAS_PORT]-> Port relationship exists
                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr})
                                MATCH (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                ip_addr=resolved_ip, port_number=port_number
                            )

                    # Process technologies from both httpx and wappalyzer
                    # Track processed tech names to avoid duplicates
                    processed_techs = set()

                    # 1. Process technologies from httpx first
                    httpx_technologies = url_info.get("technologies", [])
                    for tech_str in httpx_technologies:
                        try:
                            # Parse technology string (e.g., "Nginx:1.19.0" or "Ubuntu")
                            if ":" in tech_str:
                                tech_name, tech_version = tech_str.split(":", 1)
                            else:
                                tech_name = tech_str
                                tech_version = None

                            # Get additional info from wappalyzer if available
                            wap_info = all_technologies.get(tech_name, {})
                            categories = wap_info.get("categories", [])
                            confidence = wap_info.get("confidence", 100)

                            tech_props = {
                                "name": tech_name,
                                "user_id": user_id,
                                "project_id": project_id,
                                "version": tech_version,
                                "categories": categories,
                                "confidence": confidence,
                                "detected_by": "httpx"
                            }

                            # Remove None values
                            tech_props = {k: v for k, v in tech_props.items() if v is not None}

                            # Create Technology node (unique by name + version)
                            if tech_version:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version})
                                    SET t += $props,
                                        t.updated_at = datetime()
                                    """,
                                    name=tech_name, version=tech_version, props=tech_props
                                )
                                processed_techs.add((tech_name, tech_version))
                            else:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name})
                                    ON CREATE SET t += $props, t.updated_at = datetime()
                                    ON MATCH SET t.updated_at = datetime()
                                    """,
                                    name=tech_name, props=tech_props
                                )
                                processed_techs.add((tech_name, None))
                            stats["technologies_created"] += 1

                            # Create relationship: BaseURL -[:USES_TECHNOLOGY]-> Technology
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, tech_version=tech_version, confidence=confidence
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url})
                                    MATCH (t:Technology {name: $tech_name})
                                    WHERE t.version IS NULL
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'httpx'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, confidence=confidence
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Technology {tech_str} failed: {e}")

                    # 2. Process wappalyzer technologies not found by httpx
                    # wappalyzer.by_url contains complete tech list per URL
                    # (plugins, analytics, security_tools, frameworks are just filtered subsets by category)
                    wappalyzer_by_url = wappalyzer.get("by_url", {})
                    wap_techs_for_url = wappalyzer_by_url.get(url, [])

                    for wap_tech in wap_techs_for_url:
                        try:
                            tech_name = wap_tech.get("name", "")
                            tech_version = wap_tech.get("version")  # Can be None

                            # Skip if already processed from httpx
                            if (tech_name, tech_version) in processed_techs:
                                continue
                            # Also skip if httpx found it without version but wappalyzer has version
                            if (tech_name, None) in processed_techs:
                                continue

                            categories = wap_tech.get("categories", [])
                            confidence = wap_tech.get("confidence", 100)

                            tech_props = {
                                "name": tech_name,
                                "user_id": user_id,
                                "project_id": project_id,
                                "version": tech_version,
                                "categories": categories,
                                "confidence": confidence,
                                "detected_by": "wappalyzer"
                            }

                            # Remove None values
                            tech_props = {k: v for k, v in tech_props.items() if v is not None}

                            # Create Technology node
                            if tech_version:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name, version: $version})
                                    SET t += $props,
                                        t.updated_at = datetime()
                                    """,
                                    name=tech_name, version=tech_version, props=tech_props
                                )
                            else:
                                session.run(
                                    """
                                    MERGE (t:Technology {name: $name})
                                    ON CREATE SET t += $props, t.updated_at = datetime()
                                    ON MATCH SET t.updated_at = datetime()
                                    """,
                                    name=tech_name, props=tech_props
                                )
                            stats["technologies_created"] += 1

                            # Create relationship: BaseURL -[:USES_TECHNOLOGY]-> Technology
                            if tech_version:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url})
                                    MATCH (t:Technology {name: $tech_name, version: $tech_version})
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, tech_version=tech_version, confidence=confidence
                                )
                            else:
                                session.run(
                                    """
                                    MATCH (u:BaseURL {url: $url})
                                    MATCH (t:Technology {name: $tech_name})
                                    WHERE t.version IS NULL
                                    MERGE (u)-[:USES_TECHNOLOGY {confidence: $confidence, detected_by: 'wappalyzer'}]->(t)
                                    """,
                                    url=url, tech_name=tech_name, confidence=confidence
                                )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Wappalyzer technology {tech_name} failed: {e}")

                    # Process headers
                    headers = url_info.get("headers", {})
                    security_headers = ["x-frame-options", "x-xss-protection", "content-security-policy",
                                        "strict-transport-security", "x-content-type-options"]
                    tech_revealing_headers = ["server", "x-powered-by", "x-aspnet-version"]

                    for header_name, header_value in headers.items():
                        try:
                            is_security = header_name.lower() in security_headers
                            reveals_tech = header_name.lower() in tech_revealing_headers

                            session.run(
                                """
                                MERGE (h:Header {name: $name, value: $value, baseurl: $url})
                                SET h.user_id = $user_id,
                                    h.project_id = $project_id,
                                    h.is_security_header = $is_security,
                                    h.reveals_technology = $reveals_tech,
                                    h.updated_at = datetime()
                                """,
                                name=header_name, value=str(header_value), url=url,
                                user_id=user_id, project_id=project_id,
                                is_security=is_security, reveals_tech=reveals_tech
                            )
                            stats["headers_created"] += 1

                            # Create relationship: BaseURL -[:HAS_HEADER]-> Header
                            session.run(
                                """
                                MATCH (u:BaseURL {url: $url})
                                MATCH (h:Header {name: $name, value: $value, baseurl: $url})
                                MERGE (u)-[:HAS_HEADER]->(h)
                                """,
                                url=url, name=header_name, value=str(header_value)
                            )
                            stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"Header {header_name} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"URL {url} processing failed: {e}")

            # Update Domain node with http probe metadata
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            summary = http_probe_data.get("summary", {})

            if root_domain:
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $root_domain, user_id: $user_id, project_id: $project_id})
                        SET d.http_probe_timestamp = $scan_timestamp,
                            d.http_probe_live_urls = $live_urls,
                            d.http_probe_technology_count = $tech_count,
                            d.updated_at = datetime()
                        """,
                        root_domain=root_domain, user_id=user_id, project_id=project_id,
                        scan_timestamp=scan_metadata.get("scan_timestamp"),
                        live_urls=summary.get("live_urls", 0),
                        tech_count=summary.get("technology_count", 0)
                    )
                except Exception as e:
                    stats["errors"].append(f"Domain update failed: {e}")

            print(f"[+] Created {stats['baseurls_created']} BaseURL nodes")
            print(f"[+] Created/Updated {stats['services_created']} Service nodes")
            print(f"[+] Created {stats['technologies_created']} Technology nodes")
            print(f"[+] Created {stats['headers_created']} Header nodes")
            print(f"[+] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!] {len(stats['errors'])} errors occurred")

        return stats

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
        import json

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

        with self.driver.session() as session:
            # Ensure schema is initialized
            self._init_schema(session)

            scan_metadata = vuln_scan_data.get("scan_metadata", {})
            discovered_urls = vuln_scan_data.get("discovered_urls", {})
            by_target = vuln_scan_data.get("by_target", {})

            # Track created endpoints and parameters for deduplication
            created_endpoints = set()  # (baseurl, path, method)
            created_parameters = set()  # (endpoint_path, param_name, param_position)

            # Process discovered URLs with parameters (from Katana crawling)
            dast_urls = discovered_urls.get("dast_urls_with_params", [])
            base_urls = discovered_urls.get("base_urls", [])

            for dast_url in dast_urls:
                try:
                    # Parse the URL to extract components
                    from urllib.parse import urlparse, parse_qs
                    parsed = urlparse(dast_url)

                    # Determine scheme, host, path
                    scheme = parsed.scheme or "http"
                    host = parsed.netloc
                    path = parsed.path or "/"
                    query_string = parsed.query

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
                            MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl})
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

                        # Create relationship: BaseURL -[:HAS_ENDPOINT]-> Endpoint
                        session.run(
                            """
                            MATCH (bu:BaseURL {url: $baseurl})
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl})
                            MERGE (bu)-[:HAS_ENDPOINT]->(e)
                            """,
                            baseurl=base_url, path=path, method=method
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
                                    MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl})
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
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, method=method, baseurl=base_url,
                                    param_name=param_name, position="query"
                                )
                                stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"DAST URL {dast_url} processing failed: {e}")

            # Process vulnerability findings by target
            for target_host, target_data in by_target.items():
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
                        from urllib.parse import urlparse
                        matched_parsed = urlparse(matched_at)
                        vuln_path = matched_parsed.path or "/"
                        vuln_scheme = matched_parsed.scheme or "http"
                        vuln_host = matched_parsed.netloc or target_host
                        vuln_base_url = f"{vuln_scheme}://{vuln_host}"

                        # Create Vulnerability node with all fields
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
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

                        # Create relationship: BaseURL -[:HAS_VULNERABILITY]-> Vulnerability
                        session.run(
                            """
                            MATCH (bu:BaseURL {url: $baseurl})
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MERGE (bu)-[:HAS_VULNERABILITY]->(v)
                            """,
                            baseurl=vuln_base_url, vuln_id=vuln_id
                        )
                        stats["relationships_created"] += 1

                        # Create Endpoint node for the vulnerability path if not exists
                        fuzzing_method = raw.get("fuzzing_method", "GET")
                        endpoint_key = (vuln_base_url, vuln_path, fuzzing_method)

                        if endpoint_key not in created_endpoints:
                            session.run(
                                """
                                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl})
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

                            # Create relationship: BaseURL -[:HAS_ENDPOINT]-> Endpoint
                            session.run(
                                """
                                MATCH (bu:BaseURL {url: $baseurl})
                                MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl})
                                MERGE (bu)-[:HAS_ENDPOINT]->(e)
                                """,
                                baseurl=vuln_base_url, path=vuln_path, method=fuzzing_method
                            )
                            stats["relationships_created"] += 1

                        # Create relationship: Vulnerability -[:FOUND_AT]-> Endpoint
                        session.run(
                            """
                            MATCH (v:Vulnerability {id: $vuln_id})
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl})
                            MERGE (v)-[:FOUND_AT]->(e)
                            """,
                            vuln_id=vuln_id, path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url
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
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl})
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
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                    param_name=fuzzing_param, position=fuzzing_position
                                )
                                stats["relationships_created"] += 1

                            # Create relationship: Vulnerability -[:AFFECTS_PARAMETER]-> Parameter
                            session.run(
                                """
                                MATCH (v:Vulnerability {id: $vuln_id})
                                MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl})
                                MERGE (v)-[:AFFECTS_PARAMETER]->(p)
                                """,
                                vuln_id=vuln_id, param_name=fuzzing_param, position=fuzzing_position,
                                path=vuln_path, baseurl=vuln_base_url
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

                for cve in cves:
                    try:
                        cve_id = cve.get("id")
                        if not cve_id:
                            continue

                        # Create CVE node with all properties
                        cve_props = {
                            "id": cve_id,
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
                        # Match Technology node by name AND version (case-insensitive)
                        # Try multiple matching strategies:
                        # 1. Match by product name + version
                        # 2. Match by tech_name key + version
                        # 3. Match by product name only (for technologies without version)
                        if tech_version:
                            # First try: exact product + version match
                            result = session.run(
                                """
                                MATCH (t:Technology {project_id: $project_id})
                                WHERE (toLower(t.name) = toLower($tech_product)
                                       OR toLower(t.name) = toLower($tech_key))
                                  AND t.version = $tech_version
                                MATCH (c:CVE {id: $cve_id})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                project_id=project_id, tech_product=tech_product,
                                tech_key=tech_name, tech_version=tech_version, cve_id=cve_id
                            )
                            matched = result.single()["matched"]
                            if matched > 0:
                                cve_relationships_created += 1
                        else:
                            # No version specified - match technologies without version
                            result = session.run(
                                """
                                MATCH (t:Technology {project_id: $project_id})
                                WHERE (toLower(t.name) = toLower($tech_product)
                                       OR toLower(t.name) = toLower($tech_key))
                                  AND t.version IS NULL
                                MATCH (c:CVE {id: $cve_id})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                project_id=project_id, tech_product=tech_product,
                                tech_key=tech_name, cve_id=cve_id
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
                print(f"[+] Created {cves_created} CVE nodes")
                print(f"[+] Created {cve_relationships_created} Technology-CVE relationships")
            if mitre_stats["nodes"] > 0:
                print(f"[+] Created {mitre_stats['nodes']} MitreData (CWE) nodes")
            if mitre_stats["capec"] > 0:
                print(f"[+] Created {mitre_stats['capec']} Capec nodes")

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

            print(f"[+] Created {stats['endpoints_created']} Endpoint nodes")
            print(f"[+] Created {stats['parameters_created']} Parameter nodes")
            print(f"[+] Created {stats['vulnerabilities_created']} Vulnerability nodes")
            print(f"[+] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!] {len(stats['errors'])} errors occurred")

        return stats


if __name__ == "__main__":
    # Quick connection test
    print("[*] Testing Neo4j connection...")
    with Neo4jClient() as client:
        if client.verify_connection():
            print("[+] Successfully connected to Neo4j!")
        else:
            print("[-] Failed to connect to Neo4j")
