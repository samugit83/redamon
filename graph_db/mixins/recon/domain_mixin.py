"""Domain and IP recon graph updates.

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address

class DomainMixin:
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

            # Extract data from recon_data
            metadata = recon_data.get("metadata", {})
            whois_data = recon_data.get("whois", {})
            subdomains = recon_data.get("subdomains", [])
            dns_data = recon_data.get("dns") or {}

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
                print(f"[+][graph-db] Created Domain node: {root_domain}")
            except Exception as e:
                stats["errors"].append(f"Domain creation failed: {e}")
                print(f"[!][graph-db] Domain creation failed: {e}")

            # 2. Create Subdomain nodes and relationships
            subdomain_dns = dns_data.get("subdomains", {})
            domain_dns = dns_data.get("domain", {})  # DNS data for root domain
            subdomain_status_map = recon_data.get("subdomain_status_map", {})

            for subdomain in subdomains:
                try:
                    # Get DNS info: use domain_dns if subdomain equals root_domain, else use subdomain_dns
                    if subdomain == root_domain:
                        subdomain_info = domain_dns  # Root domain DNS is in dns.domain
                    else:
                        subdomain_info = subdomain_dns.get(subdomain, {})
                    has_records = subdomain_info.get("has_records", False)

                    # Create Subdomain node
                    status = subdomain_status_map.get(subdomain)  # None for unresolved subs
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        SET s.has_dns_records = $has_records,
                            s.status = coalesce(s.status, $status),
                            s.discovered_at = coalesce(s.discovered_at, datetime()),
                            s.updated_at = datetime()
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                        has_records=has_records, status=status
                    )
                    stats["subdomains_created"] += 1

                    # Create relationships: Subdomain -[:BELONGS_TO]-> Domain and Domain -[:HAS_SUBDOMAIN]-> Subdomain
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                        MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
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
                                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                        SET i.version = $version,
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
                                        MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[:RESOLVES_TO {record_type: $record_type}]->(i)
                                        """,
                                        subdomain=subdomain, ip=ip_addr, record_type=record_type,
                                        user_id=user_id, project_id=project_id
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
                                            MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain, user_id: $user_id, project_id: $project_id})
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
                                            MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                            MATCH (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain, user_id: $user_id, project_id: $project_id})
                                            MERGE (s)-[:HAS_DNS_RECORD]->(dns)
                                            """,
                                            subdomain=subdomain, type=record_type, value=str(value),
                                            user_id=user_id, project_id=project_id
                                        )
                                        stats["relationships_created"] += 1
                                    except Exception as e:
                                        stats["errors"].append(f"DNSRecord {record_type}={value} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain} processing failed: {e}")
                    print(f"[!][graph-db] Subdomain {subdomain} processing failed: {e}")

            print(f"[+][graph-db] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+][graph-db] Created {stats['ips_created']} IP nodes")
            print(f"[+][graph-db] Created {stats['dns_records_created']} DNSRecord nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_ip_recon(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Initialize the Neo4j graph for IP-based reconnaissance.

        Creates:
        - Mock Domain node (ip-targets.{project_id}) with ip_mode: True
        - Subdomain nodes (real hostnames from PTR or mock IP-based names)
        - IP nodes and RESOLVES_TO relationships
        - BELONGS_TO relationships from subdomains to mock domain
        - Per-IP WHOIS data on IP nodes
        """
        stats = {
            "domain_created": False,
            "subdomains_created": 0,
            "ips_created": 0,
            "relationships_created": 0,
            "errors": []
        }

        with self.driver.session() as session:

            metadata = recon_data.get("metadata", {})
            whois_data = recon_data.get("whois", {})
            subdomains = recon_data.get("subdomains", [])
            dns_data = recon_data.get("dns") or {}
            ip_to_hostname = metadata.get("ip_to_hostname", {})
            ip_whois = whois_data.get("ip_whois", {})

            mock_domain = metadata.get("root_domain", f"ip-targets.{project_id}")

            # 1. Create mock Domain node
            try:
                domain_props = {
                    "name": mock_domain,
                    "user_id": user_id,
                    "project_id": project_id,
                    "ip_mode": True,
                    "is_mock": True,
                    "scan_timestamp": metadata.get("scan_timestamp"),
                    "scan_type": metadata.get("scan_type"),
                    "target_ips": metadata.get("target_ips", []),
                    "expanded_ips": metadata.get("expanded_ips", []),
                    "modules_executed": metadata.get("modules_executed", []),
                    "updated_at": datetime.now().isoformat()
                }
                domain_props = {k: v for k, v in domain_props.items() if v is not None}

                session.run(
                    """
                    MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                    SET d += $props
                    """,
                    name=mock_domain, user_id=user_id, project_id=project_id, props=domain_props
                )
                stats["domain_created"] = True
                print(f"[+][graph-db] Created mock Domain node: {mock_domain}")
            except Exception as e:
                stats["errors"].append(f"Domain creation failed: {e}")
                print(f"[!][graph-db] Domain creation failed: {e}")

            # 2. Create Subdomain nodes, IP nodes, and relationships
            subdomains_dns = dns_data.get("subdomains", {})

            for subdomain_name in subdomains:
                try:
                    sub_dns = subdomains_dns.get(subdomain_name, {})
                    is_mock = sub_dns.get("is_mock", False)
                    actual_ip = sub_dns.get("actual_ip", "")

                    # Create Subdomain node
                    sub_props = {
                        "name": subdomain_name,
                        "user_id": user_id,
                        "project_id": project_id,
                        "has_records": sub_dns.get("has_records", False),
                        "is_mock": is_mock,
                        "ip_mode": True,
                        "updated_at": datetime.now().isoformat()
                    }
                    if actual_ip:
                        sub_props["actual_ip"] = actual_ip

                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        ON CREATE SET s += $props, s.status = 'resolved'
                        ON MATCH SET s += $props
                        WITH s
                        WHERE s.status IS NULL
                        SET s.status = 'resolved'
                        """,
                        name=subdomain_name, user_id=user_id, project_id=project_id, props=sub_props
                    )
                    stats["subdomains_created"] += 1

                    # Create BELONGS_TO and HAS_SUBDOMAIN relationships to mock domain
                    session.run(
                        """
                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                        """,
                        sub=subdomain_name, domain=mock_domain, uid=user_id, pid=project_id
                    )
                    stats["relationships_created"] += 1

                    # Create IP nodes and RESOLVES_TO relationships
                    ips = sub_dns.get("ips", {})
                    all_ips = (ips.get("ipv4", []) or []) + (ips.get("ipv6", []) or [])

                    for ip in all_ips:
                        # Get WHOIS info for this IP if available
                        whois_info = ip_whois.get(ip, {})

                        ip_props = {
                            "address": ip,
                            "user_id": user_id,
                            "project_id": project_id,
                            "version": "v6" if ":" in ip else "v4",
                            "ip_mode": True,
                            "updated_at": datetime.now().isoformat()
                        }
                        if whois_info:
                            ip_props["organization"] = whois_info.get("org", "")
                            ip_props["country"] = whois_info.get("country", "")

                        session.run(
                            """
                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            SET i += $props
                            """,
                            addr=ip, uid=user_id, pid=project_id, props=ip_props
                        )
                        stats["ips_created"] += 1

                        # RESOLVES_TO
                        session.run(
                            """
                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                            MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                            MERGE (s)-[:RESOLVES_TO]->(i)
                            """,
                            sub=subdomain_name, ip=ip, uid=user_id, pid=project_id
                        )
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain_name}: {e}")
                    print(f"[!][graph-db] Error processing {subdomain_name}: {e}")

            print(f"[+][graph-db] IP Recon graph update complete:")
            print(f"[+][graph-db] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+][graph-db] Created {stats['ips_created']} IP nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats
