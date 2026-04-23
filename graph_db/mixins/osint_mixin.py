"""
OsintMixin: OSINT enrichment graph operations (11 sources).

Provides methods to ingest OSINT enrichment data:
- update_graph_from_shodan
- update_graph_from_urlscan_discovery
- update_graph_from_urlscan_enrichment
- update_graph_from_external_domains
- update_graph_from_censys
- update_graph_from_fofa
- update_graph_from_otx
- update_graph_from_netlas
- update_graph_from_virustotal
- update_graph_from_zoomeye
- update_graph_from_criminalip
"""

import re
import json
from datetime import datetime
from urllib.parse import urlparse as _urlparse



class OsintMixin:
    def update_graph_from_shodan(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with Shodan OSINT enrichment data.

        Creates/updates:
        - IP nodes with geo/ISP/OS metadata (from host lookup)
        - Port + Service nodes (from host lookup services)
        - Subdomain nodes + RESOLVES_TO (from reverse DNS / domain DNS)
        - DNSRecord nodes (from domain DNS)
        - Vulnerability + CVE nodes (from passive CVEs)

        Uses MERGE for automatic deduplication with data from other tools.
        """
        stats = {
            "ips_enriched": 0,
            "ports_created": 0,
            "services_created": 0,
            "subdomains_created": 0,
            "dns_records_created": 0,
            "vulnerabilities_created": 0,
            "cves_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        shodan_data = recon_data.get("shodan", {})
        if not shodan_data:
            stats["errors"].append("No shodan data found in recon_data")
            return stats

        domain = recon_data.get("domain", "")

        with self.driver.session() as session:

            # ── 1. IP Enrichment (from host lookup) ──
            for host in shodan_data.get("hosts", []):
                ip = host.get("ip")
                if not ip:
                    continue
                try:
                    props = {k: v for k, v in {
                        "os": host.get("os"),
                        "isp": host.get("isp"),
                        "organization": host.get("org"),
                        "country": host.get("country_name"),
                        "city": host.get("city"),
                        "shodan_enriched": True,
                    }.items() if v is not None}

                    session.run(
                        """
                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        SET i += $props, i.updated_at = datetime()
                        """,
                        address=ip, user_id=user_id, project_id=project_id, props=props
                    )
                    stats["ips_enriched"] += 1

                    # Port + Service nodes from host services
                    for svc in host.get("services", []):
                        port_num = svc.get("port")
                        if not port_num:
                            continue
                        protocol = svc.get("transport", "tcp")

                        # MERGE Port
                        session.run(
                            """
                            MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                           user_id: $user_id, project_id: $project_id})
                            ON CREATE SET p.state = 'open', p.source = 'shodan', p.updated_at = datetime()
                            ON MATCH SET p.updated_at = datetime()
                            MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                            MERGE (i)-[:HAS_PORT]->(p)
                            """,
                            port=port_num, protocol=protocol, ip=ip,
                            user_id=user_id, project_id=project_id
                        )
                        stats["ports_created"] += 1
                        stats["relationships_created"] += 1

                        # MERGE Service (if product is known)
                        product = svc.get("product", "").strip()
                        if product:
                            svc_props = {k: v for k, v in {
                                "version": svc.get("version"),
                                "banner": svc.get("banner"),
                                "source": "shodan",
                                "module": svc.get("module"),
                            }.items() if v is not None}

                            session.run(
                                """
                                MERGE (svc:Service {name: $name, port_number: $port, ip_address: $ip,
                                                    user_id: $user_id, project_id: $project_id})
                                ON CREATE SET svc += $props, svc.updated_at = datetime()
                                ON MATCH SET svc.updated_at = datetime()
                                WITH svc
                                MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                               user_id: $user_id, project_id: $project_id})
                                MERGE (p)-[:RUNS_SERVICE]->(svc)
                                """,
                                name=product, port=port_num, protocol=protocol, ip=ip,
                                user_id=user_id, project_id=project_id, props=svc_props
                            )
                            stats["services_created"] += 1
                            stats["relationships_created"] += 1

                    # InternetDB port arrays (no service detail available)
                    # Only process ports not already covered by the services loop above
                    service_ports = {svc.get("port") for svc in host.get("services", []) if svc.get("port")}
                    for port_num in host.get("ports", []):
                        if not port_num or port_num in service_ports:
                            continue
                        try:
                            session.run(
                                """
                                MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                               user_id: $user_id, project_id: $project_id})
                                ON CREATE SET p.state = 'open', p.source = 'shodan', p.updated_at = datetime()
                                ON MATCH SET p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                port=port_num, protocol="tcp", ip=ip,
                                user_id=user_id, project_id=project_id
                            )
                            stats["ports_created"] += 1
                            stats["relationships_created"] += 1
                        except Exception as e:
                            stats["errors"].append(f"Failed to create InternetDB port {port_num} for {ip}: {e}")

                except Exception as e:
                    stats["errors"].append(f"Failed to enrich IP {ip}: {e}")

            # ── 2. Reverse DNS → Subdomain or ExternalDomain nodes ──
            for ip, hostnames in shodan_data.get("reverse_dns", {}).items():
                for hostname in hostnames:
                    if not hostname:
                        continue
                    try:
                        # Check if hostname is in scope (belongs to target domain)
                        is_in_scope = domain and (hostname == domain or hostname.endswith("." + domain))

                        if is_in_scope:
                            session.run(
                                """
                                MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET s.source = 'shodan_rdns', s.status = 'resolved',
                                              s.discovered_at = datetime(), s.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:RESOLVES_TO {record_type: 'A', timestamp: datetime()}]->(i)
                                """,
                                name=hostname, ip=ip, user_id=user_id, project_id=project_id
                            )
                            stats["subdomains_created"] += 1
                            stats["relationships_created"] += 1

                            # Link to domain
                            if domain:
                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                    MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                    """,
                                    name=hostname, domain=domain,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1
                        else:
                            # Out-of-scope hostname → ExternalDomain
                            session.run(
                                """
                                MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET ed.first_seen_at = datetime()
                                SET ed.sources = coalesce(ed.sources, []) + CASE WHEN NOT 'shodan_rdns' IN coalesce(ed.sources, []) THEN ['shodan_rdns'] ELSE [] END,
                                    ed.ips_seen = coalesce(ed.ips_seen, []) + CASE WHEN NOT $ip IN coalesce(ed.ips_seen, []) THEN [$ip] ELSE [] END,
                                    ed.updated_at = datetime()
                                WITH ed
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (ed)-[:DISCOVERED_BY]->(d)
                                """,
                                ed_domain=hostname, ip=ip, domain=domain,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Failed to create subdomain {hostname}: {e}")

            # ── 3. Domain DNS → Subdomain + DNSRecord nodes ──
            domain_dns = shodan_data.get("domain_dns", {})
            for sub_name in domain_dns.get("subdomains", []):
                if not sub_name:
                    continue
                fqdn = f"{sub_name}.{domain}" if domain and not sub_name.endswith(domain) else sub_name

                # Check if the FQDN is in scope
                is_in_scope = domain and (fqdn == domain or fqdn.endswith("." + domain))

                try:
                    if is_in_scope:
                        session.run(
                            """
                            MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET s.source = 'shodan_dns', s.status = 'resolved',
                                          s.discovered_at = datetime(), s.updated_at = datetime()
                            """,
                            name=fqdn, user_id=user_id, project_id=project_id
                        )
                        stats["subdomains_created"] += 1

                        if domain:
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:BELONGS_TO]->(d)
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                """,
                                name=fqdn, domain=domain,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1
                    else:
                        # Out-of-scope → ExternalDomain
                        session.run(
                            """
                            MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET ed.first_seen_at = datetime()
                            SET ed.sources = coalesce(ed.sources, []) + CASE WHEN NOT 'shodan_dns' IN coalesce(ed.sources, []) THEN ['shodan_dns'] ELSE [] END,
                                ed.updated_at = datetime()
                            WITH ed
                            MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                            MERGE (ed)-[:DISCOVERED_BY]->(d)
                            """,
                            ed_domain=fqdn, domain=domain,
                            user_id=user_id, project_id=project_id
                        )

                except Exception as e:
                    stats["errors"].append(f"Failed to create subdomain {fqdn}: {e}")

            for record in domain_dns.get("records", []):
                rec_type = record.get("type", "")
                rec_value = record.get("value", "")
                rec_sub = record.get("subdomain", "")
                if not rec_type or not rec_value:
                    continue
                fqdn = f"{rec_sub}.{domain}" if rec_sub and domain else domain
                try:
                    session.run(
                        """
                        MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $subdomain,
                                              user_id: $user_id, project_id: $project_id})
                        ON CREATE SET dns.source = 'shodan', dns.updated_at = datetime()
                        """,
                        type=rec_type, value=rec_value, subdomain=fqdn,
                        user_id=user_id, project_id=project_id
                    )
                    stats["dns_records_created"] += 1

                    # Link A/AAAA records to IP nodes
                    if rec_type in ("A", "AAAA"):
                        session.run(
                            """
                            MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                            MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                            MERGE (s)-[:RESOLVES_TO {record_type: $type, timestamp: datetime()}]->(i)
                            """,
                            subdomain=fqdn, ip=rec_value, type=rec_type,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to create DNS record {rec_type}={rec_value}: {e}")

            # ── 4. Passive CVEs → Vulnerability + CVE nodes ──
            for cve_entry in shodan_data.get("cves", []):
                cve_id = cve_entry.get("cve_id", "")
                ip = cve_entry.get("ip", "")
                cve_source = cve_entry.get("source", "shodan")
                if not cve_id or not ip:
                    continue
                vuln_id = f"shodan-{cve_id}-{ip}"
                try:
                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $vuln_id})
                        ON CREATE SET v.source = $source, v.name = $cve_id,
                                      v.cves = [$cve_id], v.user_id = $user_id,
                                      v.project_id = $project_id, v.updated_at = datetime()
                        """,
                        vuln_id=vuln_id, cve_id=cve_id, source=cve_source,
                        user_id=user_id, project_id=project_id
                    )
                    stats["vulnerabilities_created"] += 1

                    session.run(
                        """
                        MERGE (c:CVE {id: $cve_id})
                        ON CREATE SET c.source = $source, c.user_id = $user_id,
                                      c.project_id = $project_id, c.updated_at = datetime()
                        """,
                        cve_id=cve_id, source=cve_source,
                        user_id=user_id, project_id=project_id
                    )
                    stats["cves_created"] += 1

                    session.run(
                        """
                        MATCH (v:Vulnerability {id: $vuln_id})
                        MATCH (c:CVE {id: $cve_id})
                        MERGE (v)-[:INCLUDES_CVE]->(c)
                        """,
                        vuln_id=vuln_id, cve_id=cve_id
                    )
                    stats["relationships_created"] += 1

                    session.run(
                        """
                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                        MATCH (v:Vulnerability {id: $vuln_id})
                        MERGE (i)-[:HAS_VULNERABILITY]->(v)
                        """,
                        ip=ip, vuln_id=vuln_id,
                        user_id=user_id, project_id=project_id
                    )
                    stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"Failed to create CVE {cve_id} for {ip}: {e}")

            # Print summary
            print(f"\n[+][graph-db] Shodan Graph Update Summary:")
            print(f"[+][graph-db] Enriched {stats['ips_enriched']} IP nodes")
            print(f"[+][graph-db] Created {stats['ports_created']} Port nodes")
            print(f"[+][graph-db] Created {stats['services_created']} Service nodes")
            print(f"[+][graph-db] Created {stats['subdomains_created']} Subdomain nodes")
            print(f"[+][graph-db] Created {stats['dns_records_created']} DNSRecord nodes")
            print(f"[+][graph-db] Created {stats['vulnerabilities_created']} Vulnerability nodes")
            print(f"[+][graph-db] Created {stats['cves_created']} CVE nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats


    def update_graph_from_urlscan_discovery(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Phase A: Update graph with URLScan discovery data (before port scan).

        Creates/updates:
        - Subdomain nodes discovered by URLScan
        - IP nodes with ASN/country enrichment
        - Domain node with domain_age_days
        """
        stats = {
            "subdomains_created": 0,
            "ips_enriched": 0,
            "domain_enriched": False,
            "relationships_created": 0,
            "errors": [],
        }

        urlscan_data = recon_data.get("urlscan", {})
        if not urlscan_data or urlscan_data.get("results_count", 0) == 0:
            return stats

        domain = recon_data.get("domain", "")

        with self.driver.session() as session:

            # ── 1. Subdomain + IP discovery ──
            seen_subs = set()
            seen_ips = set()
            seen_sub_ip_links = set()
            for entry in urlscan_data.get("entries", []):
                subdomain = entry.get("domain", "")
                ip = entry.get("ip", "")
                asn = entry.get("asn", "")
                asn_name = entry.get("asn_name", "")
                country = entry.get("country", "")

                # Create/update subdomain or external domain node
                if subdomain and subdomain != domain and subdomain not in seen_subs:
                    seen_subs.add(subdomain)
                    is_in_scope = domain and (subdomain == domain or subdomain.endswith("." + domain))
                    try:
                        if is_in_scope:
                            session.run(
                                """
                                MERGE (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (s:Subdomain {name: $subdomain, user_id: $uid, project_id: $pid})
                                ON CREATE SET s.discovered_by = 'urlscan', s.status = 'resolved',
                                              s.updated_at = datetime()
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                """,
                                domain=domain, subdomain=subdomain,
                                uid=user_id, pid=project_id
                            )
                            stats["subdomains_created"] += 1
                            stats["relationships_created"] += 1
                        else:
                            session.run(
                                """
                                MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $uid, project_id: $pid})
                                ON CREATE SET ed.first_seen_at = datetime()
                                SET ed.sources = coalesce(ed.sources, []) + CASE WHEN NOT 'urlscan' IN coalesce(ed.sources, []) THEN ['urlscan'] ELSE [] END,
                                    ed.updated_at = datetime()
                                WITH ed
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (ed)-[:DISCOVERED_BY]->(d)
                                """,
                                ed_domain=subdomain, domain=domain,
                                uid=user_id, pid=project_id
                            )
                    except Exception as e:
                        stats["errors"].append(f"Subdomain {subdomain}: {e}")

                # Enrich IP with ASN/country (deduplicate — many entries share the same IP)
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    try:
                        props = {k: v for k, v in {
                            "country": country or None,
                            "asn": asn or None,
                            "asn_name": asn_name or None,
                            "urlscan_enriched": True,
                        }.items() if v is not None}

                        session.run(
                            """
                            MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                            SET i += $props, i.updated_at = datetime()
                            """,
                            ip=ip, uid=user_id, pid=project_id, props=props
                        )
                        stats["ips_enriched"] += 1
                    except Exception as e:
                        stats["errors"].append(f"IP {ip}: {e}")

                # Link subdomain -> IP (deduplicate the pair, skip root domain)
                if subdomain and ip and subdomain != domain:
                    link_key = (subdomain, ip)
                    if link_key not in seen_sub_ip_links:
                        seen_sub_ip_links.add(link_key)
                        try:
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $subdomain, user_id: $uid, project_id: $pid})
                                MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                                MERGE (s)-[:RESOLVES_TO]->(i)
                                """,
                                subdomain=subdomain, ip=ip,
                                uid=user_id, pid=project_id
                            )
                            stats["relationships_created"] += 1
                        except Exception as e:
                            stats["errors"].append(f"Link {subdomain}->{ip}: {e}")

            # ── 2. Domain age enrichment ──
            domain_age = urlscan_data.get("domain_age_days")
            apex_age = urlscan_data.get("apex_domain_age_days")
            if domain and (domain_age is not None or apex_age is not None):
                try:
                    props = {k: v for k, v in {
                        "domain_age_days": domain_age,
                        "apex_domain_age_days": apex_age,
                        "urlscan_enriched": True,
                    }.items() if v is not None}

                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        SET d += $props, d.updated_at = datetime()
                        """,
                        domain=domain, uid=user_id, pid=project_id, props=props
                    )
                    stats["domain_enriched"] = True
                except Exception as e:
                    stats["errors"].append(f"Domain age: {e}")

            print(f"[+][graph-db] URLScan discovery: {stats['subdomains_created']} subdomains, "
                  f"{stats['ips_enriched']} IPs enriched")
            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    def update_graph_from_urlscan_enrichment(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """
        Phase B: Enrich existing graph nodes with URLScan data (after http_probe).

        MATCH-only for BaseURL/Certificate (never creates from stale data).
        Creates Endpoint/Parameter nodes only where parent BaseURL exists.
        """
        stats = {
            "baseurls_enriched": 0,
            "baseurls_not_found": 0,
            "endpoints_created": 0,
            "endpoints_skipped": 0,
            "parameters_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        urlscan_data = recon_data.get("urlscan", {})
        if not urlscan_data or urlscan_data.get("results_count", 0) == 0:
            return stats

        with self.driver.session() as session:

            # ── 1. Enrich existing BaseURL nodes with screenshot/server/title ──
            # Group entries by base_url for efficient enrichment
            baseurl_data: dict[str, dict] = {}
            for entry in urlscan_data.get("entries", []):
                url = entry.get("url", "")
                if not url:
                    continue
                try:
                    parsed = _urlparse(url)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                except Exception:
                    continue

                if base_url not in baseurl_data:
                    baseurl_data[base_url] = {
                        "screenshot_url": entry.get("screenshot_url", ""),
                        "server": entry.get("server", ""),
                        "title": entry.get("title", ""),
                    }

            for base_url, data in baseurl_data.items():
                try:
                    props = {k: v for k, v in {
                        "urlscan_screenshot_url": data["screenshot_url"] or None,
                        "urlscan_server": data["server"] or None,
                        "urlscan_title": data["title"] or None,
                        "urlscan_enriched": True,
                    }.items() if v is not None}

                    if props:
                        result = session.run(
                            """
                            MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                            SET bu += $props, bu.updated_at = datetime()
                            RETURN bu.url AS url
                            """,
                            base_url=base_url, uid=user_id, pid=project_id, props=props
                        )
                        if result.single():
                            stats["baseurls_enriched"] += 1
                        else:
                            stats["baseurls_not_found"] += 1
                except Exception as e:
                    stats["errors"].append(f"BaseURL {base_url}: {e}")

            # ── 2. Create Endpoint + Parameter nodes for URLs with paths ──
            for url_entry in urlscan_data.get("urls_with_paths", []):
                base_url = url_entry.get("base_url", "")
                path = url_entry.get("path", "")
                full_url = url_entry.get("full_url", "")
                params = url_entry.get("params", {})

                if not base_url or not path:
                    continue

                try:
                    has_params = bool(params)
                    # Only create endpoint if BaseURL exists (confirmed live by http_probe)
                    result = session.run(
                        """
                        MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                        MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url,
                                           user_id: $uid, project_id: $pid})
                        ON CREATE SET e.source = 'urlscan', e.full_url = $full_url,
                                      e.has_parameters = $has_params, e.updated_at = datetime()
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        RETURN e.path AS path
                        """,
                        base_url=base_url, path=path, full_url=full_url,
                        has_params=has_params, uid=user_id, pid=project_id
                    )
                    record = result.single()
                    if record:
                        stats["endpoints_created"] += 1
                        stats["relationships_created"] += 1

                        # Create Parameter nodes from query string
                        for param_name, param_value in params.items():
                            try:
                                sample_val = param_value if isinstance(param_value, str) else str(param_value)
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url,
                                                       user_id: $uid, project_id: $pid})
                                    MERGE (p:Parameter {name: $param_name, position: 'query',
                                                        endpoint_path: $path, baseurl: $base_url,
                                                        user_id: $uid, project_id: $pid})
                                    ON CREATE SET p.source = 'urlscan', p.sample_value = $sample_val,
                                                  p.is_injectable = false, p.updated_at = datetime()
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, base_url=base_url, param_name=param_name,
                                    sample_val=sample_val[:500],
                                    uid=user_id, pid=project_id
                                )
                                stats["parameters_created"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e:
                                stats["errors"].append(f"Parameter {param_name}: {e}")
                    else:
                        stats["endpoints_skipped"] += 1

                except Exception as e:
                    stats["errors"].append(f"Endpoint {path}: {e}")

            print(f"[+][graph-db] URLScan enrichment: {stats['baseurls_enriched']} BaseURLs enriched, "
                  f"{stats['endpoints_created']} endpoints, {stats['parameters_created']} parameters")
            if stats["baseurls_not_found"]:
                print(f"[*][graph-db] {stats['baseurls_not_found']} BaseURLs not in graph (stale URLScan data, expected)")
            if stats["endpoints_skipped"]:
                print(f"[*][graph-db] {stats['endpoints_skipped']} endpoints skipped (BaseURL not live)")
            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats


    def update_graph_from_external_domains(self, recon_data, user_id, project_id):
        """Update graph with aggregated external (out-of-scope) domains.

        Creates ExternalDomain nodes and links them to the target Domain node
        via HAS_EXTERNAL_DOMAIN relationship. These nodes are informational only —
        they are never scanned or attacked.
        """
        external_domains = recon_data.get("external_domains_aggregated", [])
        domain = recon_data.get("domain", "")
        if not external_domains:
            return

        print(f"\n[GRAPH] External Domains: {len(external_domains)} foreign domains")

        created = 0
        with self.driver.session() as session:
            for ed in external_domains:
                ed_domain = ed.get("domain", "")
                if not ed_domain:
                    continue
                try:
                    result = session.run("""
                        MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $uid, project_id: $pid})
                        ON CREATE SET ed.first_seen_at = datetime()
                        SET ed.sources = $sources,
                            ed.redirect_from_urls = $redirect_from,
                            ed.redirect_to_urls = $redirect_to,
                            ed.status_codes_seen = $status_codes,
                            ed.titles_seen = $titles,
                            ed.servers_seen = $servers,
                            ed.ips_seen = $ips,
                            ed.countries_seen = $countries,
                            ed.times_seen = $times_seen,
                            ed.updated_at = datetime()
                        RETURN ed.first_seen_at = ed.updated_at AS is_new
                    """, ed_domain=ed_domain, uid=user_id, pid=project_id,
                        sources=ed.get("sources", []),
                        redirect_from=ed.get("redirect_from_urls", []),
                        redirect_to=ed.get("redirect_to_urls", []),
                        status_codes=ed.get("status_codes_seen", []),
                        titles=ed.get("titles_seen", []),
                        servers=ed.get("servers_seen", []),
                        ips=ed.get("ips_seen", []),
                        countries=ed.get("countries_seen", []),
                        times_seen=ed.get("times_seen", 0),
                    )
                    record = result.single()
                    if record and record["is_new"]:
                        created += 1

                    # Link to Domain node
                    if domain:
                        session.run("""
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                            MATCH (ed:ExternalDomain {domain: $ed_domain, user_id: $uid, project_id: $pid})
                            MERGE (d)-[:HAS_EXTERNAL_DOMAIN]->(ed)
                        """, domain=domain, ed_domain=ed_domain, uid=user_id, pid=project_id)
                except Exception as e:
                    logger.warning(f"ExternalDomain graph error for {ed_domain}: {e}")

        print(f"[+][graph-db] External domains: {created} created, {len(external_domains) - created} updated")

    def update_graph_from_censys(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0, "ports_merged": 0, "services_merged": 0,
            "certificates_merged": 0, "subdomains_merged": 0,
            "relationships_created": 0, "errors": [],
        }
        domain = recon_data.get("domain", "") or ""
        try:
            hosts = (recon_data.get("censys") or {}).get("hosts") or []
            if not hosts:
                stats["errors"].append("No censys hosts in recon_data")
            else:
                with self.driver.session() as session:
                    for host in hosts:
                        ip = host.get("ip")
                        if not ip:
                            continue
                        try:
                            asn = host.get("autonomous_system") or {}
                            if not isinstance(asn, dict):
                                asn = {}
                            loc = host.get("location") or {}
                            if not isinstance(loc, dict):
                                loc = {}

                            ip_props: dict = {"censys_enriched": True}
                            # ASN
                            for src_key, dst_key in (
                                ("name",        "autonomous_system_name"),
                                ("bgp_prefix",  "asn_bgp_prefix"),
                                ("description", "asn_description"),
                                ("country_code","asn_country_code"),
                                ("rir",         "asn_rir"),
                            ):
                                v = asn.get(src_key)
                                if v:
                                    ip_props[dst_key] = v
                            if asn.get("asn") is not None:
                                ip_props["autonomous_system_number"] = asn["asn"]
                            # Location
                            for src_key, dst_key in (
                                ("country",            "country"),
                                ("country_code",       "country_code"),
                                ("city",               "city"),
                                ("timezone",           "timezone"),
                                ("registered_country", "registered_country"),
                            ):
                                v = loc.get(src_key)
                                if v:
                                    ip_props[dst_key] = v
                            lat = loc.get("latitude")
                            lon = loc.get("longitude")
                            if lat is not None:
                                ip_props["latitude"] = lat
                            if lon is not None:
                                ip_props["longitude"] = lon
                            # OS / last seen
                            os_v = host.get("os")
                            if os_v:
                                ip_props["os"] = os_v
                            lu = host.get("last_updated")
                            if lu:
                                ip_props["censys_last_seen"] = str(lu)

                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            # Services → Port + Service + Certificate
                            for svc in host.get("services") or []:
                                if not isinstance(svc, dict):
                                    continue
                                port_num = svc.get("port")
                                if port_num is None:
                                    continue
                                protocol = (svc.get("transport_protocol") or "tcp").lower() or "tcp"
                                session.run(
                                    """
                                    MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                    SET p.source = 'censys', p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_PORT]->(p)
                                    """,
                                    port=int(port_num), protocol=protocol, ip=ip,
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["ports_merged"] += 1
                                stats["relationships_created"] += 1

                                sname = (svc.get("service_name") or "").strip()
                                if sname:
                                    svc_props: dict = {"source": "censys"}
                                    ext = (svc.get("extended_service_name") or "").strip()
                                    if ext:
                                        svc_props["extended_service_name"] = ext
                                    banner = (svc.get("banner") or "").strip()
                                    if banner:
                                        svc_props["banner"] = banner
                                    labels = svc.get("labels") or []
                                    if labels:
                                        svc_props["labels"] = labels
                                    http_meta = svc.get("http") or {}
                                    if isinstance(http_meta, dict):
                                        if http_meta.get("title"):
                                            svc_props["http_title"] = http_meta["title"]
                                        if http_meta.get("status_code") is not None:
                                            svc_props["http_status_code"] = http_meta["status_code"]
                                    software = svc.get("software") or []
                                    if software:
                                        sw_strs = [
                                            f"{s.get('product', '')} {s.get('version', '')}".strip()
                                            for s in software if isinstance(s, dict) and s.get("product")
                                        ]
                                        if sw_strs:
                                            svc_props["software_products"] = sw_strs
                                    session.run(
                                        """
                                        MERGE (svc:Service {name: $name, port_number: $port, ip_address: $ip,
                                                            user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET svc.updated_at = datetime()
                                        SET svc += $props, svc.updated_at = datetime()
                                        WITH svc
                                        MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                       user_id: $user_id, project_id: $project_id})
                                        MERGE (p)-[:RUNS_SERVICE]->(svc)
                                        """,
                                        name=sname, port=int(port_num), protocol=protocol, ip=ip,
                                        user_id=user_id, project_id=project_id, props=svc_props,
                                    )
                                    stats["services_merged"] += 1
                                    stats["relationships_created"] += 1

                                # TLS → Certificate node linked to IP
                                tls_data = svc.get("tls")
                                if isinstance(tls_data, dict):
                                    subject_cn = tls_data.get("subject_cn") or ""
                                    if subject_cn:
                                        cert_props = {k: v for k, v in {
                                            "issuer":      tls_data.get("issuer"),
                                            "san":         tls_data.get("san"),
                                            "not_before":  tls_data.get("not_before"),
                                            "not_after":   tls_data.get("not_after"),
                                            "fingerprint": tls_data.get("fingerprint"),
                                            "tls_version": tls_data.get("tls_version"),
                                            "cipher":      tls_data.get("cipher"),
                                            "source":      "censys",
                                        }.items() if v is not None and v != "" and v != []}
                                        try:
                                            session.run(
                                                """
                                                MERGE (c:Certificate {subject_cn: $subject_cn,
                                                                       user_id: $user_id,
                                                                       project_id: $project_id})
                                                SET c += $props, c.updated_at = datetime()
                                                WITH c
                                                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                                MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                                """,
                                                subject_cn=subject_cn, user_id=user_id,
                                                project_id=project_id, props=cert_props, ip=ip,
                                            )
                                            stats["certificates_merged"] += 1
                                            stats["relationships_created"] += 1
                                        except Exception as e:
                                            stats["errors"].append(f"Censys cert {subject_cn}: {e}")

                            # Reverse DNS → Subdomain nodes
                            for hostname in host.get("reverse_dns_names") or []:
                                if not hostname or not domain:
                                    continue
                                if not (hostname == domain or hostname.endswith("." + domain)):
                                    continue
                                try:
                                    session.run(
                                        """
                                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET s.discovered_at = datetime(), s.updated_at = datetime()
                                        SET s.source = 'censys_rdns', s.status = 'unverified',
                                            s.updated_at = datetime()
                                        MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[:RESOLVES_TO {record_type: 'A', timestamp: datetime()}]->(i)
                                        """,
                                        name=hostname, ip=ip, user_id=user_id, project_id=project_id,
                                    )
                                    session.run(
                                        """
                                        MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[:BELONGS_TO]->(d)
                                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                        """,
                                        name=hostname, domain=domain,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["subdomains_merged"] += 1
                                    stats["relationships_created"] += 2
                                except Exception as e:
                                    stats["errors"].append(f"Censys rdns {hostname}: {e}")

                        except Exception as e:
                            stats["errors"].append(f"Censys host {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_censys: {e}")
        print(f"[graph-db] update_graph_from_censys complete: {stats}")
        return stats

    def update_graph_from_fofa(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0, "ports_merged": 0, "services_merged": 0,
            "subdomains_merged": 0, "certificates_merged": 0,
            "relationships_created": 0, "errors": [],
        }
        try:
            rows = (recon_data.get("fofa") or {}).get("results") or []
            domain = recon_data.get("domain", "") or ""
            if not rows:
                stats["errors"].append("No fofa results in recon_data")
            else:
                with self.driver.session() as session:
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        ip = row.get("ip")
                        if not ip:
                            continue
                        try:
                            # --- IP node ---
                            ip_props = {"fofa_enriched": True}
                            if row.get("country"):
                                ip_props["country_code"] = row["country"]
                            if row.get("country_name"):
                                ip_props["country"] = row["country_name"]
                            if row.get("city"):
                                ip_props["city"] = row["city"]
                            if row.get("region"):
                                ip_props["region"] = row["region"]
                            if row.get("isp"):
                                ip_props["isp"] = row["isp"]
                            if row.get("as_organization"):
                                ip_props["asn_org"] = row["as_organization"]
                            if row.get("as_number"):
                                asn_raw = str(row["as_number"]).strip()
                                ip_props["asn"] = asn_raw if asn_raw.upper().startswith("AS") else f"AS{asn_raw}"
                            if row.get("os"):
                                ip_props["os"] = row["os"]
                            if row.get("lastupdatetime"):
                                ip_props["fofa_last_seen"] = row["lastupdatetime"]
                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            # --- Port node ---
                            port_raw = row.get("port")
                            try:
                                pnum = int(port_raw) if port_raw not in (None, "", 0) else None
                            except (TypeError, ValueError):
                                pnum = None
                            if pnum is None:
                                continue
                            session.run(
                                """
                                MERGE (p:Port {number: $port, protocol: 'tcp', ip_address: $ip,
                                               user_id: $user_id, project_id: $project_id})
                                ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                SET p.source = 'fofa', p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                port=pnum, ip=ip, user_id=user_id, project_id=project_id,
                            )
                            stats["ports_merged"] += 1
                            stats["relationships_created"] += 1

                            # --- Service node ---
                            # Prefer server software name; fall back to application protocol label
                            server = (row.get("server") or "").strip()
                            app_proto = (row.get("protocol") or "").strip()
                            svc_name = server or app_proto
                            if svc_name:
                                session.run(
                                    """
                                    MERGE (svc:Service {name: $name, port_number: $port, ip_address: $ip,
                                                        user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET svc.updated_at = datetime()
                                    SET svc.source = 'fofa', svc.updated_at = datetime(),
                                        svc.http_title   = CASE WHEN $http_title <> '' THEN $http_title ELSE svc.http_title END,
                                        svc.product      = CASE WHEN $product <> '' THEN $product ELSE svc.product END,
                                        svc.version      = CASE WHEN $version <> '' THEN $version ELSE svc.version END,
                                        svc.app_protocol = CASE WHEN $app_proto <> '' THEN $app_proto ELSE svc.app_protocol END,
                                        svc.jarm         = CASE WHEN $jarm <> '' THEN $jarm ELSE svc.jarm END,
                                        svc.tls_version  = CASE WHEN $tls_ver <> '' THEN $tls_ver ELSE svc.tls_version END
                                    WITH svc
                                    MATCH (p:Port {number: $port, protocol: 'tcp', ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    MERGE (p)-[:RUNS_SERVICE]->(svc)
                                    """,
                                    name=svc_name, port=pnum, ip=ip,
                                    http_title=row.get("title") or "",
                                    product=row.get("product") or "",
                                    version=row.get("version") or "",
                                    app_proto=app_proto,
                                    jarm=row.get("jarm") or "",
                                    tls_ver=row.get("tls_version") or "",
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["services_merged"] += 1
                                stats["relationships_created"] += 1

                            # --- Certificate node ---
                            cert_cn = (row.get("certs_subject_cn") or "").strip()
                            if cert_cn:
                                session.run(
                                    """
                                    MERGE (c:Certificate {subject_cn: $cn, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET c.source = 'fofa', c.updated_at = datetime()
                                    SET c.issuer       = CASE WHEN $issuer_cn <> '' THEN $issuer_cn ELSE c.issuer END,
                                        c.subject_org  = CASE WHEN $subject_org <> '' THEN $subject_org ELSE c.subject_org END,
                                        c.tls_version  = CASE WHEN $tls_ver <> '' THEN $tls_ver ELSE c.tls_version END,
                                        c.is_valid     = CASE WHEN $cert_valid <> '' THEN ($cert_valid = 'true') ELSE c.is_valid END,
                                        c.updated_at   = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                    """,
                                    cn=cert_cn,
                                    issuer_cn=row.get("certs_issuer_cn") or "",
                                    subject_org=row.get("certs_subject_org") or "",
                                    tls_ver=row.get("tls_version") or "",
                                    cert_valid=str(row.get("certs_valid") or "").lower(),
                                    ip=ip, user_id=user_id, project_id=project_id,
                                )
                                stats["certificates_merged"] += 1
                                stats["relationships_created"] += 1

                            # --- Subdomain node ---
                            # FOFA host may carry port suffix (e.g. "sub.example.com:8080") — strip it
                            host_raw = (row.get("host") or "").strip()
                            host = host_raw.split(":")[0] if ":" in host_raw else host_raw
                            if host and domain and host != ip and (
                                host == domain or host.endswith("." + domain)
                            ):
                                session.run(
                                    """
                                    MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET s.status = 'unverified', s.discovered_at = datetime(), s.updated_at = datetime()
                                    SET s.source = 'fofa', s.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (s)-[:RESOLVES_TO {record_type: 'A', timestamp: datetime()}]->(i)
                                    """,
                                    name=host, ip=ip, user_id=user_id, project_id=project_id,
                                )
                                stats["subdomains_merged"] += 1
                                stats["relationships_created"] += 1
                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                    MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                    """,
                                    name=host, domain=domain, user_id=user_id, project_id=project_id,
                                )
                                stats["relationships_created"] += 1
                        except Exception as e:
                            stats["errors"].append(f"FOFA row {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_fofa: {e}")
        print(f"[graph-db] update_graph_from_fofa complete: {stats}")
        return stats

    def update_graph_from_otx(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0,
            "subdomains_merged": 0,
            "external_domains_merged": 0,
            "domains_updated": 0,
            "threat_pulses_merged": 0,
            "malware_merged": 0,
            "relationships_created": 0,
            "errors": [],
        }
        try:
            otx = recon_data.get("otx") or {}
            reports = otx.get("ip_reports") or []
            domain = recon_data.get("domain", "") or ""
            dr = otx.get("domain_report")
            if not reports and not (dr and isinstance(dr, dict) and dr.get("domain")):
                stats["errors"].append("No otx ip_reports or domain_report in recon_data")
                print(f"[graph-db] update_graph_from_otx complete: {stats}")
                return stats

            with self.driver.session() as session:
                # ── IP reports ──────────────────────────────────────────────
                for rep in reports:
                    if not isinstance(rep, dict):
                        continue
                    ip = rep.get("ip")
                    if not ip:
                        continue
                    try:
                        geo = rep.get("geo") or {}
                        pulse_details = rep.get("pulse_details") or {}
                        session.run(
                            """
                            MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            SET i.otx_enriched = true,
                                i.otx_pulse_count = $pulse,
                                i.otx_reputation = $reputation,
                                i.otx_url_count = $url_count,
                                i.otx_adversaries = $adversaries,
                                i.otx_malware_families = $malware_families,
                                i.otx_tlp = $tlp,
                                i.otx_attack_ids = $attack_ids,
                                i.country_name = CASE WHEN i.country_name IS NULL OR i.country_name = '' THEN $country_name ELSE i.country_name END,
                                i.city = CASE WHEN i.city IS NULL OR i.city = '' THEN $city ELSE i.city END,
                                i.asn = CASE WHEN i.asn IS NULL OR i.asn = '' THEN $asn ELSE i.asn END,
                                i.updated_at = datetime()
                            """,
                            address=ip, user_id=user_id, project_id=project_id,
                            pulse=rep.get("pulse_count"),
                            reputation=rep.get("reputation"),
                            url_count=rep.get("url_count", 0),
                            adversaries=pulse_details.get("adversaries") or [],
                            malware_families=pulse_details.get("malware_families") or [],
                            tlp=pulse_details.get("tlp") or "",
                            attack_ids=pulse_details.get("attack_ids") or [],
                            country_name=geo.get("country_name") or "",
                            city=geo.get("city") or "",
                            asn=geo.get("asn") or "",
                        )
                        stats["ips_enriched"] += 1

                        # ── passive DNS hostnames ────────────────────────
                        pdns_records = rep.get("passive_dns") or []
                        # Fallback to legacy hostname list if new format absent
                        if not pdns_records:
                            pdns_records = [
                                {"hostname": h, "first": "", "last": "", "record_type": ""}
                                for h in (rep.get("passive_dns_hostnames") or [])
                            ]

                        for rec in pdns_records:
                            if not isinstance(rec, dict):
                                continue
                            hostname = rec.get("hostname") or ""
                            if not hostname:
                                continue
                            record_type = rec.get("record_type") or "A"
                            first_seen = rec.get("first") or ""
                            last_seen = rec.get("last") or ""

                            if domain and (hostname == domain or hostname.endswith("." + domain)):
                                # In-scope → Subdomain node
                                try:
                                    session.run(
                                        """
                                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET s.discovered_at = datetime(), s.updated_at = datetime()
                                        SET s.source = 'otx_passive_dns', s.status = 'unverified', s.updated_at = datetime()
                                        WITH s
                                        MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[r:RESOLVES_TO {record_type: $record_type}]->(i)
                                        ON CREATE SET r.first_seen = $first_seen, r.last_seen = $last_seen, r.timestamp = datetime()
                                        SET r.last_seen = CASE WHEN $last_seen <> '' THEN $last_seen ELSE r.last_seen END
                                        """,
                                        name=hostname, ip=ip, user_id=user_id, project_id=project_id,
                                        record_type=record_type, first_seen=first_seen, last_seen=last_seen,
                                    )
                                    stats["subdomains_merged"] += 1
                                    stats["relationships_created"] += 1
                                    if domain:
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                            MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                            MERGE (s)-[:BELONGS_TO]->(d)
                                            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                            """,
                                            name=hostname, domain=domain, user_id=user_id, project_id=project_id,
                                        )
                                        stats["relationships_created"] += 1
                                except Exception as e2:
                                    stats["errors"].append(f"OTX pdns in-scope {hostname}: {e2}")
                            elif hostname and "@" not in hostname:
                                # Out-of-scope → ExternalDomain node
                                try:
                                    session.run(
                                        """
                                        MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET ed.first_seen_at = datetime()
                                        SET ed.sources = coalesce(ed.sources, []) + CASE WHEN NOT 'otx_passive_dns' IN coalesce(ed.sources, []) THEN ['otx_passive_dns'] ELSE [] END,
                                            ed.ips_seen = coalesce(ed.ips_seen, []) + CASE WHEN NOT $ip IN coalesce(ed.ips_seen, []) THEN [$ip] ELSE [] END,
                                            ed.updated_at = datetime()
                                        WITH ed
                                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                        MERGE (d)-[:HAS_EXTERNAL_DOMAIN]->(ed)
                                        """,
                                        ed_domain=hostname, ip=ip, domain=domain,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["external_domains_merged"] += 1
                                    stats["relationships_created"] += 1
                                except Exception as e2:
                                    stats["errors"].append(f"OTX pdns external {hostname}: {e2}")

                        # ── Malware samples ──────────────────────────────
                        for sample in rep.get("malware") or []:
                            if not isinstance(sample, dict):
                                continue
                            h = sample.get("hash")
                            if not h:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (m:Malware {hash: $hash, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET m.first_seen = datetime()
                                    SET m.hash_type = $hash_type,
                                        m.file_type = $file_type,
                                        m.file_name = $file_name,
                                        m.source = 'otx',
                                        m.updated_at = datetime()
                                    WITH m
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:ASSOCIATED_WITH_MALWARE]->(m)
                                    """,
                                    hash=h, user_id=user_id, project_id=project_id,
                                    hash_type=sample.get("hash_type") or "",
                                    file_type=sample.get("file_type") or "",
                                    file_name=sample.get("file_name") or "",
                                    ip=ip,
                                )
                                stats["malware_merged"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX malware {h} (ip {ip}): {e2}")

                        # ── ThreatPulse nodes ────────────────────────────
                        for pulse in (pulse_details.get("pulses") or []):
                            if not isinstance(pulse, dict):
                                continue
                            pulse_id = pulse.get("pulse_id") or ""
                            if not pulse_id:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (tp:ThreatPulse {pulse_id: $pulse_id, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET tp.created_at = datetime()
                                    SET tp.name = $name,
                                        tp.adversary = $adversary,
                                        tp.malware_families = $malware_families,
                                        tp.attack_ids = $attack_ids,
                                        tp.tags = $tags,
                                        tp.tlp = $tlp,
                                        tp.author_name = $author_name,
                                        tp.targeted_countries = $targeted_countries,
                                        tp.modified = $modified,
                                        tp.updated_at = datetime()
                                    WITH tp
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:APPEARS_IN_PULSE]->(tp)
                                    """,
                                    pulse_id=pulse_id, user_id=user_id, project_id=project_id,
                                    name=pulse.get("name") or "",
                                    adversary=pulse.get("adversary") or "",
                                    malware_families=pulse.get("malware_families") or [],
                                    attack_ids=pulse.get("attack_ids") or [],
                                    tags=pulse.get("tags") or [],
                                    tlp=pulse.get("tlp") or "",
                                    author_name=pulse.get("author_name") or "",
                                    targeted_countries=pulse.get("targeted_countries") or [],
                                    modified=pulse.get("modified") or "",
                                    ip=ip,
                                )
                                stats["threat_pulses_merged"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX ThreatPulse {pulse_id} (ip {ip}): {e2}")

                    except Exception as e:
                        stats["errors"].append(f"OTX IP {ip}: {e}")

                # ── Domain report ────────────────────────────────────────
                if dr and isinstance(dr, dict) and dr.get("domain"):
                    try:
                        dom_name = dr["domain"]
                        dom_pulse_details = dr.get("pulse_details") or {}
                        whois = dr.get("whois") or {}

                        # Safely extract registrar/nameservers from OTX whois dict
                        registrar = str(whois.get("registrar") or "")
                        raw_ns = whois.get("nameservers") or []
                        nameservers = raw_ns if isinstance(raw_ns, list) else [str(raw_ns)]
                        registrant_email = str(whois.get("registrant_email") or whois.get("emails") or "")

                        session.run(
                            """
                            MATCH (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                            SET d.otx_pulse_count = $pulse,
                                d.otx_url_count = $url_count,
                                d.otx_adversaries = $adversaries,
                                d.otx_malware_families = $malware_families,
                                d.otx_tlp = $tlp,
                                d.otx_attack_ids = $attack_ids,
                                d.registrar = CASE WHEN d.registrar IS NULL OR d.registrar = '' THEN $registrar ELSE d.registrar END,
                                d.name_servers = CASE WHEN d.name_servers IS NULL OR size(d.name_servers) = 0 THEN $nameservers ELSE d.name_servers END,
                                d.updated_at = datetime()
                            """,
                            name=dom_name, user_id=user_id, project_id=project_id,
                            pulse=dr.get("pulse_count"),
                            url_count=dr.get("url_count", 0),
                            adversaries=dom_pulse_details.get("adversaries") or [],
                            malware_families=dom_pulse_details.get("malware_families") or [],
                            tlp=dom_pulse_details.get("tlp") or "",
                            attack_ids=dom_pulse_details.get("attack_ids") or [],
                            registrar=registrar,
                            nameservers=nameservers,
                        )
                        stats["domains_updated"] += 1

                        # ── Domain malware samples ───────────────────────
                        for sample in dr.get("malware") or []:
                            if not isinstance(sample, dict):
                                continue
                            h = sample.get("hash")
                            if not h:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (m:Malware {hash: $hash, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET m.first_seen = datetime()
                                    SET m.hash_type = $hash_type,
                                        m.file_type = $file_type,
                                        m.file_name = $file_name,
                                        m.source = 'otx',
                                        m.updated_at = datetime()
                                    WITH m
                                    MATCH (d:Domain {name: $dom_name, user_id: $user_id, project_id: $project_id})
                                    MERGE (d)-[:ASSOCIATED_WITH_MALWARE]->(m)
                                    """,
                                    hash=h, user_id=user_id, project_id=project_id,
                                    hash_type=sample.get("hash_type") or "",
                                    file_type=sample.get("file_type") or "",
                                    file_name=sample.get("file_name") or "",
                                    dom_name=dom_name,
                                )
                                stats["malware_merged"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX domain malware {h}: {e2}")

                        # ── Domain ThreatPulse nodes ─────────────────────
                        for pulse in (dom_pulse_details.get("pulses") or []):
                            if not isinstance(pulse, dict):
                                continue
                            pulse_id = pulse.get("pulse_id") or ""
                            if not pulse_id:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (tp:ThreatPulse {pulse_id: $pulse_id, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET tp.created_at = datetime()
                                    SET tp.name = $name,
                                        tp.adversary = $adversary,
                                        tp.malware_families = $malware_families,
                                        tp.attack_ids = $attack_ids,
                                        tp.tags = $tags,
                                        tp.tlp = $tlp,
                                        tp.author_name = $author_name,
                                        tp.targeted_countries = $targeted_countries,
                                        tp.modified = $modified,
                                        tp.updated_at = datetime()
                                    WITH tp
                                    MATCH (d:Domain {name: $dom_name, user_id: $user_id, project_id: $project_id})
                                    MERGE (d)-[:APPEARS_IN_PULSE]->(tp)
                                    """,
                                    pulse_id=pulse_id, user_id=user_id, project_id=project_id,
                                    name=pulse.get("name") or "",
                                    adversary=pulse.get("adversary") or "",
                                    malware_families=pulse.get("malware_families") or [],
                                    attack_ids=pulse.get("attack_ids") or [],
                                    tags=pulse.get("tags") or [],
                                    tlp=pulse.get("tlp") or "",
                                    author_name=pulse.get("author_name") or "",
                                    targeted_countries=pulse.get("targeted_countries") or [],
                                    modified=pulse.get("modified") or "",
                                    dom_name=dom_name,
                                )
                                stats["threat_pulses_merged"] += 1
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX domain ThreatPulse {pulse_id}: {e2}")

                        # ── Domain historical IPs (domain/passive_dns) ───
                        for hist in dr.get("historical_ips") or []:
                            if not isinstance(hist, dict):
                                continue
                            addr = hist.get("address")
                            if not addr:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET i.created_at = datetime()
                                    SET i.updated_at = datetime()
                                    WITH i
                                    MATCH (d:Domain {name: $dom_name, user_id: $user_id, project_id: $project_id})
                                    MERGE (d)-[r:HISTORICALLY_RESOLVED_TO]->(i)
                                    ON CREATE SET r.first_seen = $first_seen, r.last_seen = $last_seen, r.record_type = $record_type
                                    """,
                                    address=addr, dom_name=dom_name,
                                    user_id=user_id, project_id=project_id,
                                    first_seen=hist.get("first") or "",
                                    last_seen=hist.get("last") or "",
                                    record_type=hist.get("record_type") or "A",
                                )
                                stats["relationships_created"] += 1
                            except Exception as e2:
                                stats["errors"].append(f"OTX hist IP {addr}: {e2}")

                    except Exception as e:
                        stats["errors"].append(f"OTX domain_report: {e}")

        except Exception as e:
            stats["errors"].append(f"update_graph_from_otx: {e}")
        print(f"[graph-db] update_graph_from_otx complete: {stats}")
        return stats

    def update_graph_from_netlas(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0, "ports_merged": 0, "services_merged": 0,
            "vulnerabilities_merged": 0, "relationships_created": 0, "errors": [],
        }
        try:
            rows = (recon_data.get("netlas") or {}).get("results") or []
            if not rows:
                stats["errors"].append("No netlas results in recon_data")
            else:
                with self.driver.session() as session:
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        ip = row.get("ip")
                        if not ip:
                            continue
                        try:
                            # --- IP node enrichment ---
                            ip_props: dict = {"netlas_enriched": True}
                            for src, dst in (
                                ("isp",        "isp"),
                                ("country",    "country"),
                                ("city",       "city"),
                                ("timezone",   "timezone"),
                                ("asn_name",   "asn_org"),
                                ("asn_number", "asn"),
                                ("asn_route",  "asn_bgp_prefix"),
                            ):
                                v = row.get(src)
                                if v:
                                    ip_props[dst] = v
                            lat = row.get("latitude")
                            lon = row.get("longitude")
                            if lat is not None:
                                ip_props["latitude"] = lat
                            if lon is not None:
                                ip_props["longitude"] = lon

                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            # --- Port node ---
                            port_raw = row.get("port")
                            try:
                                pnum = int(port_raw) if port_raw is not None else 0
                            except (TypeError, ValueError):
                                pnum = 0
                            if not pnum:
                                continue
                            proto = (row.get("protocol") or "tcp")
                            protocol = (proto.lower() if isinstance(proto, str) else "tcp") or "tcp"
                            session.run(
                                """
                                MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                               user_id: $user_id, project_id: $project_id})
                                ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                SET p.source = 'netlas', p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                port=pnum, protocol=protocol, ip=ip, user_id=user_id, project_id=project_id,
                            )
                            stats["ports_merged"] += 1
                            stats["relationships_created"] += 1

                            # --- Service node (enriched) ---
                            prot_name = (row.get("protocol") or "").strip()
                            if prot_name:
                                svc_props: dict = {"source": "netlas"}
                                title = row.get("title") or ""
                                if title:
                                    svc_props["http_title"] = title
                                http_sc = row.get("http_status_code")
                                if http_sc is not None:
                                    try:
                                        svc_props["http_status_code"] = int(http_sc)
                                    except (TypeError, ValueError):
                                        pass
                                banner = row.get("banner") or ""
                                if banner:
                                    svc_props["banner"] = banner
                                session.run(
                                    """
                                    MERGE (svc:Service {name: $name, port_number: $port, ip_address: $ip,
                                                        user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET svc.updated_at = datetime()
                                    SET svc += $props, svc.updated_at = datetime()
                                    WITH svc
                                    MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    MERGE (p)-[:RUNS_SERVICE]->(svc)
                                    """,
                                    name=prot_name, port=pnum, protocol=protocol, ip=ip,
                                    user_id=user_id, project_id=project_id, props=svc_props,
                                )
                                stats["services_merged"] += 1
                                stats["relationships_created"] += 1

                                # --- CVE Vulnerability nodes ---
                                for cve in (row.get("cve_list") or []):
                                    if not isinstance(cve, dict):
                                        continue
                                    cve_id = cve.get("id") or ""
                                    if not cve_id:
                                        continue
                                    try:
                                        vuln_props: dict = {
                                            "source": "netlas",
                                            "name": cve_id,
                                        }
                                        severity = cve.get("severity") or ""
                                        if severity:
                                            vuln_props["severity"] = severity
                                        base_score = cve.get("base_score")
                                        if base_score is not None:
                                            try:
                                                vuln_props["cvss_score"] = float(base_score)
                                            except (TypeError, ValueError):
                                                pass
                                        vuln_props["has_exploit"] = bool(cve.get("has_exploit", False))
                                        session.run(
                                            """
                                            MERGE (v:Vulnerability {id: $cve_id,
                                                                     user_id: $user_id,
                                                                     project_id: $project_id})
                                            ON CREATE SET v.created_at = datetime()
                                            SET v += $props, v.updated_at = datetime()
                                            WITH v
                                            MATCH (svc:Service {name: $svc_name, port_number: $port,
                                                                ip_address: $ip,
                                                                user_id: $user_id,
                                                                project_id: $project_id})
                                            MERGE (svc)-[:HAS_VULNERABILITY]->(v)
                                            """,
                                            cve_id=cve_id, user_id=user_id, project_id=project_id,
                                            props=vuln_props, svc_name=prot_name, port=pnum, ip=ip,
                                        )
                                        stats["vulnerabilities_merged"] += 1
                                        stats["relationships_created"] += 1
                                    except Exception as e:
                                        stats["errors"].append(f"Netlas CVE {cve_id} on {ip}:{pnum}: {e}")

                        except Exception as e:
                            stats["errors"].append(f"Netlas row {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_netlas: {e}")
        print(f"[graph-db] update_graph_from_netlas complete: {stats}")
        return stats

    def update_graph_from_virustotal(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {"domains_updated": 0, "ips_enriched": 0, "errors": []}
        try:
            vt = recon_data.get("virustotal") or {}
            dr = vt.get("domain_report")
            reports = vt.get("ip_reports") or []
            if dr is None and not reports:
                stats["errors"].append("No virustotal domain_report or ip_reports in recon_data")
            else:
                with self.driver.session() as session:
                    if dr and isinstance(dr, dict) and dr.get("domain"):
                        try:
                            _ast = (dr.get("analysis_stats") or {}) if isinstance(dr.get("analysis_stats"), dict) else {}
                            cats = dr.get("categories")
                            cats_stored = json.dumps(cats) if cats is not None else None
                            votes = dr.get("total_votes") or {}
                            session.run(
                                """
                                MATCH (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                                SET d.vt_enriched = true,
                                    d.vt_reputation = $reputation,
                                    d.vt_malicious_count = $malicious,
                                    d.vt_suspicious_count = $suspicious,
                                    d.vt_harmless_count = $harmless,
                                    d.vt_undetected_count = $undetected,
                                    d.vt_categories = $categories,
                                    d.vt_registrar = $registrar,
                                    d.vt_tags = $tags,
                                    d.vt_community_malicious = $community_malicious,
                                    d.vt_community_harmless = $community_harmless,
                                    d.vt_last_analysis_date = $last_analysis_date,
                                    d.vt_jarm = $jarm,
                                    d.vt_popularity_alexa = $popularity_alexa,
                                    d.vt_popularity_umbrella = $popularity_umbrella,
                                    d.updated_at = datetime()
                                """,
                                name=dr["domain"], user_id=user_id, project_id=project_id,
                                reputation=dr.get("reputation"),
                                malicious=_ast.get("malicious"),
                                suspicious=_ast.get("suspicious"),
                                harmless=_ast.get("harmless"),
                                undetected=_ast.get("undetected"),
                                categories=cats_stored,
                                registrar=dr.get("registrar"),
                                tags=dr.get("tags") or [],
                                community_malicious=votes.get("malicious"),
                                community_harmless=votes.get("harmless"),
                                last_analysis_date=dr.get("last_analysis_date"),
                                jarm=dr.get("jarm"),
                                popularity_alexa=dr.get("popularity_alexa"),
                                popularity_umbrella=dr.get("popularity_umbrella"),
                            )
                            stats["domains_updated"] += 1
                        except Exception as e:
                            stats["errors"].append(f"VirusTotal domain_report: {e}")
                    for rep in reports:
                        if not isinstance(rep, dict):
                            continue
                        ip = rep.get("ip")
                        if not ip:
                            continue
                        try:
                            _ast = (rep.get("analysis_stats") or {}) if isinstance(rep.get("analysis_stats"), dict) else {}
                            votes = rep.get("total_votes") or {}
                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i.vt_enriched = true,
                                    i.vt_reputation = $reputation,
                                    i.vt_malicious_count = $malicious,
                                    i.vt_suspicious_count = $suspicious,
                                    i.vt_harmless_count = $harmless,
                                    i.vt_undetected_count = $undetected,
                                    i.vt_tags = $tags,
                                    i.vt_community_malicious = $community_malicious,
                                    i.vt_community_harmless = $community_harmless,
                                    i.vt_last_analysis_date = $last_analysis_date,
                                    i.vt_network = $network,
                                    i.vt_rir = $rir,
                                    i.vt_continent = $continent,
                                    i.vt_jarm = $jarm,
                                    i.asn = CASE WHEN i.asn IS NOT NULL THEN i.asn ELSE $asn END,
                                    i.as_owner = CASE WHEN i.as_owner IS NOT NULL THEN i.as_owner ELSE $as_owner END,
                                    i.country = CASE WHEN i.country IS NOT NULL THEN i.country ELSE $country END,
                                    i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id,
                                reputation=rep.get("reputation"),
                                malicious=_ast.get("malicious"),
                                suspicious=_ast.get("suspicious"),
                                harmless=_ast.get("harmless"),
                                undetected=_ast.get("undetected"),
                                tags=rep.get("tags") or [],
                                community_malicious=votes.get("malicious"),
                                community_harmless=votes.get("harmless"),
                                last_analysis_date=rep.get("last_analysis_date"),
                                network=rep.get("network"),
                                rir=rep.get("regional_internet_registry"),
                                continent=rep.get("continent"),
                                jarm=rep.get("jarm"),
                                asn=rep.get("asn"),
                                as_owner=rep.get("as_owner"),
                                country=rep.get("country"),
                            )
                            stats["ips_enriched"] += 1
                        except Exception as e:
                            stats["errors"].append(f"VirusTotal IP {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_virustotal: {e}")
        print(f"[graph-db] update_graph_from_virustotal complete: {stats}")
        return stats

    def update_graph_from_zoomeye(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {"ips_enriched": 0, "ports_merged": 0, "services_merged": 0,
                 "subdomains_merged": 0, "relationships_created": 0, "errors": []}
        try:
            rows = (recon_data.get("zoomeye") or {}).get("results") or []
            domain = recon_data.get("domain", "")
            if not rows:
                stats["errors"].append("No zoomeye results in recon_data")
            else:
                with self.driver.session() as session:
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        ip = row.get("ip")
                        if not ip:
                            continue
                        try:
                            # Build IP props dict — only set non-empty values to avoid
                            # overwriting richer data from other tools with empty strings
                            ip_props: dict = {"zoomeye_enriched": True}
                            for field, prop in (
                                ("os",          "os"),
                                ("country",     "country"),
                                ("city",        "city"),
                                ("isp",         "isp"),
                                ("asn",         "asn"),
                                ("update_time", "zoomeye_last_seen"),
                            ):
                                val = row.get(field)
                                if val:
                                    ip_props[prop] = val
                            lat = row.get("latitude")
                            lon = row.get("longitude")
                            if lat is not None:
                                ip_props["latitude"] = lat
                            if lon is not None:
                                ip_props["longitude"] = lon

                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            port_raw = row.get("port")
                            try:
                                pnum = int(port_raw) if port_raw is not None else 0
                            except (TypeError, ValueError):
                                pnum = 0
                            if not pnum:
                                # Even without a port, try hostname/rdns → Subdomain
                                pass
                            else:
                                protocol = (row.get("protocol") or "tcp").lower() or "tcp"
                                session.run(
                                    """
                                    MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                    SET p.source = 'zoomeye', p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_PORT]->(p)
                                    """,
                                    port=pnum, protocol=protocol, ip=ip,
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["ports_merged"] += 1
                                stats["relationships_created"] += 1

                                # Service node — use app name; fall back to service field
                                svc_name = (row.get("app") or row.get("service") or "").strip()
                                if svc_name:
                                    svc_props: dict = {"source": "zoomeye"}
                                    banner = (row.get("banner") or "")[:500]
                                    if banner:
                                        svc_props["banner"] = banner
                                    version = (row.get("version") or "").strip()
                                    if version:
                                        svc_props["version"] = version
                                    product = (row.get("product") or "").strip()
                                    if product:
                                        svc_props["product"] = product
                                    title = (row.get("title") or "").strip()
                                    if title:
                                        svc_props["http_title"] = title
                                    session.run(
                                        """
                                        MERGE (svc:Service {name: $name, port_number: $port,
                                                            ip_address: $ip,
                                                            user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET svc.updated_at = datetime()
                                        SET svc += $props, svc.updated_at = datetime()
                                        WITH svc
                                        MATCH (p:Port {number: $port, protocol: $protocol,
                                                       ip_address: $ip,
                                                       user_id: $user_id, project_id: $project_id})
                                        MERGE (p)-[:RUNS_SERVICE]->(svc)
                                        """,
                                        name=svc_name, port=pnum, protocol=protocol, ip=ip,
                                        props=svc_props, user_id=user_id, project_id=project_id,
                                    )
                                    stats["services_merged"] += 1
                                    stats["relationships_created"] += 1

                            # Hostname / rDNS → Subdomain node (in-scope only)
                            for hostname_val in {row.get("hostname"), row.get("rdns")}:
                                if not hostname_val:
                                    continue
                                hostname_val = hostname_val.strip().lower()
                                if not hostname_val:
                                    continue
                                is_in_scope = domain and (
                                    hostname_val == domain
                                    or hostname_val.endswith("." + domain)
                                )
                                if is_in_scope:
                                    session.run(
                                        """
                                        MERGE (s:Subdomain {name: $name, user_id: $user_id,
                                                            project_id: $project_id})
                                        ON CREATE SET s.source = 'zoomeye_rdns',
                                                      s.status = 'resolved',
                                                      s.discovered_at = datetime(),
                                                      s.updated_at = datetime()
                                        MERGE (i:IP {address: $ip, user_id: $user_id,
                                                     project_id: $project_id})
                                        MERGE (s)-[:RESOLVES_TO {record_type: 'A',
                                                                  timestamp: datetime()}]->(i)
                                        """,
                                        name=hostname_val, ip=ip,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["subdomains_merged"] += 1
                                    stats["relationships_created"] += 1

                        except Exception as e:
                            stats["errors"].append(f"ZoomEye row {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_zoomeye: {e}")
        print(f"[graph-db] update_graph_from_zoomeye complete: {stats}")
        return stats

    def update_graph_from_criminalip(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        stats = {
            "ips_enriched": 0, "ports_merged": 0, "services_created": 0,
            "vulnerabilities_created": 0, "cves_created": 0,
            "domains_updated": 0, "relationships_created": 0, "errors": [],
        }
        try:
            cip = recon_data.get("criminalip") or {}
            reports = cip.get("ip_reports") or []
            domain_report = cip.get("domain_report")

            if not reports and not domain_report:
                stats["errors"].append("No criminalip data in recon_data")
            else:
                with self.driver.session() as session:
                    # ── 1. Domain report → Domain node enrichment ──
                    if domain_report and isinstance(domain_report, dict):
                        domain_name = domain_report.get("domain")
                        risk = domain_report.get("risk") or {}
                        if domain_name and isinstance(risk, dict):
                            try:
                                session.run(
                                    """
                                    MATCH (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                                    SET d.criminalip_enriched = true,
                                        d.criminalip_risk_score = $risk_score,
                                        d.criminalip_risk_grade = $risk_grade,
                                        d.criminalip_abuse_count = $abuse_count,
                                        d.criminalip_current_service = $current_service,
                                        d.updated_at = datetime()
                                    """,
                                    name=domain_name, user_id=user_id, project_id=project_id,
                                    risk_score=risk.get("score"),
                                    risk_grade=risk.get("grade"),
                                    abuse_count=risk.get("abuse_record_count"),
                                    current_service=risk.get("current_service"),
                                )
                                stats["domains_updated"] += 1
                            except Exception as e:
                                stats["errors"].append(f"CriminalIP domain_report: {e}")

                    # ── 2. Per-IP reports ──
                    for rep in reports:
                        if not isinstance(rep, dict):
                            continue
                        ip = rep.get("ip")
                        if not ip:
                            continue
                        try:
                            score = rep.get("score") or {}
                            if not isinstance(score, dict):
                                score = {}
                            issues = rep.get("issues") or {}
                            if not isinstance(issues, dict):
                                issues = {}
                            whois = rep.get("whois") or {}
                            if not isinstance(whois, dict):
                                whois = {}

                            ip_props: dict = {"criminalip_enriched": True}

                            # Scores
                            ins, outs = score.get("inbound"), score.get("outbound")
                            if ins is not None:
                                ip_props["criminalip_score_inbound"] = ins
                            if outs is not None:
                                ip_props["criminalip_score_outbound"] = outs

                            # Boolean threat flags
                            for fk, dk in (
                                ("is_vpn",     "criminalip_is_vpn"),
                                ("is_proxy",   "criminalip_is_proxy"),
                                ("is_tor",     "criminalip_is_tor"),
                                ("is_hosting", "criminalip_is_hosting"),
                                ("is_cloud",   "criminalip_is_cloud"),
                                ("is_mobile",  "criminalip_is_mobile"),
                                ("is_darkweb", "criminalip_is_darkweb"),
                                ("is_scanner", "criminalip_is_scanner"),
                                ("is_snort",   "criminalip_is_snort"),
                            ):
                                if fk in issues:
                                    ip_props[dk] = issues[fk]

                            # Whois / geolocation / ASN
                            for fk, dk in (
                                ("org_name",    "criminalip_org_name"),
                                ("country",     "criminalip_country"),
                                ("city",        "criminalip_city"),
                                ("latitude",    "criminalip_latitude"),
                                ("longitude",   "criminalip_longitude"),
                                ("asn_name",    "criminalip_asn_name"),
                                ("asn_no",      "criminalip_asn_no"),
                            ):
                                val = whois.get(fk)
                                if val is not None:
                                    ip_props[dk] = val

                            # IDS / scanning counts and categories
                            ids_count = rep.get("ids_count")
                            if ids_count is not None:
                                ip_props["criminalip_ids_count"] = ids_count
                            scanning_count = rep.get("scanning_count")
                            if scanning_count is not None:
                                ip_props["criminalip_scanning_count"] = scanning_count
                            categories = rep.get("categories")
                            if categories:
                                ip_props["criminalip_categories"] = json.dumps(categories)

                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i += $props, i.updated_at = datetime()
                                """,
                                address=ip, user_id=user_id, project_id=project_id, props=ip_props,
                            )
                            stats["ips_enriched"] += 1

                            # ── 3. Ports + Services ──
                            for pentry in rep.get("ports") or []:
                                if not isinstance(pentry, dict):
                                    continue
                                try:
                                    pnum = int(pentry.get("port") or 0)
                                except (TypeError, ValueError):
                                    continue
                                if pnum <= 0:
                                    continue
                                proto = (pentry.get("socket") or "tcp").lower()
                                session.run(
                                    """
                                    MERGE (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                   user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET p.state = 'open', p.updated_at = datetime()
                                    SET p.source = 'criminalip', p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_PORT]->(p)
                                    """,
                                    port=pnum, protocol=proto, ip=ip,
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["ports_merged"] += 1
                                stats["relationships_created"] += 1

                                app_name = pentry.get("app_name")
                                if app_name:
                                    svc_name = app_name.lower()
                                    session.run(
                                        """
                                        MERGE (svc:Service {name: $svc_name, port_number: $port,
                                                            ip_address: $ip, user_id: $user_id,
                                                            project_id: $project_id})
                                        SET svc.source = 'criminalip',
                                            svc.version = $version,
                                            svc.banner  = $banner,
                                            svc.updated_at = datetime()
                                        WITH svc
                                        MATCH (p:Port {number: $port, protocol: $protocol, ip_address: $ip,
                                                       user_id: $user_id, project_id: $project_id})
                                        MERGE (p)-[:RUNS_SERVICE]->(svc)
                                        """,
                                        svc_name=svc_name, port=pnum, protocol=proto, ip=ip,
                                        version=pentry.get("app_version"),
                                        banner=(pentry.get("banner") or "")[:500] or None,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["services_created"] += 1
                                    stats["relationships_created"] += 1

                            # ── 4. Vulnerabilities (CVE data from full=true) ──
                            for vuln in rep.get("vulnerabilities") or []:
                                if not isinstance(vuln, dict):
                                    continue
                                cve_id = vuln.get("cve_id")
                                if not cve_id:
                                    continue
                                vuln_id = f"criminalip-{cve_id}-{ip}"
                                try:
                                    cvss = vuln.get("cvssv3_score") or vuln.get("cvssv2_score")
                                    session.run(
                                        """
                                        MERGE (v:Vulnerability {id: $vuln_id})
                                        ON CREATE SET v.source = 'criminalip', v.name = $cve_id,
                                                      v.cves = [$cve_id], v.cvss = $cvss,
                                                      v.user_id = $user_id, v.project_id = $project_id,
                                                      v.updated_at = datetime()
                                        """,
                                        vuln_id=vuln_id, cve_id=cve_id, cvss=cvss,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["vulnerabilities_created"] += 1

                                    session.run(
                                        """
                                        MERGE (c:CVE {id: $cve_id})
                                        ON CREATE SET c.source = 'criminalip',
                                                      c.user_id = $user_id, c.project_id = $project_id,
                                                      c.updated_at = datetime()
                                        SET c.cvss = $cvss, c.description = $description
                                        """,
                                        cve_id=cve_id, cvss=cvss,
                                        description=vuln.get("description"),
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["cves_created"] += 1

                                    session.run(
                                        """
                                        MATCH (v:Vulnerability {id: $vuln_id})
                                        MATCH (c:CVE {id: $cve_id})
                                        MERGE (v)-[:INCLUDES_CVE]->(c)
                                        """,
                                        vuln_id=vuln_id, cve_id=cve_id,
                                    )
                                    session.run(
                                        """
                                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MATCH (v:Vulnerability {id: $vuln_id})
                                        MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                        """,
                                        ip=ip, vuln_id=vuln_id,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["relationships_created"] += 2
                                except Exception as e:
                                    stats["errors"].append(f"CriminalIP CVE {cve_id} for {ip}: {e}")

                        except Exception as e:
                            stats["errors"].append(f"CriminalIP {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_criminalip: {e}")
        print(f"[graph-db] update_graph_from_criminalip complete: {stats}")
        return stats

    def update_graph_from_uncover(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """Update Neo4j graph with uncover target expansion results.

        Creates Subdomain and IP nodes for newly discovered assets.
        Uses ON CREATE SET to avoid overwriting richer data from other tools.
        """
        stats = {
            "subdomains_created": 0, "ips_created": 0,
            "urls_created": 0,
            "relationships_created": 0, "errors": [],
        }
        domain = recon_data.get("domain", "") or ""
        try:
            uncover = recon_data.get("uncover") or {}
            hosts = uncover.get("hosts") or []
            ips = uncover.get("ips") or []
            ip_ports = uncover.get("ip_ports") or {}
            urls = uncover.get("urls") or []
            sources = uncover.get("sources") or []
            source_counts = uncover.get("source_counts") or {}
            total_raw = uncover.get("total_raw", 0)
            total_deduped = uncover.get("total_deduped", 0)

            if not hosts and not ips and not urls:
                return stats

            with self.driver.session() as session:
                for hostname in hosts:
                    if not hostname:
                        continue
                    try:
                        session.run(
                            """
                            MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET s.discovered_at = datetime(), s.updated_at = datetime(),
                                          s.source = 'uncover', s.status = 'unverified'
                            SET s.uncover_sources = $sources,
                                s.uncover_total_raw = $total_raw,
                                s.uncover_total_deduped = $total_deduped
                            """,
                            name=hostname, user_id=user_id, project_id=project_id,
                            sources=sources, total_raw=total_raw, total_deduped=total_deduped,
                        )
                        stats["subdomains_created"] += 1
                        if domain:
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:BELONGS_TO]->(d)
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                """,
                                name=hostname, domain=domain,
                                user_id=user_id, project_id=project_id,
                            )
                            stats["relationships_created"] += 2
                    except Exception as e:
                        stats["errors"].append(f"Uncover subdomain {hostname}: {e}")

                for ip in ips:
                    if not ip:
                        continue
                    try:
                        session.run(
                            """
                            MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET i.updated_at = datetime(), i.uncover_discovered = true
                            SET i.uncover_enriched = true, i.updated_at = datetime(),
                                i.uncover_sources = $sources,
                                i.uncover_source_counts = $source_counts_str,
                                i.uncover_total_raw = $total_raw,
                                i.uncover_total_deduped = $total_deduped
                            """,
                            address=ip, user_id=user_id, project_id=project_id,
                            sources=sources,
                            source_counts_str=str(source_counts),
                            total_raw=total_raw, total_deduped=total_deduped,
                        )
                        stats["ips_created"] += 1

                        # Link IP to Domain (prevents orphaned IP nodes)
                        if domain:
                            session.run(
                                """
                                MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (d)-[:HAS_IP]->(i)
                                """,
                                address=ip, domain=domain,
                                user_id=user_id, project_id=project_id,
                            )
                            stats["relationships_created"] += 1

                        ports = ip_ports.get(ip, [])
                        for port_num in ports:
                            if not port_num or port_num <= 0:
                                continue
                            session.run(
                                """
                                MERGE (p:Port {number: $port, protocol: 'tcp', ip_address: $ip,
                                               user_id: $user_id, project_id: $project_id})
                                ON CREATE SET p.state = 'open', p.source = 'uncover',
                                              p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                port=int(port_num), ip=ip,
                                user_id=user_id, project_id=project_id,
                            )
                            stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Uncover IP {ip}: {e}")

                for url in urls:
                    if not url:
                        continue
                    try:
                        session.run(
                            """
                            MERGE (e:Endpoint {url: $url, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET e.discovered_at = datetime(), e.updated_at = datetime(),
                                          e.source = 'uncover', e.method = 'GET'
                            """,
                            url=url, user_id=user_id, project_id=project_id,
                        )
                        stats["urls_created"] += 1
                        # Link Endpoint to Domain
                        if domain:
                            session.run(
                                """
                                MATCH (e:Endpoint {url: $url, user_id: $user_id, project_id: $project_id})
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (d)-[:HAS_ENDPOINT]->(e)
                                """,
                                url=url, domain=domain,
                                user_id=user_id, project_id=project_id,
                            )
                            stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Uncover URL {url}: {e}")

        except Exception as e:
            stats["errors"].append(f"update_graph_from_uncover: {e}")

        print(f"[+][graph-db] Uncover Graph Update: "
              f"{stats['subdomains_created']} subdomains, "
              f"{stats['ips_created']} IPs, "
              f"{stats['urls_created']} URLs, "
              f"{stats['relationships_created']} relationships")
        print(f"[graph-db] update_graph_from_uncover complete")
        return stats
