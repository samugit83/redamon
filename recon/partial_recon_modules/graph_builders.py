import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import _classify_ip


def _build_recon_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_port_scan expects.

    Returns a dict with 'domain' and 'dns' keys matching the structure
    produced by domain_recon.py (domain IPs + subdomain IPs).
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Query domain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:RESOLVES_TO]->(i:IP)
                RETURN i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])
                recon_data["dns"]["domain"]["ips"][bucket].append(addr)

            if (recon_data["dns"]["domain"]["ips"]["ipv4"]
                    or recon_data["dns"]["domain"]["ips"]["ipv6"]):
                recon_data["dns"]["domain"]["has_records"] = True

            # Query subdomain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[:RESOLVES_TO]->(i:IP)
                RETURN s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                sub = record["subdomain"]
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])

                if sub not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][sub] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                recon_data["dns"]["subdomains"][sub]["ips"][bucket].append(addr)

    return recon_data


def _build_port_scan_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_nmap_scan expects.

    Returns a dict with 'port_scan' key containing by_ip, by_host, and
    ip_to_hostnames structures matching what build_nmap_targets() consumes.
    Also populates a 'dns' section for user-IP linking logic.
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "port_scan": {
            "by_ip": {},
            "by_host": {},
            "ip_to_hostnames": {},
            "all_ports": [],
            "scan_metadata": {"scanners": ["naabu"]},
            "summary": {},
        },
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
    }

    all_ports_set = set()

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Query domain -> IP -> Port relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:RESOLVES_TO]->(i:IP)
                OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                RETURN i.address AS ip, i.version AS version,
                       collect(DISTINCT {number: p.number, protocol: p.protocol}) AS ports
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                ip_addr = record["ip"]
                ip_version = record["version"]
                ports_data = record["ports"]

                # Populate dns section
                bucket = _classify_ip(ip_addr, ip_version)
                if ip_addr not in recon_data["dns"]["domain"]["ips"][bucket]:
                    recon_data["dns"]["domain"]["ips"][bucket].append(ip_addr)
                    recon_data["dns"]["domain"]["has_records"] = True

                # Filter out null ports (from OPTIONAL MATCH when no ports exist)
                port_numbers = []
                port_details = []
                for p in ports_data:
                    if p["number"] is not None:
                        pnum = int(p["number"])
                        port_numbers.append(pnum)
                        all_ports_set.add(pnum)
                        port_details.append({
                            "port": pnum,
                            "protocol": p["protocol"] or "tcp",
                            "service": "",
                        })

                if ip_addr not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_addr] = {
                        "ip": ip_addr,
                        "hostnames": [domain],
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_ip"][ip_addr]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
                if domain not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
                    recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(domain)

                # Populate by_host for domain IPs (build_nmap_targets reads by_host too)
                if domain not in recon_data["port_scan"]["by_host"]:
                    recon_data["port_scan"]["by_host"][domain] = {
                        "host": domain,
                        "ip": ip_addr,
                        "ports": list(port_numbers),
                        "port_details": list(port_details),
                    }
                else:
                    existing = recon_data["port_scan"]["by_host"][domain]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

            # Query subdomain -> IP -> Port relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)
                OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                RETURN s.name AS subdomain, i.address AS ip, i.version AS version,
                       collect(DISTINCT {number: p.number, protocol: p.protocol}) AS ports
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                subdomain = record["subdomain"]
                ip_addr = record["ip"]
                ip_version = record["version"]
                ports_data = record["ports"]

                # Populate dns section
                bucket = _classify_ip(ip_addr, ip_version)
                if subdomain not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][subdomain] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                sub_ips = recon_data["dns"]["subdomains"][subdomain]["ips"]
                if ip_addr not in sub_ips[bucket]:
                    sub_ips[bucket].append(ip_addr)

                # Filter out null ports
                port_numbers = []
                port_details = []
                for p in ports_data:
                    if p["number"] is not None:
                        pnum = int(p["number"])
                        port_numbers.append(pnum)
                        all_ports_set.add(pnum)
                        port_details.append({
                            "port": pnum,
                            "protocol": p["protocol"] or "tcp",
                            "service": "",
                        })

                # Populate by_ip
                if ip_addr not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_addr] = {
                        "ip": ip_addr,
                        "hostnames": [subdomain],
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_ip"][ip_addr]
                    if subdomain not in existing["hostnames"]:
                        existing["hostnames"].append(subdomain)
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                # Populate by_host
                if subdomain not in recon_data["port_scan"]["by_host"]:
                    recon_data["port_scan"]["by_host"][subdomain] = {
                        "host": subdomain,
                        "ip": ip_addr,
                        "ports": port_numbers,
                        "port_details": port_details,
                    }
                else:
                    existing = recon_data["port_scan"]["by_host"][subdomain]
                    for pnum in port_numbers:
                        if pnum not in existing["ports"]:
                            existing["ports"].append(pnum)
                    for pd in port_details:
                        if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                            existing["port_details"].append(pd)

                # Populate ip_to_hostnames
                recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
                if subdomain not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
                    recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(subdomain)

    recon_data["port_scan"]["all_ports"] = sorted(all_ports_set)
    return recon_data


def _build_http_probe_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict for Katana/Hakrawler partial recon.

    Returns a dict with 'http_probe' key containing by_url structure
    (BaseURL -> metadata). Also populates 'domain' and 'subdomains' for
    scope filtering in update_graph_from_resource_enum.
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "subdomains": [],
        "http_probe": {
            "by_url": {},
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Query all BaseURL nodes for this project
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                RETURN b.url AS url, b.status_code AS status_code,
                       b.host AS host, b.content_type AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                status_code = record["status_code"]
                # Skip URLs with server errors (same filter as resource_enum)
                if status_code is not None and int(status_code) >= 500:
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(status_code) if status_code is not None else 200,
                    "content_type": record["content_type"] or "",
                }

            # Get subdomains for scope filtering
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN collect(DISTINCT s.name) AS subdomains
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            record = result.single()
            if record:
                recon_data["subdomains"] = record["subdomains"] or []

    return recon_data


def _build_vuln_scan_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_vuln_scan expects.

    Returns a dict with 'domain', 'dns', 'subdomains', 'http_probe', and
    'resource_enum' keys. The vuln_scan module uses extract_targets_from_recon()
    (needs dns) and build_target_urls() (prefers resource_enum > http_probe).
    """
    from graph_db import Neo4jClient

    recon_data = {
        "domain": domain,
        "subdomains": [],
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "http_probe": {
            "by_url": {},
        },
        "resource_enum": {
            "by_base_url": {},
            "discovered_urls": [],
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # 1) Domain -> IP relationships (for extract_targets_from_recon)
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:RESOLVES_TO]->(i:IP)
                RETURN i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            for record in result:
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])
                recon_data["dns"]["domain"]["ips"][bucket].append(addr)

            if (recon_data["dns"]["domain"]["ips"]["ipv4"]
                    or recon_data["dns"]["domain"]["ips"]["ipv6"]):
                recon_data["dns"]["domain"]["has_records"] = True

            # 2) Subdomain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[:RESOLVES_TO]->(i:IP)
                RETURN s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            subdomain_set = set()
            for record in result:
                sub = record["subdomain"]
                addr = record["address"]
                bucket = _classify_ip(addr, record["version"])
                subdomain_set.add(sub)

                if sub not in recon_data["dns"]["subdomains"]:
                    recon_data["dns"]["subdomains"][sub] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                recon_data["dns"]["subdomains"][sub]["ips"][bucket].append(addr)

            # Also get subdomains without IPs for the subdomains list
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN collect(DISTINCT s.name) AS subdomains
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            record = result.single()
            if record:
                recon_data["subdomains"] = record["subdomains"] or []

            # 3) BaseURL nodes (for build_target_urls http_probe fallback)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                RETURN b.url AS url, b.status_code AS status_code,
                       b.host AS host, b.content_type AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                status_code = record["status_code"]
                if status_code is not None and int(status_code) >= 500:
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(status_code) if status_code is not None else 200,
                    "content_type": record["content_type"] or "",
                }

            # 4) Endpoints with parameters (for DAST mode)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.full_url IS NOT NULL
                RETURN e.full_url AS url
                """,
                uid=user_id, pid=project_id,
            )
            discovered_urls = []
            for record in result:
                url = record["url"]
                if url:
                    discovered_urls.append(url)
            recon_data["resource_enum"]["discovered_urls"] = discovered_urls

    return recon_data


def _build_graphql_data_from_graph(domain: str, user_id: str, project_id: str) -> dict:
    """
    Build recon_data for GraphQL security scanning.

    Populates the three sections discover_graphql_endpoints() reads:
      - http_probe.by_url        (from BaseURL nodes -- headers, status_code)
      - resource_enum.endpoints  ({base_url: [{path, method}]} -- from Endpoint nodes)
      - resource_enum.parameters ({base_url: [{name}]}         -- from Parameter nodes)
      - js_recon.findings        ([{type, path, method}]       -- GraphQL-tagged JsReconFindings)
    Plus metadata.roe so filter_by_roe() still works.
    """
    from graph_db import Neo4jClient
    from recon.project_settings import get_settings

    settings = get_settings()
    recon_data = {
        "domain": domain,
        "http_probe": {"by_url": {}},
        "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
        "js_recon": {"findings": []},
        "metadata": {
            "roe": {
                "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
            }
        },
    }

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # 1) BaseURLs -> http_probe.by_url
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                RETURN b.url AS url,
                       b.host AS host,
                       b.status_code AS status_code,
                       b.content_type AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if not url:
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(record["status_code"]) if record["status_code"] is not None else 200,
                    "content_type": record["content_type"] or "",
                    "headers": {},
                }

            # 2) Endpoints grouped by BaseURL -> resource_enum.endpoints
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.path IS NOT NULL
                RETURN b.url AS base_url,
                       collect(DISTINCT {path: e.path, method: coalesce(e.method, 'GET')}) AS endpoints
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base_url"]
                if base:
                    recon_data["resource_enum"]["endpoints"][base] = list(record["endpoints"] or [])

            # 3) Parameters grouped by BaseURL -> resource_enum.parameters
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                      -[:HAS_PARAMETER]->(p:Parameter)
                WHERE p.name IS NOT NULL
                RETURN b.url AS base_url,
                       collect(DISTINCT {name: p.name}) AS parameters
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base_url"]
                if base:
                    recon_data["resource_enum"]["parameters"][base] = list(record["parameters"] or [])

            # 4) GraphQL-tagged JsReconFindings -> js_recon.findings
            result = session.run(
                """
                MATCH (jr:JsReconFinding {user_id: $uid, project_id: $pid})
                WHERE jr.finding_type IN ['graphql', 'graphql_introspection']
                   OR (jr.finding_type = 'rest' AND toLower(coalesce(jr.path, '')) CONTAINS 'graphql')
                RETURN jr.finding_type AS type,
                       jr.path AS path,
                       coalesce(jr.method, 'POST') AS method
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                path = record["path"]
                if not path:
                    continue
                recon_data["js_recon"]["findings"].append({
                    "type": record["type"] or "rest",
                    "path": path,
                    "method": record["method"] or "POST",
                })

    return recon_data
