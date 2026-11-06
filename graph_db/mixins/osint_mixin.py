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

import logging
import re
import json
from datetime import datetime, timezone

from graph_db.cert_key import build_cert_key
from graph_db.cpe_resolver import _is_ip_address
from graph_db.mixins.recon.scope import (
    IN_SCOPE, OUT_OF_SCOPE, attach_for_host, attach_roots, classify_host, home_domain,
    org_for_scan_root, scope_groups_by_root,
)
from graph_db.mixins.recon.vuln_mixin import stable_vuln_id
from urllib.parse import urlparse as _urlparse
from graph_db.endpoint_paths import normalize_endpoint_path


def _cvss_severity(cvss) -> str | None:
    """CVSS v3 qualitative rating. None when there is no score: a blanket
    severity on an ungraded advisory buries the graded ones."""
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return None


def _shodan_cve_props(cve_entry: dict) -> dict:
    """Properties a Shodan/InternetDB passive CVE carries. Unknown fields are
    left out rather than set to None, which would erase what an earlier,
    better-informed run stored."""
    cve_id = cve_entry.get("cve_id", "")
    cvss = cve_entry.get("cvss")
    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None
    port = cve_entry.get("port")
    props = {
        "name": cve_id,
        "cves": [cve_id],
        # Rows written before this grading carry no detection_method; the
        # Priority Board reads that as a catalog match, which they all were.
        "detection_method": cve_entry.get("detection_method") or "passive_catalog",
        "verified": bool(cve_entry.get("verified")),
        "target_ip": cve_entry.get("ip") or None,
        "target_port": int(port) if isinstance(port, int) or (isinstance(port, str) and port.isdigit()) else None,
        "product": cve_entry.get("product") or None,
        "version": cve_entry.get("version") or None,
        "cvss_score": cvss,
        "severity": _cvss_severity(cvss),
    }
    return {k: v for k, v in props.items() if v is not None}


#: The passive CVE sources whose id ends in the IP (`shodan-<cve>-<ip>`,
#: `criminalip-<cve>-<ip>`). Kept in step with PASSIVE_CVE_SOURCES in
#: recon/helpers/finding_sources.py, which this package cannot import.
_IP_KEYED_PASSIVE_SOURCES = ("shodan_api", "internetdb", "shodan", "shodan_host_lookup",
                             "criminalip")

_PASSIVE_CVE_ID = re.compile(r"^(?:shodan|criminalip)-CVE-\d{4}-\d+-(.+)$", re.IGNORECASE)


def _ip_from_passive_cve_id(vid) -> str | None:
    """The IP a Shodan or CriminalIP CVE's id names, or None."""
    match = _PASSIVE_CVE_ID.match(str(vid or ""))
    if not match:
        return None
    candidate = match.group(1)
    return candidate if _is_ip_address(candidate) else None


_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def netlas_vuln_id(cve_id: str, ip: str, port) -> str:
    """A Netlas finding's id: one per CVE, IP and port."""
    return f"netlas-{cve_id}-{ip}-{port}"


_SEVERITIES = ("info", "low", "medium", "high", "critical")


def _history_severity(severity, live=False) -> str:
    """A finding seen only in urlscan's history is at most high: critical needs
    this scan to confirm it live."""
    sev = str(severity or "medium").strip().lower()
    if sev not in _SEVERITIES:
        sev = "medium"
    return sev if live or sev != "critical" else "high"


def _split_url(url: str) -> tuple[str, str]:
    """(base_url, path), where base_url is scheme://netloc and path defaults to
    '/'. Query and fragment are dropped.

    Endpoint identity is (path, method, baseurl) everywhere in the graph. This
    MUST stay byte-identical to `_split_url` in
    graph_db/mixins/recon/http_mixin.py: the two producing different splits for
    one URL would create a duplicate Endpoint (K23). It is copied rather than
    imported because that module pulls a heavy dependency chain the hand-stubbed
    osint tests do not load.
    """
    parsed = _urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}", normalize_endpoint_path(parsed.path or "/")

# K19: one except block logs through `logger`, which was never defined here, so
# the handler raised NameError while handling an error and took the whole
# ExternalDomain batch with it.
logger = logging.getLogger(__name__)


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

        # `domain` is the scan root this group looked up. A host under any of
        # the project's scan roots is in scope and joins its root's org Domain
        # (attach_for_host); anything else is an ExternalDomain found by `home`.
        domain = recon_data.get("domain", "")
        home = home_domain(recon_data)

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
                            ON CREATE SET p.state = 'open', p.source = 'shodan', p.passive_only = true,
                                          p.updated_at = datetime()
                            ON MATCH SET p.updated_at = datetime()
                            MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                            SET i.updated_at = datetime()
                            MERGE (i)-[:HAS_PORT]->(p)
                            """,
                            port=port_num, protocol=protocol, ip=ip,
                            user_id=user_id, project_id=project_id
                        )
                        stats["ports_created"] += 1
                        stats["relationships_created"] += 1

                        # Certificate from Shodan's per-service ssl block
                        # (Phase 0.6). Free data: Shodan already handshook.
                        ssl_cert = svc.get("ssl") or {}
                        if ssl_cert.get("subject_cn") or ssl_cert.get("fingerprint_sha256"):
                            try:
                                cert_key = build_cert_key(
                                    fingerprint_sha256=ssl_cert.get("fingerprint_sha256"),
                                    subject_cn=ssl_cert.get("subject_cn"),
                                    issuer=ssl_cert.get("issuer"),
                                    not_before=ssl_cert.get("not_before"),
                                    not_after=ssl_cert.get("not_after"),
                                )
                                cert_props = {k: v for k, v in {
                                    "subject_cn": ssl_cert.get("subject_cn") or None,
                                    "issuer": ssl_cert.get("issuer"),
                                    "issuer_cn": ssl_cert.get("issuer_cn"),
                                    "serial": ssl_cert.get("serial"),
                                    "not_before": ssl_cert.get("not_before"),
                                    "not_after": ssl_cert.get("not_after"),
                                    "fingerprint_sha256": ssl_cert.get("fingerprint_sha256"),
                                    "expired": ssl_cert.get("expired"),
                                    "jarm": ssl_cert.get("jarm"),
                                    "ja3s": ssl_cert.get("ja3s"),
                                    "cipher": ssl_cert.get("cipher"),
                                    "tls_versions_supported": ssl_cert.get("versions") or None,
                                }.items() if v is not None}
                                session.run(
                                    """
                                    MERGE (c:Certificate {cert_key: $cert_key, user_id: $user_id,
                                                          project_id: $project_id})
                                    ON CREATE SET c.source = 'shodan'
                                    SET c += $props,
                                        c.observed_by = CASE WHEN 'shodan' IN coalesce(c.observed_by, [])
                                                             THEN c.observed_by
                                                             ELSE coalesce(c.observed_by, []) + 'shodan' END,
                                        c.updated_at = datetime()
                                    WITH c
                                    MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                    """,
                                    cert_key=cert_key, user_id=user_id, project_id=project_id,
                                    props=cert_props, ip=ip,
                                )
                                stats["relationships_created"] += 1
                            except Exception as e:
                                stats.setdefault("errors", []).append(f"Shodan cert {ip}: {e}")

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
                                ON CREATE SET p.state = 'open', p.source = 'shodan', p.passive_only = true,
                                          p.updated_at = datetime()
                                ON MATCH SET p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                SET i.updated_at = datetime()
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
            # A PTR answer is not forward DNS: the edge it creates carries
            # source 'shodan_rdns' (and a domain-DNS record's 'shodan_dns'), so
            # readers that mean "resolves now" skip it. ON CREATE only: an edge
            # DNS wrote first stays forward DNS.
            for ip, hostnames in shodan_data.get("reverse_dns", {}).items():
                for hostname in hostnames:
                    if not hostname:
                        continue
                    try:
                        kind, root = attach_for_host(hostname, recon_data)

                        if root:
                            session.run(
                                """
                                MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET s.source = 'shodan_rdns', s.status = 'resolved',
                                              s.discovered_at = datetime(), s.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                SET i.updated_at = datetime()
                                MERGE (s)-[r:RESOLVES_TO]->(i)
                                ON CREATE SET r.timestamp = datetime(), r.source = 'shodan_rdns'
                                SET r.last_seen_at = datetime(),
                                    r.record_type = coalesce(r.record_type,
                                        CASE WHEN $ip CONTAINS ':' THEN 'AAAA' ELSE 'A' END)
                                """,
                                name=hostname, ip=ip, user_id=user_id, project_id=project_id
                            )
                            stats["subdomains_created"] += 1
                            stats["relationships_created"] += 1

                            session.run(
                                """
                                MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:BELONGS_TO]->(d)
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                """,
                                name=hostname, domain=root,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1
                        elif kind == OUT_OF_SCOPE:
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
                                ed_domain=hostname, ip=ip, domain=home,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                    except Exception as e:
                        stats["errors"].append(f"Failed to create subdomain {hostname}: {e}")

            # ── 3. Domain DNS → Subdomain + DNSRecord nodes ──
            # Shodan answers for the name recon queried (the org); its labels
            # are relative to THAT name, never to this group's scan root, or an
            # org record would be written as mail.<scan root> (§4.9).
            domain_dns = shodan_data.get("domain_dns", {})
            dns_base = domain_dns.get("domain") or domain
            for sub_name in domain_dns.get("subdomains", []):
                if not sub_name:
                    continue
                fqdn = f"{sub_name}.{dns_base}" if dns_base and not sub_name.endswith(dns_base) else sub_name
                kind, root = attach_for_host(fqdn, recon_data)

                try:
                    if root:
                        session.run(
                            """
                            MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET s.source = 'shodan_dns', s.status = 'resolved',
                                          s.discovered_at = datetime(), s.updated_at = datetime()
                            """,
                            name=fqdn, user_id=user_id, project_id=project_id
                        )
                        stats["subdomains_created"] += 1

                        session.run(
                            """
                            MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                            MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                            MERGE (s)-[:BELONGS_TO]->(d)
                            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                            """,
                            name=fqdn, domain=root,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1
                    elif kind == OUT_OF_SCOPE:
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
                            ed_domain=fqdn, domain=home,
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
                fqdn = f"{rec_sub}.{dns_base}" if rec_sub and dns_base else dns_base
                if attach_for_host(fqdn, recon_data)[0] != IN_SCOPE:
                    continue
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
                            SET i.updated_at = datetime()
                            MERGE (s)-[r:RESOLVES_TO]->(i)
                            ON CREATE SET r.timestamp = datetime(), r.source = 'shodan_dns'
                            SET r.last_seen_at = datetime(),
                                r.record_type = coalesce(r.record_type, $type)
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
                    # Refreshed on every run that still reports it, so a row
                    # written before the evidence fields existed gains them.
                    # Only what this run knows is written, and the grade only
                    # rises: a run that fell back to InternetDB (the host API
                    # refused or paused) must not erase a banner's evidence.
                    # The IP is the finding's only parent; a Service parent
                    # would make the board read its product name as the host.
                    props = _shodan_cve_props(cve_entry)
                    method = props.pop("detection_method")
                    verified = props.pop("verified")
                    # A full run's port scan decides port_confirmed, an unknown
                    # (None) included; an entry with no verdict at all (partial
                    # recon could not say) leaves the stored one alone.
                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $vuln_id, user_id: $user_id,
                                                project_id: $project_id})
                        ON CREATE SET v.source = $source
                        SET v += $props, v.updated_at = datetime(),
                            v.verified = coalesce(v.verified, false) OR $verified
                        FOREACH (_ IN CASE WHEN $set_port_confirmed THEN [1] ELSE [] END |
                          SET v.port_confirmed = $port_confirmed)
                        WITH v, {passive_catalog: 0, passive_version_match: 1, passive_verified: 2} AS rank
                        SET v.detection_method = CASE
                            WHEN coalesce(rank[v.detection_method], -1) > rank[$method]
                            THEN v.detection_method ELSE $method END
                        """,
                        vuln_id=vuln_id, source=cve_source, props=props, method=method,
                        verified=verified, user_id=user_id, project_id=project_id,
                        set_port_confirmed="port_confirmed" in cve_entry,
                        port_confirmed=cve_entry.get("port_confirmed"),
                    )
                    stats["vulnerabilities_created"] += 1

                    session.run(
                        """
                        // Global reference node: no tenant stamp, or a project
                        // wipe deletes it for every other project too.
                        MERGE (c:CVE {id: $cve_id})
                        ON CREATE SET c.source = $source
                        SET c.updated_at = datetime()
                        """,
                        cve_id=cve_id, source=cve_source
                    )
                    stats["cves_created"] += 1

                    session.run(
                        """
                        MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id,
                                                project_id: $project_id})
                        MATCH (c:CVE {id: $cve_id})
                        MERGE (v)-[:INCLUDES_CVE]->(c)
                        """,
                        vuln_id=vuln_id, cve_id=cve_id,
                        user_id=user_id, project_id=project_id
                    )
                    stats["relationships_created"] += 1

                    session.run(
                        """
                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                        MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
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

    def backfill_passive_cve_hosts(self, user_id: str, project_id: str) -> int:
        """Give older Shodan and CriminalIP CVEs the `target_ip` their id names.

        The recon prune keeps an IP the run could not look up by matching a
        finding's host fields, and `target_ip` is the only one these carry.
        Shodan stores it since its evidence grading, CriminalIP since its CVEs
        are pruned at all; a row written before would otherwise be deleted
        when its IP was the one not re-checked. Run before the prune. Never
        writes `updated_at`; idempotent.
        """
        with self.driver.session() as session:
            rows = []
            for record in session.run(
                """
                MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
                WHERE v.target_ip IS NULL AND v.source IN $sources
                RETURN v.id AS id
                """,
                uid=user_id, pid=project_id, sources=list(_IP_KEYED_PASSIVE_SOURCES),
            ):
                ip = _ip_from_passive_cve_id(record["id"])
                if ip:
                    rows.append({"id": record["id"], "ip": ip})
            if not rows:
                return 0
            session.run(
                """
                UNWIND $rows AS r
                MATCH (v:Vulnerability {id: r.id, user_id: $uid, project_id: $pid})
                WHERE v.target_ip IS NULL
                SET v.target_ip = r.ip
                """,
                rows=rows, uid=user_id, pid=project_id,
            )
        print(f"[*][graph-db] Backfilled target_ip on {len(rows)} older passive CVE(s)")
        return len(rows)


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
        # The redirect search can find start hosts when the main search found nothing.
        if not urlscan_data or (urlscan_data.get("results_count", 0) == 0
                                and not urlscan_data.get("redirect_start_hosts")):
            return stats

        domain = recon_data.get("domain", "")
        # `domain` is the scan root this pass looked up; a host under any of the
        # run's scan roots is in scope and joins its root's org Domain. A scan
        # root itself is a Subdomain only when its group made it a target
        # (attach_for_host); a legacy file, with no scope groups, never makes
        # an apex a Subdomain, as before.
        home = home_domain(recon_data)
        roots = attach_roots(recon_data)
        apexes = set() if scope_groups_by_root(recon_data) else {r.lower() for r in roots}

        with self.driver.session() as session:

            # ── 1. Subdomain + IP discovery ──
            # A visit's page.ip is history, not current DNS: written only as
            # HISTORICALLY_RESOLVED_TO {source: 'urlscan'} (S5), only for a host
            # the scan may target and a routable address the RoE does not
            # exclude (urlscan_enrich tags each entry; an entry without the tag,
            # from an older recon file, gets no IP at all), and only through an
            # existing Subdomain, so no orphan IP is left (B11).
            seen_subs = set()
            history: dict = {}
            for entry in urlscan_data.get("entries", []):
                subdomain = entry.get("domain", "")
                in_scope = entry.get("in_scope", True)

                # Create/update subdomain or external domain node
                if subdomain and subdomain.lower() not in apexes and subdomain not in seen_subs:
                    seen_subs.add(subdomain)
                    kind, root = attach_for_host(subdomain, recon_data)
                    try:
                        if root and in_scope:
                            # MATCH, never MERGE: the run's domain write (or
                            # ensure_root_domains, in a batch) made the root's
                            # Domain, and creating one here could leave a Domain
                            # the scope no longer names. Unverified until DNS
                            # resolves it: urlscan only saw it in the past.
                            rec = session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                SET d.updated_at = datetime()
                                MERGE (s:Subdomain {name: $subdomain, user_id: $uid, project_id: $pid})
                                ON CREATE SET s.source = 'urlscan', s.discovered_by = 'urlscan',
                                              s.status = 'unverified', s.updated_at = datetime()
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                MERGE (s)-[:BELONGS_TO]->(d)
                                RETURN count(s) AS n
                                """,
                                domain=root, subdomain=subdomain,
                                uid=user_id, pid=project_id
                            ).single()
                            if rec and rec["n"]:
                                stats["subdomains_created"] += 1
                                stats["relationships_created"] += 1
                        elif kind == OUT_OF_SCOPE:
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
                                ed_domain=subdomain, domain=home,
                                uid=user_id, pid=project_id
                            )
                    except Exception as e:
                        stats["errors"].append(f"Subdomain {subdomain}: {e}")

                ip = entry.get("ip", "")
                if subdomain and ip and entry.get("ip_in_scope") and subdomain.lower() not in apexes:
                    key = (subdomain, ip)
                    seen = entry.get("scan_time") or ""
                    slot = history.setdefault(key, {
                        "first": seen, "last": seen,
                        "props": {k: v for k, v in {
                            "country": entry.get("country") or None,
                            "asn": entry.get("asn") or None,
                            "asn_name": entry.get("asn_name") or None,
                            "urlscan_enriched": True,
                        }.items() if v is not None},
                    })
                    if seen:
                        slot["first"] = min(slot["first"] or seen, seen)
                        slot["last"] = max(slot["last"] or seen, seen)

            for (subdomain, ip), slot in history.items():
                try:
                    rec = session.run(
                        """
                        MATCH (s:Subdomain {name: $subdomain, user_id: $uid, project_id: $pid})
                        MERGE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                        SET i += $props, i.updated_at = datetime()
                        MERGE (s)-[r:HISTORICALLY_RESOLVED_TO {source: 'urlscan'}]->(i)
                        ON CREATE SET r.first_seen = $first, r.last_seen = $last
                        ON MATCH SET r.first_seen = CASE WHEN $first <> '' AND (r.first_seen IS NULL OR r.first_seen = '' OR $first < r.first_seen) THEN $first ELSE r.first_seen END,
                                     r.last_seen = CASE WHEN $last > coalesce(r.last_seen, '') THEN $last ELSE r.last_seen END
                        RETURN count(r) AS n
                        """,
                        subdomain=subdomain, ip=ip, props=slot["props"],
                        first=slot["first"], last=slot["last"],
                        uid=user_id, pid=project_id
                    ).single()
                    if rec and rec["n"]:
                        stats["ips_enriched"] += 1
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"IP history {subdomain}->{ip}: {e}")

            # Hosts a visit STARTED on and urlscan saw nowhere else (the
            # redirect search): no IP, since the visit's page.ip is the other
            # site's address.
            for host in urlscan_data.get("redirect_start_hosts") or []:
                if not host or host in seen_subs or host.lower() in apexes:
                    continue
                seen_subs.add(host)
                kind, root = attach_for_host(host, recon_data)
                if kind != IN_SCOPE or not root:
                    continue
                try:
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        MERGE (s:Subdomain {name: $subdomain, user_id: $uid, project_id: $pid})
                        ON CREATE SET s.source = 'urlscan', s.discovered_by = 'urlscan',
                                      s.status = 'unverified', s.updated_at = datetime()
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                        MERGE (s)-[:BELONGS_TO]->(d)
                        """, domain=root, subdomain=host, uid=user_id, pid=project_id)
                    stats["subdomains_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Redirect start host {host}: {e}")

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
                        domain=home, uid=user_id, pid=project_id, props=props
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
        if not urlscan_data or (urlscan_data.get("results_count", 0) == 0
                                and not urlscan_data.get("redirect_entries")
                                and not urlscan_data.get("quarantined_urls")):
            return stats

        with self.driver.session() as session:

            # ── 1. Enrich existing BaseURL nodes with screenshot/server/title ──
            # Group entries by base_url for efficient enrichment
            baseurl_data: dict[str, dict] = {}
            for entry in urlscan_data.get("entries", []):
                url = entry.get("url", "")
                # A quarantined visit's screenshot and scan ID open the
                # unmasked scan on urlscan: never the BaseURL's evidence.
                if not url or entry.get("quarantined"):
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
                        "tls_issuer": entry.get("tls_issuer", ""),
                        "tls_valid_days": entry.get("tls_valid_days"),
                        "tls_valid_from": entry.get("tls_valid_from", ""),
                        "tls_age_days": entry.get("tls_age_days"),
                    }

            for base_url, data in baseurl_data.items():
                try:
                    props = {k: v for k, v in {
                        "urlscan_screenshot_url": data["screenshot_url"] or None,
                        "urlscan_server": data["server"] or None,
                        "urlscan_title": data["title"] or None,
                        "urlscan_enriched": True,
                        # Phase 0.6: urlscan already parses these and they were
                        # dropped on the floor. Certificate posture for free, on
                        # a page we never had to fetch ourselves.
                        "urlscan_tls_issuer": data.get("tls_issuer") or None,
                        "urlscan_tls_valid_days": data.get("tls_valid_days"),
                        "urlscan_tls_valid_from": data.get("tls_valid_from") or None,
                        "urlscan_tls_age_days": data.get("tls_age_days"),
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
                path = normalize_endpoint_path(url_entry.get("path", "")) if url_entry.get("path") else ""
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
                        SET e.full_url = CASE WHEN e.source = 'urlscan' THEN $full_url ELSE e.full_url END
                        SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                        SET e += $file_props
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        RETURN e.path AS path
                        """,
                        base_url=base_url, path=path, full_url=full_url,
                        has_params=has_params, uid=user_id, pid=project_id,
                        # Item 3: a document's type, its content type, and a
                        # sensitive file's kind (partial Route Exposure reads it).
                        file_props={k: url_entry[k] for k in
                                    ("document_type", "urlscan_mime_type", "urlscan_file_kind")
                                    if url_entry.get(k)},
                    )
                    record = result.single()
                    if record:
                        stats["endpoints_created"] += 1
                        stats["relationships_created"] += 1

                        # Parameter nodes from the query string: names only. An
                        # archived value is someone's old request, so none is
                        # stored (S4); a value an older run stored is removed.
                        for param_name in params:
                            try:
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url,
                                                       user_id: $uid, project_id: $pid})
                                    MERGE (p:Parameter {name: $param_name, position: 'query',
                                                        endpoint_path: $path, baseurl: $base_url,
                                                        user_id: $uid, project_id: $pid})
                                    ON CREATE SET p.source = 'urlscan', p.is_injectable = false,
                                                  p.updated_at = datetime()
                                    REMOVE p.sample_value
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, base_url=base_url, param_name=param_name,
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

            # ── 2b. Item 1: the target's own URL a visit started on before it
            # was redirected away. Names only; the other site's origin is the
            # redirect target, kept as a label and never scanned.
            stats["redirect_endpoints"] = 0
            for row in urlscan_data.get("redirect_entries") or []:
                base_url = row.get("base_url", "")
                path = normalize_endpoint_path(row.get("path") or "/")
                if not base_url:
                    continue
                try:
                    rec = session.run(
                        """
                        MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                        MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url,
                                           user_id: $uid, project_id: $pid})
                        ON CREATE SET e.source = 'urlscan', e.updated_at = datetime()
                        SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                        SET e.urlscan_redirect_target = $target,
                            e.has_parameters = coalesce(e.has_parameters, false) OR size($names) > 0
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        WITH e
                        UNWIND (CASE WHEN size($names) = 0 THEN [null] ELSE $names END) AS name
                        WITH e, name WHERE name IS NOT NULL
                        MERGE (p:Parameter {name: name, position: 'query', endpoint_path: $path,
                                            baseurl: $base_url, user_id: $uid, project_id: $pid})
                        ON CREATE SET p.source = 'urlscan', p.is_injectable = false,
                                      p.updated_at = datetime()
                        MERGE (e)-[:HAS_PARAMETER]->(p)
                        RETURN count(DISTINCT e) AS n
                        """,
                        base_url=base_url, path=path, target=row.get("end_origin") or "",
                        names=[n for n in row.get("param_names") or [] if isinstance(n, str) and n],
                        uid=user_id, pid=project_id,
                    ).single()
                    if rec is not None:
                        stats["redirect_endpoints"] += 1
                except Exception as e:
                    stats["errors"].append(f"Redirect endpoint {path}: {e}")

            # ── 3. Quarantined URLs: a leaked one-time link, a secret, a state-
            # changing link with a value, a web-shell trace. The Endpoint is
            # kept (the path, masked, and the parameter NAMES) so the agent and
            # the operator see it, flagged so every reader that turns graph
            # Endpoints into requests skips it. A plain SET flags one another
            # tool wrote too; its full_url and parameter values are removed.
            stats["endpoints_quarantined"] = 0
            for row in urlscan_data.get("quarantined_urls", []) or []:
                base_url = row.get("base_url", "")
                path = normalize_endpoint_path(row.get("path", "")) if row.get("path") else ""
                if not base_url or not path:
                    continue
                try:
                    rec = session.run(
                        """
                        MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})
                        MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url,
                                           user_id: $uid, project_id: $pid})
                        ON CREATE SET e.source = 'urlscan', e.updated_at = datetime()
                        SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                        SET e.quarantined = true, e.quarantine_reasons = $reasons,
                            e.has_parameters = coalesce(e.has_parameters, false) OR size($names) > 0
                        REMOVE e.full_url
                        MERGE (bu)-[:HAS_ENDPOINT]->(e)
                        WITH e
                        UNWIND (CASE WHEN size($names) = 0 THEN [null] ELSE $names END) AS name
                        WITH e, name WHERE name IS NOT NULL
                        MERGE (p:Parameter {name: name, position: 'query', endpoint_path: $path,
                                            baseurl: $base_url, user_id: $uid, project_id: $pid})
                        ON CREATE SET p.source = 'urlscan', p.is_injectable = false,
                                      p.updated_at = datetime()
                        REMOVE p.sample_value, p.sample_values
                        MERGE (e)-[:HAS_PARAMETER]->(p)
                        RETURN count(DISTINCT e) AS n
                        """,
                        base_url=base_url, path=path, reasons=list(row.get("reasons") or []),
                        names=[n for n in row.get("param_names") or [] if isinstance(n, str) and n],
                        uid=user_id, pid=project_id,
                    ).single()
                    if rec is not None:
                        stats["endpoints_quarantined"] += 1
                except Exception as e:
                    stats["errors"].append(f"Quarantined endpoint {path}: {e}")

            print(f"[+][graph-db] URLScan enrichment: {stats['baseurls_enriched']} BaseURLs enriched, "
                  f"{stats['endpoints_created']} endpoints, {stats['parameters_created']} parameters, "
                  f"{stats['endpoints_quarantined']} quarantined")
            if stats["baseurls_not_found"]:
                print(f"[*][graph-db] {stats['baseurls_not_found']} BaseURLs not in graph (stale URLScan data, expected)")
            if stats["endpoints_skipped"]:
                print(f"[*][graph-db] {stats['endpoints_skipped']} endpoints skipped (BaseURL not live)")
            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats


    def update_graph_from_urlscan_takeover(self, recon_data: dict, user_id: str,
                                           project_id: str) -> dict:
        """The takeover verdict's findings (item 5), decided after httpx: the
        same writer, reading only that list."""
        return self.update_graph_from_urlscan_findings(recon_data, user_id, project_id,
                                                       keys=("takeover_findings",))

    def update_graph_from_urlscan_findings(self, recon_data: dict, user_id: str, project_id: str,
                                           keys: tuple = ("findings", "problem_pages")) -> dict:
        """The findings urlscan's history gives about the target: leaked links,
        exposed files, open redirects, problem and takeover pages (Vulnerability
        {source: 'urlscan_leak'}) and secrets written in URLs (Secret {source:
        'urlscan'}).

        Its own writer, queued with the discovery writer (GROUP 1), not the
        enrichment one, which runs only inside the httpx step. `keys` names the
        urlscan lists to read: the takeover verdict, decided after httpx, is a
        second call that writes only its own list. It never prunes.

        Every finding is a public record ("seen in a public urlscan scan on
        DATE"), never confirmed by RedAmon and never an agent lead: no
        needs_agent_confirmation. History alone is at most high.
        """
        stats = {"findings_written": 0, "secrets_written": 0, "skipped_out_of_scope": 0, "errors": []}
        urlscan_data = recon_data.get("urlscan") or {}
        rows = [f for key in keys for f in (urlscan_data.get(key) or []) if isinstance(f, dict)]
        secrets = [s for s in (urlscan_data.get("url_secrets") or []) if isinstance(s, dict)] \
            if "findings" in keys else []
        if not rows and not secrets:
            return stats

        def _parent(session, host: str, rel: str, label: str, node_id: str) -> bool:
            kind, org = attach_for_host(host, recon_data)
            if kind != IN_SCOPE or not org:
                return False
            if host.strip().lower() == org.strip().lower():
                session.run(
                    f"""
                    MATCH (d:Domain {{name: $org, user_id: $uid, project_id: $pid}})
                    MATCH (n:{label} {{id: $id, user_id: $uid, project_id: $pid}})
                    MERGE (d)-[:{rel}]->(n)
                    """, org=org, id=node_id, uid=user_id, pid=project_id)
                return True
            # A host seen only in a visit's start URL has no Subdomain yet.
            session.run(
                f"""
                MATCH (d:Domain {{name: $org, user_id: $uid, project_id: $pid}})
                MERGE (s:Subdomain {{name: $host, user_id: $uid, project_id: $pid}})
                ON CREATE SET s.source = 'urlscan', s.discovered_by = 'urlscan',
                              s.status = 'unverified', s.updated_at = datetime()
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                MERGE (s)-[:BELONGS_TO]->(d)
                WITH s
                MATCH (n:{label} {{id: $id, user_id: $uid, project_id: $pid}})
                MERGE (s)-[:{rel}]->(n)
                """, org=org, host=host.strip().lower(), id=node_id, uid=user_id, pid=project_id)
            return True

        with self.driver.session() as session:
            for f in rows:
                host = (f.get("host") or "").strip().lower()
                ftype = f.get("type") or ""
                if not host or not ftype:
                    continue
                kind = f.get("kind") or ""
                path = f.get("path") or "/"
                vid = "urlscan-" + stable_vuln_id(f"{ftype}:{kind}" if kind else ftype, path, host,
                                                  user_id, project_id)
                props = {k: v for k, v in (f.get("props") or {}).items()
                         if v is not None and not isinstance(v, (dict, list)) or isinstance(v, list)
                         and all(not isinstance(x, (dict, list)) for x in v)}
                if f.get("kind_field") and kind:
                    props[f["kind_field"]] = kind
                props.update({
                    "type": ftype,
                    "name": f.get("name") or ftype,
                    "description": f.get("description") or "",
                    "severity": _history_severity(f.get("severity"), f.get("live")),
                    "matched_at": f.get("url") or f"https://{host}{path}",
                    "url": f.get("url") or f"https://{host}{path}",
                    "hostname": host,
                    "first_seen": f.get("first_seen") or "",
                    "last_seen": f.get("last_seen") or "",
                })
                if f.get("urlscan_scan_id"):
                    props["urlscan_scan_id"] = f["urlscan_scan_id"]
                try:
                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})
                        ON CREATE SET v.source = 'urlscan_leak', v.created_at = datetime()
                        SET v += $props, v.updated_at = datetime()
                        """, id=vid, props=props, uid=user_id, pid=project_id)
                    if _parent(session, host, "HAS_VULNERABILITY", "Vulnerability", vid):
                        stats["findings_written"] += 1
                    else:
                        stats["skipped_out_of_scope"] += 1
                        session.run(
                            "MATCH (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid}) "
                            "WHERE NOT (v)--() DELETE v", id=vid, uid=user_id, pid=project_id)
                except Exception as e:
                    stats["errors"].append(f"urlscan finding {ftype}: {e}")

            for sec in secrets:
                host = (sec.get("host") or "").strip().lower()
                stype = sec.get("secret_type") or ""
                if not host or not stype:
                    continue
                # One Secret per distinct value (its HMAC); with no HMAC key, one
                # per host, type and parameter.
                ident = sec.get("value_hmac") or sec.get("param_name") or ""
                sid = "secret-urlscan-" + stable_vuln_id(stype, ident, host, user_id, project_id)
                props = {k: v for k, v in {
                    "secret_type": stype,
                    "param_name": sec.get("param_name"),
                    "value_length": sec.get("value_length"),
                    "value_hmac": sec.get("value_hmac"),
                    "jwt_alg": sec.get("jwt_alg"),
                    "jwt_expired": sec.get("jwt_expired"),
                    "masked_url": sec.get("masked_url"),
                    "base_url": sec.get("base_url"),
                    "severity": _history_severity(sec.get("severity"), False),
                    "first_seen": sec.get("first_seen") or "",
                    "last_seen": sec.get("last_seen") or "",
                    "sighting_count": sec.get("count"),
                }.items() if v is not None}
                try:
                    session.run(
                        """
                        MERGE (s:Secret {id: $id, user_id: $uid, project_id: $pid})
                        ON CREATE SET s.source = 'urlscan', s.created_at = datetime()
                        SET s += $props, s.updated_at = datetime()
                        """, id=sid, props=props, uid=user_id, pid=project_id)
                    if _parent(session, host, "HAS_SECRET", "Secret", sid):
                        stats["secrets_written"] += 1
                    else:
                        stats["skipped_out_of_scope"] += 1
                        session.run(
                            "MATCH (s:Secret {id: $id, user_id: $uid, project_id: $pid}) "
                            "WHERE NOT (s)--() DELETE s", id=sid, uid=user_id, pid=project_id)
                except Exception as e:
                    stats["errors"].append(f"urlscan secret {stype}: {e}")

        print(f"[+][graph-db] URLScan findings: {stats['findings_written']} findings, "
              f"{stats['secrets_written']} secrets")
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
        # The org Domain of this group's scan root: its ExternalDomains hang off it.
        domain = home_domain(recon_data)
        if not external_domains:
            return
        # Each module judged "external" against the one scan root it scanned, so
        # in a Domain batch a host under a SIBLING scan root lands here too. It
        # is not foreign: it joins that root's org as a Subdomain. A scan root
        # itself is left to the domain writer, which makes it a node only when
        # it is a target.

        print(f"\n[GRAPH] External Domains: {len(external_domains)} foreign domains")

        created = 0
        with self.driver.session() as session:
            for ed in external_domains:
                ed_domain = ed.get("domain", "")
                if not ed_domain:
                    continue
                kind, root = classify_host(ed_domain, recon_data)
                if kind != OUT_OF_SCOPE:
                    if kind == IN_SCOPE and ed_domain.strip().lower() != root.strip().lower():
                        try:
                            session.run("""
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                                ON CREATE SET s.source = $source, s.discovered_at = datetime(),
                                              s.updated_at = datetime()
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                MERGE (s)-[:BELONGS_TO]->(d)
                            """, domain=org_for_scan_root(root, recon_data), name=ed_domain.strip().lower(),
                                uid=user_id, pid=project_id,
                                source=(ed.get("sources") or ["external_reference"])[0])
                        except Exception as e:
                            logger.warning(f"Cross-root Subdomain graph error for {ed_domain}: {e}")
                    continue
                try:
                    # Additive: a partial run writes only its own source's
                    # sightings, so it must not overwrite what a full run
                    # (or another source) recorded on the same node.
                    result = session.run("""
                        MERGE (ed:ExternalDomain {domain: $ed_domain, user_id: $uid, project_id: $pid})
                        ON CREATE SET ed.first_seen_at = datetime()
                        SET ed.sources = coalesce(ed.sources, []) + [x IN $sources WHERE NOT x IN coalesce(ed.sources, [])],
                            ed.redirect_from_urls = coalesce(ed.redirect_from_urls, []) + [x IN $redirect_from WHERE NOT x IN coalesce(ed.redirect_from_urls, [])],
                            ed.redirect_to_urls = coalesce(ed.redirect_to_urls, []) + [x IN $redirect_to WHERE NOT x IN coalesce(ed.redirect_to_urls, [])],
                            ed.status_codes_seen = coalesce(ed.status_codes_seen, []) + [x IN $status_codes WHERE NOT x IN coalesce(ed.status_codes_seen, [])],
                            ed.titles_seen = coalesce(ed.titles_seen, []) + [x IN $titles WHERE NOT x IN coalesce(ed.titles_seen, [])],
                            ed.servers_seen = coalesce(ed.servers_seen, []) + [x IN $servers WHERE NOT x IN coalesce(ed.servers_seen, [])],
                            ed.ips_seen = coalesce(ed.ips_seen, []) + [x IN $ips WHERE NOT x IN coalesce(ed.ips_seen, [])],
                            ed.countries_seen = coalesce(ed.countries_seen, []) + [x IN $countries WHERE NOT x IN coalesce(ed.countries_seen, [])],
                            ed.times_seen = coalesce(ed.times_seen, 0) + $times_seen,
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
                                    ON CREATE SET p.state = 'open', p.source = 'censys'
                                    SET p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    SET i.updated_at = datetime()
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
                                    issuer = tls_data.get("issuer")
                                    not_before = tls_data.get("not_before")
                                    not_after = tls_data.get("not_after")
                                    fingerprint = tls_data.get("fingerprint")
                                    if subject_cn or fingerprint:
                                        issuer_str = (", ".join(issuer) if isinstance(issuer, list)
                                                      else issuer)
                                        cert_key = build_cert_key(
                                            fingerprint_sha256=fingerprint, subject_cn=subject_cn,
                                            issuer=issuer_str, not_before=not_before, not_after=not_after,
                                        )
                                        cert_props = {k: v for k, v in {
                                            "subject_cn":  subject_cn or None,
                                            "issuer":      issuer,
                                            "san":         tls_data.get("san"),
                                            "not_before":  not_before,
                                            "not_after":   not_after,
                                            "fingerprint_sha256": fingerprint,
                                            "tls_version": tls_data.get("tls_version"),
                                            "cipher":      tls_data.get("cipher"),
                                        }.items() if v is not None and v != "" and v != []}
                                        try:
                                            session.run(
                                                """
                                                MERGE (c:Certificate {cert_key: $cert_key,
                                                                       user_id: $user_id,
                                                                       project_id: $project_id})
                                                ON CREATE SET c.source = 'censys'
                                                SET c += $props,
                                                    c.observed_by = CASE WHEN 'censys' IN coalesce(c.observed_by, [])
                                                                         THEN c.observed_by
                                                                         ELSE coalesce(c.observed_by, []) + 'censys' END,
                                                    c.updated_at = datetime()
                                                WITH c
                                                MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                                MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                                """,
                                                cert_key=cert_key, user_id=user_id,
                                                project_id=project_id, props=cert_props, ip=ip,
                                            )
                                            stats["certificates_merged"] += 1
                                            stats["relationships_created"] += 1
                                        except Exception as e:
                                            stats["errors"].append(f"Censys cert {subject_cn}: {e}")

                            # Reverse DNS → Subdomain nodes
                            for hostname in host.get("reverse_dns_names") or []:
                                root = attach_for_host(hostname, recon_data)[1] if hostname else None
                                if not root:
                                    continue
                                try:
                                    session.run(
                                        """
                                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET s.discovered_at = datetime(), s.updated_at = datetime()
                                        SET s.source = 'censys_rdns', s.status = 'unverified',
                                            s.updated_at = datetime()
                                        MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        SET i.updated_at = datetime()
                                        MERGE (s)-[r:RESOLVES_TO]->(i)
                                        ON CREATE SET r.timestamp = datetime(), r.source = 'censys_dns'
                                        SET r.last_seen_at = datetime(),
                                            r.record_type = coalesce(r.record_type,
                                                CASE WHEN $ip CONTAINS ':' THEN 'AAAA' ELSE 'A' END)
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
                                        name=hostname, domain=root,
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
                                ON CREATE SET p.state = 'open', p.source = 'fofa'
                                SET p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                SET i.updated_at = datetime()
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
                                issuer_cn = row.get("certs_issuer_cn") or ""
                                # FOFA carries no fingerprint: surrogate key over CN+issuer.
                                cert_key = build_cert_key(subject_cn=cert_cn, issuer=issuer_cn)
                                session.run(
                                    """
                                    MERGE (c:Certificate {cert_key: $cert_key, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET c.source = 'fofa'
                                    SET c.subject_cn   = $cn,
                                        c.issuer       = CASE WHEN $issuer_cn <> '' THEN $issuer_cn ELSE c.issuer END,
                                        c.subject_org  = CASE WHEN $subject_org <> '' THEN $subject_org ELSE c.subject_org END,
                                        c.tls_version  = CASE WHEN $tls_ver <> '' THEN $tls_ver ELSE c.tls_version END,
                                        c.is_valid     = CASE WHEN $cert_valid <> '' THEN ($cert_valid = 'true') ELSE c.is_valid END,
                                        c.observed_by  = CASE WHEN 'fofa' IN coalesce(c.observed_by, [])
                                                              THEN c.observed_by
                                                              ELSE coalesce(c.observed_by, []) + 'fofa' END,
                                        c.updated_at   = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    SET i.updated_at = datetime()
                                    MERGE (i)-[:HAS_CERTIFICATE]->(c)
                                    """,
                                    cert_key=cert_key, cn=cert_cn,
                                    issuer_cn=issuer_cn,
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
                            root = attach_for_host(host, recon_data)[1] if host and host != ip else None
                            if root:
                                session.run(
                                    """
                                    MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                    ON CREATE SET s.status = 'unverified', s.discovered_at = datetime(), s.updated_at = datetime()
                                    SET s.source = 'fofa', s.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    SET i.updated_at = datetime()
                                    MERGE (s)-[r:RESOLVES_TO]->(i)
                                    ON CREATE SET r.timestamp = datetime(), r.source = 'fofa_dns'
                                    SET r.last_seen_at = datetime(),
                                        r.record_type = coalesce(r.record_type,
                                            CASE WHEN $ip CONTAINS ':' THEN 'AAAA' ELSE 'A' END)
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
                                    name=host, domain=root, user_id=user_id, project_id=project_id,
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
            # `domain` is the org Domain of the scan root this group looked up
            # (external names and the org-level report hang off it); a name
            # under any of the project's scan roots joins its root's org.
            domain = home_domain(recon_data) or ""
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

                            kind, root = attach_for_host(hostname, recon_data)
                            if root:
                                # In-scope → Subdomain node
                                try:
                                    # The edge usually exists already from DNS
                                    # resolution, so the passive-DNS dates widen
                                    # its window rather than being set on create.
                                    session.run(
                                        """
                                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                        ON CREATE SET s.discovered_at = datetime(), s.updated_at = datetime()
                                        SET s.source = 'otx_passive_dns', s.status = 'unverified', s.updated_at = datetime()
                                        WITH s
                                        MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        SET i.updated_at = datetime()
                                        MERGE (s)-[r:RESOLVES_TO]->(i)
                                        ON CREATE SET r.timestamp = datetime(), r.source = 'otx_passive_dns'
                                        SET r.record_type = coalesce(r.record_type, $record_type),
                                            r.first_seen = CASE
                                                WHEN $first_seen = '' THEN r.first_seen
                                                WHEN coalesce(r.first_seen, '') = '' OR $first_seen < r.first_seen
                                                    THEN $first_seen
                                                ELSE r.first_seen END,
                                            r.last_seen = CASE
                                                WHEN $last_seen = '' THEN r.last_seen
                                                WHEN coalesce(r.last_seen, '') = '' OR $last_seen > r.last_seen
                                                    THEN $last_seen
                                                ELSE r.last_seen END
                                        """,
                                        name=hostname, ip=ip, user_id=user_id, project_id=project_id,
                                        record_type=record_type, first_seen=first_seen, last_seen=last_seen,
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
                                        name=hostname, domain=root, user_id=user_id, project_id=project_id,
                                    )
                                    stats["relationships_created"] += 1
                                except Exception as e2:
                                    stats["errors"].append(f"OTX pdns in-scope {hostname}: {e2}")
                            elif kind == OUT_OF_SCOPE and "@" not in hostname:
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
                                    SET i.updated_at = datetime()
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
                                    SET i.updated_at = datetime()
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
                        # An org-level report: it lands on the org Domain of
                        # this group's scan root (the report names the org).
                        dom_name = domain or dr["domain"]
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
            "vulnerabilities_merged": 0, "relationships_created": 0,
            "historical_skipped": 0, "errors": [],
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
                        attribution = row.get("attribution")
                        if attribution == "historical":
                            stats["historical_skipped"] += 1
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
                                ON CREATE SET p.state = 'open', p.source = 'netlas'
                                SET p.updated_at = datetime()
                                MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                SET i.updated_at = datetime()
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
                            # A shared edge's CVEs describe the provider and its
                            # other tenants, not the target.
                            if attribution == "shared_edge":
                                continue
                            for cve in (row.get("cve_list") or []):
                                if not isinstance(cve, dict):
                                    continue
                                cve_id = str(cve.get("id") or "").strip().upper()
                                if not _CVE_ID.match(cve_id):
                                    continue
                                try:
                                    self._write_netlas_cve(session, cve, cve_id, ip, pnum,
                                                           user_id, project_id)
                                    stats["vulnerabilities_merged"] += 1
                                    stats["relationships_created"] += 2
                                except Exception as e:
                                    stats["errors"].append(f"Netlas CVE {cve_id} on {ip}:{pnum}: {e}")

                        except Exception as e:
                            stats["errors"].append(f"Netlas row {ip}: {e}")
        except Exception as e:
            stats["errors"].append(f"update_graph_from_netlas: {e}")
        print(f"[graph-db] update_graph_from_netlas complete: {stats}")
        return stats

    @staticmethod
    def _write_netlas_cve(session, cve: dict, cve_id: str, ip: str, port: int,
                          user_id: str, project_id: str) -> None:
        """One Netlas CVE on one IP and port, the IP its only parent.

        Shodan's shape: the board reads a finding's host from its parent, and a
        Service parent read the protocol ("ssh") as the host. `cve_ids` and the
        CVE reference edge carry the KEV and EPSS intel to it. The id was the
        bare CVE once, one node per CVE per project however many IPs carried
        it; tooling/scripts/netlas_finding_rekey.py moves those.
        """
        props: dict = {
            "name": cve_id, "cves": [cve_id], "cve_ids": [cve_id],
            "target_ip": ip, "target_port": port,
            "has_exploit": bool(cve.get("has_exploit", False)),
        }
        severity = str(cve.get("severity") or "").lower()
        if severity:
            props["severity"] = severity
        try:
            if cve.get("base_score") is not None:
                props["cvss_score"] = float(cve["base_score"])
        except (TypeError, ValueError):
            pass
        session.run(
            """
            MERGE (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
            ON CREATE SET v.source = 'netlas', v.created_at = datetime()
            SET v += $props, v.updated_at = datetime()
            WITH v
            OPTIONAL MATCH (:Service)-[stale:HAS_VULNERABILITY]->(v)
            DELETE stale
            WITH DISTINCT v
            MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
            MERGE (i)-[:HAS_VULNERABILITY]->(v)
            """,
            vuln_id=netlas_vuln_id(cve_id, ip, port), props=props, ip=ip,
            user_id=user_id, project_id=project_id,
        )
        session.run(
            """
            // Global reference node: no tenant stamp.
            MERGE (c:CVE {id: $cve_id})
            ON CREATE SET c.source = 'netlas'
            SET c.updated_at = datetime()
            WITH c
            MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
            MERGE (v)-[:INCLUDES_CVE]->(c)
            """,
            cve_id=cve_id, vuln_id=netlas_vuln_id(cve_id, ip, port),
            user_id=user_id, project_id=project_id,
        )

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
                                # An org-level report: the org Domain of this group.
                                name=home_domain(recon_data) or dr["domain"],
                                user_id=user_id, project_id=project_id,
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
                                # Phase 0.6: ZoomEye hands us these TLS stack
                                # fingerprints for free; they were parsed and
                                # then discarded.
                                ("ssl_jarm",    "jarm"),
                                ("ssl_ja3s",    "ja3s"),
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
                                    ON CREATE SET p.state = 'open', p.source = 'zoomeye'
                                    SET p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    SET i.updated_at = datetime()
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
                                if attach_for_host(hostname_val, recon_data)[1]:
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
                                        SET i.updated_at = datetime()
                                        MERGE (s)-[r:RESOLVES_TO]->(i)
                                        ON CREATE SET r.timestamp = datetime(), r.source = 'zoomeye_dns'
                                        SET r.last_seen_at = datetime(),
                                            r.record_type = coalesce(r.record_type,
                                                CASE WHEN $ip CONTAINS ':' THEN 'AAAA' ELSE 'A' END)
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
                        # An org-level report: the org Domain of this group.
                        domain_name = (home_domain(recon_data) or domain_report.get("domain")
                                       if domain_report.get("domain") else None)
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
                                    ON CREATE SET p.state = 'open', p.source = 'criminalip'
                                    SET p.updated_at = datetime()
                                    MERGE (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                    SET i.updated_at = datetime()
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
                                        MERGE (v:Vulnerability {id: $vuln_id,
                                                                user_id: $user_id,
                                                                project_id: $project_id})
                                        ON CREATE SET v.source = 'criminalip'
                                        // Every run: the prune deletes what a run did
                                        // not touch, and keeps an IP it could not look
                                        // up by target_ip. The board reads the score
                                        // as cvss_score; rows that hold it as `cvss`
                                        // converge here.
                                        SET v.name = $cve_id, v.cves = [$cve_id],
                                            v.cvss_score = $cvss,
                                            v.updated_at = datetime(), v.target_ip = $ip
                                        REMOVE v.cvss
                                        """,
                                        vuln_id=vuln_id, cve_id=cve_id, cvss=cvss, ip=ip,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    stats["vulnerabilities_created"] += 1

                                    session.run(
                                        """
                                        // Global reference node: no tenant stamp,
                                        // and therefore SHARED by every project.
                                        // K22: an unconditional SET here let one
                                        // project's CriminalIP reading overwrite the
                                        // authoritative NVD score and description that
                                        // another project's GVM scan had written. Fill
                                        // in only what is missing.
                                        MERGE (c:CVE {id: $cve_id})
                                        ON CREATE SET c.source = 'criminalip'
                                        SET c.cvss = coalesce(c.cvss, $cvss),
                                            c.description = CASE
                                              WHEN coalesce(c.description, '') = ''
                                              THEN $description ELSE c.description END,
                                            c.updated_at = datetime()
                                        """,
                                        cve_id=cve_id, cvss=cvss,
                                        description=vuln.get("description"),
                                    )
                                    stats["cves_created"] += 1

                                    session.run(
                                        """
                                        MATCH (v:Vulnerability {id: $vuln_id,
                                                                user_id: $user_id,
                                                                project_id: $project_id})
                                        MATCH (c:CVE {id: $cve_id})
                                        MERGE (v)-[:INCLUDES_CVE]->(c)
                                        """,
                                        vuln_id=vuln_id, cve_id=cve_id,
                                        user_id=user_id, project_id=project_id,
                                    )
                                    session.run(
                                        """
                                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
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
        roots = attach_roots(recon_data)
        # An IP, or a URL under no scan root, belongs to the org Domain of the
        # scan root this pass queried.
        domain = home_domain(recon_data) or (org_for_scan_root(roots[0], recon_data) if roots else "")
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
                    # A host under no scan root (or a scan root that is no
                    # target) gets no node: uncover searches by org and
                    # certificate, so its hosts are not scope by themselves.
                    host_org = attach_for_host(hostname, recon_data)[1]
                    if not host_org:
                        stats.setdefault("hosts_out_of_scope", 0)
                        stats["hosts_out_of_scope"] += 1
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
                        host_root = host_org
                        if host_root:
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (s)-[:BELONGS_TO]->(d)
                                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                """,
                                name=hostname, domain=host_root,
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
                                SET i.updated_at = datetime()
                                MERGE (i)-[:HAS_PORT]->(p)
                                """,
                                port=int(port_num), ip=ip,
                                user_id=user_id, project_id=project_id,
                            )
                            stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Uncover IP {ip}: {e}")

                # K23. These used to MERGE on `url` and hang off the Domain,
                # which is the key nothing else in the graph uses. An uncover
                # URL therefore became a SECOND Endpoint for a path http_probe
                # had already written, outside the BaseURL tree, so it was
                # invisible to every reachability read (which walks
                # BaseURL -> HAS_ENDPOINT) and to the liveness facts the
                # Priority Board scores R from.
                for url in urls:
                    if not url:
                        continue
                    try:
                        base_url, path = _split_url(url)
                        if not base_url or base_url == "://":
                            stats["errors"].append(f"Uncover URL {url}: no host")
                            continue
                        session.run(
                            """
                            MERGE (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET u.source = 'uncover', u.updated_at = datetime()
                            MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $base_url,
                                               user_id: $user_id, project_id: $project_id})
                            ON CREATE SET e.discovered_at = datetime(), e.source = 'uncover'
                            SET e.url = $url, e.updated_at = datetime()
                            SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                            MERGE (u)-[:HAS_ENDPOINT]->(e)
                            """,
                            url=url, base_url=base_url, path=path,
                            user_id=user_id, project_id=project_id,
                        )
                        stats["urls_created"] += 1
                        stats["relationships_created"] += 1
                        # The BaseURL, not the Endpoint, is what a host owns.
                        # Subdomain first: uncover expands a target into hosts,
                        # and hanging every URL off the apex Domain loses which
                        # host it was actually found on. An IP literal is NOT a
                        # Subdomain: IP mode mints a dashed placeholder name for
                        # it ("1.2.3.4" -> "1-2-3-4", http_mixin), so a dotted
                        # Subdomain would be a duplicate host nothing else
                        # links to. Those fall through to the Domain.
                        host = _urlparse(url).hostname or ""
                        if host and not _is_ip_address(host):
                            session.run(
                                """
                                MATCH (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                                MERGE (s:Subdomain {name: $host, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET s.source = 'uncover', s.status = 'unverified',
                                              s.updated_at = datetime()
                                MERGE (s)-[:HAS_BASE_URL]->(u)
                                """,
                                base_url=base_url, host=host,
                                user_id=user_id, project_id=project_id,
                            )
                            stats["relationships_created"] += 1
                        elif domain:
                            session.run(
                                """
                                MATCH (u:BaseURL {url: $base_url, user_id: $user_id, project_id: $project_id})
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MERGE (d)-[:HAS_BASE_URL]->(u)
                                """,
                                base_url=base_url, domain=domain,
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

    def update_graph_from_origin_discovery(self, recon_data: dict, user_id: str, project_id: str) -> dict:
        """Persist confirmed origin-IP discoveries (behind CDN/WAF).

        Reuses the existing IP and Vulnerability labels (no new node type):
        - MERGE the origin IP on the tenant key + origin provenance props.
        - MERGE (Subdomain)-[:HAS_ORIGIN]->(IP) and the existing WAF_BYPASS_VIA edge.
        - Emit the exposure as a Vulnerability(type='waf_bypass', source='origin_discovery')
          whose id is the shared stable_vuln_id, so it MERGEs to the SAME node the
          security-check producer writes for the same (type, url, ip) exposure (G1).
        first_seen/last_seen/created_at are stamped like the sibling recon mixins so
        Recon Delta (identity-key based) diffs it correctly (G8).
        """
        # Lazy import: tests that load this file with `graph_db` stubbed as a
        # MagicMock (not a package) would fail a top-level graph_db.mixins.* import.
        from graph_db.mixins.recon.vuln_mixin import stable_vuln_id

        stats = {"ips": 0, "vulns": 0, "has_origin_rels": 0, "waf_bypass_rels": 0, "errors": []}
        data = recon_data.get("origin_discovery") or {}
        confirmed = data.get("confirmed") or []
        if not confirmed:
            print("[graph-db] update_graph_from_origin_discovery complete (no confirmed origins)")
            return stats

        now_iso = datetime.now(timezone.utc).isoformat()

        with self.driver.session() as session:
            for finding in confirmed:
                try:
                    host = finding.get("subdomain")
                    ip = finding.get("matched_ip")
                    probe_url = finding.get("url") or (f"https://{ip}" if ip else "")
                    if not ip or not host:
                        continue
                    # Canonical, port-less url for the Vulnerability identity so
                    # this exposure MERGEs onto the SAME node the security-check
                    # producer writes (check_waf_bypass uses https://{ip}); the
                    # specific discovered port lives in v.port + v.probe_url. Without
                    # this, url=https://{ip}:443 vs https://{ip} would double-count.
                    # IPv6 is bracketed so the url is well-formed.
                    url = f"https://[{ip}]" if ":" in ip else f"https://{ip}"

                    method = finding.get("origin_discovery_method") or "unknown"
                    origin_source = finding.get("origin_source") or "unknown"
                    confidence = finding.get("confidence_score")
                    cdn = finding.get("cdn_fronting")

                    # --- origin IP node (+ provenance) ---
                    ip_props = {
                        "origin_discovery_enriched": True,
                        "is_origin_candidate": True,
                        "origin_confirmed": True,
                        "origin_discovery_method": method,
                        "origin_source": origin_source,
                        "origin_for": host,
                        "last_seen": now_iso,
                    }
                    if confidence is not None:
                        ip_props["origin_confidence"] = confidence
                    if cdn:
                        ip_props["cdn_fronting"] = cdn
                    session.run(
                        """
                        MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        ON CREATE SET i.source = 'origin_discovery',
                                      i.first_seen = $now, i.created_at = $now
                        SET i += $props, i.updated_at = datetime()
                        """,
                        address=ip, user_id=user_id, project_id=project_id,
                        now=now_iso, props=ip_props,
                    )
                    stats["ips"] += 1

                    # --- Subdomain -[:HAS_ORIGIN]-> IP ---
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $host, user_id: $user_id, project_id: $project_id})
                        ON CREATE SET s.source = 'origin_discovery', s.first_seen = $now
                        SET s.updated_at = datetime()
                        WITH s
                        MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        MERGE (s)-[r:HAS_ORIGIN]->(i)
                        ON CREATE SET r.discovered_at = datetime(), r.method = $method
                        SET r.confidence = $confidence, r.origin_source = $origin_source
                        """,
                        host=host, address=ip, user_id=user_id, project_id=project_id,
                        now=now_iso, method=method, confidence=confidence, origin_source=origin_source,
                    )
                    stats["has_origin_rels"] += 1

                    # --- Vulnerability (shared, tenant-scoped id → converges
                    #     with security_check for this tenant, never across tenants) ---
                    vuln_id = stable_vuln_id("waf_bypass", url, ip, user_id, project_id)
                    vuln_props = {
                        "id": vuln_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "type": "waf_bypass",
                        "severity": finding.get("severity", "high"),
                        "name": finding.get("name", "Origin Server Exposed (CDN Bypass)"),
                        "url": url,
                        "matched_at": url,          # Recon Delta identity field (G8)
                        "matched_ip": ip,
                        "hostname": host,
                        "origin_discovery_method": method,
                        "origin_source": origin_source,
                        "is_dast_finding": False,
                        "probe_url": probe_url,     # the actual scheme://ip:port probed
                        "last_seen": now_iso,
                    }
                    for k in ("confidence_score", "port", "match_method", "html_similarity",
                              "cert_match", "header_match", "status_code", "evidence",
                              "file_match", "own_file", "urlscan_seen_at"):
                        if finding.get(k) is not None:
                            vuln_props[k] = finding[k]
                    if cdn:
                        vuln_props["cdn_fronting"] = cdn
                    vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id, user_id: $props.user_id,
                                                project_id: $props.project_id})
                        ON CREATE SET v.source = 'origin_discovery',
                                      v.first_seen = $now, v.created_at = $now
                        SET v += $props, v.updated_at = datetime()
                        """,
                        id=vuln_id, props=vuln_props, now=now_iso,
                    )
                    stats["vulns"] += 1

                    # IP -[:HAS_VULNERABILITY]-> Vulnerability
                    session.run(
                        """
                        MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        MATCH (v:Vulnerability {id: $id, user_id: $user_id, project_id: $project_id})
                        MERGE (i)-[:HAS_VULNERABILITY]->(v)
                        """,
                        address=ip, id=vuln_id, user_id=user_id, project_id=project_id,
                    )

                    # Subdomain -[:WAF_BYPASS_VIA]-> IP (existing security-check edge)
                    session.run(
                        """
                        MATCH (s:Subdomain {name: $host, user_id: $user_id, project_id: $project_id})
                        MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                        MERGE (s)-[r:WAF_BYPASS_VIA]->(i)
                        ON CREATE SET r.discovered_at = datetime()
                        SET r.evidence = $evidence, r.source = 'origin_discovery'
                        """,
                        host=host, address=ip, user_id=user_id, project_id=project_id,
                        evidence=finding.get("evidence") or "",
                    )
                    stats["waf_bypass_rels"] += 1
                except Exception as e:
                    stats["errors"].append(f"origin_discovery finding {finding.get('matched_ip')}: {e}")

        print(f"[+][graph-db] Origin Discovery Graph Update: {stats['ips']} IPs, "
              f"{stats['vulns']} vulnerabilities, {stats['has_origin_rels']} HAS_ORIGIN, "
              f"{stats['waf_bypass_rels']} WAF_BYPASS_VIA")
        print("[graph-db] update_graph_from_origin_discovery complete")
        return stats
