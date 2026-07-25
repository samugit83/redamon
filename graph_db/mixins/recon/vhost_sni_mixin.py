"""
VHost & SNI enumeration graph updates.

Writes Vulnerability nodes with source="vhost_sni_enum" that reuse the existing
Vulnerability label (no new node type). Each finding is attached to the
Subdomain node corresponding to the discovered hidden vhost. The IP node is
also enriched with vhost_* properties (baseline, reverse-proxy flag, hidden
vhost count). When the module discovers a hidden vhost and inject_discovered
is enabled, a BaseURL is also created so downstream tools (Nuclei, Katana in
follow-up partial recon runs) can pick it up.

Properties written on each Vulnerability:
    id                       deterministic hash (hostname+ip+port+layer)
    user_id, project_id      tenant isolation
    source                   "vhost_sni_enum"
    type                     "hidden_vhost" | "hidden_sni_route" | "host_header_bypass"
    name                     human-readable
    severity                 high | medium | low | info
    description              short summary
    hostname                 the hidden vhost FQDN
    ip                       target IP that hosts the vhost
    port                     target port
    scheme                   http | https
    layer                    "L7" | "L4" | "both"
    baseline_status          status code returned by raw IP request
    baseline_size            body size returned by raw IP request
    observed_status          status code returned with vhost lie applied
    observed_size            body size returned with vhost lie applied
    size_delta               observed_size - baseline_size
    internal_pattern_match   matched internal-keyword (e.g. "admin"), or None
    detected_at              tool-native detection timestamp

Properties enriched on existing Subdomain nodes:
    vhost_tested, vhost_hidden, vhost_routing_layer, vhost_status_code,
    vhost_size_delta, sni_routed, vhost_tested_at

Properties enriched on existing IP nodes:
    vhost_sni_tested, vhost_baseline_status, vhost_baseline_size,
    hosts_hidden_vhosts, hidden_vhost_count, is_reverse_proxy
"""

from __future__ import annotations

from datetime import datetime, timezone


class VhostSniMixin:
    def update_graph_from_vhost_sni(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
    ) -> dict:
        """Persist VHost/SNI findings as Vulnerability nodes + enrich IP/Subdomain."""
        stats = {
            "vulnerabilities_created": 0,
            "subdomains_enriched": 0,
            "ips_enriched": 0,
            "baseurls_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        vhost_data = recon_data.get("vhost_sni") or {}
        findings = vhost_data.get("findings") or []
        by_ip = vhost_data.get("by_ip") or {}
        discovered_baseurls = vhost_data.get("discovered_baseurls") or []

        if not findings and not by_ip and not discovered_baseurls:
            return stats

        target_domain = (
            recon_data.get("domain")
            or recon_data.get("metadata", {}).get("target", "")
            or ""
        ).strip().lower()

        with self.driver.session() as session:
            # ----------------------------------------------------------
            # 1. IP-level enrichment (baseline + reverse-proxy flag)
            # ----------------------------------------------------------
            for ip_addr, ip_info in by_ip.items():
                try:
                    baseline = ip_info.get("baseline") or {}
                    ip_props = {
                        "vhost_sni_tested": True,
                        "vhost_baseline_status": baseline.get("status"),
                        "vhost_baseline_size": baseline.get("size"),
                        "vhost_candidates_tested": int(ip_info.get("candidates_tested") or 0),
                        "vhost_ports_tested": int(ip_info.get("ports_tested") or 0),
                        "hosts_hidden_vhosts": bool(ip_info.get("hosts_hidden_vhosts")),
                        "hidden_vhost_count": int(ip_info.get("anomaly_count") or 0),
                        "is_reverse_proxy": bool(ip_info.get("is_reverse_proxy")),
                        "is_permissive_frontend": bool(ip_info.get("is_permissive_frontend")),
                        "vhost_sni_suppressed_by_control": int(ip_info.get("suppressed_by_control") or 0),
                        "vhost_sni_tested_at": datetime.now(timezone.utc).isoformat(),
                    }
                    ip_props = {k: v for k, v in ip_props.items() if v is not None}

                    res = session.run(
                        """
                        MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                        SET i += $props,
                            i.first_seen = coalesce(i.first_seen, datetime($recon_job_started_at)),
                            i.first_seen_job_id = coalesce(i.first_seen_job_id, $recon_job_id),
                            i.last_seen = datetime($recon_job_started_at),
                            i.last_seen_job_id = $recon_job_id
                        RETURN count(i) AS matched
                        """,
                        addr=ip_addr, uid=user_id, pid=project_id, props=ip_props,
                        **self._recon_job_params(),
                    )
                    if res.single()["matched"] > 0:
                        stats["ips_enriched"] += 1
                except Exception as e:
                    stats["errors"].append(f"vhost_sni IP {ip_addr} enrichment failed: {e}")

            # ----------------------------------------------------------
            # 2. Per-finding Vulnerability nodes + Subdomain enrichment
            # ----------------------------------------------------------
            for finding in findings:
                try:
                    vuln_id = finding.get("id")
                    hostname = (finding.get("hostname") or "").strip().lower()
                    ip_addr = finding.get("ip")
                    port = finding.get("port")
                    layer = finding.get("layer") or "L7"
                    severity = finding.get("severity") or "info"
                    detected_at = finding.get("discovered_at") or datetime.now(timezone.utc).isoformat()

                    if not vuln_id or not hostname:
                        continue

                    vuln_props = {
                        "id": vuln_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "source": "vhost_sni_enum",
                        "type": finding.get("type") or "hidden_vhost",
                        "name": finding.get("name") or f"Hidden Virtual Host: {hostname}",
                        "severity": severity,
                        "description": finding.get("description") or "",
                        "hostname": hostname,
                        "host": hostname,
                        "ip": ip_addr,
                        "port": port,
                        "scheme": finding.get("scheme") or "https",
                        "layer": layer,
                        "baseline_status": finding.get("baseline_status"),
                        "baseline_size": finding.get("baseline_size"),
                        "observed_status": finding.get("observed_status"),
                        "observed_size": finding.get("observed_size"),
                        "size_delta": finding.get("size_delta"),
                        "internal_pattern_match": finding.get("internal_pattern_match"),
                        "matched_at": _build_url(hostname, port, finding.get("scheme") or "https"),
                        "is_dast_finding": False,
                        "detected_at": detected_at,
                    }
                    vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id})
                        ON CREATE SET v.first_seen = coalesce(v.first_seen, datetime($recon_job_started_at)),
                                      v.first_seen_job_id = coalesce(v.first_seen_job_id, $recon_job_id)
                        SET v += $props,
                            v.updated_at = datetime(),
                            v.first_seen = coalesce(v.first_seen, datetime($recon_job_started_at)),
                            v.first_seen_job_id = coalesce(v.first_seen_job_id, $recon_job_id),
                            v.last_seen = datetime($recon_job_started_at),
                            v.last_seen_job_id = $recon_job_id
                        """,
                        id=vuln_id, props=vuln_props,
                        **self._recon_job_params(),
                    )
                    stats["vulnerabilities_created"] += 1

                    # Attach to Subdomain (creating defensively if missing).
                    sub_props = {
                        "vhost_tested": True,
                        "vhost_hidden": True,
                        "vhost_routing_layer": layer,
                        "vhost_status_code": finding.get("observed_status"),
                        "vhost_size_delta": finding.get("size_delta"),
                        "sni_routed": layer in ("L4", "both"),
                        "vhost_tested_at": detected_at,
                    }
                    sub_props = {k: v for k, v in sub_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (s:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                        ON CREATE SET s.source = 'vhost_sni_enum',
                                      s.created_at = datetime(),
                                      s.first_seen = coalesce(s.first_seen, datetime($recon_job_started_at)),
                                      s.first_seen_job_id = coalesce(s.first_seen_job_id, $recon_job_id),
                                      s.last_seen = datetime($recon_job_started_at),
                                      s.last_seen_job_id = $recon_job_id
                        SET s += $sprops,
                            s.updated_at = datetime(),
                            s.first_seen = coalesce(s.first_seen, datetime($recon_job_started_at)),
                            s.first_seen_job_id = coalesce(s.first_seen_job_id, $recon_job_id),
                            s.last_seen = datetime($recon_job_started_at),
                            s.last_seen_job_id = $recon_job_id
                        WITH s
                        MATCH (v:Vulnerability {id: $id})
                        MERGE (s)-[:HAS_VULNERABILITY]->(v)
                        """,
                        hostname=hostname, uid=user_id, pid=project_id,
                        id=vuln_id, sprops=sub_props,
                        **self._recon_job_params(),
                    )
                    stats["subdomains_enriched"] += 1
                    stats["relationships_created"] += 1

                    # Wire the Subdomain into the rest of the graph so it isn't
                    # orphaned when vhost_sni invented it (a newly discovered
                    # hidden vhost won't exist as a Subdomain yet). Link to the
                    # parent Domain (BELONGS_TO/HAS_SUBDOMAIN) when the hostname
                    # falls under the project's target domain, and to the IP
                    # (RESOLVES_TO) it was discovered on.
                    if target_domain and hostname.endswith(target_domain) and hostname != target_domain:
                        res_d = session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                            MATCH (s:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                            MERGE (s)-[:BELONGS_TO]->(d)
                            MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                            RETURN count(d) AS matched
                            """,
                            domain=target_domain, hostname=hostname,
                            uid=user_id, pid=project_id,
                        )
                        if res_d.single()["matched"] > 0:
                            stats["relationships_created"] += 2

                    if ip_addr:
                        res_ip = session.run(
                            """
                            MATCH (s:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                            MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            MERGE (s)-[:RESOLVES_TO {discovered_via: 'vhost_sni_enum'}]->(i)
                            RETURN count(i) AS matched
                            """,
                            hostname=hostname, addr=ip_addr,
                            uid=user_id, pid=project_id,
                        )
                        if res_ip.single()["matched"] > 0:
                            stats["relationships_created"] += 1

                    # For host_header_bypass (L7 vs L4 disagreement) the IP is
                    # also a vulnerable surface — attach the same Vulnerability
                    # to the IP node so it surfaces in IP-level dashboards.
                    if finding.get("type") == "host_header_bypass" and ip_addr:
                        session.run(
                            """
                            MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            MATCH (v:Vulnerability {id: $id})
                            MERGE (i)-[:HAS_VULNERABILITY]->(v)
                            """,
                            addr=ip_addr, uid=user_id, pid=project_id, id=vuln_id,
                        )
                        stats["relationships_created"] += 1

                    # Attach to Domain too, when the hostname IS the apex.
                    if target_domain and hostname == target_domain:
                        session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                            MATCH (v:Vulnerability {id: $id})
                            MERGE (d)-[:HAS_VULNERABILITY]->(v)
                            """,
                            domain=target_domain, uid=user_id, pid=project_id, id=vuln_id,
                        )
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"vhost_sni finding {finding.get('id', '?')} failed: {e}")

            # ----------------------------------------------------------
            # 3. BaseURLs for newly discovered hidden vhosts
            # ----------------------------------------------------------
            for url in discovered_baseurls:
                try:
                    hostname = _extract_hostname(url)
                    if not hostname:
                        continue
                    res = session.run(
                        """
                        MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                        ON CREATE SET b.discovery_source = 'vhost_sni_enum',
                                      b.created_at = datetime(),
                                      b.scheme = $scheme,
                                      b.host = $host,
                                      b.port = $port,
                                      b.first_seen = coalesce(b.first_seen, datetime($recon_job_started_at)),
                                      b.first_seen_job_id = coalesce(b.first_seen_job_id, $recon_job_id),
                                      b.last_seen = datetime($recon_job_started_at),
                                      b.last_seen_job_id = $recon_job_id
                        SET b.updated_at = datetime(),
                            b.first_seen = coalesce(b.first_seen, datetime($recon_job_started_at)),
                            b.first_seen_job_id = coalesce(b.first_seen_job_id, $recon_job_id),
                            b.last_seen = datetime($recon_job_started_at),
                            b.last_seen_job_id = $recon_job_id
                        WITH b
                        MERGE (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
                        ON CREATE SET s.source = 'vhost_sni_enum',
                                      s.created_at = datetime(),
                                      s.first_seen = coalesce(s.first_seen, datetime($recon_job_started_at)),
                                      s.first_seen_job_id = coalesce(s.first_seen_job_id, $recon_job_id),
                                      s.last_seen = datetime($recon_job_started_at),
                                      s.last_seen_job_id = $recon_job_id
                        ON MATCH SET s.first_seen = coalesce(s.first_seen, datetime($recon_job_started_at)),
                                     s.first_seen_job_id = coalesce(s.first_seen_job_id, $recon_job_id),
                                     s.last_seen = datetime($recon_job_started_at),
                                     s.last_seen_job_id = $recon_job_id
                        MERGE (s)-[:HAS_BASEURL]->(b)
                        RETURN count(b) AS created
                        """,
                        url=url, uid=user_id, pid=project_id,
                        scheme=_scheme(url), host=hostname, port=_port(url),
                        **self._recon_job_params(),
                    )
                    if res.single()["created"] > 0:
                        stats["baseurls_created"] += 1
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"vhost_sni baseurl {url} failed: {e}")

        if stats["vulnerabilities_created"] > 0 or stats["ips_enriched"] > 0:
            print(
                f"[+][graph-db] vhost_sni: {stats['vulnerabilities_created']} Vulnerability node(s), "
                f"{stats['subdomains_enriched']} Subdomain enriched, "
                f"{stats['ips_enriched']} IP enriched, "
                f"{stats['baseurls_created']} BaseURL created, "
                f"{stats['relationships_created']} relationship(s)"
            )
        if stats["errors"]:
            print(f"[!][graph-db] vhost_sni: {len(stats['errors'])} error(s) during graph update")

        return stats


# =============================================================================
# Helpers
# =============================================================================
def _build_url(hostname: str, port, scheme: str) -> str:
    if not hostname:
        return ""
    try:
        port_i = int(port) if port is not None else 0
    except (TypeError, ValueError):
        port_i = 0
    if (scheme == "https" and port_i == 443) or (scheme == "http" and port_i == 80) or port_i == 0:
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port_i}"


def _extract_hostname(url: str) -> str:
    if not url:
        return ""
    after_scheme = url.split("://", 1)[-1]
    host_part = after_scheme.split("/", 1)[0]
    return host_part.split(":", 1)[0].lower()


def _scheme(url: str) -> str:
    if "://" in url:
        return url.split("://", 1)[0].lower()
    return "https"


def _port(url: str) -> int:
    after_scheme = url.split("://", 1)[-1]
    host_part = after_scheme.split("/", 1)[0]
    if ":" in host_part:
        try:
            return int(host_part.split(":", 1)[1])
        except ValueError:
            pass
    return 443 if url.startswith("https://") else 80
