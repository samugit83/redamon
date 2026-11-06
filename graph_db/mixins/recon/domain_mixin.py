"""Domain and IP recon graph updates.

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.cpe_resolver import _is_ip_address
from graph_db.mixins.recon.scope import home_domain, org_for_scan_root, project_orgs

# The first clause of every read-modify-write on an org Domain (GDB-11). Several
# scan roots share one org Domain and up to twelve partial recons run at once,
# so the node's write lock is taken BEFORE anything is read, and held to commit.
# The property never commits (set and removed in the same clause).
ORG_DOMAIN_LOCK = "SET d._scope_lock = true REMOVE d._scope_lock"

# Run fields the domain writer no longer puts on a Domain: one per-run value on
# a node several scan roots share means nothing (§4.11.3). scan_timestamp stays.
RETIRED_DOMAIN_RUN_PROPS = ("target", "filtered_mode", "wildcard_mode", "subdomain_filter",
                            "modules_executed", "anonymous_mode", "bruteforce_mode", "scan_type")


def _unrecognized_quiet_session(driver):
    """A session that does not log UNRECOGNIZED notifications (01N52).

    `ip_mode` is written only by an IP-mode scan, so on a database that never
    ran one Neo4j does not know the key and warns on every read of it, though
    `coalesce(d.ip_mode, false)` handles the absence on purpose. Scoped to the
    one query that reads it, so a real typo elsewhere still warns.
    """
    try:
        from neo4j import NotificationDisabledClassification
    except ImportError:  # pragma: no cover - an older driver logs the warning
        return driver.session()
    return driver.session(notifications_disabled_classifications=[
        NotificationDisabledClassification.UNRECOGNIZED])


def _merge_unique(existing: list, new: list) -> list:
    out = list(existing)
    for item in new:
        if item not in out:
            out.append(item)
    return out


def merge_coverage(stored: dict, record: dict, scan_root: str, run_started_at) -> dict:
    """The coverage record an org Domain keeps after this group stamps it (§4.11.4).

    The first group of a run (recon_coverage_run is not this run's start)
    overwrites; a later group of the same run merges: gaps and skipped hosts
    are unioned, nuclei truncation is OR-ed, and recon_coverage_roots lists
    every scan root that stamped. Pure, because the unit of work that calls it
    is retried. Each gap entry carries the scan root it came from, so a reader
    can drop a removed root's entries (§4.11.7).
    """
    import json as _json
    try:
        gaps = _json.loads(record.get("gaps_json") or "[]")
    except (TypeError, ValueError):
        gaps = []
    gaps = [dict(g, root=g.get("root") or scan_root) if isinstance(g, dict) else g
            for g in gaps if g is not None]
    skipped = [h for h in record.get("skipped_hosts") or [] if h]
    truncated = bool(record.get("nuclei_truncated"))
    first = run_started_at is None or stored.get("run") != run_started_at
    if not first:
        try:
            old_gaps = _json.loads(stored.get("gaps") or "[]")
        except (TypeError, ValueError):
            old_gaps = []
        gaps = _merge_unique(old_gaps, gaps)
        skipped = _merge_unique(list(stored.get("skipped") or []), skipped)
        truncated = truncated or bool(stored.get("truncated"))
        roots = _merge_unique(list(stored.get("roots") or []), [scan_root])
    else:
        roots = [scan_root]
    return {"gaps_json": _json.dumps(gaps), "skipped_hosts": skipped,
            "nuclei_truncated": truncated, "roots": roots}


class DomainMixin:
    def _org_write(self, work):
        """Run `work(tx)` as ONE managed write transaction (the driver retries
        it on a deadlock or a transient error)."""
        with self.driver.session() as session:
            return session.execute_write(work)

    def ensure_root_domains(self, roots: list, user_id: str, project_id: str) -> int:
        """MERGE a bare Domain node for every org; return how many exist.

        `roots` are org (registrable) domains: a Domain node is the org, and
        every scan root's hosts attach to it. A Domain batch clears the graph
        once and then scans one group at a time, so while group 1 runs the
        later groups' Domain nodes do not exist yet. A writer attaching a host
        it found under a sibling root (attach_roots) links it to that root's
        org Domain, and without the node the Subdomain is left unlinked. Only
        the tenant key and updated_at: the group's own domain write fills in
        the rest.
        """
        names = [r.strip() for r in roots or [] if isinstance(r, str) and r.strip()]
        if not names:
            return 0
        with self.driver.session() as session:
            record = session.run(
                """
                UNWIND $names AS name
                MERGE (d:Domain {name: name, user_id: $user_id, project_id: $project_id})
                ON CREATE SET d.updated_at = datetime()
                RETURN count(d) AS seeded
                """,
                names=names, user_id=user_id, project_id=project_id,
            ).single()
        return record["seeded"] if record else 0

    def update_graph_coverage(self, user_id: str, project_id: str, domain: str,
                              record: dict, run_started_at=None) -> int:
        """Stamp on the org Domain what this group could NOT check; return nodes matched.

        `domain` is the group's scan root; the record lands on its org Domain,
        ``record["org_domain"]`` (default: the scan root itself, as in IP mode
        and a legacy caller), matched case-insensitively. Written for every full-run group, clean or not: `recon_coverage_at` on
        a Domain the run re-created is what separates "known clean" (gaps
        "[]") from "unknown" (a crashed run, a down graph, an older recon).
        Groups of one org merge into one record (merge_coverage), keyed on
        `run_started_at`, never on run_timestamp(), which changes on every
        call; a caller passing none overwrites. A MATCH, not a MERGE: 0 matched
        means the write failed, which the caller treats as "coverage unknown".

        ``record``: {"at": ISO-8601, "gaps_json": JSON array string (each entry
        carries "root"), "skipped_hosts": [host:port, ...],
        "nuclei_truncated": bool, "org_domain": org}.
        """
        org_key = str(record.get("org_domain") or domain or "").strip().lower()
        scan_root = domain
        run = str(run_started_at) if run_started_at is not None else None

        def work(tx):
            stored = tx.run(
                f"""
                MATCH (d:Domain {{user_id: $user_id, project_id: $project_id}})
                WHERE toLower(d.name) = $org
                {ORG_DOMAIN_LOCK}
                RETURN elementId(d) AS eid, d.recon_coverage_run AS run,
                       d.recon_coverage_gaps AS gaps, d.recon_skipped_hosts AS skipped,
                       d.recon_nuclei_truncated AS truncated, d.recon_coverage_roots AS roots
                """,
                org=org_key, user_id=user_id, project_id=project_id,
            ).single()
            if stored is None:
                return 0
            merged = merge_coverage(dict(stored), record, scan_root, run)
            written = tx.run(
                """
                MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
                WHERE elementId(d) = $eid
                SET d.recon_coverage_at = datetime($at),
                    d.recon_coverage_gaps = $gaps_json,
                    d.recon_skipped_hosts = $skipped_hosts,
                    d.recon_nuclei_truncated = $nuclei_truncated,
                    d.recon_coverage_roots = $roots,
                    d.recon_coverage_run = $run
                RETURN count(d) AS n
                """,
                eid=stored["eid"], user_id=user_id, project_id=project_id, at=record["at"],
                gaps_json=merged["gaps_json"], skipped_hosts=merged["skipped_hosts"],
                nuclei_truncated=merged["nuclei_truncated"], roots=merged["roots"], run=run,
            ).single()
            return int(written["n"]) if written else 0

        return self._org_write(work)

    def legacy_domain_nodes(self, user_id: str, project_id: str,
                            expected, related) -> list:
        """Domain nodes an older scope model left holding data; [] when none.

        `expected` is the names the current scope's Domain nodes carry
        (expectedDomainNames: the scan roots until the org model ships, the
        orgs after); `related` is the orgs and scan roots. A Domain that is
        neither expected nor unrelated to the scope (a removed root keeps its
        ordinary stale semantics) but still holds subdomains or a coverage
        record is old-model, e.g. `Domain(co.uk)` after the batch regrouped to
        `acme.co.uk`. A partial run must not attach to it: refuse until a full
        recon rebuilds the graph. Case-insensitive, because legacy
        single-domain targets were stored with the case they were typed in.
        Mirrored by the webapp's graph-inputs route (`legacy_graph`); both read
        tests/fixtures/legacy_domain_vectors.json.
        """
        expected = sorted({str(n).strip().lower() for n in expected or [] if str(n).strip()})
        related = sorted({str(n).strip().lower() for n in related or [] if str(n).strip()})
        if not related:
            return []
        with _unrecognized_quiet_session(self.driver) as session:
            record = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                WITH d, toLower(d.name) AS n
                WHERE NOT n IN $expected AND coalesce(d.ip_mode, false) = false
                  AND ANY(r IN $related WHERE n = r OR n ENDS WITH '.' + r OR r ENDS WITH '.' + n)
                  AND (EXISTS { (d)-[:HAS_SUBDOMAIN]->() } OR d.recon_coverage_at IS NOT NULL)
                RETURN collect(d.name) AS legacy
                """,
                uid=user_id, pid=project_id, expected=expected, related=related,
            ).single()
        return sorted(record["legacy"]) if record else []

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

            # The group's scan root; its hosts attach to the org Domain. A
            # legacy file has no org: the scan root is its own Domain, as before.
            root_domain = metadata.get("root_domain", "")
            org_domain = (metadata.get("org_domain")
                          or (org_for_scan_root(root_domain, recon_data) if root_domain else ""))

            if not root_domain:
                stats["errors"].append("No root_domain found in metadata")
                return stats

            # 1. Create the org Domain node with WHOIS data. The per-run fields
            # (target, filtered_mode, ...) are no longer written: several scan
            # roots share this node, and the scope lives in scopeGroups.
            try:
                domain_props = {
                    "name": org_domain,
                    "user_id": user_id,
                    "project_id": project_id,
                    "scan_timestamp": metadata.get("scan_timestamp"),
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

                # Drop empty values: a later group of the same org whose WHOIS
                # came back empty must not blank what an earlier one wrote.
                domain_props = {k: v for k, v in domain_props.items()
                                if v is not None and v != [] and v != ""}

                session.run(
                    """
                    MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                    SET d += $props,
                        d.updated_at = datetime()
                    """,
                    name=org_domain, user_id=user_id, project_id=project_id, props=domain_props
                )
                stats["domain_created"] = True
                print(f"[+][graph-db] Created Domain node: {org_domain}")
            except Exception as e:
                stats["errors"].append(f"Domain creation failed: {e}")
                print(f"[!][graph-db] Domain creation failed: {e}")

            # 2. Create Subdomain nodes and relationships
            subdomain_dns = dns_data.get("subdomains", {})
            domain_dns = dns_data.get("domain", {})  # DNS data for root domain
            subdomain_status_map = recon_data.get("subdomain_status_map", {})

            for subdomain in subdomains:
                try:
                    # The scan root's own DNS is in dns.domain (recon keeps it
                    # only when the root is a target).
                    if subdomain == root_domain:
                        subdomain_info = domain_dns
                    else:
                        subdomain_info = subdomain_dns.get(subdomain, {})
                    has_records = subdomain_info.get("has_records", False)

                    # Create Subdomain node
                    status = subdomain_status_map.get(subdomain)  # None for unresolved subs
                    # AI surface recon: lap-1 TXT/NS hint set by domain_recon._annotate_ai_service_hint
                    ai_service_hint = subdomain_info.get("ai_service_hint")
                    # A scan root below its org is a Subdomain of the org, marked
                    # as the root it is (D-16); the org apex keeps today's shape.
                    is_scan_root = subdomain == root_domain and root_domain != org_domain
                    # A name another source found (urlscan, a certificate SAN,
                    # uncover, JS Recon) keeps it: first writer only.
                    source = subdomain_info.get("source") if isinstance(subdomain_info.get("source"), str) else None
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        SET s.is_scan_root = CASE WHEN $is_scan_root THEN true ELSE s.is_scan_root END,
                            s.source = coalesce(s.source, $source),
                            s.has_dns_records = $has_records,
                            s.status = coalesce(s.status, $status),
                            s.discovered_at = coalesce(s.discovered_at, datetime()),
                            s.updated_at = datetime(),
                            s.ai_service_hint = CASE
                                WHEN $ai_service_hint IS NULL THEN s.ai_service_hint
                                WHEN s.ai_service_hint IS NULL THEN $ai_service_hint
                                WHEN $ai_service_hint = 'ai-hosting-candidate' AND s.ai_service_hint <> 'ai-hosting-candidate' THEN s.ai_service_hint
                                ELSE $ai_service_hint
                            END
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                        has_records=has_records, status=status,
                        ai_service_hint=ai_service_hint, is_scan_root=is_scan_root,
                        source=source,
                    )
                    stats["subdomains_created"] += 1
                    if ai_service_hint:
                        stats.setdefault("ai_service_hint_set", 0)
                        stats["ai_service_hint_set"] += 1

                    # Create relationships: Subdomain -[:BELONGS_TO]-> Domain and Domain -[:HAS_SUBDOMAIN]-> Subdomain
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                        MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                        """,
                        domain=org_domain, subdomain=subdomain,
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

                                    # Create relationship: Subdomain -[:RESOLVES_TO]-> IP.
                                    # DNS resolved it, so an edge Shodan's reverse DNS
                                    # created first (source 'shodan_rdns') is forward DNS now.
                                    record_type = "A" if ip_version == "ipv4" else "AAAA"
                                    session.run(
                                        """
                                        MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                        MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})
                                        MERGE (s)-[r:RESOLVES_TO]->(i)
                                        SET r.record_type = coalesce(r.record_type, $record_type)
                                        REMOVE r.source
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

        try:
            stats["wildcard_zones_stamped"] = self.update_graph_wildcard_zones(
                recon_data, user_id, project_id)
        except Exception as e:
            stats["errors"].append(f"Wildcard zone stamp failed: {e}")
        return stats

    def update_graph_wildcard_zones(self, recon_data: dict, user_id: str, project_id: str) -> int:
        """Stamp is_wildcard_zone and wildcard_ips on each zone the wildcard
        control checked; return how many nodes were stamped.

        ``recon_data["wildcard_zones"]``: {zone: {"is_wildcard", "ips"}}, only
        zones with a definite answer. An org zone is its Domain; any deeper
        zone (a scan root below its org, a parent many names sat under) is the
        Subdomain of that name. MATCH only: a zone with no node yet is stamped
        by the next run that writes one, and a Domain is never created here.
        """
        zones = (recon_data or {}).get("wildcard_zones")
        if not isinstance(zones, dict) or not zones:
            return 0
        orgs = {o.strip().lower() for o in project_orgs(recon_data) if o}
        home = home_domain(recon_data)
        if home:
            orgs.add(home.strip().lower())
        stamped = 0
        with self.driver.session() as session:
            for zone, info in zones.items():
                zone = str(zone or "").strip().rstrip(".").lower()
                if not zone or not isinstance(info, dict):
                    continue
                params = {
                    "zone": zone, "user_id": user_id, "project_id": project_id,
                    "is_wildcard": bool(info.get("is_wildcard")),
                    "ips": [ip for ip in info.get("ips") or [] if isinstance(ip, str) and ip],
                }
                if zone in orgs:
                    query = """
                        MATCH (d:Domain {name: $zone, user_id: $user_id, project_id: $project_id})
                        SET d.is_wildcard_zone = $is_wildcard, d.wildcard_ips = $ips
                        RETURN count(d) AS n
                    """
                else:
                    query = """
                        MATCH (s:Subdomain {name: $zone, user_id: $user_id, project_id: $project_id})
                        SET s.is_wildcard_zone = $is_wildcard, s.wildcard_ips = $ips
                        RETURN count(s) AS n
                    """
                record = session.run(query, **params).single()
                stamped += record["n"] if record else 0
        return stamped

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
                }
                domain_props = {k: v for k, v in domain_props.items() if v is not None}

                session.run(
                    """
                    MERGE (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                    SET d += $props,
                        d.updated_at = datetime()
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
                    }
                    if actual_ip:
                        sub_props["actual_ip"] = actual_ip
                    # AI surface recon (lap-1): TXT/NS hint set by domain_recon._annotate_ai_service_hint
                    ai_hint = sub_dns.get("ai_service_hint")
                    if ai_hint:
                        sub_props["ai_service_hint"] = ai_hint

                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        ON CREATE SET s += $props, s.status = 'resolved', s.updated_at = datetime()
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
                        whois_info = ip_whois.get(ip) or {}

                        ip_props = {
                            "address": ip,
                            "user_id": user_id,
                            "project_id": project_id,
                            "version": "ipv6" if ":" in ip else "ipv4",
                            "ip_mode": True,
                        }
                        # A blank whois field is left unset: "" reads as present
                        # to every IS NOT NULL / coalesce() reader. Nothing to
                        # REMOVE: a full run clears IP nodes before this first
                        # writer, and a REMOVE could erase an OSINT country.
                        if whois_info.get("org"):
                            ip_props["organization"] = whois_info["org"]
                        if whois_info.get("country"):
                            ip_props["country"] = whois_info["country"]

                        session.run(
                            """
                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            SET i += $props,
                                i.updated_at = datetime()
                            """,
                            addr=ip, uid=user_id, pid=project_id, props=ip_props
                        )
                        stats["ips_created"] += 1

                        # RESOLVES_TO
                        session.run(
                            """
                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                            MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                            MERGE (s)-[r:RESOLVES_TO]->(i)
                            REMOVE r.source
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
