"""User-supplied input nodes and partial discovery graph updates.

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import json

from graph_db.cpe_resolver import _is_ip_address
from graph_db.mixins.recon.scope import _normalize_host, org_for_scan_root, root_for_host

# The UserInput ids create_user_input_node made in this process. A partial run
# is one container process, so these are the run's own nodes: the only
# still-running ones its end-of-run orphan cleanup may delete, since another
# run's node may be waiting for that run's results (httpx makes its node before
# it scans).
_CREATED_THIS_RUN: set = set()


def user_inputs_created_this_run() -> frozenset:
    return frozenset(_CREATED_THIS_RUN)


def _user_input_root(domain, values: list) -> str:
    """The root a UserInput attaches to.

    `domain` is one root, or the run's roots: then the root the first hostname
    value sits under, else the first root (IP-only input names no host).
    """
    if isinstance(domain, str):
        return domain.strip()
    roots = [r for r in (domain or []) if isinstance(r, str) and r.strip()]
    if not roots:
        return ""
    for value in values or []:
        host = _normalize_host(str(value or ""))
        if host and not _is_ip_address(host):
            return root_for_host(host, roots) or roots[0]
    return roots[0]


class UserInputMixin:
    def create_user_input_node(self, domain, user_input_data: dict, user_id: str, project_id: str,
                               root_orgs: dict = None) -> str:
        """
        Create a UserInput node for partial recon user-provided values.

        Args:
            domain: Root domain to attach the UserInput to, or the run's roots
                (a list); see _user_input_root.
            user_input_data: Dict with keys: id, input_type, values, tool_id
            user_id: Tenant user ID
            project_id: Tenant project ID
            root_orgs: {scan root: org}. The UserInput hangs off the org
                Domain of the root its values name (a Domain node is the org);
                without the map the root itself, as before the org model.

        Returns:
            The UserInput node ID

        Raises:
            ValueError: there is no root to attach to. The MERGE below would
                otherwise create a Domain named "".
        """
        domain = _user_input_root(domain, user_input_data.get("values") or [])
        if not domain:
            raise ValueError("No root domain to attach the UserInput node to")
        domain = (root_orgs or {}).get(domain) or domain
        node_id = user_input_data["id"]

        with self.driver.session() as session:
            # Create UserInput node
            session.run(
                """
                MERGE (ui:UserInput {id: $id, user_id: $user_id,
                                     project_id: $project_id})
                SET ui.input_type = $input_type,
                    ui.values = $values,
                    ui.tool_id = $tool_id,
                    ui.source = 'user',
                    ui.status = 'running',
                    ui.created_at = datetime(),
                    ui.user_id = $user_id,
                    ui.project_id = $project_id
                SET ui.updated_at = datetime()
                """,
                id=node_id,
                input_type=user_input_data.get("input_type", "subdomains"),
                values=user_input_data.get("values", []),
                tool_id=user_input_data.get("tool_id", ""),
                user_id=user_id,
                project_id=project_id,
            )
        _CREATED_THIS_RUN.add(node_id)

        # A missing root Domain is created through ensure_root_domains, the only
        # root-Domain MERGE outside the run's own domain write
        # (tests/test_no_stray_domain_merge.py).
        self.ensure_root_domains([domain], user_id, project_id)
        with self.driver.session() as session:
            session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                MATCH (ui:UserInput {id: $ui_id, user_id: $user_id, project_id: $project_id})
                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                """,
                domain=domain, user_id=user_id, project_id=project_id, ui_id=node_id,
            )

            print(f"[+][graph-db] Created UserInput node {node_id} for {domain}")

        return node_id

    def update_user_input_status(self, user_input_id: str, status: str, stats: dict = None, *,
                                 user_id: str, project_id: str) -> bool:
        """Set a UserInput node's status ("completed" or "error") and stats.

        The node is matched on its key, {id, user_id, project_id}: a UserInput
        id alone does not name one project's node. Returns whether the node
        was found; a miss is printed, since the run's record then stays
        "running".
        """
        props = {"status": status}
        if stats:
            props["stats"] = json.dumps(stats, default=str)
        completed = ", ui.completed_at = datetime()" if status == "completed" else ""
        with self.driver.session() as session:
            record = session.run(
                f"""
                MATCH (ui:UserInput {{id: $id, user_id: $user_id, project_id: $project_id}})
                SET ui += $props, ui.updated_at = datetime(){completed}
                RETURN count(ui) AS matched
                """,
                id=user_input_id, user_id=user_id, project_id=project_id, props=props,
            ).single()
        matched = bool(record and record["matched"])
        if not matched:
            print(f"[!][graph-db] UserInput {user_input_id} not found; status {status!r} not recorded")
        return matched

    def update_graph_from_partial_discovery(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
        user_input_id: str = None,
        org_domain: str = None,
    ) -> dict:
        """
        Update Neo4j graph with results from a partial subdomain discovery run.

        Creates Subdomain, IP, DNSRecord nodes and relationships using the same
        MERGE patterns as update_graph_from_domain_discovery(). Optionally links
        all produced nodes to a UserInput node via PRODUCED relationships.

        Args:
            recon_data: Discovery result dict (same format as domain_recon output)
            user_id: Tenant user ID
            project_id: Tenant project ID
            user_input_id: Optional UserInput node ID to link produced nodes
            org_domain: The org Domain the scan root's hosts attach to;
                default org_for_scan_root (recon_data["scope_groups"]), else
                the scan root itself

        Returns:
            Stats dict with counts
        """

        stats = {
            "subdomains_total": 0,
            "subdomains_new": 0,
            "subdomains_existing": 0,
            "ips_total": 0,
            "ips_new": 0,
            "dns_records_created": 0,
            "relationships_created": 0,
            "errors": [],
        }

        subdomains = recon_data.get("subdomains", [])
        dns_data = recon_data.get("dns") or {}
        domain = recon_data.get("domain", "")

        if not domain:
            stats["errors"].append("No domain found in recon_data")
            return stats
        # `domain` is the run's scan root; its hosts attach to the org Domain.
        org = org_domain or org_for_scan_root(domain, recon_data)

        self.ensure_root_domains([org], user_id, project_id)
        with self.driver.session() as session:
            session.run(
                """
                MATCH (d:Domain {name: $name, user_id: $user_id, project_id: $project_id})
                SET d.updated_at = datetime()
                """,
                name=org, user_id=user_id, project_id=project_id,
            )

            subdomain_dns = dns_data.get("subdomains", {}) if dns_data else {}
            domain_dns = dns_data.get("domain", {}) if dns_data else {}
            subdomain_status_map = recon_data.get("subdomain_status_map", {})

            for subdomain in subdomains:
                try:
                    # Get DNS info
                    if subdomain == domain:
                        subdomain_info = domain_dns
                    else:
                        subdomain_info = subdomain_dns.get(subdomain, {})
                    has_records = subdomain_info.get("has_records", False)
                    sub_status = subdomain_status_map.get(subdomain)

                    # Check if subdomain already exists (for stats tracking)
                    result = session.run(
                        """
                        OPTIONAL MATCH (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        RETURN s IS NOT NULL AS exists
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                    )
                    existed = result.single()["exists"]

                    # MERGE subdomain node (same pattern as full recon); a scan
                    # root below its org is marked as such (D-16).
                    session.run(
                        """
                        MERGE (s:Subdomain {name: $name, user_id: $user_id, project_id: $project_id})
                        SET s.is_scan_root = CASE WHEN $is_scan_root THEN true ELSE s.is_scan_root END,
                            s.has_dns_records = $has_records,
                            s.status = coalesce(s.status, $status),
                            s.discovered_at = coalesce(s.discovered_at, datetime()),
                            s.updated_at = datetime()
                        """,
                        name=subdomain, user_id=user_id, project_id=project_id,
                        has_records=has_records, status=sub_status,
                        is_scan_root=(subdomain == domain and domain != org),
                    )
                    stats["subdomains_total"] += 1
                    if existed:
                        stats["subdomains_existing"] += 1
                    else:
                        stats["subdomains_new"] += 1

                    # Relationships: Subdomain <-> Domain
                    session.run(
                        """
                        MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                        MERGE (s)-[:BELONGS_TO]->(d)
                        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                        """,
                        domain=org, sub=subdomain, uid=user_id, pid=project_id,
                    )
                    stats["relationships_created"] += 1

                    # Link to UserInput via PRODUCED
                    if user_input_id:
                        session.run(
                            """
                            MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                            MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                            MERGE (ui)-[:PRODUCED]->(s)
                            """,
                            ui_id=user_input_id, name=subdomain, uid=user_id, pid=project_id,
                        )

                    # Create IP nodes from resolved IPs
                    records = subdomain_info.get("records", {})
                    ips_data = subdomain_info.get("ips", {})

                    for ip_version in ["ipv4", "ipv6"]:
                        for ip_addr in ips_data.get(ip_version, []):
                            if not ip_addr:
                                continue
                            try:
                                # Check if IP already exists
                                ip_exists = session.run(
                                    """
                                    OPTIONAL MATCH (i:IP {address: $address, user_id: $uid, project_id: $pid})
                                    RETURN i IS NOT NULL AS exists
                                    """,
                                    address=ip_addr, uid=user_id, pid=project_id,
                                ).single()["exists"]

                                session.run(
                                    """
                                    MERGE (i:IP {address: $address, user_id: $uid, project_id: $pid})
                                    SET i.version = $version,
                                        i.updated_at = datetime()
                                    """,
                                    address=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version,
                                )
                                stats["ips_total"] += 1
                                if not ip_exists:
                                    stats["ips_new"] += 1

                                # Subdomain -[:RESOLVES_TO]-> IP
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[r:RESOLVES_TO]->(i)
                                    SET r.record_type = coalesce(r.record_type, $rt)
                                    """,
                                    sub=subdomain, ip=ip_addr, rt=record_type,
                                    uid=user_id, pid=project_id,
                                )
                                stats["relationships_created"] += 1

                                # Link IP to UserInput
                                if user_input_id:
                                    session.run(
                                        """
                                        MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                        MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        MERGE (ui)-[:PRODUCED]->(i)
                                        """,
                                        ui_id=user_input_id, addr=ip_addr,
                                        uid=user_id, pid=project_id,
                                    )
                            except Exception as e:
                                stats["errors"].append(f"IP {ip_addr} failed: {e}")

                    # Create DNSRecord nodes (non-A/AAAA)
                    for record_type, record_values in records.items():
                        if not record_values or record_type in ["A", "AAAA"]:
                            continue
                        if not isinstance(record_values, list):
                            record_values = [record_values]
                        for value in record_values:
                            if not value:
                                continue
                            try:
                                session.run(
                                    """
                                    MERGE (dns:DNSRecord {type: $type, value: $value, subdomain: $sub, user_id: $uid, project_id: $pid})
                                    SET dns.updated_at = datetime()
                                    """,
                                    type=record_type, value=str(value), sub=subdomain,
                                    uid=user_id, pid=project_id,
                                )
                                stats["dns_records_created"] += 1

                                session.run(
                                    """
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MATCH (dns:DNSRecord {type: $type, value: $value, subdomain: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:HAS_DNS_RECORD]->(dns)
                                    """,
                                    sub=subdomain, type=record_type, value=str(value),
                                    uid=user_id, pid=project_id,
                                )
                                stats["relationships_created"] += 1
                            except Exception as e:
                                stats["errors"].append(f"DNSRecord {record_type}={value} failed: {e}")

                except Exception as e:
                    stats["errors"].append(f"Subdomain {subdomain} processing failed: {e}")
                    print(f"[!][graph-db] Partial discovery: {subdomain} failed: {e}")

            # Count new IPs (approximate -- count those without prior discovered_at)
            # For simplicity, ips_new tracking is done at MERGE time above

            print(f"[+][graph-db] Partial discovery: {stats['subdomains_total']} subdomains "
                  f"({stats['subdomains_new']} new, {stats['subdomains_existing']} existing)")
            print(f"[+][graph-db] Partial discovery: {stats['ips_total']} IPs, "
                  f"{stats['dns_records_created']} DNS records")
            if stats["errors"]:
                print(f"[!][graph-db] Partial discovery: {len(stats['errors'])} errors")

        try:
            stats["wildcard_zones_stamped"] = self.update_graph_wildcard_zones(
                recon_data, user_id, project_id)
        except Exception as e:
            stats["errors"].append(f"Wildcard zone stamp failed: {e}")
        return stats
