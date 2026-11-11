"""Vulnerability scan graph updates (Vulnerability, CVE, CWE, CAPEC, Exploit, MitreData).

Part of the recon_mixin.py split. Methods pasted unchanged.
"""
import ipaddress
import json
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from graph_db.coverage_stamps import stamp_base_url_coverage
from graph_db.cpe_resolver import _is_ip_address
from graph_db.mixins.recon.scope import build_host_scope, host_in_scope, org_for_scan_root
from graph_db.endpoint_paths import normalize_endpoint_path


def stable_vuln_id(finding_type: str, url: str, ip_or_host: str = "",
                   user_id: str = "", project_id: str = "") -> str:
    """Deterministic, TENANT-SCOPED Vulnerability node id.

    One (type, url, ip/host) exposure within one tenant hashes to a single id
    regardless of which producer emits it (security_check or origin_discovery) or
    the run order, so the Vulnerability MERGE converges instead of duplicating on
    re-run. sha1 is used because builtin hash() is per-process randomized
    (PYTHONHASHSEED), which spawned a fresh node on every re-run.

    The tenant (user_id, project_id) MUST be part of the key: the Vulnerability
    node carries a GLOBAL uniqueness constraint on `id` (schema.py) and the MERGE
    keys on `{id}` alone. Without the tenant salt, two projects that discover the
    same (type, url, ip) would collide into one node and the second writer's
    `SET v += {user_id, project_id}` would silently steal the first tenant's node.
    """
    unique_key = f"{finding_type or ''}|{url or ''}|{ip_or_host or ''}|{user_id or ''}|{project_id or ''}"
    return hashlib.sha1(unique_key.encode("utf-8", "replace")).hexdigest()[:12]


def _authority_host(parsed) -> str:
    """A parsed URL's host without its port, case kept; an IPv6 literal unbracketed.

    A plain netloc.split(':') cuts "[2001:db8::1]:8080" to "[2001", which no IP
    node matches.
    """
    netloc = parsed.netloc
    if netloc.startswith("["):
        return netloc[1:].partition("]")[0]
    return netloc.split(":")[0]


def _ip_port_key(ip: str, port) -> str:
    """The id key of a finding scoped to one IP (and port): "ip:port", IPv6 bracketed."""
    if not port:
        return ip
    try:
        bracket = ipaddress.ip_address(ip).version == 6
    except ValueError:
        bracket = False
    return f"[{ip}]:{port}" if bracket else f"{ip}:{port}"


#: Security-check fields with no fixed column of their own, copied onto the
#: node when the check set them: how a waf_bypass was decided and how sure the
#: classifier was (triage weighs a finding by them), and a port's service.
_SECURITY_CHECK_EXTRA_FIELDS = (
    "detection_method", "waf_confidence", "waf_type", "ai_reasoning", "service",
    "control_check",
    # Page Content checks (item 5): the catalog row that matched.
    "family", "matched", "problem", "provider", "outcome",
)

#: Words nmap and the fingerprinters put after a product name without making
#: it another product: "Apache httpd", "Microsoft IIS httpd", "Apache HTTP
#: Server", "Squid http proxy", "PostgreSQL DB", "Node.js Express framework",
#: "OpenResty web app server", "Elasticsearch REST API", "Golang net/http
#: server", "Samba smbd". "rest" counts only as "rest api": "Django REST
#: framework" is a product of its own, not Django.
_TECH_DESCRIPTOR_WORDS = (
    "http", "https", "httpd", "server", "web", "webserver", "daemon", "smtpd",
    "ftpd", "sshd", "imapd", "pop3d", "smbd", "proxy", "accelerator", "framework",
    "db", "database", "app", "application", r"rest[\s-]+api", "api", "net",
)


def tech_name_regex(product: str) -> str:
    """The regex a lower-cased Technology.name must fully match to BE `product`.

    `product` is the CVE lookup's normalised name ("apache", "iis", "openssh").
    The name must be the product's whole words, optionally behind one vendor
    word and followed by descriptor words, then anything after "/", ":" or "("
    (version, distro). So "Apache httpd/2.4.41", "Microsoft IIS httpd/10.0",
    "Apache Tomcat" (for "tomcat") match, while "phpMyAdmin" (php), "Django"
    (go), "Preact" (react) and "Apache Tomcat" (apache) do not.

    Only constructs Java and Python read alike, so the Cypher `=~` and
    tech_matches_cve_product decide the same way.
    """
    tokens = [t for t in re.split(r"[\s-]+", str(product or "").strip().lower()) if t]
    if not tokens:
        return "(?!)"
    sep = r"[\s-]+"
    core = sep.join(re.escape(t) for t in tokens)
    descriptors = "|".join(_TECH_DESCRIPTOR_WORDS)
    return rf"(?:[^\s/:(-]+{sep})?{core}(?:{sep}(?:{descriptors}))*(?:\s*[/:(].*)?"


def tech_version_regex(version: str) -> str:
    """The regex a Technology.version must fully match to be `version` in another
    spelling: "8.2p1", "8.2-1ubuntu" and nmap's dotted qualifiers
    ("9.4.44.v20210927", "5.3.20.RELEASE", "7.1.1.Final") are the version before
    them, "10.0" is 10; "8.20" and "8.2.1" are not 8.2."""
    v = re.sub(r"^[vV]", "", str(version or "").strip())
    v = re.sub(r"(?:\.0)+$", "", v) or v
    return rf"[vV]?{re.escape(v)}(?:\.0)*(?:[^0-9.].*|\.[^0-9].*)?"


def tech_matches_cve_product(tech_name: str, product: str, *exact_names: str) -> bool:
    """Python mirror of the writer's Technology name predicate (see tech_name_regex).

    An exact, case-insensitive name match on the product or one of
    `exact_names` (the lookup key with and without its version) always holds.
    Otherwise the product must sit inside the name (the CONTAINS guard) AND
    match as a whole product, so it only ever narrows substring matching.
    """
    name = str(tech_name or "").lower()
    if not name:
        return False
    if any(name == str(n).lower() for n in (product, *exact_names) if n):
        return True
    p = str(product or "").lower()
    return bool(p) and p in name and re.fullmatch(tech_name_regex(p), name) is not None


def nuclei_cve_ids(cves) -> list:
    """The CVE ids of a parsed nuclei finding, as the `cves` property stores them.

    parse_nuclei_finding hands `cves` over as {id, cvss, url} maps, and Neo4j
    stores only primitives and arrays of them: a single map fails the whole
    Vulnerability write, and the per-finding `except` turns that into a silently
    missing finding. Only the id is kept; the score is already `cvss_score` and
    the url is built from the id.
    """
    ids = []
    for cve in cves or []:
        cve_id = cve.get("id") if isinstance(cve, dict) else cve
        if isinstance(cve_id, str) and cve_id and cve_id not in ids:
            ids.append(cve_id)
    return ids


_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


def canonical_cve_id(value) -> str:
    """`value` as an upper-case CVE id, or "" when it is not exactly one.

    CVE is a global node every tenant shares, and a nuclei template's
    classification is free text: only a well-formed id may name one.
    """
    text = value.strip().upper() if isinstance(value, str) else ""
    return text if _CVE_ID.match(text) else ""


def _cvss_or_none(value):
    if isinstance(value, bool):
        return None
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


class VulnMixin:
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

        # Get CWE ID (support both "cwe_id" and "id" keys)
        cwe_id = cwe_node.get("cwe_id") or cwe_node.get("id")
        if not cwe_id:
            return

        # Generate unique MitreData node ID (per CVE + CWE combination)
        mitre_id = f"{cve_id}-{cwe_id}"

        # Create MitreData node with CWE properties
        # GLOBAL reference node: keyed on its natural id alone, one node per
        # CWE for the whole database. It carries NO tenant property - a stamp
        # made the last project to touch it the owner, and every project-scoped
        # delete then took the shared node down with it.
        mitre_props = {
            "id": mitre_id,
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
            # Global reference node — see the MitreData note above.
            capec_props = {
                "capec_id": capec_node_id,
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

    def _link_cve_mitre(self, session, cve_id: str, mitre_attack, user_id: str,
                        project_id: str, stats_mitre: dict):
        """CVE -[:HAS_CWE]-> MitreData -[:HAS_CAPEC]-> Capec from one CVE's
        `mitre_attack` (add_mitre.enrich_cve), for the technology lookup's CVEs
        and nuclei's alike. The CVE node must already exist."""
        if not isinstance(mitre_attack, dict) or not mitre_attack.get("enriched"):
            return
        hierarchies = [mitre_attack.get("cwe_hierarchy"),
                       *(mitre_attack.get("additional_cwe_hierarchies") or [])]
        for hierarchy in hierarchies:
            if not hierarchy:
                continue
            cwes_with_capec = []
            self._find_cwes_with_capec(hierarchy, cwes_with_capec)
            for cwe_node in cwes_with_capec:
                self._process_cwe_with_capec(
                    session, cwe_node, cve_id, user_id, project_id,
                    stats_mitre=stats_mitre
                )

    def _link_nuclei_finding_cves(self, session, vuln_id: str, cves, user_id: str,
                                  project_id: str) -> list:
        """Link a nuclei finding to the CVEs it cites; returns the linked ids.

        The finding's INCLUDES_CVE edges become exactly these CVEs, so this
        runs for a finding that cites none too: a template that dropped its
        CVEs loses their edges. Only edges go; the CVE nodes are shared.

        Only fields the CVE lacks are filled: the NVD lookup (technology_cves)
        owns cvss and the rest, and may have written them first.
        """
        rows = {}
        for cve in cves or []:
            cve_id = canonical_cve_id(cve.get("id") if isinstance(cve, dict) else cve)
            if cve_id and cve_id not in rows:
                rows[cve_id] = {
                    "id": cve_id,
                    "cvss": _cvss_or_none(cve.get("cvss")) if isinstance(cve, dict) else None,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
        session.run(
            """
            MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
            // A template whose classification changed no longer cites that CVE.
            OPTIONAL MATCH (v)-[stale:INCLUDES_CVE]->(old:CVE)
            WHERE NOT old.id IN $cve_ids
            DELETE stale
            WITH DISTINCT v
            UNWIND $cves AS row
            // Global reference node: keyed on its id alone, no tenant stamp.
            MERGE (c:CVE {id: row.id})
              ON CREATE SET c.cve_id = row.id, c.name = row.id, c.source = 'nuclei'
            SET c.cvss = coalesce(c.cvss, row.cvss),
                c.url = coalesce(c.url, row.url),
                c.updated_at = datetime()
            MERGE (v)-[:INCLUDES_CVE]->(c)
            """,
            vuln_id=vuln_id, cve_ids=list(rows), cves=list(rows.values()),
            user_id=user_id, project_id=project_id,
        )
        return list(rows)

    def backfill_security_check_domains(self, user_id: str, project_id: str) -> int:
        """Give older domain-level security_check findings the `domain` they now store.

        SPF, DMARC, DNSSEC and zone-transfer findings name no url, host or
        IP: their org is their only host field, and the prune deletes one
        only on an org its check re-checked. One written before the field
        existed would never match, so it would never be pruned once its
        record is fixed. The org is the Domain it hangs off, picked the way
        the writer picks a domain-level finding. Run before the prune. Never
        writes `updated_at`; idempotent.
        """
        with self.driver.session() as session:
            record = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:HAS_VULNERABILITY]->
                      (v:Vulnerability {user_id: $uid, project_id: $pid, source: 'security_check'})
                WHERE v.domain IS NULL AND coalesce(v.url, '') = ''
                  AND v.matched_ip IS NULL AND v.hostname IS NULL
                WITH v, min(toLower(d.name)) AS org
                SET v.domain = org
                RETURN count(v) AS backfilled
                """,
                uid=user_id, pid=project_id,
            ).single()
        count = int((record["backfilled"] if record else 0) or 0)
        if count:
            print(f"[*][graph-db] Backfilled domain on {count} older DNS security finding(s)")
        return count

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
        - Relationships: Vulnerability -[:INCLUDES_CVE]-> CVE for the CVEs a nuclei
          finding cites, and CVE -[:HAS_CWE]-> MitreData -[:HAS_CAPEC]-> Capec once
          add_mitre has enriched vuln_scan.all_cves or technology_cves

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

        # Only create nodes for hosts inside the scan scope. In IP mode the
        # scope is the IP literals, not the dashed placeholder names that end
        # up in recon_data["subdomains"] -- see build_host_scope.
        target_hosts = build_host_scope(recon_data)

        def is_in_scope(hostname: str) -> bool:
            """Check if a hostname is within the scan scope."""
            return host_in_scope(hostname, target_hosts)

        with self.driver.session() as session:
            # Ensure schema is initialized

            scan_metadata = vuln_scan_data.get("scan_metadata", {})
            discovered_urls = vuln_scan_data.get("discovered_urls", {})
            by_target = vuln_scan_data.get("by_target", {})

            # Track created endpoints and parameters for deduplication
            created_endpoints = set()  # (baseurl, path, method)
            created_parameters = set()  # (endpoint_path, param_name, param_position)
            skipped_out_of_scope = 0  # Track skipped URLs
            nuclei_cves_linked = set()

            # Process discovered URLs with parameters (from Katana crawling)
            dast_urls = discovered_urls.get("dast_urls_with_params", [])
            base_urls = discovered_urls.get("base_urls", [])

            for dast_url in dast_urls:
                try:
                    # Parse the URL to extract components
                    parsed = urlparse(dast_url)

                    # Determine scheme, host, path
                    scheme = parsed.scheme or "http"
                    host = parsed.netloc
                    path = normalize_endpoint_path(parsed.path or "/")
                    query_string = parsed.query

                    # Skip URLs that are not in scan scope (discovered subdomains only)
                    if not is_in_scope(host):
                        skipped_out_of_scope += 1
                        continue

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
                            MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            SET e.user_id = $user_id,
                                e.project_id = $project_id,
                                e.has_parameters = $has_parameters,
                                e.full_url = $full_url,
                                e.source = 'katana_crawl',
                                e.updated_at = datetime()
                            SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                            """,
                            path=path, method=method, baseurl=base_url,
                            user_id=user_id, project_id=project_id,
                            has_parameters=has_parameters,
                            full_url=dast_url.split('?')[0]  # URL without query params
                        )
                        stats["endpoints_created"] += 1
                        created_endpoints.add(endpoint_key)

                        # Create BaseURL node if it doesn't exist and relationship
                        # BaseURL may not exist if endpoint was discovered by crawling a different subdomain
                        session.run(
                            """
                            MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                            ON CREATE SET bu.source = 'resource_enum',
                                          bu.updated_at = datetime()
                            WITH bu
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            MERGE (bu)-[:HAS_ENDPOINT]->(e)
                            """,
                            baseurl=base_url, path=path, method=method,
                            user_id=user_id, project_id=project_id
                        )
                        stats["relationships_created"] += 1


                    # Parse and create Parameter nodes from query string
                    if query_string:
                        params = parse_qs(query_string, keep_blank_values=True)
                        for param_name in params:
                            param_key = (path, param_name, "query")
                            if param_key not in created_parameters:
                                # No value: a DAST URL can be an archived one (urlscan's
                                # are masked, GAU's are raw) and the resource writer owns
                                # `sample_values` for what a crawler saw (B10, B15).
                                session.run(
                                    """
                                    MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    SET p.user_id = $user_id,
                                        p.project_id = $project_id,
                                        p.is_injectable = coalesce(p.is_injectable, false),
                                        p.updated_at = datetime()
                                    """,
                                    name=param_name, position="query", endpoint_path=path, baseurl=base_url,
                                    user_id=user_id, project_id=project_id,
                                )
                                stats["parameters_created"] += 1
                                created_parameters.add(param_key)

                                # Create relationship: Endpoint -[:HAS_PARAMETER]-> Parameter
                                session.run(
                                    """
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=path, method=method, baseurl=base_url,
                                    param_name=param_name, position="query",
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                except Exception as e:
                    stats["errors"].append(f"DAST URL {dast_url} processing failed: {e}")

            # Process vulnerability findings by target
            for target_host, target_data in by_target.items():
                # Skip targets that are not in scan scope
                target_host_only = target_host.split(":")[0] if ":" in target_host else target_host
                if not is_in_scope(target_host_only):
                    skipped_out_of_scope += 1
                    continue

                findings = target_data.get("findings", [])

                for finding in findings:
                    try:
                        # Extract raw data for detailed information
                        raw = finding.get("raw", {})
                        raw_info = raw.get("info", {})
                        raw_metadata = raw_info.get("metadata", {})

                        # G1: a STABLE id for this finding.
                        #
                        # This used to end in `hash(matched_at) % 10000`, and
                        # Python's builtin hash() is randomised per process
                        # unless PYTHONHASHSEED is pinned, which it is not here.
                        # So the same nuclei finding got a different id on every
                        # single scan: the MERGE missed, a duplicate node was
                        # created, and the operator's mute, their verdict and
                        # the AI's cached review all stayed behind on a node
                        # nothing pointed at any more.
                        #
                        # sha1 of the natural key instead: same finding, same
                        # id, for ever. (sha1 for length, not for security -
                        # there is nothing to forge here.)
                        template_id = finding.get("template_id", "unknown")
                        matched_at = finding.get("matched_at", "")
                        fuzzing_param = raw.get("fuzzing_parameter", "")
                        vuln_id = "nuclei-" + hashlib.sha1(
                            f"{template_id}|{target_host}|{fuzzing_param}|{matched_at}"
                            .encode("utf-8", "replace")
                        ).hexdigest()[:16]

                        # Extract path from matched_at URL
                        matched_parsed = urlparse(matched_at)
                        vuln_path = normalize_endpoint_path(matched_parsed.path or "/")
                        vuln_scheme = matched_parsed.scheme or "http"
                        vuln_host = matched_parsed.netloc or target_host

                        # Also check if matched_at URL host is in scope
                        vuln_host_only = vuln_host.split(":")[0] if ":" in vuln_host else vuln_host
                        if not is_in_scope(vuln_host_only):
                            skipped_out_of_scope += 1
                            continue

                        vuln_base_url = f"{vuln_scheme}://{vuln_host}"

                        # Create Vulnerability node with all fields
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "source": "nuclei",
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
                            "cves": nuclei_cve_ids(finding.get("cves")),
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
                            MERGE (v:Vulnerability {id: $id, user_id: $props.user_id,
                                                    project_id: $props.project_id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        stats["vulnerabilities_created"] += 1

                        # Note: We don't create BaseURL -[:HAS_VULNERABILITY]-> Vulnerability
                        # because the vulnerability is connected via:
                        # BaseURL -> Endpoint <- Vulnerability (FOUND_AT)
                        # and optionally: Endpoint -> Parameter <- Vulnerability (AFFECTS_PARAMETER)
                        # This avoids redundant connections in the graph.

                        # Create Endpoint node for the vulnerability path if not exists
                        fuzzing_method = raw.get("fuzzing_method", "GET")
                        endpoint_key = (vuln_base_url, vuln_path, fuzzing_method)

                        if endpoint_key not in created_endpoints:
                            session.run(
                                """
                                MERGE (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                SET e.user_id = $user_id,
                                    e.project_id = $project_id,
                                    e.has_parameters = true,
                                    e.source = 'vuln_scan',
                                    e.updated_at = datetime()
                                SET e.openapi_declared_only = CASE WHEN coalesce(e.openapi_declared_only, e.openapi_declared, false) THEN false ELSE e.openapi_declared_only END
                                """,
                                path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["endpoints_created"] += 1
                            created_endpoints.add(endpoint_key)

                            # Create BaseURL node if it doesn't exist and relationship
                            session.run(
                                """
                                MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                ON CREATE SET bu.source = 'vuln_scan',
                                              bu.updated_at = datetime()
                                WITH bu
                                MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (bu)-[:HAS_ENDPOINT]->(e)
                                """,
                                baseurl=vuln_base_url, path=vuln_path, method=fuzzing_method,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # Create relationship: Vulnerability -[:FOUND_AT]-> Endpoint
                        session.run(
                            """
                            MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                            MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                            MERGE (v)-[:FOUND_AT]->(e)
                            """,
                            vuln_id=vuln_id, path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                            user_id=user_id, project_id=project_id
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
                                MERGE (p:Parameter {name: $name, position: $position, endpoint_path: $endpoint_path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
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
                                    MATCH (e:Endpoint {path: $path, method: $method, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                    MERGE (e)-[:HAS_PARAMETER]->(p)
                                    """,
                                    path=vuln_path, method=fuzzing_method, baseurl=vuln_base_url,
                                    param_name=fuzzing_param, position=fuzzing_position,
                                    user_id=user_id, project_id=project_id
                                )
                                stats["relationships_created"] += 1

                            # Create relationship: Vulnerability -[:AFFECTS_PARAMETER]-> Parameter
                            session.run(
                                """
                                MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                                MATCH (p:Parameter {name: $param_name, position: $position, endpoint_path: $path, baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
                                MERGE (v)-[:AFFECTS_PARAMETER]->(p)
                                """,
                                vuln_id=vuln_id, param_name=fuzzing_param, position=fuzzing_position,
                                path=vuln_path, baseurl=vuln_base_url,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        linked = self._link_nuclei_finding_cves(
                            session, vuln_id, finding.get("cves"), user_id, project_id)
                        nuclei_cves_linked.update(linked)
                        stats["relationships_created"] += len(linked)

                    except Exception as e:
                        stats["errors"].append(f"Finding {finding.get('template_id', 'unknown')} processing failed: {e}")

            mitre_stats = {"nodes": 0, "capec": 0, "rels": 0}  # Shared stats for MITRE processing

            # The CWE / CAPEC chain of the CVEs written findings cite, from the
            # enrichment add_mitre puts on vuln_scan.all_cves. The full pipeline
            # writes before that enrichment (Group 6 Phase A) and again after it
            # (Phase B), so the chain lands on the second pass; every write here
            # is a MERGE, so the repeat duplicates nothing.
            nuclei_mitre = {}
            for cve in vuln_scan_data.get("all_cves") or []:
                cve_id = canonical_cve_id(cve.get("id")) if isinstance(cve, dict) else ""
                if cve_id in nuclei_cves_linked and cve_id not in nuclei_mitre:
                    nuclei_mitre[cve_id] = cve.get("mitre_attack")
            for cve_id, mitre_attack in nuclei_mitre.items():
                try:
                    self._link_cve_mitre(session, cve_id, mitre_attack, user_id, project_id,
                                         mitre_stats)
                except Exception as e:
                    stats["errors"].append(f"MITRE data of {cve_id} processing failed: {e}")

            # =========================================================================
            # Process technology_cves - CVE, MitreData, and Capec nodes
            # =========================================================================
            technology_cves = recon_data.get("technology_cves", {})
            by_technology = technology_cves.get("by_technology", {})

            cves_created = 0
            cve_relationships_created = 0

            for tech_name, tech_data in by_technology.items():
                tech_product = tech_data.get("product", tech_name)
                tech_version = tech_data.get("version")  # Version from CVE lookup
                cves = tech_data.get("cves", [])

                # Extract clean technology name from key by stripping version suffix
                # e.g. "Apache HTTP Server:2.4.49" → "Apache HTTP Server"
                # e.g. "Apache/2.4.49" → "Apache"
                tech_name_clean = tech_name
                if tech_version:
                    for sep in [":", "/"]:
                        suffix = f"{sep}{tech_version}"
                        if tech_name_clean.endswith(suffix):
                            tech_name_clean = tech_name_clean[:-len(suffix)]
                            break

                for cve in cves:
                    try:
                        cve_id = cve.get("id")
                        if not cve_id:
                            continue

                        # Create CVE node with all properties
                        # Global reference node — see the MitreData note above.
                        cve_props = {
                            "id": cve_id,
                            "cve_id": cve_id,
                            "name": cve_id,
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
                        # Match Technology node by name (case-insensitive)
                        # Matching strategies (in order):
                        # 1. Exact match by clean name (key without version suffix)
                        # 2. Exact match by NVD product name or raw key
                        # 3. The product as a whole name inside the technology name
                        #    (tech_name_regex): "Apache httpd/2.4.41" for "apache",
                        #    but not "phpMyAdmin" for "php" nor "Apache Tomcat" for
                        #    "apache". The CONTAINS guard keeps it a narrowing of
                        #    substring matching: a name without the product never matches.
                        # Version matching:
                        # - First try exact version match
                        # - Then fall back to nodes with no version, or the same
                        #   version spelled differently ("8.2p1" for 8.2) - never a
                        #   node of another version (handles httpx detecting
                        #   "Apache Tomcat" without version while NVD uses "Apache-Coyote/1.1")
                        name_where = """
                            (toLower(t.name) = toLower($tech_name_clean)
                             OR toLower(t.name) = toLower($tech_product)
                             OR toLower(t.name) = toLower($tech_key)
                             OR (toLower(t.name) CONTAINS toLower($tech_product)
                                 AND toLower(t.name) =~ $tech_name_regex))
                        """
                        name_params = dict(
                            tech_name_clean=tech_name_clean, tech_product=tech_product,
                            tech_key=tech_name, tech_name_regex=tech_name_regex(tech_product),
                        )

                        matched = 0

                        if tech_version:
                            # Try 1: exact name + exact version
                            result = session.run(
                                f"""
                                MATCH (t:Technology {{user_id: $user_id, project_id: $project_id}})
                                WHERE {name_where} AND t.version = $tech_version
                                MATCH (c:CVE {{id: $cve_id}})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                user_id=user_id, project_id=project_id, **name_params,
                                tech_version=tech_version, cve_id=cve_id
                            )
                            matched = result.single()["matched"]

                        if matched == 0:
                            # Try 2: a node whose version is unknown, or this one in another spelling
                            version_where = ("AND (coalesce(t.version, '') = '' "
                                             "OR t.version =~ $tech_version_regex)"
                                             if tech_version else "")
                            result = session.run(
                                f"""
                                MATCH (t:Technology {{user_id: $user_id, project_id: $project_id}})
                                WHERE {name_where} {version_where}
                                MATCH (c:CVE {{id: $cve_id}})
                                MERGE (t)-[:HAS_KNOWN_CVE]->(c)
                                RETURN count(*) as matched
                                """,
                                user_id=user_id, project_id=project_id, **name_params,
                                tech_version_regex=tech_version_regex(tech_version or ""),
                                cve_id=cve_id
                            )
                            matched = result.single()["matched"]

                        if matched > 0:
                            cve_relationships_created += 1

                        self._link_cve_mitre(session, cve_id, cve.get("mitre_attack"),
                                             user_id, project_id, mitre_stats)

                    except Exception as e:
                        stats["errors"].append(f"CVE {cve.get('id', 'unknown')} processing failed: {e}")

            if cves_created > 0:
                print(f"[+][graph-db] Created {cves_created} CVE nodes")
                print(f"[+][graph-db] Created {cve_relationships_created} Technology-CVE relationships")
            if nuclei_cves_linked:
                print(f"[+][graph-db] Linked {len(nuclei_cves_linked)} CVEs to nuclei findings")
            if mitre_stats["nodes"] > 0:
                print(f"[+][graph-db] Created {mitre_stats['nodes']} MitreData (CWE) nodes")
            if mitre_stats["capec"] > 0:
                print(f"[+][graph-db] Created {mitre_stats['capec']} Capec nodes")

            # =========================================================================
            # Process security_checks - Direct IP access, WAF bypass, etc.
            # =========================================================================
            security_checks_created = 0
            waf_bypass_rels = 0

            for target_host, target_data in by_target.items():
                security_checks = target_data.get("security_checks", {})

                if not security_checks:
                    continue

                # Process direct_ip_access checks
                direct_ip_access = security_checks.get("direct_ip_access", {})
                ip_address = direct_ip_access.get("ip")
                checks = direct_ip_access.get("checks", [])

                for check in checks:
                    try:
                        check_type = check.get("check_type", "unknown")
                        severity = check.get("severity", "info")
                        url = check.get("url", "")
                        finding = check.get("finding", "")
                        evidence = check.get("evidence")
                        status_code = check.get("status_code")
                        content_length = check.get("content_length")

                        # Deterministic, tenant-scoped id: converges with
                        # origin_discovery on the same (type, url, ip) exposure
                        # within this tenant and survives re-runs.
                        vuln_id = stable_vuln_id(check_type, url, ip_address, user_id, project_id)

                        # Human-readable names for check types
                        check_names = {
                            "direct_ip_http": "HTTP accessible directly via IP",
                            "direct_ip_https": "HTTPS accessible directly via IP",
                            "ip_api_exposed": "API endpoint exposed on IP without TLS",
                            "waf_bypass": "WAF bypass via direct IP access",
                            "tls_mismatch": "TLS certificate mismatch",
                            "http_on_ip": "HTTP service on direct IP",
                        }

                        # Create Vulnerability node (source='security_check')
                        vuln_props = {
                            "id": vuln_id,
                            "user_id": user_id,
                            "project_id": project_id,
                            "source": "security_check",
                            "type": check_type,
                            "severity": severity,
                            "name": check_names.get(check_type, f"Security check: {check_type}"),
                            "description": finding,
                            "url": url,
                            "matched_at": url,
                            "host": target_host,
                            "matched_ip": ip_address,
                            "template_id": None,
                            "is_dast_finding": False,
                        }

                        if evidence:
                            vuln_props["evidence"] = evidence
                        if status_code:
                            vuln_props["status_code"] = status_code
                        if content_length:
                            vuln_props["content_length"] = content_length

                        vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                        session.run(
                            """
                            MERGE (v:Vulnerability {id: $id, user_id: $props.user_id,
                                                    project_id: $props.project_id})
                            SET v += $props,
                                v.updated_at = datetime()
                            """,
                            id=vuln_id, props=vuln_props
                        )
                        security_checks_created += 1
                        stats["vulnerabilities_created"] += 1

                        # Create relationship: IP -[:HAS_VULNERABILITY]-> Vulnerability
                        # These are IP-level findings (direct IP access), so IP relationship is correct
                        if ip_address:
                            session.run(
                                """
                                MERGE (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                SET i.updated_at = datetime()
                                """,
                                address=ip_address, user_id=user_id, project_id=project_id
                            )

                            session.run(
                                """
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                """,
                                ip_addr=ip_address, vuln_id=vuln_id,
                                user_id=user_id, project_id=project_id
                            )
                            stats["relationships_created"] += 1

                        # For WAF bypass: create WAF_BYPASS_VIA relationship (not HAS_VULNERABILITY)
                        # The vulnerability is already connected to IP; WAF_BYPASS_VIA shows the bypass path
                        if check_type == "waf_bypass" and target_host:
                            # Subdomain -[:WAF_BYPASS_VIA]-> IP (shows which subdomain can bypass WAF via IP)
                            session.run(
                                """
                                MATCH (s:Subdomain {name: $subdomain, user_id: $user_id, project_id: $project_id})
                                MATCH (i:IP {address: $ip_addr, user_id: $user_id, project_id: $project_id})
                                // K12: `datetime()` inside the MERGE pattern is
                                // part of the KEY, so every run produced a
                                // different key and a brand-new relationship.
                                // The timestamp belongs in ON CREATE.
                                MERGE (s)-[w:WAF_BYPASS_VIA {evidence: $evidence}]->(i)
                                ON CREATE SET w.discovered_at = datetime()
                                SET w.last_seen_at = datetime()
                                """,
                                subdomain=target_host, ip_addr=ip_address,
                                evidence=evidence or "",
                                user_id=user_id, project_id=project_id
                            )
                            waf_bypass_rels += 1

                    except Exception as e:
                        stats["errors"].append(f"Security check {check_type} failed: {e}")

            if security_checks_created > 0:
                print(f"[+][graph-db] Created {security_checks_created} security check Vulnerability nodes")
            if waf_bypass_rels > 0:
                print(f"[+][graph-db] Created {waf_bypass_rels} WAF_BYPASS_VIA relationships")

            # =========================================================================
            # Process top-level security_checks.findings (new structure)
            # =========================================================================
            top_level_security_checks = vuln_scan_data.get("security_checks", {})
            security_findings = top_level_security_checks.get("findings", [])
            domain_batch = bool((recon_data.get("metadata") or {}).get("domain_batch"))

            for finding in security_findings:
                try:
                    finding_type = finding.get("type", "unknown")
                    severity = finding.get("severity", "info")
                    name = finding.get("name", f"Security Issue: {finding_type}")
                    description = finding.get("description", "")
                    url = finding.get("url", "")
                    matched_ip = finding.get("matched_ip")
                    hostname = finding.get("hostname")
                    evidence = finding.get("evidence")
                    status_code = finding.get("status_code")
                    server = finding.get("server")
                    recommendation = finding.get("recommendation")
                    missing_header = finding.get("missing_header")
                    port = finding.get("port")

                    # Port/service checks report the scanned host as `ip`, with no
                    # url, hostname or matched_ip. Keyed on those alone, every IP's
                    # finding of a type would hash to one unlinked node; key it on
                    # ip:port and treat the ip as matched_ip (property + IP link).
                    ip_port_key = ""
                    if not (url or matched_ip or hostname) and finding.get("ip"):
                        matched_ip = finding["ip"]
                        ip_port_key = _ip_port_key(matched_ip, port)

                    # Deterministic, tenant-scoped id: converges with
                    # origin_discovery on the same (type, url, ip/host) exposure
                    # within this tenant and survives re-runs.
                    # A domain-level finding (SPF, DMARC, DNSSEC, zone transfer)
                    # has no url, host or ip, so every org of a Domain batch
                    # would hash to one node; a batch keys it on its org. A
                    # single-domain project keeps the id its fix items and mute
                    # exemptions already reference (D-23).
                    org = (org_for_scan_root(finding.get("domain") or "", recon_data)
                           if not (url or matched_ip or hostname) else "")
                    finding_domain = org if domain_batch else ""
                    vuln_id = stable_vuln_id(finding_type, url,
                                             ip_port_key or matched_ip or hostname or finding_domain,
                                             user_id, project_id)

                    # Create Vulnerability node
                    vuln_props = {
                        "id": vuln_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "source": "security_check",
                        "type": finding_type,
                        "severity": severity,
                        "name": name,
                        "description": description,
                        "url": url,
                        # Recon Delta keys a Vulnerability on template_id/
                        # matched_at/name; with no url, every IP's port finding
                        # of a name would share one key without the ip:port.
                        "matched_at": ip_port_key or url,
                        "is_dast_finding": False,
                    }

                    if matched_ip:
                        vuln_props["matched_ip"] = matched_ip
                    if hostname:
                        vuln_props["hostname"] = hostname
                    if org:
                        # The org is a domain-level finding's only host: the
                        # prune keeps or deletes it by org (_KEEP_HOST_FIELDS).
                        vuln_props["domain"] = org.strip().lower().rstrip(".")
                    if evidence:
                        vuln_props["evidence"] = evidence
                    if status_code:
                        vuln_props["status_code"] = status_code
                    if server:
                        vuln_props["server"] = server
                    if recommendation:
                        vuln_props["recommendation"] = recommendation
                    if missing_header:
                        vuln_props["missing_header"] = missing_header
                    if port:
                        vuln_props["port"] = port
                    for extra in _SECURITY_CHECK_EXTRA_FIELDS:
                        value = finding.get(extra)
                        # Primitives only: one map value fails the whole node write.
                        if isinstance(value, (str, int, float, bool)) and value != "":
                            vuln_props[extra] = value

                    vuln_props = {k: v for k, v in vuln_props.items() if v is not None}

                    session.run(
                        """
                        MERGE (v:Vulnerability {id: $id, user_id: $props.user_id,
                                                project_id: $props.project_id})
                        SET v += $props,
                            v.updated_at = datetime()
                        """,
                        id=vuln_id, props=vuln_props
                    )
                    security_checks_created += 1
                    stats["vulnerabilities_created"] += 1

                    # Create relationships based on finding type
                    # Priority: IP (for IP-based URLs) > BaseURL (for hostname URLs) > Subdomain/Domain > IP
                    # Only ONE relationship is created per vulnerability to avoid redundancy
                    # (You can always traverse: BaseURL <- Service <- Port <- IP <- Subdomain <- Domain)
                    
                    relationship_created = False
                    
                    # For URL-based findings
                    if url and (url.startswith("http://") or url.startswith("https://")):
                        parsed = urlparse(url)
                        url_host = _authority_host(parsed)
                        
                        # If URL host is an IP address, connect to IP node (not BaseURL)
                        # This keeps the vulnerability connected to the existing IP node in the graph
                        if _is_ip_address(url_host):
                            result = session.run(
                                """
                                MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                                MERGE (i)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                address=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True
                        else:
                            # URL host is a hostname - connect to existing BaseURL if it exists
                            base_url = f"{parsed.scheme}://{parsed.netloc}"
                            result = session.run(
                                """
                                MATCH (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                                MERGE (bu)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                baseurl=base_url, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True
                            else:
                                # BaseURL doesn't exist, try Subdomain/Domain
                                result = session.run(
                                    """
                                    MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                    MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                                    MERGE (s)-[:HAS_VULNERABILITY]->(v)
                                    RETURN count(*) as matched
                                    """,
                                    hostname=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                                )
                                if result.single()["matched"] > 0:
                                    stats["relationships_created"] += 1
                                    relationship_created = True
                                else:
                                    # Try Domain
                                    result = session.run(
                                        """
                                        MATCH (d:Domain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                        MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                                        MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                        RETURN count(*) as matched
                                        """,
                                        hostname=url_host, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                                    )
                                    if result.single()["matched"] > 0:
                                        stats["relationships_created"] += 1
                                        relationship_created = True

                    # For hostname-only findings (no URL): connect to Subdomain/Domain
                    elif hostname and not relationship_created:
                        # Try to link to Subdomain node
                        result = session.run(
                            """
                            MATCH (s:Subdomain {name: $hostname, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                            MERGE (s)-[:HAS_VULNERABILITY]->(v)
                            RETURN count(*) as matched
                            """,
                            hostname=hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                        )
                        if result.single()["matched"] > 0:
                            stats["relationships_created"] += 1
                            relationship_created = True
                        else:
                            # Try Domain node if not a subdomain
                            result = session.run(
                                """
                                MATCH (d:Domain {name: $hostname, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                hostname=hostname, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True

                    # For IP-only findings (no URL, no hostname): connect to IP
                    elif matched_ip and not relationship_created:
                        session.run(
                            """
                            MATCH (i:IP {address: $address, user_id: $user_id, project_id: $project_id})
                            MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                            MERGE (i)-[:HAS_VULNERABILITY]->(v)
                            """,
                            address=matched_ip, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                        )
                        stats["relationships_created"] += 1
                        relationship_created = True

                    # For domain-only findings (e.g., SPF/DMARC missing): connect to
                    # the org Domain (the checks run on the org; a legacy file
                    # names its scan root, which maps to the org).
                    if not relationship_created:
                        finding_domain = finding.get("domain")
                        if finding_domain:
                            finding_domain = org_for_scan_root(finding_domain, recon_data)
                            result = session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $user_id, project_id: $project_id})
                                MATCH (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})
                                MERGE (d)-[:HAS_VULNERABILITY]->(v)
                                RETURN count(*) as matched
                                """,
                                domain=finding_domain, user_id=user_id, project_id=project_id, vuln_id=vuln_id
                            )
                            if result.single()["matched"] > 0:
                                stats["relationships_created"] += 1
                                relationship_created = True

                except Exception as e:
                    stats["errors"].append(f"Security finding {finding.get('type', 'unknown')} failed: {e}")

            if security_checks_created > 0:
                print(f"[+][graph-db] Created {security_checks_created} SecurityCheck Vulnerability nodes")

            # Update the org Domain node with vuln_scan metadata (flat, latest
            # group wins; §4.11.3)
            metadata = recon_data.get("metadata", {})
            root_domain = metadata.get("root_domain", "")
            if root_domain:
                root_domain = metadata.get("org_domain") or org_for_scan_root(root_domain, recon_data)
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

            # Connect orphaned BaseURLs to their Subdomain node.
            # vuln_scan creates BaseURLs on the fly when Nuclei finds something
            # on a subdomain that httpx never probed (no Service -[:SERVES_URL]-> link).
            # Without this pass, those BaseURLs stay disconnected from Subdomain.
            # Host match is exact (via apoc-free URL host parsing) to avoid the
            # CONTAINS substring trap (where "https://api.example.com" wrongly
            # matches Subdomain "example.com").
            try:
                orphan_result = session.run(
                    """
                    MATCH (bu:BaseURL {user_id: $user_id, project_id: $project_id})
                    WHERE NOT (bu)<-[:SERVES_URL]-()
                      AND NOT (:Subdomain)-[:HAS_BASE_URL]->(bu)
                    WITH bu,
                         split(split(replace(replace(bu.url, 'https://', ''), 'http://', ''), '/')[0], ':')[0] AS bu_host
                    MATCH (sub:Subdomain {user_id: $user_id, project_id: $project_id})
                    WHERE sub.name = bu_host
                    MERGE (sub)-[:HAS_BASE_URL]->(bu)
                    RETURN count(*) AS linked
                    """,
                    user_id=user_id, project_id=project_id
                )
                orphans_linked = orphan_result.single()["linked"]
                if orphans_linked > 0:
                    print(f"[+][graph-db] Linked {orphans_linked} orphaned BaseURL(s) to Subdomain (vuln_scan)")
                    stats["relationships_created"] += orphans_linked
            except Exception as e:
                stats["errors"].append(f"Orphan BaseURL cleanup failed: {e}")

            # Apex / root-domain pass.
            # Security checks (and Nuclei templates that target the bare domain)
            # produce findings for URLs like https://example.com -- the host is
            # the Domain itself, not a Subdomain. The Subdomain-only cleanup
            # above can't link those, so we attach them directly to the Domain
            # node. Skips BaseURLs already attached via Subdomain or via the
            # httpx Service -[:SERVES_URL]-> path.
            try:
                apex_result = session.run(
                    """
                    MATCH (bu:BaseURL {user_id: $user_id, project_id: $project_id})
                    WHERE NOT (bu)<-[:SERVES_URL]-()
                      AND NOT (:Subdomain)-[:HAS_BASE_URL]->(bu)
                      AND NOT (:Domain)-[:HAS_BASE_URL]->(bu)
                    WITH bu,
                         split(split(replace(replace(bu.url, 'https://', ''), 'http://', ''), '/')[0], ':')[0] AS bu_host
                    MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
                    WHERE d.name = bu_host
                    MERGE (d)-[:HAS_BASE_URL]->(bu)
                    RETURN count(*) AS linked
                    """,
                    user_id=user_id, project_id=project_id
                )
                apex_linked = apex_result.single()["linked"]
                if apex_linked > 0:
                    print(f"[+][graph-db] Linked {apex_linked} apex BaseURL(s) to Domain (vuln_scan)")
                    stats["relationships_created"] += apex_linked
            except Exception as e:
                stats["errors"].append(f"Apex BaseURL cleanup failed: {e}")

            coverage = scan_metadata.get("coverage")
            if coverage:
                try:
                    stats["coverage_stamped"] = stamp_base_url_coverage(
                        session, "nuclei", coverage, user_id, project_id, in_scope=is_in_scope)
                except Exception as e:
                    stats["errors"].append(f"Nuclei coverage stamp failed: {e}")

            print(f"[+][graph-db] Created {stats['endpoints_created']} Endpoint nodes")
            print(f"[+][graph-db] Created {stats['parameters_created']} Parameter nodes")
            print(f"[+][graph-db] Created {stats['vulnerabilities_created']} Vulnerability nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            if skipped_out_of_scope > 0:
                print(f"[*][graph-db] Skipped {skipped_out_of_scope} items out of scan scope")
                stats["skipped_out_of_scope"] = skipped_out_of_scope

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats
