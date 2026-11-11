import os
import sys
from pathlib import Path
from urllib.parse import urlencode

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.ip_placeholders import is_placeholder
from recon.partial_recon_modules.helpers import (
    _classify_ip, allowed_hosts_for, include_root_for, ip_mode_recon, org_for_root, project_scan_roots,
    roe_excluded, root_for_host, run_ip_targets, run_is_ip_mode,
)

#: A path known only from an API specification is requested with GET or HEAD
#: only (D15). A node with openapi_declared but no openapi_declared_only was
#: written by an earlier release and counts as declared-only: fail closed.
DECLARED_ONLY = "coalesce({a}.openapi_declared_only, {a}.openapi_declared, false)"
DECLARED_ONLY_UNSAFE = "(" + DECLARED_ONLY + " AND NOT {a}.method IN ['GET','HEAD'])"


def declared_only(alias: str = "e") -> str:
    """Cypher, true for an Endpoint known only from an API specification."""
    return DECLARED_ONLY.format(a=alias)


def declared_only_unsafe(alias: str = "e") -> str:
    """Cypher, true for an Endpoint a GET consumer must not request."""
    return DECLARED_ONLY_UNSAFE.format(a=alias)


#: An Endpoint whose archived URL carried a leaked one-time link, a secret, a
#: state-changing link with a value or a web-shell trace (recon/helpers/url_leaks.py).
#: Never a request target, whatever the method: it has no full_url and no
#: parameter value, and every reader that turns graph Endpoints into requests
#: filters it.
QUARANTINED = "coalesce({a}.quarantined, false)"


def quarantined(alias: str = "e") -> str:
    """Cypher, true for an Endpoint no tool may request."""
    return QUARANTINED.format(a=alias)


#: Cypher, true for an Endpoint only web archives reported (urlscan, GAU,
#: ParamSpider read history, not the live site).
ARCHIVE_ONLY = (
    "(size([s IN coalesce(e.sources, CASE WHEN e.source IS NULL THEN [] ELSE [e.source] END) "
    "| toLower(s)]) > 0 AND all(s IN [x IN coalesce(e.sources, CASE WHEN e.source IS NULL "
    "THEN [] ELSE [e.source] END) | toLower(x)] WHERE s IN ['urlscan', 'gau', 'paramspider']))"
)


#: True for a RESOLVES_TO edge `r` that is current forward DNS. Every passive
#: writer (Shodan's reverse DNS and domain DNS, Censys, FOFA, OTX passive DNS,
#: ZoomEye) sets `source` when it creates the edge, and a DNS resolution of the
#: pair REMOVEs it; an edge the one-off urlscan backfill could not vouch for
#: carries 'legacy_unknown'. A partial run reading a passive edge as current
#: would scan an address the name had years ago, which may be someone else's now.
FORWARD_DNS = "r.source IS NULL"


#: A BaseURL is a thin service-identity node: httpx writes the response data
#: (status, content type, CDN flags) onto the Endpoint it probed, never onto the
#: BaseURL. Reading `b.status_code` therefore always saw null, so every partial
#: target looked like a 200 and the CDN prefilter never fired. Pick the probed
#: Endpoint: the root path first, then one httpx wrote (it alone sets `server`).
#: The `coalesce(b.x, probe.x)` readers still honour a graph from before the split.
_PROBED_ENDPOINT = """
                OPTIONAL MATCH (b)-[:HAS_ENDPOINT]->(probe:Endpoint)
                WHERE probe.status_code IS NOT NULL
                WITH b, probe
                ORDER BY CASE WHEN probe.path = '/' THEN 0
                              WHEN probe.server IS NOT NULL THEN 1 ELSE 2 END,
                         probe.path
                WITH b, head(collect(probe)) AS probe
"""

#: Rebuilds the http_probe by_url "technologies" strings the full pipeline
#: hands the CVE lookup and the Nuclei AI tag fingerprint: httpx's
#: "Name:version" (bare "Name" without one), with wappalyzer's merged in the
#: same spelling. http_mixin split each on its first ':' into Technology
#: {name, version ''|v}. Only the httpx/wappalyzer edges, since an AI-surface
#: or nmap Technology was never in that list; the 0-hop BaseURL edge is a graph
#: from before technologies moved onto the Endpoint.
_URL_TECHNOLOGIES = """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT*0..1]->(n)
                      -[r:USES_TECHNOLOGY]->(t:Technology {user_id: $uid, project_id: $pid})
                WHERE coalesce(r.detected_by, 'httpx') IN ['httpx', 'wappalyzer']
                  AND t.name IS NOT NULL AND t.name <> ''
                  AND ($urls IS NULL OR b.url IN $urls)
                WITH b.url AS url, t.name AS name, coalesce(t.version, '') AS version
                ORDER BY url, name, version
                RETURN url, collect(DISTINCT CASE WHEN version = '' THEN name
                                                  ELSE name + ':' + version END) AS technologies
"""


def _field(record, key):
    """A column a query may not return in every caller's graph, read as None when absent."""
    try:
        return record[key]
    except (KeyError, IndexError):
        return None


def _graph_url_technologies(session, user_id: str, project_id: str, urls=None) -> dict:
    """{baseurl: ["Name:version", ...]} for the BaseURLs that carry any."""
    out = {}
    for record in session.run(_URL_TECHNOLOGIES, uid=user_id, pid=project_id, urls=urls):
        url = _field(record, "url")
        techs = [t for t in (_field(record, "technologies") or []) if isinstance(t, str) and t]
        if isinstance(url, str) and techs:
            out[url] = techs
    return out


def _graph_nmap_services(session, user_id: str, project_id: str, ips: list) -> list:
    """nmap -sV product/version on this run's IPs, shaped like nmap_scan.services_detected."""
    if not ips:
        return []
    result = session.run(
        """
        MATCH (p:Port {user_id: $uid, project_id: $pid})
        WHERE p.ip_address IN $ips
          AND p.product IS NOT NULL AND p.product <> ''
          AND p.version IS NOT NULL AND p.version <> ''
        RETURN p.ip_address AS ip, p.number AS port, p.product AS product,
               p.version AS version, p.cpe AS cpe
        ORDER BY ip, port
        """,
        ips=ips, uid=user_id, pid=project_id,
    )
    services = []
    for record in result:
        product, version = _field(record, "product"), _field(record, "version")
        if isinstance(product, str) and isinstance(version, str) and product and version:
            services.append({"product": product, "version": version,
                             "port": _field(record, "port"), "host": _field(record, "ip"),
                             "cpe": _field(record, "cpe") or ""})
    return services


def graph_url_fingerprints(base_urls, user_id: str, project_id: str) -> dict:
    """{baseurl: {"technologies": [...], "server": str|None}} from the graph. Never raises.

    For URLs a user typed into partial Nuclei: without the BaseURL's
    fingerprint they reach the CVE lookup and the AI tag selector empty.
    """
    urls = sorted({u for u in (base_urls or []) if isinstance(u, str) and u})
    if not urls:
        return {}
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return {}
            with graph_client.driver.session() as session:
                out = {}
                result = session.run(
                    """
                    MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                    WHERE b.url IN $urls
                    """ + _PROBED_ENDPOINT + """
                    RETURN b.url AS url, coalesce(b.server, probe.server) AS server
                    """,
                    urls=urls, uid=user_id, pid=project_id,
                )
                for record in result:
                    url = _field(record, "url")
                    if isinstance(url, str):
                        out.setdefault(url, {"technologies": [], "server": None})["server"] = (
                            _field(record, "server"))
                for url, techs in _graph_url_technologies(session, user_id, project_id,
                                                          urls=urls).items():
                    out.setdefault(url, {"technologies": [], "server": None})["technologies"] = techs
                return out
    except Exception as e:
        print(f"[!][Partial Recon] Could not read technologies for user URLs: {e}")
        return {}


def graph_takeover_page_hosts(user_id: str, project_id: str) -> list:
    """The hosts a urlscan takeover verdict kept (item 5: `takeover_page_seen`),
    which partial Subdomain Takeover adds to its list as the full run does with
    urlscan.takeover_hosts. The caller applies the run's scope and RoE. Never
    raises."""
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return []
            with graph_client.driver.session() as session:
                result = session.run(
                    """
                    MATCH (v:Vulnerability {user_id: $uid, project_id: $pid,
                                           source: 'urlscan_leak', type: 'takeover_page_seen'})
                    WHERE v.hostname IS NOT NULL AND NOT v:Muted
                    RETURN collect(DISTINCT toLower(v.hostname)) AS hosts
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                return sorted(h for h in (_field(record, "hosts") or []) if isinstance(h, str) and h)
    except Exception as e:  # noqa: BLE001
        print(f"[!][Partial Recon] Could not read urlscan takeover hosts: {e}")
        return []


def graph_open_ports(ips, user_id: str, project_id: str) -> dict:
    """{ip: [open port numbers]} from the graph's Port nodes. Never raises.

    The port/service security checks read open ports from port_scan.by_ip,
    which the vuln-scan builder fills with CDN metadata only.
    """
    ips = sorted({ip for ip in (ips or []) if isinstance(ip, str) and ip})
    if not ips:
        return {}
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return {}
            with graph_client.driver.session() as session:
                result = session.run(
                    """
                    MATCH (p:Port {user_id: $uid, project_id: $pid})
                    WHERE p.ip_address IN $ips AND p.number IS NOT NULL
                      AND coalesce(p.state, 'open') = 'open'
                    RETURN p.ip_address AS ip, collect(DISTINCT p.number) AS ports
                    """,
                    ips=ips, uid=user_id, pid=project_id,
                )
                out = {}
                for record in result:
                    ports = sorted({int(p) for p in (_field(record, "ports") or [])
                                    if isinstance(p, int) or str(p).isdigit()})
                    if ports:
                        out[_field(record, "ip")] = ports
                return out
    except Exception as e:
        print(f"[!][Partial Recon] Could not read open ports for the port checks: {e}")
        return {}


def _as_roots(domains) -> list:
    """A builder's roots: a list, or one root from a caller not yet migrated."""
    if isinstance(domains, str):
        return [domains] if domains else []
    return [d for d in (domains or []) if isinstance(d, str) and d]


def _root_scope(roots: list, domain_groups, include_root_domain: bool):
    """Which roots' apexes are targets, and each literal root's allowed hosts.

    With domain_groups (the scope partial_recon.main built from settings), each
    root follows its own group. Without them, a caller not yet migrated gets
    the single include_root_domain flag and no host narrowing, as before.
    Returns (apex_roots, {root: allowed_host_set}).
    """
    if domain_groups is None:
        return (list(roots) if include_root_domain else []), {}
    apex_roots = [r for r in roots if include_root_for(r, domain_groups)]
    allowed = {}
    for root in roots:
        hosts = allowed_hosts_for(root, domain_groups)
        if hosts is not None:
            allowed[root] = hosts
    return apex_roots, allowed


def _host_allowed(root: str, host: str, allowed: dict) -> bool:
    """A literal batch group scans exactly its listed hosts; anything else passes."""
    hosts = allowed.get(root)
    return hosts is None or (host or "").strip().lower() in hosts


class _GraphScope:
    """Which graph hosts are this partial run's targets.

    With the run's scope groups the graph names a Domain after the org (P6):
    hosts are read under the selected groups' orgs (``orgs``) and each one is
    assigned to the LONGEST scan root of the whole project it sits under. It is
    a target only when that root is one of this run's and the root's group
    admits it (§4.6: strictly under an ENUMERATE root, an EXACT group's listed
    hosts, the root itself only with includeRoot). A host of a root removed
    from scope, or of another group of the same org, is never a target.

    Without scope groups (IP mode, whose hosts are dashed addresses under the
    synthetic root, or a caller not yet migrated) the Domain names are the
    roots, as before, and only a literal group's list narrows.
    """

    def __init__(self, roots: list, domain_groups, include_root_domain: bool):
        self.roots = roots
        self.apex_roots, self.allowed = _root_scope(roots, domain_groups, include_root_domain)
        self.scoped = bool(domain_groups) and all(
            isinstance(g, dict) and "scanRoot" in g for g in domain_groups)
        if self.scoped:
            self.orgs = list(dict.fromkeys(org_for_root(r, domain_groups).lower() for r in roots))
            self._selected = {r.lower(): r for r in roots}
            self.project_roots = sorted({*self._selected, *project_scan_roots()}, key=len, reverse=True)
        else:
            self.orgs = list(roots)
            self.project_roots = []

    def root_of(self, host, record_root=None, apex: bool = True):
        """The run's root ``host`` is a target of, or None. ``apex=False`` keeps
        a root itself even when its group leaves it out (the tools that never
        honoured Include Root)."""
        h = (host or "").strip().strip(".").lower()
        if roe_excluded(h):
            return None
        if not self.scoped:
            root = record_root or root_for_host(h, self.roots)
            return root if root is not None and _host_allowed(root, h, self.allowed) else None
        best = next((r for r in self.project_roots if h == r or h.endswith("." + r)), None)
        root = self._selected.get(best) if best else None
        if root is None:
            return None
        if h == best:
            return root if (not apex or root in self.apex_roots) else None
        return root if _host_allowed(root, h, self.allowed) else None

    def keeps(self, host, record_root=None) -> bool:
        if roe_excluded(host):
            return False
        if not self.scoped:
            # A host under no root (IP mode's dashed names) was always kept.
            root = record_root or root_for_host(host, self.roots)
            return _host_allowed(root, host, self.allowed)
        return self.root_of(host, record_root) is not None

    def under_project(self, host) -> bool:
        """``host`` sits under a scan root of the project (a target or not)."""
        h = (host or "").strip().strip(".").lower()
        return any(h == r or h.endswith("." + r) for r in self.project_roots)


def _apex_rows(session, user_id: str, project_id: str, apex_roots: list, returns: str):
    """The included roots' own addresses, from the apex Subdomain: a Domain
    never carries RESOLVES_TO (its writers record HAS_IP), so an apex is read
    where its records live. ``returns`` is the RETURN tail after the root."""
    by_lower = {r.lower(): r for r in apex_roots}
    rows = session.run(
        """
        MATCH (s:Subdomain {user_id: $uid, project_id: $pid})-[r:RESOLVES_TO]->(i:IP)
        WHERE toLower(s.name) IN $apex_roots AND """ + FORWARD_DNS + """
        """ + returns.replace("{ROOT}", "s.name AS root"),
        apex_roots=list(by_lower), uid=user_id, pid=project_id,
    )
    return [_ApexRow(record, by_lower) for record in rows]


class _ApexRow:
    """A row whose `root` is the run's root as the caller spelled it (the query
    matched it case-insensitively); every other key reads through."""

    __slots__ = ("_record", "_root")

    def __init__(self, record, by_lower: dict):
        self._record = record
        root = record["root"]
        self._root = by_lower.get(str(root or "").lower(), root)

    def __getitem__(self, key):
        return self._root if key == "root" else self._record[key]


def graph_scope_subdomains(session, user_id: str, project_id: str, roots: list,
                           domain_groups) -> list:
    """The run's Subdomain names for a writer's scope list: every name under
    the run's org Domains that belongs to one of its scan roots (the roots
    themselves included). Without scope groups, every Subdomain under the
    roots, as before."""
    scope = _GraphScope(roots, domain_groups, include_root_domain=False)
    record = session.run(
        """
        MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:HAS_SUBDOMAIN]->(s:Subdomain)
        WHERE toLower(d.name) IN $domains
        RETURN collect(DISTINCT s.name) AS subdomains
        """,
        domains=scope.orgs, uid=user_id, pid=project_id,
    ).single()
    subs = (record["subdomains"] if record else None) or []
    if not scope.scoped:
        return subs
    return [sub for sub in subs if scope.root_of(sub, apex=False) is not None]


def _other_domains(session, user_id: str, project_id: str, roots: list) -> list:
    """The project's Domain nodes this run does not cover.

    A root removed from the batch keeps its node (and its hosts' BaseURLs)
    until the next full recon clears the graph, and the operator may have left
    a current root unticked. BaseURLs are read project-wide, so without this
    their hosts would still be scanned.
    """
    wanted = {r.lower() for r in roots}
    result = session.run(
        "MATCH (d:Domain {user_id: $uid, project_id: $pid}) RETURN d.name AS name",
        uid=user_id, pid=project_id,
    )
    return [r["name"] for r in result if r["name"] and r["name"].lower() not in wanted]


def _co_hosted_vhost_hosts(session, user_id: str, project_id: str) -> frozenset:
    """Hostnames the graph knows only as a co-hosted third party's virtual host.

    VHost/SNI enumeration keeps a BaseURL for a name it found on a target IP
    even when the name is outside the engagement (hung off the Service, owned by
    no Subdomain). That is a record of what the IP serves, not a target: the
    name resolves wherever its own DNS says, usually a third party's server.
    A host some other writer also recorded is left alone. Never raises; on a
    failed read nothing extra is dropped.
    """
    try:
        result = session.run(
            """
            MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
            WHERE b.discovery_source = 'vhost_sni_enum' AND b.host IS NOT NULL
              AND NOT EXISTS { MATCH (b)<-[:HAS_BASE_URL]-(:Subdomain) }
            WITH DISTINCT toLower(b.host) AS host
            WHERE NOT EXISTS {
                MATCH (o:BaseURL {user_id: $uid, project_id: $pid})
                WHERE toLower(o.host) = host
                  AND coalesce(o.discovery_source, '') <> 'vhost_sni_enum'
            }
            RETURN collect(host) AS co_hosted_vhost_hosts
            """,
            uid=user_id, pid=project_id,
        )
        hosts = set()
        for record in result:
            hosts.update(h for h in (record.get("co_hosted_vhost_hosts") or []) if h)
        return frozenset(hosts)
    except Exception:  # noqa: BLE001
        return frozenset()


#: Coverage-note module of the refusals the partial graph readers make.
_ADMISSION_MODULE = "partial_graph_targets"


def _run_roe() -> dict:
    """The run's RoE in settings form, for the admission gate: the builders get
    no settings, partial_recon sets the exclusions once (set_run_roe)."""
    from recon.partial_recon_modules import helpers
    excluded = list(helpers._RUN_ROE_EXCLUDED)
    return {"ROE_ENABLED": bool(excluded), "ROE_EXCLUDED_HOSTS": excluded}


def _graph_address_gate(session, user_id: str, project_id: str):
    """``admits(host)`` under the run's RoE IP and CIDR entries, on the addresses
    the graph resolved each name to (forward DNS).

    The rule is admit_targets', as admit_urls applies it to httpx: a tool
    handed a URL resolves its host itself, so a name with any excluded address,
    or with none while such entries exist, is no target. Without an IP or CIDR
    entry it admits everything and never queries (the name entries are
    roe_excluded's).
    """
    from recon.helpers.target_admission import admission_context, admit_targets

    roe = _run_roe()
    if not admission_context(roe).ip_rules:
        return lambda host: True
    addresses: dict = {}
    for record in session.run(
        """
        MATCH (s:Subdomain {user_id: $uid, project_id: $pid})-[r:RESOLVES_TO]->(i:IP)
        WHERE """ + FORWARD_DNS + """
        RETURN toLower(s.name) AS host, i.address AS address
        """,
        uid=user_id, pid=project_id,
    ):
        holders = addresses.setdefault(record["host"], [])
        if record["address"] not in holders:
            holders.append(record["address"])
    verdicts: dict = {}

    def admits(host: str) -> bool:
        if host not in verdicts:
            adm = admit_targets(roe, names={host: addresses.get(host, [])},
                                module=_ADMISSION_MODULE, resolves_names=True)
            verdicts[host] = host in adm.names
        return verdicts[host]

    return admits


def _ip_mode_gate():
    """IP mode: the recon dict the admission gate reads the run's targets
    from, or None outside IP mode."""
    targets = run_ip_targets()
    return None if targets is None else {"metadata": {"ip_mode": True, "expanded_ips": targets}}


def _ip_mode_names(names: dict) -> tuple:
    """IP mode: of ``{host: [addresses]}``, the names a tool may be handed and
    the target addresses, as the admission gate rules (B-21): a real name only
    when it has an address and every one is a target, a label only as its own
    target address. Refusals are logged once. ``(None, None)`` outside IP mode.
    """
    gate = _ip_mode_gate()
    if gate is None:
        return None, None
    from recon.helpers.target_admission import admit_targets
    adm = admit_targets(None, gate, names=names, module=_ADMISSION_MODULE, resolves_names=True)
    return set(adm.names), set(adm.ips)


def _ip_mode_rows(rows, host_key: str, ip_key: str):
    """IP mode: the Subdomain -> IP rows that stay targets.

    The graph holds, under the synthetic root, each target's label and the
    PTR names a full run kept, with source-less RESOLVES_TO edges: an older
    run (B-01) or a typed attach (B-20) may have left one on an address that
    is no target. A label keeps only its target address; a name is kept
    whole only when every address it resolves to is a target, the rule the
    full run applies to a PTR name. Outside IP mode the rows pass as they are.
    """
    if not run_is_ip_mode():
        return rows
    rows = list(rows)
    answers: dict = {}
    for row in rows:
        answers.setdefault(row[host_key], []).append(row[ip_key])
    names, addresses = _ip_mode_names(answers)
    return [row for row in rows
            if row[host_key] in names or (is_placeholder(row[host_key]) and row[ip_key] in addresses)]


def _ip_mode_kept_host(recon_data: dict, host) -> bool:
    """IP mode: a name in the flat ``subdomains`` list stays only when its
    forward rows survived _ip_mode_rows (it is in dns.subdomains). Always
    True outside IP mode."""
    if not run_is_ip_mode():
        return True
    return host in ((recon_data.get("dns") or {}).get("subdomains") or {})


def _ip_mode_url_scope(session, user_id: str, project_id: str, orgs: list):
    """IP mode: ``keeps(host)`` for a graph URL's host, or None outside IP
    mode. The forward answers under the run's roots are read and judged once,
    and only when a host is a name: an address-only run never queries."""
    gate = _ip_mode_gate()
    if gate is None:
        return None
    import ipaddress
    from recon.helpers.target_admission import ip_mode_targets, is_target
    targets = ip_mode_targets(gate)
    admitted: dict = {}

    def keeps(host: str) -> bool:
        try:
            ipaddress.ip_address(host.strip("[]"))
            return is_target(host, targets)
        except ValueError:
            pass
        if "names" not in admitted:
            admitted["names"], _ = _ip_mode_names(_forward_answers(session, user_id, project_id, orgs))
        return host in admitted["names"]

    return keeps


def _forward_answers(session, user_id: str, project_id: str, orgs: list) -> dict:
    """{name (lower case): [addresses]} from the forward-DNS edges of the
    Subdomains under ``orgs``."""
    answers: dict = {}
    for record in session.run(
        """
        MATCH (d:Domain {user_id: $uid, project_id: $pid})
              -[:HAS_SUBDOMAIN]->(s:Subdomain)-[r:RESOLVES_TO]->(i:IP)
        WHERE toLower(d.name) IN $domains AND """ + FORWARD_DNS + """
        RETURN s.name AS subdomain, i.address AS address
        """,
        domains=[str(o).lower() for o in orgs], uid=user_id, pid=project_id,
    ):
        name, address = record["subdomain"], record["address"]
        if isinstance(name, str) and address:
            holders = answers.setdefault(name.strip().rstrip(".").lower(), [])
            if address not in holders:
                holders.append(address)
    return answers


def graph_url_scope(session, user_id: str, project_id: str, domains, domain_groups,
                    include_root_domain: bool = False, apex_filter: bool = True):
    """A predicate over a graph URL's host: is it a target of this run?

    Drops a host under a Domain this run does not cover, and a host a literal
    batch group never listed. With apex_filter, also an apex its group
    excludes (the tools that always honoured Include Root Domain). A host under
    no project root (an IP, a third-party host) is kept, as before, unless the
    graph knows it only as a co-hosted vhost name (_co_hosted_vhost_hosts). A caller
    not yet migrated (no domain_groups) gets only the apex rule it had. With
    scope groups the decision is _GraphScope's (§4.6, longest scan root).
    A host the scope keeps must also pass the RoE admission gate on every
    address the graph resolved it to (_graph_address_gate).

    IP mode (B-21) keeps a host only when it is a target address, or a name
    under the run's roots whose every forward address is a target. A host
    under no Domain (a redirect target, a third party, a co-hosted vhost name)
    and a label are never kept.
    """
    roots = _as_roots(domains)
    scope = _GraphScope(roots, domain_groups, include_root_domain)
    apex_roots, allowed = scope.apex_roots, scope.allowed
    other_roots = _other_domains(session, user_id, project_id, roots) if domain_groups is not None else []
    known = roots + other_roots
    # Loaded lazily, and only when a host under no project root turns up: the
    # common run has none, so the extra query never fires (and fixed-sequence
    # test mocks are untouched).
    co_hosted_cache: dict = {}

    def _co_hosted() -> frozenset:
        if "set" not in co_hosted_cache:
            co_hosted_cache["set"] = _co_hosted_vhost_hosts(session, user_id, project_id)
        return co_hosted_cache["set"]

    admits = _graph_address_gate(session, user_id, project_id)
    ip_mode_keeps = _ip_mode_url_scope(session, user_id, project_id, scope.orgs)

    def keep(host) -> bool:
        host = (host or "").strip().lower()
        if ip_mode_keeps is not None:
            return not host or (not roe_excluded(host) and ip_mode_keeps(host) and admits(host))
        # Only a host the scope keeps reaches the gate, so a refusal is noted
        # for a target the RoE took out, never for an out-of-scope host.
        return not host or (_in_scope(host) and admits(host))

    def _in_scope(host) -> bool:
        if roe_excluded(host):
            return False
        if scope.scoped:
            if scope.root_of(host, apex=apex_filter) is not None:
                return True
            # Under the project (another group, a removed scan root, an org's
            # names outside every scan root) but no target of this run.
            if scope.under_project(host) or root_for_host(host, other_roots) is not None:
                return False
            return host not in _co_hosted()
        root = root_for_host(host, known)
        if root is None:
            return host not in _co_hosted()
        if root in other_roots:
            return False
        if apex_filter and host == root.lower() and root not in apex_roots:
            return False
        return _host_allowed(root, host, allowed)

    return keep


def url_host(url: str, host: str = "") -> str:
    """A BaseURL's host: its stored `host`, else parsed from the URL (older nodes lack it)."""
    if host:
        return host.lower()
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def graph_target_hosts(user_id: str, project_id: str, domains, domain_groups,
                       include_root_domain: bool = False, include_graph: bool = True) -> list:
    """The in-scope hosts to hand a passive URL source (Gau, ParamSpider) for a
    whole run.

    Each root's apex is a target when its group includes it (always for a
    wildcard or single-domain root, matching today's single-root behaviour),
    plus every Subdomain under the run's roots, dropping the hosts a literal
    group never listed. With the graph unreachable, only the apexes are
    returned. A caller not yet migrated (a single string) keeps its one root.
    IP mode: _ip_mode_target_hosts.

    Every host then passes the RoE admission gate on the addresses the graph
    resolved it to (_graph_address_gate): Gau's verifier and method probe
    request each archived URL on these hosts, and resolve the name themselves.
    Under RoE IP or CIDR entries those addresses are read even when the
    graph's names are left out, and with no graph to read them from no host is
    admitted (nothing shows it stays off the excluded ranges).
    """
    from graph_db import Neo4jClient
    from recon.helpers.target_admission import admission_context, admit_targets

    roots = _as_roots(domains)
    if run_is_ip_mode():
        return _ip_mode_target_hosts(user_id, project_id, roots, include_graph)
    scope = _GraphScope(roots, domain_groups, include_root_domain)
    allowed = scope.allowed
    hosts = set()
    for root in roots:
        if scope.scoped:
            # §4.6: a scan root is a target only with Include Root.
            if root in scope.apex_roots:
                hosts.add(root)
        elif root not in allowed or root.lower() in allowed[root]:
            # Without scope groups a wildcard/single root keeps its apex, and a
            # literal group lists its apex only when it wrote ".".
            hosts.add(root)
    address_rules = admission_context(_run_roe()).ip_rules
    if not roots or not (include_graph or address_rules):
        return sorted(hosts)

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph subdomains")
            if not address_rules:
                return sorted(hosts)
            return sorted(admit_targets(_run_roe(), names=dict.fromkeys(hosts, ()),
                                        module=_ADMISSION_MODULE, resolves_names=True).names)
        with graph_client.driver.session() as session:
            if include_graph:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})-[:HAS_SUBDOMAIN]->(s:Subdomain)
                    WHERE toLower(d.name) IN $domains
                    RETURN d.name AS root, s.name AS sub
                    """,
                    domains=scope.orgs, uid=user_id, pid=project_id,
                )
                for record in result:
                    if scope.keeps(record["sub"], record["root"]):
                        hosts.add(record["sub"])
            admits = _graph_address_gate(session, user_id, project_id)
            return sorted(h for h in hosts if admits(h.strip().lower()))


def _ip_mode_target_hosts(user_id: str, project_id: str, roots: list, include_graph: bool) -> list:
    """IP mode: the names an archive may be asked about (S-6). Never the
    synthetic root, which is the project id, nor a label, which no archive
    knows; a name only when every address it resolves to is a target."""
    if not include_graph or not roots:
        return []
    from graph_db import Neo4jClient
    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph subdomains")
            return []
        with graph_client.driver.session() as session:
            answers = _forward_answers(session, user_id, project_id, roots)
    names, _ = _ip_mode_names(answers)
    return sorted(name for name in names if not roe_excluded(name))


def _recon_data_ips(recon_data: dict) -> list:
    ips = set(((recon_data.get("port_scan") or {}).get("by_ip")) or {})
    dns = recon_data.get("dns") or {}
    for entry in [dns.get("domain") or {}, *((dns.get("subdomains") or {}).values())]:
        ip_lists = (entry or {}).get("ips") or {}
        ips.update(ip_lists.get("ipv4") or [])
        ips.update(ip_lists.get("ipv6") or [])
    return sorted(ip for ip in ips if ip)


def attach_graph_ownership(recon_data: dict, user_id: str, project_id: str) -> None:
    """Load the IP attribution tag (IP.ownership) of the run's IPs from the graph.

    A partial run does not re-run IP attribution, so the consumers that read
    its tag (vhost/SNI, origin discovery, the Shodan and Netlas CVE writers)
    read the last one written, in the shape the full run leaves in memory. An
    IP with no tag is absent, and the consumers fall back to their own CDN
    checks. Never raises: on any failure nothing is loaded.
    """
    ips = _recon_data_ips(recon_data)
    if not ips:
        return
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return
            with graph_client.driver.session() as session:
                rows = session.run(
                    """
                    MATCH (i:IP {user_id: $uid, project_id: $pid})
                    WHERE i.address IN $ips AND i.ownership IS NOT NULL
                    RETURN i.address AS ip, i.ownership AS ownership
                    """,
                    ips=ips, uid=user_id, pid=project_id,
                )
                by_ip = {r["ip"]: {"ownership": r["ownership"]} for r in rows if r["ip"]}
    except Exception as e:  # noqa: BLE001 - no tag only means the CDN fallbacks apply
        print(f"[!][Partial Recon] Could not read the IP attribution tags: {type(e).__name__}")
        return
    if by_ip:
        recon_data["ip_attribution"] = {"by_ip": by_ip, "source": "graph"}


def _build_recon_data_from_graph(domains, user_id: str, project_id: str,
                                 include_root_domain: bool = False,
                                 domain_groups: list = None) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_port_scan expects.

    Returns a dict with 'domain' and 'dns' keys matching the structure
    produced by domain_recon.py (domain IPs + subdomain IPs).

    `domains` is the run's roots (or one root from a caller not yet migrated),
    scoped per root as in _build_port_scan_data_from_graph: an apex is loaded
    only when its group includes it, and a literal batch group only its listed
    hosts. The first root's apex fills dns.domain and another root's apex is a
    host under dns.subdomains. metadata.include_root_domain describes the first
    root, so extract_targets_from_recon adds that apex only when in scope.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    scope = _GraphScope(roots, domain_groups, include_root_domain)
    apex_roots, allowed = scope.apex_roots, scope.allowed
    primary = roots[0] if roots else ""

    recon_data = ip_mode_recon({
        "domain": primary,
        "domains": roots,
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "metadata": {"include_root_domain": primary in apex_roots},
    })
    if not roots:
        return recon_data

    def _add_ip(ips: dict, addr: str, version) -> None:
        if roe_excluded(addr):
            return
        bucket = _classify_ip(addr, version)
        if addr not in ips[bucket]:
            ips[bucket].append(addr)

    def _dns_entry(host: str) -> dict:
        return recon_data["dns"]["subdomains"].setdefault(
            host, {"ips": {"ipv4": [], "ipv6": []}, "has_records": True})

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            if apex_roots:
                result = _apex_rows(session, user_id, project_id, apex_roots,
                                    "RETURN {ROOT}, i.address AS address, i.version AS version")
                for record in result:
                    if record["root"] == primary:
                        _add_ip(recon_data["dns"]["domain"]["ips"], record["address"], record["version"])
                        recon_data["dns"]["domain"]["has_records"] = True
                    else:
                        _add_ip(_dns_entry(record["root"])["ips"], record["address"], record["version"])

            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[r:RESOLVES_TO]->(i:IP)
                WHERE toLower(d.name) IN $domains AND """ + FORWARD_DNS + """
                RETURN d.name AS root, s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domains=scope.orgs, uid=user_id, pid=project_id,
            )
            for record in _ip_mode_rows(result, "subdomain", "address"):
                if not scope.keeps(record["subdomain"], record["root"]):
                    continue
                _add_ip(_dns_entry(record["subdomain"])["ips"], record["address"], record["version"])

    return recon_data


def _build_port_scan_data_from_graph(domains, user_id: str, project_id: str,
                                     include_root_domain: bool = False,
                                     domain_groups: list = None) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_nmap_scan expects.

    Returns a dict with 'port_scan' key containing by_ip, by_host, and
    ip_to_hostnames structures matching what build_nmap_targets() consumes.
    Also populates a 'dns' section for user-IP linking logic.

    `domains` is the run's roots (or one root from a caller not yet migrated).
    Each root's apex is a target only when its group includes it, and a literal
    batch group loads only its listed hosts, not every Subdomain a writer has
    since hung under the root (certificate SANs, urlscan). The first root's apex
    fills dns.domain; another root's apex is recorded as a host under
    dns.subdomains, the one place extract_targets_from_recon reads a second
    apex from. metadata.include_root_domain describes the first root.

    An RoE-excluded address is in dns only, never in the port maps: the
    admission gate reads dns (known_addresses, extract_targets_from_recon) and
    needs it to see that a name with one excluded address is no by-name target,
    while nmap, tlsx and the banner grab connect to what the maps hold.
    metadata.roe carries the run's RoE, while it has exclusions, for a reader
    that gets no settings.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    scope = _GraphScope(roots, domain_groups, include_root_domain)
    apex_roots, allowed = scope.apex_roots, scope.allowed
    primary = roots[0] if roots else ""

    recon_data = ip_mode_recon({
        "domain": primary,
        "domains": roots,
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
        "metadata": {"include_root_domain": primary in apex_roots},
    })
    roe = _run_roe()
    if roe["ROE_ENABLED"]:
        recon_data["metadata"]["roe"] = roe

    all_ports_set = set()
    ip_mode = run_is_ip_mode()

    def _add_host(host: str, ip_addr: str, port_numbers: list, port_details: list,
                  record=None) -> None:
        """Record one host -> IP -> ports row in by_ip, by_host and ip_to_hostnames.

        Everything a write-back through update_graph_from_port_scan could lower
        rides along: the IP's CDN tag, and on each port detail the IP it is open
        on and the graph's passive_only mark (null on a Port from before the
        mark), which tells the writer the port is no active hit of this run.
        by_host stays keyed by hostname and lists every address's ports, the
        way the target builders (httpx) read it; the detail's `ip` keeps a
        port of the host's second address off its first.

        IP mode keys a label's row by its address, as the full run's naabu
        does (B-21): httpx then probes ``http://<address>``, never the label,
        and no tool is handed the label as a name.
        """
        named = not (ip_mode and is_placeholder(host))
        if not named:
            host = ip_addr
        get = getattr(record, "get", None)
        is_cdn = bool(get("is_cdn")) if get else False
        cdn = (get("cdn_name") if get else None) or None
        port_details = [{**pd, "ip": ip_addr} for pd in port_details]
        if ip_addr not in recon_data["port_scan"]["by_ip"]:
            recon_data["port_scan"]["by_ip"][ip_addr] = {
                "ip": ip_addr,
                "hostnames": [host] if named else [],
                "ports": list(port_numbers),
                "port_details": list(port_details),
                "is_cdn": is_cdn,
                "cdn": cdn,
            }
        else:
            existing = recon_data["port_scan"]["by_ip"][ip_addr]
            if named and host not in existing["hostnames"]:
                existing["hostnames"].append(host)
            for pnum in port_numbers:
                if pnum not in existing["ports"]:
                    existing["ports"].append(pnum)
            for pd in port_details:
                if not any(epd["port"] == pd["port"] for epd in existing["port_details"]):
                    existing["port_details"].append(pd)

        if host not in recon_data["port_scan"]["by_host"]:
            recon_data["port_scan"]["by_host"][host] = {
                "host": host,
                "ip": ip_addr,
                "ports": list(port_numbers),
                "port_details": list(port_details),
                "is_cdn": is_cdn,
                "cdn": cdn,
            }
        else:
            existing = recon_data["port_scan"]["by_host"][host]
            for pnum in port_numbers:
                if pnum not in existing["ports"]:
                    existing["ports"].append(pnum)
            for pd in port_details:
                if not any(epd["port"] == pd["port"] and epd.get("ip") == pd["ip"]
                           for epd in existing["port_details"]):
                    existing["port_details"].append(pd)

        if not named:
            return
        recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
        if host not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
            recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(host)

    def _ports(ports_data) -> tuple:
        # OPTIONAL MATCH yields one null-port map when an IP has no ports.
        numbers, details = [], []
        for p in ports_data:
            if p["number"] is not None:
                pnum = int(p["number"])
                numbers.append(pnum)
                all_ports_set.add(pnum)
                details.append({"port": pnum, "protocol": p["protocol"] or "tcp", "service": "",
                                "passive_only": p.get("passive_only")})
        return numbers, details

    def _dns_entry(host: str) -> dict:
        return recon_data["dns"]["subdomains"].setdefault(
            host, {"ips": {"ipv4": [], "ipv6": []}, "has_records": True})

    if not roots:
        return recon_data

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # Apex Domain -> IP -> Port, only for the roots whose scope includes it.
            apex_records = []
            if apex_roots:
                apex_records = _apex_rows(
                    session, user_id, project_id, apex_roots,
                    "OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)\n"
                    "RETURN {ROOT}, i.address AS ip, i.version AS version, "
                    "i.is_cdn AS is_cdn, i.cdn_name AS cdn_name, "
                    "collect(DISTINCT {number: p.number, protocol: p.protocol, "
                    "passive_only: p.passive_only}) AS ports")
            for record in apex_records:
                root = record["root"]
                ip_addr = record["ip"]
                bucket = _classify_ip(ip_addr, record["version"])
                if root == primary:
                    if ip_addr not in recon_data["dns"]["domain"]["ips"][bucket]:
                        recon_data["dns"]["domain"]["ips"][bucket].append(ip_addr)
                        recon_data["dns"]["domain"]["has_records"] = True
                else:
                    ips = _dns_entry(root)["ips"][bucket]
                    if ip_addr not in ips:
                        ips.append(ip_addr)
                if roe_excluded(ip_addr):
                    continue
                port_numbers, port_details = _ports(record["ports"])
                _add_host(root, ip_addr, port_numbers, port_details, record)

            # Subdomain -> IP -> Port relationships
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)-[r:RESOLVES_TO]->(i:IP)
                WHERE toLower(d.name) IN $domains AND """ + FORWARD_DNS + """
                OPTIONAL MATCH (i)-[:HAS_PORT]->(p:Port)
                RETURN d.name AS root, s.name AS subdomain, i.address AS ip, i.version AS version,
                       i.is_cdn AS is_cdn, i.cdn_name AS cdn_name,
                       collect(DISTINCT {number: p.number, protocol: p.protocol,
                                         passive_only: p.passive_only}) AS ports
                """,
                domains=scope.orgs, uid=user_id, pid=project_id,
            )
            for record in _ip_mode_rows(result, "subdomain", "ip"):
                subdomain = record["subdomain"]
                if not scope.keeps(subdomain, record["root"]):
                    continue
                ip_addr = record["ip"]
                bucket = _classify_ip(ip_addr, record["version"])
                sub_ips = _dns_entry(subdomain)["ips"]
                if ip_addr not in sub_ips[bucket]:
                    sub_ips[bucket].append(ip_addr)
                if roe_excluded(ip_addr):
                    continue
                port_numbers, port_details = _ports(record["ports"])
                _add_host(subdomain, ip_addr, port_numbers, port_details, record)

    recon_data["port_scan"]["all_ports"] = sorted(all_ports_set)
    return recon_data


def _build_http_probe_data_from_graph(domains, user_id: str, project_id: str,
                                      include_root_domain: bool = False,
                                      domain_groups: list = None) -> dict:
    """
    Query Neo4j to build the recon_data dict for crawlers/fuzzers running in
    partial recon (Katana, Hakrawler, FFuf, Kiterunner).

    Populates:
      - 'http_probe.by_url': BaseURL nodes (Source 2 of build_target_urls)
      - 'dns.domain': the first root's apex IPs (Source 3 fallback), only when
        its group includes the apex; another root's apex is a dns.subdomains host
      - 'dns.subdomains': every Subdomain with its IPs + has_records
      - 'subdomains': flat list for scope filtering in graph updates
      - 'metadata.include_root_domain': stamped so extract_targets_from_recon
        excludes the first root's apex when scope says so.
      - 'metadata.roe': the run's RoE, while it has exclusions, for a reader
        that gets no settings.

    `domains` is the run's roots, scoped per root like the other builders.
    BaseURLs are read project-wide and then filtered by graph_url_scope: an
    excluded apex, a host a literal group never listed, a host under a
    Domain this run does not cover, and a host the RoE admission gate refuses
    are all dropped.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    scope = _GraphScope(roots, domain_groups, include_root_domain)
    apex_roots, allowed = scope.apex_roots, scope.allowed
    primary = roots[0] if roots else ""

    recon_data = ip_mode_recon({
        "domain": primary,
        "domains": roots,
        "subdomains": [],
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "http_probe": {
            "by_url": {},
        },
        "metadata": {"include_root_domain": primary in apex_roots},
    })
    roe = _run_roe()
    if roe["ROE_ENABLED"]:
        recon_data["metadata"]["roe"] = roe
    if not roots:
        return recon_data

    # An RoE-excluded address is kept: every reader of these addresses passes
    # them through the admission gate (extract_targets_from_recon), which needs
    # it to see that a name with one excluded address is no by-name target.
    # Dropped here, the name would look wholly allowed.
    def _add_ip(ips: dict, addr: str, version) -> None:
        bucket = _classify_ip(addr, version)
        if addr not in ips[bucket]:
            ips[bucket].append(addr)

    def _dns_entry(host: str) -> dict:
        return recon_data["dns"]["subdomains"].setdefault(
            host, {"ips": {"ipv4": [], "ipv6": []}, "has_records": True})

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # 1) Apex Domain -> IP (Source 3 fallback), only for included apexes.
            if apex_roots:
                result = _apex_rows(session, user_id, project_id, apex_roots,
                                    "RETURN {ROOT}, i.address AS address, i.version AS version")
                for record in result:
                    if record["root"] == primary:
                        _add_ip(recon_data["dns"]["domain"]["ips"], record["address"], record["version"])
                        recon_data["dns"]["domain"]["has_records"] = True
                    else:
                        _add_ip(_dns_entry(record["root"])["ips"], record["address"], record["version"])

            # 2) Subdomain -> IP relationships (Source 3 fallback for unprobed subs)
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[r:RESOLVES_TO]->(i:IP)
                WHERE toLower(d.name) IN $domains AND """ + FORWARD_DNS + """
                RETURN d.name AS root, s.name AS subdomain, i.address AS address, i.version AS version
                """,
                domains=scope.orgs, uid=user_id, pid=project_id,
            )
            for record in _ip_mode_rows(result, "subdomain", "address"):
                if not scope.keeps(record["subdomain"], record["root"]):
                    continue
                _add_ip(_dns_entry(record["subdomain"])["ips"], record["address"], record["version"])

            # 3) BaseURL nodes (Source 2: live URLs verified by httpx)
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   include_root_domain=include_root_domain)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                RETURN b.url AS url, coalesce(b.status_code, probe.status_code) AS status_code,
                       b.host AS host, coalesce(b.content_type, probe.content_type) AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                status_code = record["status_code"]
                # Skip URLs with server errors (same filter as resource_enum)
                if status_code is not None and int(status_code) >= 500:
                    continue
                if not keep(url_host(url, record["host"] or "")):
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(status_code) if status_code is not None else 200,
                    "content_type": record["content_type"] or "",
                }

            # 4) Flat subdomain list for graph-update scope filtering
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                WHERE toLower(d.name) IN $domains
                RETURN collect(DISTINCT s.name) AS subdomains
                """,
                domains=scope.orgs, uid=user_id, pid=project_id,
            )
            record = result.single()
            if record:
                recon_data["subdomains"] = [
                    sub for sub in record["subdomains"] or []
                    if scope.keeps(sub) and _ip_mode_kept_host(recon_data, sub)
                ]

    return recon_data


def _build_vuln_scan_data_from_graph(domains, user_id: str, project_id: str,
                                     include_root_domain: bool = False,
                                     domain_groups: list = None) -> dict:
    """
    Query Neo4j to build the recon_data dict that run_vuln_scan expects.

    Returns a dict with 'domain', 'dns', 'subdomains', 'http_probe', and
    'resource_enum' keys. The vuln_scan module uses extract_targets_from_recon()
    (needs dns) and build_target_urls() (prefers resource_enum > http_probe).

    `domains` is the run's roots, scoped per root like the other builders: an
    apex only when its group includes it, a literal group's listed hosts only,
    and BaseURLs/Endpoints filtered by graph_url_scope (a host under a Domain
    this run does not cover, or an excluded apex, is dropped). The first root's
    apex fills dns.domain; another root's apex is a dns.subdomains host.

    An RoE-excluded address is in dns only, never in port_scan.by_ip or the
    nmap services, as in the port-scan builder: every reader's admission gate
    (partial Nuclei, takeover, security checks, vhost) reads dns and needs it
    to see that a name with one excluded address is no by-name target, and
    that a name whose only address is excluded is excluded rather than
    unresolved. metadata.roe carries the run's RoE, while it has exclusions,
    outside IP mode, whose targets the RoE already filtered.
    """
    from graph_db import Neo4jClient

    roots = _as_roots(domains)
    scope = _GraphScope(roots, domain_groups, include_root_domain)
    apex_roots, allowed = scope.apex_roots, scope.allowed
    primary = roots[0] if roots else ""

    recon_data = ip_mode_recon({
        "domain": primary,
        "domains": roots,
        "subdomains": [],
        "dns": {
            "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {},
        },
        "metadata": {"include_root_domain": primary in apex_roots},
        "http_probe": {
            "by_url": {},
        },
        "port_scan": {
            "by_ip": {},
        },
        "resource_enum": {
            "by_base_url": {},
            "discovered_urls": [],
        },
    })
    roe = _run_roe()
    if roe["ROE_ENABLED"] and not run_is_ip_mode():
        recon_data["metadata"]["roe"] = roe
    if not roots:
        return recon_data

    def _hydrate_ip_metadata(addr: str, is_cdn, cdn_name, asn) -> None:
        """Populate port_scan.by_ip with CDN/ASN metadata so collect_cdn_ips
        and collect_asn_cdn_ips can detect CDN IPs in partial-recon mode."""
        if not addr or roe_excluded(addr):
            return
        entry = recon_data["port_scan"]["by_ip"].setdefault(addr, {
            "ip": addr,
            "hostnames": [],
            "ports": [],
            "is_cdn": False,
            "cdn": None,
            "asn": None,
        })
        if is_cdn and not entry["is_cdn"]:
            entry["is_cdn"] = True
        if cdn_name and not entry["cdn"]:
            entry["cdn"] = cdn_name
        if asn and not entry["asn"]:
            entry["asn"] = asn

    def _add_ip(ips: dict, addr: str, version) -> None:
        if run_is_ip_mode() and roe_excluded(addr):
            return
        bucket = _classify_ip(addr, version)
        if addr not in ips[bucket]:
            ips[bucket].append(addr)

    def _dns_entry(host: str) -> dict:
        return recon_data["dns"]["subdomains"].setdefault(
            host, {"ips": {"ipv4": [], "ipv6": []}, "has_records": True})

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # 1) Apex Domain -> IP, only for the roots whose group includes it.
            if apex_roots:
                result = _apex_rows(session, user_id, project_id, apex_roots,
                                    "RETURN {ROOT}, i.address AS address, i.version AS version, "
                                    "i.is_cdn AS is_cdn, i.cdn_name AS cdn_name, i.asn AS asn")
                for record in result:
                    addr = record["address"]
                    if record["root"] == primary:
                        _add_ip(recon_data["dns"]["domain"]["ips"], addr, record["version"])
                        recon_data["dns"]["domain"]["has_records"] = True
                    else:
                        _add_ip(_dns_entry(record["root"])["ips"], addr, record["version"])
                    _hydrate_ip_metadata(addr, record["is_cdn"], record["cdn_name"], record["asn"])

            # 2) Subdomain -> IP relationships
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                      -[r:RESOLVES_TO]->(i:IP)
                WHERE toLower(d.name) IN $domains AND """ + FORWARD_DNS + """
                RETURN d.name AS root, s.name AS subdomain, i.address AS address, i.version AS version,
                       i.is_cdn AS is_cdn, i.cdn_name AS cdn_name, i.asn AS asn
                """,
                domains=scope.orgs, uid=user_id, pid=project_id,
            )
            for record in _ip_mode_rows(result, "subdomain", "address"):
                if not scope.keeps(record["subdomain"], record["root"]):
                    continue
                addr = record["address"]
                _add_ip(_dns_entry(record["subdomain"])["ips"], addr, record["version"])
                _hydrate_ip_metadata(addr, record["is_cdn"], record["cdn_name"], record["asn"])

            # Also get subdomains without IPs for the subdomains list
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                WHERE toLower(d.name) IN $domains
                RETURN collect(DISTINCT s.name) AS subdomains
                """,
                domains=scope.orgs, uid=user_id, pid=project_id,
            )
            record = result.single()
            if record:
                recon_data["subdomains"] = [
                    sub for sub in record["subdomains"] or []
                    if scope.keeps(sub) and _ip_mode_kept_host(recon_data, sub)
                ]

            # 3) BaseURL nodes (for build_target_urls http_probe fallback)
            #    Also fetch is_cdn / cdn / asn so the CDN prefilter in
            #    run_security_checks (collect_cdn_ips, collect_asn_cdn_ips)
            #    can suppress findings on httpx-flagged CDN edges.
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   include_root_domain=include_root_domain)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                OPTIONAL MATCH (b)-[:HAS_CERTIFICATE]->(c:Certificate)
                WITH b, probe, head(collect(c)) AS cert
                RETURN b.url AS url, coalesce(b.status_code, probe.status_code) AS status_code,
                       b.host AS host, coalesce(b.content_type, probe.content_type) AS content_type,
                       coalesce(b.is_cdn, probe.is_cdn) AS is_cdn,
                       coalesce(b.cdn, probe.cdn) AS cdn, coalesce(b.asn, probe.asn) AS asn,
                       coalesce(b.server, probe.server) AS server,
                       probe.title AS title, probe.final_url AS final_url, probe.cname AS cname,
                       cert {.issuer, .issuer_cn, .issuer_dn, .subject_cn, .subject_dn, .san,
                             .not_after, .expired, .self_signed, .mismatched, .wildcard,
                             .tls_version, .cipher} AS cert
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                status_code = record["status_code"]
                host = record["host"] or ""
                if not keep(url_host(url, host)):
                    continue
                is_cdn = bool(record["is_cdn"])
                # Resolve host -> first IP so collect_cdn_ips can map URL flag
                # to an IP. dns.subdomains was populated above.
                resolved_ip = None
                sub_entry = recon_data["dns"]["subdomains"].get(host)
                if sub_entry:
                    sub_ips = sub_entry.get("ips", {})
                    resolved_ip = next(
                        (a for a in (sub_ips.get("ipv4") or []) + (sub_ips.get("ipv6") or [])
                         if not roe_excluded(a)), None)
                # The real status (Tomcat's and Fastly's error pages are 500s,
                # and an open console counts only at 200). An unprobed BaseURL
                # still reads as live for the target builders, which skip >= 500
                # themselves, and is marked so no status rule trusts the 200.
                entry = recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": host,
                    "status_code": int(status_code) if status_code is not None else 200,
                    "content_type": record["content_type"] or "",
                    "is_cdn": is_cdn,
                    "cdn": record["cdn"],
                    "asn": record["asn"],
                    "ip": resolved_ip,
                    "server": _field(record, "server"),
                    "technologies": [],
                }
                # What the Page Content checks read, when httpx recorded it.
                for key in ("title", "final_url", "cname"):
                    if _field(record, key) is not None:
                        entry[key] = _field(record, key)
                if status_code is None:
                    entry["status_unknown"] = True
                cert = _field(record, "cert")
                if isinstance(cert, dict) and any(cert.values()):
                    entry["tls"] = {
                        "version": cert.get("tls_version"), "cipher": cert.get("cipher"),
                        "certificate": {k: cert.get(k) for k in (
                            "issuer", "issuer_cn", "issuer_dn", "subject_cn", "subject_dn",
                            "not_after", "expired", "self_signed", "mismatched", "wildcard")}
                        | {"san": cert.get("san") or []},
                    }
                # If the URL is CDN-flagged AND the cdn name is a reliable
                # edge provider (not generic "aws"/"azure"), also stamp
                # is_cdn on every IP the host resolves to so port_scan.by_ip
                # propagates it. Generic cloud labels are not propagated
                # because the IP often serves the origin app directly.
                if is_cdn and sub_entry:
                    from recon.helpers.cdn_ranges import is_reliable_edge_cdn_name
                    if is_reliable_edge_cdn_name(record["cdn"]):
                        sub_ips = sub_entry.get("ips", {})
                        for ip_addr in (sub_ips.get("ipv4") or []) + (sub_ips.get("ipv6") or []):
                            if roe_excluded(ip_addr):
                                continue
                            entry = recon_data["port_scan"]["by_ip"].setdefault(ip_addr, {
                                "ip": ip_addr, "hostnames": [], "ports": [],
                                "is_cdn": False, "cdn": None, "asn": None,
                            })
                            entry["is_cdn"] = True
                            if not entry.get("cdn"):
                                entry["cdn"] = record["cdn"]

            # 3b) The CVE lookup (cve_helpers.run_cve_lookup) reads only by_url
            #     technologies + server and nmap_scan services, and the Nuclei
            #     AI tag selector the first two. Without them a partial run's
            #     "CVE lookup" option looked up nothing.
            by_url = recon_data["http_probe"]["by_url"]
            if by_url:
                for url, techs in _graph_url_technologies(session, user_id, project_id).items():
                    if url in by_url:
                        by_url[url]["technologies"] = techs
            scoped_ips = sorted({
                addr
                for entry in [recon_data["dns"]["domain"], *recon_data["dns"]["subdomains"].values()]
                for addr in (entry["ips"]["ipv4"] + entry["ips"]["ipv6"])
                if not roe_excluded(addr)
            })
            services = _graph_nmap_services(session, user_id, project_id, scoped_ips)
            if services:
                recon_data["nmap_scan"] = {"services_detected": services}

            # 4) Endpoints with parameters (for DAST mode). run_vuln_scan keeps
            #    only URLs carrying `?` and `=`. The crawlers' raw URLs are not
            #    stored (resource_enum writes no `full_url`), so rebuild each one
            #    from its query Parameters the way build_target_urls_from_resource_enum
            #    does: first sample value, else "1".
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                      -[:HAS_PARAMETER]->(p:Parameter)
                WHERE p.position = 'query' AND p.name IS NOT NULL AND e.path IS NOT NULL
                  AND NOT """ + declared_only_unsafe("e") + """ AND NOT """ + quarantined("e") + """
                WITH b, e, p ORDER BY p.name
                RETURN b.url AS baseurl, e.path AS path, """ + ARCHIVE_ONLY + """ AS archive_only,
                       collect(DISTINCT [p.name, coalesce(head(p.sample_values), '1')]) AS params
                """,
                uid=user_id, pid=project_id,
            )
            discovered_urls = []
            archived_urls = []
            for record in result:
                base = record["baseurl"]
                params = [(name, str(value)) for name, value in (record["params"] or []) if name]
                if base and params and keep(url_host(base)):
                    url = f"{base}{record['path']}?{urlencode(params)}"
                    discovered_urls.append(url)
                    if record.get("archive_only"):
                        archived_urls.append(url)
            # URLs other writers store whole (JS Recon, urlscan) still count.
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.full_url IS NOT NULL AND NOT """ + quarantined("e") + """
                  AND NOT """ + declared_only_unsafe("e") + """
                RETURN e.full_url AS url, e.baseurl AS baseurl, """ + ARCHIVE_ONLY + """ AS archive_only
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if url and keep(url_host(record["baseurl"] or url)):
                    discovered_urls.append(url)
                    if record.get("archive_only"):
                        archived_urls.append(url)
            recon_data["resource_enum"]["discovered_urls"] = list(dict.fromkeys(discovered_urls))
            # The full run's marker for URLs only web archives reported: the
            # rate-limit check never requests them.
            recon_data["resource_enum"]["archived_urls"] = list(dict.fromkeys(archived_urls))

    return recon_data


def _build_graphql_data_from_graph(domains, user_id: str, project_id: str,
                                   settings: dict = None, domain_groups: list = None) -> dict:
    """
    Build recon_data for GraphQL security scanning.

    Populates the sections discover_graphql_endpoints() reads, in the shapes
    the full pipeline's writers produce, so one discovery serves both:
      - http_probe.by_url          ({url: {status_code, content_type}} -- BaseURL nodes)
      - resource_enum.by_base_url  ({base: {endpoints: {path: {path, methods,
                                     parameters: {query, body, path}}}}} -- Endpoint
                                     nodes and their Parameter nodes)
      - js_recon.endpoints         ([{type, path, full_url, source_js}] -- the
                                     GraphQL Endpoint nodes JS Recon wrote)
    Plus metadata.roe, the fallback discovery reads when the settings carry no
    RoE. `settings` is the run's preloaded settings (partial_settings); only a
    direct caller omits it.

    BaseURLs, Endpoints and Parameters are read project-wide; with
    domain_groups, those on a host under a Domain this run does not cover, or a
    host a literal batch group never listed, are dropped (graph_url_scope). No
    apex rule: these tools never had one.
    """
    from graph_db import Neo4jClient

    if settings is None:
        from recon.project_settings import get_settings
        settings = get_settings()
    roots = _as_roots(domains)
    recon_data = ip_mode_recon({
        "domain": roots[0] if roots else "",
        "domains": roots,
        "http_probe": {"by_url": {}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
        "js_recon": {"endpoints": []},
        "metadata": {
            "roe": {
                "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
            }
        },
    }, settings)

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   apex_filter=False)

            # 1) BaseURLs -> http_probe.by_url
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                RETURN b.url AS url,
                       b.host AS host,
                       coalesce(b.status_code, probe.status_code) AS status_code,
                       coalesce(b.content_type, probe.content_type) AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if not url or not keep(url_host(url, record["host"] or "")):
                    continue
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(record["status_code"]) if record["status_code"] is not None else 200,
                    "content_type": record["content_type"] or "",
                    "headers": {},
                }

            # 2) Endpoints and their parameters -> resource_enum.by_base_url
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.path IS NOT NULL AND NOT """ + declared_only_unsafe("e") + """ AND NOT """ + quarantined("e") + """
                OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
                RETURN b.url AS base_url, e.path AS path,
                       coalesce(e.method, 'GET') AS method,
                       [n IN collect(DISTINCT p.name) WHERE n IS NOT NULL] AS parameters
                """,
                uid=user_id, pid=project_id,
            )
            by_base = recon_data["resource_enum"]["by_base_url"]
            for record in result:
                base = record["base_url"]
                if not base or not keep(url_host(base)):
                    continue
                endpoints = by_base.setdefault(base, {"endpoints": {}})["endpoints"]
                entry = endpoints.setdefault(record["path"], {
                    "path": record["path"], "methods": [],
                    "parameters": {"query": [], "body": [], "path": []},
                })
                if record["method"] not in entry["methods"]:
                    entry["methods"].append(record["method"])
                known = {p["name"] for p in entry["parameters"]["query"]}
                entry["parameters"]["query"].extend(
                    {"name": name} for name in record["parameters"] or [] if name not in known)

            # 3) The GraphQL endpoints JS Recon found -> js_recon.endpoints.
            # js_recon_mixin writes them as Endpoint nodes with endpoint_type;
            # a JsReconFinding never carries them.
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.endpoint_type IN ['graphql', 'graphql_introspection']
                  AND NOT """ + quarantined("e") + """
                RETURN b.url AS base_url, e.path AS path, e.endpoint_type AS type,
                       coalesce(e.full_url, '') AS full_url
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base_url"]
                if not base or not record["path"] or not keep(url_host(base)):
                    continue
                recon_data["js_recon"]["endpoints"].append({
                    "type": record["type"],
                    "path": record["path"],
                    "full_url": record["full_url"],
                    "source_js": base,
                })

    return recon_data


def _build_serialized_data_from_graph(domains, user_id: str, project_id: str,
                                      settings: dict = None, domain_groups: list = None) -> dict:
    """Build recon_data for the serialized-object scan from the existing graph.

    The scanner reads three sections (recon/serialized_scan/scanner.py): response
    headers + Set-Cookie (http_probe.by_url), enumerated endpoints/parameters
    (resource_enum.by_base_url) and crawled form fields (resource_enum.forms). A
    partial run has none of these in memory, so this rebuilds them from the nodes
    the full pipeline persisted:
      - Header nodes (Endpoint-[:HAS_HEADER]->Header) carry EVERY response header,
        Set-Cookie included, keyed by the response URL - the main detection path.
      - Parameter.sample_values (<=5, resource_mixin) carry example values.
      - Endpoint.form_input_names carry form field NAMES (values are not persisted,
        so a serialized blob baked into a hidden field's value cannot be recovered
        from the graph - only its name, which still flags a sink-named field).
    Scope is the same graph_url_scope the other builders use. `settings` is the
    run's preloaded settings; only a direct caller omits it.
    """
    from graph_db import Neo4jClient

    from recon.partial_recon_modules.helpers import _should_include_root_domain

    if settings is None:
        from recon.project_settings import get_settings
        settings = get_settings()
    roots = _as_roots(domains)
    include_root_domain = _should_include_root_domain(settings)
    recon_data = ip_mode_recon({
        "domain": roots[0] if roots else "",
        "domains": roots,
        "http_probe": {"by_url": {}},
        "resource_enum": {"endpoints": {}, "parameters": {}, "by_base_url": {},
                          "forms": [], "discovered_urls": []},
        "metadata": {
            "roe": {
                "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
            }
        },
    }, settings)
    if not roots:
        return recon_data

    by_url = recon_data["http_probe"]["by_url"]
    by_base = recon_data["resource_enum"]["by_base_url"]

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        driver = graph_client.driver
        with driver.session() as session:
            # apex_filter default (True): the serialized partial honours Include
            # Root Domain, unlike the GraphQL builder which never had an apex rule.
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   include_root_domain=include_root_domain)

            # 1) BaseURL nodes seed by_url (so a root with headers only on "/" is covered).
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                RETURN b.url AS url, b.host AS host,
                       coalesce(b.status_code, probe.status_code) AS status_code,
                       coalesce(b.content_type, probe.content_type) AS content_type
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if not url or not keep(url_host(url, record["host"] or "")):
                    continue
                by_url[url] = {
                    "url": url,
                    "host": record["host"] or "",
                    "status_code": int(record["status_code"]) if record["status_code"] is not None else 200,
                    "content_type": record["content_type"] or "",
                    "headers": {},
                }

            # 2) Response headers (Set-Cookie included) keyed by the response URL the
            # header came from; this is where the serialized blobs ride. A header on
            # an endpoint URL not seen as a BaseURL still gets its own by_url entry.
            result = session.run(
                """
                MATCH (e:Endpoint {user_id: $uid, project_id: $pid})-[:HAS_HEADER]->(h:Header)
                WHERE h.name IS NOT NULL
                RETURN coalesce(h.baseurl, e.baseurl) AS url, e.host AS host,
                       h.name AS name, h.value AS value
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if not url or not keep(url_host(url, record["host"] or "")):
                    continue
                entry = by_url.setdefault(url, {
                    "url": url, "host": record["host"] or url_host(url),
                    "status_code": 200, "content_type": "", "headers": {},
                })
                # One header name can repeat (several Set-Cookie); keep every value.
                entry.setdefault("headers", {}).setdefault(record["name"], []).append(
                    str(record["value"]) if record["value"] is not None else "")

            # 3) Endpoints + their parameters (names AND sample_values) -> by_base_url,
            # the exact shape _scan_resource_enum / _iter_params read.
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.path IS NOT NULL AND NOT """ + declared_only_unsafe("e") + """ AND NOT """ + quarantined("e") + """
                OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
                WHERE p.name IS NOT NULL
                RETURN b.url AS base, b.host AS host, e.path AS path,
                       coalesce(e.method, 'GET') AS method,
                       collect(DISTINCT {name: p.name, sample_values: coalesce(p.sample_values, [])}) AS params
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base"]
                if not base or not keep(url_host(base, record["host"] or "")):
                    continue
                params = {}
                for p in record["params"] or []:
                    name = p.get("name")
                    if not name:
                        continue
                    samples = [s for s in (p.get("sample_values") or []) if isinstance(s, str)]
                    params[str(name)] = {"sample_values": samples}
                endpoints = by_base.setdefault(base, {"endpoints": {}})["endpoints"]
                endpoints[record["path"]] = {"method": record["method"], "parameters": params}

            # 4) Form field names (values are not persisted in the graph) -> forms.
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.form_input_names IS NOT NULL AND size(e.form_input_names) > 0
                RETURN b.url AS base, b.host AS host, e.path AS path,
                       coalesce(e.method, 'GET') AS method, e.form_input_names AS names
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base"]
                if not base or not keep(url_host(base, record["host"] or "")):
                    continue
                endpoint_url = base.rstrip("/") + "/" + str(record["path"] or "").lstrip("/")
                recon_data["resource_enum"]["forms"].append({
                    "found_at": endpoint_url,
                    "action": endpoint_url,
                    "method": record["method"],
                    "inputs": [{"name": n, "value": ""} for n in (record["names"] or []) if n],
                })

    return recon_data


def _build_route_exposure_data_from_graph(domains, user_id: str, project_id: str,
                                          settings: dict = None, domain_groups: list = None) -> dict:
    """Build recon_data for the route exposure scan from the existing graph.

    The scanner reads four sections (recon/route_exposure/harvest.py): the
    probed base URLs with their page class and technologies (http_probe.by_url),
    the enumerated routes with their methods, category, sources and OpenAPI
    metadata (resource_enum.by_base_url), JS recon's endpoints with the bundle
    each came from (js_recon.endpoints), and the run's scope (subdomains,
    metadata). A declared-only route that is not GET or HEAD is never read: a
    GET consumer must not request it. Scope is graph_url_scope, as for the
    other builders; ``subdomains`` is left for the caller, which adds the typed
    URLs' hosts through _scope_partial_urls.
    """
    from graph_db import Neo4jClient

    from recon.partial_recon_modules.helpers import _should_include_root_domain

    if settings is None:
        from recon.project_settings import get_settings
        settings = get_settings()
    roots = _as_roots(domains)
    include_root_domain = _should_include_root_domain(settings)
    recon_data = ip_mode_recon({
        "domain": roots[0] if roots else "",
        "domains": roots,
        "subdomains": [],
        "http_probe": {"by_url": {}},
        "resource_enum": {"by_base_url": {}},
        "metadata": {
            "include_root_domain": include_root_domain,
            # ip_mode_recon fills it in IP mode, with the expanded targets,
            # never the raw CIDRs (B-23).
            "expanded_ips": [],
            "roe": {
                "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
            },
        },
    }, settings)
    if not roots:
        return recon_data

    by_url = recon_data["http_probe"]["by_url"]
    by_base = recon_data["resource_enum"]["by_base_url"]

    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
            return recon_data

        with graph_client.driver.session() as session:
            keep = graph_url_scope(session, user_id, project_id, roots, domain_groups,
                                   include_root_domain=include_root_domain)
            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                """ + _PROBED_ENDPOINT + """
                RETURN b.url AS url, b.host AS host,
                       coalesce(b.status_code, probe.status_code) AS status_code,
                       probe.page_class AS page_class
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                url = record["url"]
                if not url or not keep(url_host(url, record["host"] or "")):
                    continue
                by_url[url] = {
                    "url": url,
                    "host": record["host"] or url_host(url),
                    "status_code": int(record["status_code"]) if record["status_code"] is not None else 200,
                    "page_class": _field(record, "page_class") or "",
                    "technologies": [],
                }
            for url, techs in _graph_url_technologies(session, user_id, project_id,
                                                      urls=list(by_url) or None).items():
                if url in by_url:
                    by_url[url]["technologies"] = techs

            result = session.run(
                """
                MATCH (b:BaseURL {user_id: $uid, project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.path IS NOT NULL AND NOT """ + declared_only_unsafe("e") + """ AND NOT """ + quarantined("e") + """
                RETURN b.url AS base, b.host AS host, e.path AS path,
                       coalesce(e.method, 'GET') AS method, e.category AS category,
                       coalesce(e.sources, CASE WHEN e.source IS NULL THEN [] ELSE [e.source] END) AS sources,
                       e.source AS creator,
                       e.openapi_security AS openapi_security, e.openapi_tags AS openapi_tags,
                       e.openapi_declared_only AS declared_only, e.status_code AS discovery_status,
                       e.urlscan_file_kind AS urlscan_file_kind,
                       e.ffuf_category AS ffuf_category, e.js_recon_category AS js_recon_category
                """,
                uid=user_id, pid=project_id,
            )
            urlscan_files = []
            for record in result:
                base = record["base"]
                if not base or not keep(url_host(base, record["host"] or "")):
                    continue
                sources = [s for s in (record["sources"] or []) if isinstance(s, str)]
                # A sensitive file urlscan saw is handed over the way the full
                # run does it (harvest._read_urlscan), so a heap dump stays HEAD
                # and a dump is read as a backup, never fetched with a plain GET.
                file_kind = _field(record, "urlscan_file_kind")
                if file_kind:
                    urlscan_files.append({"type": "sensitive_file_seen", "kind": file_kind,
                                          "host": url_host(base, record["host"] or ""),
                                          "path": record["path"],
                                          "url": base.rstrip("/") + record["path"]})
                # A route the scan itself generated and wrote is not recon's input: a
                # full run never reads it. Read back, it became a found route, lost its
                # generated_by and variant_of (an old API version stopped being
                # version_locked) and seeded variants of its own. The generators make it
                # again from the same inputs. The creator is checked too, because the
                # scan's enrichment sets sources to ['route_exposure'] on a crawler's
                # route that had none.
                if (_field(record, "creator") == "route_exposure"
                        and all(s == "route_exposure" for s in sources)):
                    continue
                endpoints = by_base.setdefault(base, {"endpoints": {}})["endpoints"]
                entry = endpoints.setdefault(record["path"], {
                    "methods": [],
                    # JS Recon's own word ranks the route, as in a full run.
                    "category": _field(record, "js_recon_category") or record["category"] or "other",
                    "sources": sources,
                    "declared_only": record["declared_only"] is True,
                })
                if _field(record, "ffuf_category"):
                    entry["ffuf_category"] = _field(record, "ffuf_category")
                method = str(record["method"] or "GET").upper()
                if method not in entry["methods"]:
                    entry["methods"].append(method)
                security = record["openapi_security"]
                if security is not None and method in ("GET", "HEAD"):
                    entry.setdefault("openapi", {})[method] = {
                        "security": list(security), "tags": list(record["openapi_tags"] or [])}
                status = record["discovery_status"]
                # A discovery tool's 401/403 is the seen_denied hint.
                if isinstance(status, int) and status in (401, 403):
                    entry["status_code"] = status

            # JS recon's endpoints, rebuilt as its endpoint list with the bundle each
            # came from: harvest tags an API client_gated when the bundle defining a
            # router route calls it, and only the bundle -> endpoint edges keep that
            # pairing in the graph.
            js_endpoints = recon_data.setdefault("js_recon", {}).setdefault("endpoints", [])
            result = session.run(
                """
                MATCH (f:JsReconFinding {user_id: $uid, project_id: $pid, finding_type: 'js_file'})
                      -[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE NOT f:Muted AND e.path IS NOT NULL AND e.endpoint_type IS NOT NULL
                  AND NOT """ + quarantined("e") + """
                RETURN f.source_url AS source_js, e.baseurl AS base, e.path AS path,
                       coalesce(e.method, 'GET') AS method, e.endpoint_type AS kind,
                       coalesce(e.js_recon_category, e.category) AS category, e.path_template AS template
                """,
                uid=user_id, pid=project_id,
            )
            for record in result:
                base = record["base"]
                if (record["kind"] not in ("route", "rest") or not isinstance(base, str)
                        or not base.startswith(("http://", "https://")) or not keep(url_host(base))):
                    continue
                js_endpoints.append({
                    "type": record["kind"], "path": record["path"], "method": record["method"],
                    "category": record["category"] or "endpoint",
                    "resolved_url": base.rstrip("/") + record["path"],
                    "source_js": record["source_js"] or "",
                    "parameterized": record["template"] is not None,
                })

            if urlscan_files:
                recon_data["urlscan"] = {"findings": urlscan_files}

    return recon_data
