"""The graph reads behind the score model: project fact sets, then findings.

WHY THESE REPLACED SCORING_QUERIES
The old scoring queries chained `OPTIONAL MATCH` clauses, which multiplies rows:
a GVM finding hanging off three Technologies plus a Port plus a Subdomain came
back five times, each scoring differently, and whichever row Neo4j returned last
won. One OSV advisory node hangs off up to eleven Packages in the dev graph.

So the shape changed:

1. **Project fact sets**, read once per run. Which hosts are live, which ports an
   active scan found, which packages are actually served, which hosts the agent
   compromised. These are small and shared by every finding.
2. **One row per finding**, using `COUNT {}` / `EXISTS {}` subqueries instead of
   OPTIONAL MATCH, so a finding with five parents is still one row.
3. The join happens in Python, in `score_model.score(finding, facts, intel)`.

HOST IDENTITY
A host appears in the graph under several spellings: a Subdomain name, an IP
address, a BaseURL url, a Domain name. Rather than canonicalising (which needs a
resolution the graph does not always have), each fact set holds EVERY spelling of
the host it is about. A finding then matches whichever spelling its own host
resolution produced. This trades a slightly larger set for never silently losing
a fact because two writers spelled the same host differently.

MUTE IS ENFORCED HERE
These run through `run_static_query`, which deliberately does not go through
`scope_query`, so the `&!Muted` exclusion every agent query gets for free is
absent and has to be hand-written. Every finding query carries `WHERE NOT n:Muted`
for the same reason as the queries in `prompts/cypher_queries.py`.

These queries READ ONLY. Nothing here writes; publishing is Step E.
"""

from __future__ import annotations

from .score_model import ProjectFacts

# ===========================================================================
# Project fact sets
# ===========================================================================
# Each query returns rows of simple scalars. `name` selects the reducer in
# `build_project_facts`. A query that fails leaves its fact set EMPTY, which the
# model reads as "we do not know" rather than as "it is not true".
PROJECT_FACT_QUERIES = [
    {
        "name": "live_hosts",
        "description": "hosts with at least one endpoint that answered",
        "query": """
MATCH (b:BaseURL {user_id: $userId, project_id: $projectId})-[:HAS_ENDPOINT]->(e:Endpoint)
WHERE e.is_live = true OR (e.status_code IS NOT NULL AND e.status_code < 500)
OPTIONAL MATCH (s:Subdomain {user_id: $userId, project_id: $projectId})
               -[:HAS_BASE_URL|HAS_BASEURL]->(b)
RETURN collect(DISTINCT b.url) + collect(DISTINCT s.name) AS hosts
""",
    },
    {
        "name": "auth_required_hosts",
        "description": "hosts whose endpoints only answered 401/403",
        "query": """
MATCH (b:BaseURL {user_id: $userId, project_id: $projectId})-[:HAS_ENDPOINT]->(e:Endpoint)
WITH b, collect(e.status_code) AS codes
WHERE ALL(c IN codes WHERE c IS NULL OR c IN [401, 403])
  AND ANY(c IN codes WHERE c IN [401, 403])
RETURN collect(DISTINCT b.url) AS hosts
""",
    },
    {
        "name": "port_hosts",
        "description": "open ports, and whether an active scanner found them",
        "query": """
MATCH (ip:IP {user_id: $userId, project_id: $projectId})-[:HAS_PORT]->(p:Port)
WHERE toLower(coalesce(p.state, 'open')) = 'open'
RETURN ip.address AS host,
       CASE WHEN toLower(coalesce(p.source, 'nmap')) IN
            ['shodan', 'censys', 'fofa', 'netlas', 'zoomeye', 'internetdb',
             'criminalip', 'uncover']
            THEN 'passive' ELSE 'active' END AS how,
       collect(DISTINCT p.number) AS ports
""",
    },
    {
        "name": "origin_exposed_hosts",
        "description": "behind a CDN, but the origin is reachable",
        "query": """
MATCH (s:Subdomain {user_id: $userId, project_id: $projectId})
WHERE EXISTS { (s)-[:HAS_ORIGIN]->(:IP {origin_confirmed: true}) }
   OR EXISTS { (s)-[:WAF_BYPASS_VIA]->() }
RETURN collect(DISTINCT s.name) AS hosts
""",
    },
    {
        "name": "cdn_only_hosts",
        "description": "behind a CDN with no origin found",
        "query": """
MATCH (s:Subdomain {user_id: $userId, project_id: $projectId})
WHERE s.is_cdn = true
  AND NOT EXISTS { (s)-[:HAS_ORIGIN]->(:IP {origin_confirmed: true}) }
RETURN collect(DISTINCT s.name) AS hosts
""",
    },
    {
        "name": "threat_intel_hosts",
        "description": "hosts named in threat intelligence",
        "query": """
MATCH (n {user_id: $userId, project_id: $projectId})
WHERE (n:IP OR n:Subdomain OR n:Domain OR n:BaseURL)
  AND (EXISTS { (n)-[:APPEARS_IN_PULSE]->() }
       OR EXISTS { (n)-[:CONTACTS_MALICIOUS_HOST]->() }
       OR coalesce(n.vt_malicious_count, 0) >= 3
       OR toLower(coalesce(n.criminalip_score_inbound, '')) = 'dangerous'
       OR n.criminalip_is_darkweb = true)
RETURN collect(DISTINCT coalesce(n.name, n.address, n.url)) AS hosts
""",
    },
    {
        "name": "proof",
        "description": "what the agent actually demonstrated (K1)",
        "query": """
MATCH (cf:ChainFinding {user_id: $userId, project_id: $projectId})
WHERE cf.finding_type IN ['exploit_success', 'access_gained',
                          'privilege_escalation', 'credential_found',
                          'vulnerability_confirmed']
OPTIONAL MATCH (cf)-[:FINDING_RELATES_CVE]->(c:CVE)
OPTIONAL MATCH (cf)-[:CONFIRMS]->(f)
OPTIONAL MATCH (cf)-[:FOUND_ON]->(t)
RETURN cf.id AS chain_id, cf.finding_type AS finding_type,
       collect(DISTINCT c.id) AS cve_ids,
       collect(DISTINCT coalesce(f.id, f.finding_id)) AS finding_ids,
       collect(DISTINCT coalesce(t.name, t.address, t.url)) AS hosts,
       coalesce(cf.target_host, cf.target_url, '') AS target_host
""",
    },
    {
        "name": "confirmed_exploits",
        "description": "GVM exploits that ran (ExploitGvm)",
        "query": """
MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})-[:EXPLOITED_CVE]->(c:CVE)
RETURN collect(DISTINCT c.id) AS cve_ids
""",
    },
    {
        "name": "package_exposure",
        "description": "is the package served, or only in a repo or an SBOM",
        "query": """
MATCH (p:Package {user_id: $userId, project_id: $projectId})
OPTIONAL MATCH (anchor)-[:DEPENDS_ON]->(p)
WITH p, collect(DISTINCT labels(anchor)[0]) AS anchors
RETURN coalesce(p.purl, p.name) AS package,
       CASE WHEN 'BaseURL' IN anchors THEN 'served'
            WHEN 'GithubRepository' IN anchors THEN 'repo'
            WHEN 'SbomDocument' IN anchors THEN 'sbom'
            ELSE '' END AS exposure
""",
    },
    {
        "name": "sensitive_hosts",
        "description": "logins, admin vhosts, database ports, MCP and GraphQL",
        "query": """
CALL () {
    MATCH (b:BaseURL {user_id: $userId, project_id: $projectId})-[:HAS_ENDPOINT]->(e:Endpoint)
    WHERE e.is_form = true
       OR toLower(coalesce(e.category, '')) = 'authentication'
       OR (e.ai_mcp_auth_required = false AND coalesce(e.ai_mcp_tool_count, 0) > 0)
    RETURN b.url AS host, true AS login
  UNION
    MATCH (ip:IP {user_id: $userId, project_id: $projectId})-[:HAS_PORT]->(p:Port)
    WHERE p.number IN [3306, 5432, 6379, 9200, 27017, 1433, 5984, 11211]
      AND toLower(coalesce(p.state, 'open')) = 'open'
    RETURN ip.address AS host, false AS login
  UNION
    MATCH (s:Subdomain {user_id: $userId, project_id: $projectId})
    WHERE s.internal_pattern_match = true
    RETURN s.name AS host, false AS login
}
RETURN host, login
""",
    },
    {
        "name": "credential_hosts",
        "description": "hosts carrying a usable credential finding",
        "query": """
MATCH (n:Secret|MultiscannerFinding {user_id: $userId, project_id: $projectId})
WHERE NOT n:Muted
OPTIONAL MATCH (bu:BaseURL)-[:HAS_SECRET|HAS_FINDING]->(n)
RETURN collect(DISTINCT coalesce(n.base_url, bu.url, n.location)) AS hosts
""",
    },
    {
        "name": "injectable_auth_hosts",
        "description": "an injectable parameter on an authentication endpoint",
        "query": """
MATCH (b:BaseURL {user_id: $userId, project_id: $projectId})-[:HAS_ENDPOINT]->(e:Endpoint)
WHERE toLower(coalesce(e.category, '')) = 'authentication' OR e.is_form = true
  AND EXISTS {
    MATCH (e)-[:HAS_PARAMETER]->(p:Parameter) WHERE p.is_injectable = true
  }
RETURN collect(DISTINCT b.url) AS hosts
""",
    },
    {
        "name": "gone_hosts",
        "description": "no live endpoint, no open port, nothing resolves",
        "query": """
MATCH (n {user_id: $userId, project_id: $projectId})
WHERE (n:Subdomain OR n:IP)
  AND NOT EXISTS {
    MATCH (n)-[:HAS_BASE_URL|HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(e:Endpoint)
    WHERE e.is_live = true OR e.status_code IS NOT NULL
  }
  AND NOT EXISTS {
    MATCH (n)-[:HAS_PORT]->(p:Port) WHERE toLower(coalesce(p.state, 'open')) = 'open'
  }
  AND NOT EXISTS { MATCH (n)-[:RESOLVES_TO]->() }
  AND coalesce(n.is_live, false) = false
RETURN collect(DISTINCT coalesce(n.name, n.address)) AS hosts
""",
    },
    {
        "name": "detector_labels",
        "description": "this user's own Real / False positive verdicts, per detector",
        # Phase 8a. Scoped to $userId and NOT to $projectId on purpose: a
        # detector that is noise on one of your projects is noise on the next
        # one, and the whole point is that the board arrives already knowing
        # that. It is never scoped wider than the one user: pooling clicks
        # across accounts would let one operator re-rank another's board.
        #
        # `triage_detector` is written by the publish step, so a finding only
        # gets a vote after a run has ranked it. That is exactly right: the
        # click happened on the board, which means a run produced it.
        "query": """
MATCH (n:Vulnerability|JsReconFinding|Secret|MultiscannerFinding|GithubSecret
       |GithubSensitiveFile|MalPackageFinding|ExploitGvm {user_id: $userId})
WHERE n.triage_source = 'human'
  AND n.triage_status IN ['confirmed', 'likely_noise']
  AND n.triage_detector IS NOT NULL
RETURN n.triage_detector AS detector,
       count(CASE WHEN n.triage_status = 'confirmed' THEN 1 END) AS real,
       count(CASE WHEN n.triage_status = 'likely_noise' THEN 1 END) AS fp
""",
    },
]


# ===========================================================================
# Finding queries: exactly one row per finding
# ===========================================================================
# Host resolution follows the table in section 3.2.6 of the plan, and the
# resolved value is returned as `triage_host` so the board can show what the
# model actually used instead of re-deriving it.
#
# Both base-URL spellings are read (`HAS_BASE_URL|HAS_BASEURL`) until the K8
# migration has run everywhere. `EXISTS {}` is used rather than a count because
# several relationships are written again on every run (K12), so a count would
# say "three" about one fact.
FINDING_QUERIES = [
    {
        "name": "vulnerabilities",
        "label": "Vulnerability",
        "query": """
MATCH (v:Vulnerability {user_id: $userId, project_id: $projectId})
WHERE NOT v:Muted
RETURN v.id AS id, 'Vulnerability' AS label,
       v.source AS source, v.name AS name, v.severity AS severity,
       v.description AS description, v.category AS category, v.type AS type,
       v.cvss_score AS cvss_score,
       coalesce(v.cvss_vector, v.cvss_metrics) AS cvss_vector,
       // C2 / K3: the writers store CVE ids under four different names, and
       // the old scorer read only `cve_ids`. Concatenate them all; the Python
       // side filters to CVE- and de-duplicates. coalesce cannot do this: its
       // first non-null arm wins, so an empty `cve_ids` hid `cves`.
       coalesce(v.cve_ids, []) + coalesce(v.cves, []) + coalesce(v.aliases, []) +
       CASE WHEN v.cve_id IS NULL THEN [] ELSE [v.cve_id] END AS cve_ids,
       v.cisa_kev AS cisa_kev, v.has_exploit AS has_exploit,
       v.qod AS qod, v.qod_type AS qod_type, v.remediated AS remediated,
       v.stale_since AS stale_since, v.last_seen_at AS last_seen_at,
       v.matcher_status AS matcher_status, v.matched_at AS matched_at,
       v.extracted_results AS extracted_results, v.is_dast_finding AS is_dast_finding,
       v.template_id AS template_id, v.tags AS tags, v.state AS state,
       coalesce(v.oid, v.nvt_oid) AS oid,
       v.verdict AS verdict, v.confidence_tier AS confidence_tier,
       v.takeover_method AS takeover_method, v.cache_impact AS cache_impact,
       v.confidence_score AS confidence_score, v.confidence AS confidence,
       v.ai_asr AS ai_asr, v.ai_oracle_kind AS ai_oracle_kind,
       v.introspection_enabled AS introspection_enabled,
       v.raw_response AS raw_response, v.evidence AS evidence,
       v.package_version AS package_version, v.package_name AS package_name,
       v.purl AS package_purl, v.fixed_version AS fixed_version,
       v.triage_status AS triage_status, v.triage_source AS triage_source,
       v.triage_evidence_hash AS triage_evidence_hash,
       v.validation_status AS validation_status, v.validated_at AS validated_at,
       toString(v.updated_at) AS seen_updated_at,
       // Host resolution, in the order of section 3.2.6.
       // A pattern comprehension takes ONE pattern, so each candidate is its
       // own chained pattern and the first non-null wins, in the order of the
       // host-resolution table in section 3.2.6.
       head([
         host IN [
           head([(v)-[:FOUND_AT]->(:Endpoint)<-[:HAS_ENDPOINT]-(b:BaseURL) | b.url]),
           head([(b2:BaseURL)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_VULNERABILITY]->(v)
                 | b2.url]),
           head([(parent)-[:HAS_VULNERABILITY]->(v)
                 | coalesce(parent.name, parent.address, parent.url)]),
           head([(v)-[:AFFECTS]->(:Port)<-[:HAS_PORT]-(ip:IP) | ip.address]),
           head([(anchor)-[:DEPENDS_ON]->(:Package)-[:HAS_VULNERABILITY]->(v)
                 | coalesce(anchor.url, anchor.name)]),
           v.target_hostname, v.target_ip, v.matched_at
         ] WHERE host IS NOT NULL AND host <> ''
       ]) AS triage_host,
       EXISTS {
         MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})
               -[:EXPLOITED_CVE]->(c:CVE)
         WHERE c.id IN coalesce(v.cve_ids, [])
       } AS confirmed_exploits,
       // The package a dependency advisory sits on, for R and the group key.
       head([(pkg:Package)-[:HAS_VULNERABILITY]->(v) | coalesce(pkg.purl, pkg.name)])
         AS vuln_package,
       head([(pkg2:Package)-[:HAS_VULNERABILITY]->(v) | pkg2.version])
         AS vuln_package_version,
       head([(pkg3:Package)-[:HAS_VULNERABILITY]->(v) | pkg3.ecosystem])
         AS ecosystem
""",
    },
    {
        "name": "exploits",
        "label": "ExploitGvm",
        "query": """
MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})
WHERE NOT ex:Muted
RETURN ex.id AS id, 'ExploitGvm' AS label, 'gvm' AS source,
       ex.name AS name, coalesce(ex.severity, 'critical') AS severity,
       ex.cvss_vector AS cvss_vector, ex.cvss_score AS cvss_score,
       coalesce(ex.cve_ids, []) AS cve_ids, ex.cisa_kev AS cisa_kev,
       ex.description AS description, ex.qod AS qod, ex.qod_type AS qod_type,
       ex.stale_since AS stale_since,
       ex.triage_status AS triage_status, ex.triage_source AS triage_source,
       ex.triage_evidence_hash AS triage_evidence_hash,
       toString(ex.updated_at) AS seen_updated_at,
       coalesce(ex.target_ip, ex.target_hostname, '') AS triage_host,
       true AS confirmed_exploits
""",
    },
    {
        "name": "secrets",
        "label": "Secret",
        "query": """
MATCH (s:Secret {user_id: $userId, project_id: $projectId})
WHERE NOT s:Muted
RETURN s.id AS id, 'Secret' AS label, coalesce(s.source, 'js_recon') AS source,
       coalesce(s.key_type, s.secret_type, 'secret') AS name,
       coalesce(s.severity, 'medium') AS severity,
       s.secret_type AS secret_type, s.key_type AS detector_name,
       s.validation_status AS validation_status, s.validated_at AS validated_at,
       s.stale_since AS stale_since, s.confidence AS confidence,
       s.triage_status AS triage_status, s.triage_source AS triage_source,
       s.triage_evidence_hash AS triage_evidence_hash,
       toString(s.updated_at) AS seen_updated_at,
       coalesce(s.base_url,
                head([(bu:BaseURL)-[:HAS_SECRET]->(s) | bu.url]), '') AS triage_host
""",
    },
    {
        "name": "js_recon",
        "label": "JsReconFinding",
        "query": """
MATCH (j:JsReconFinding {user_id: $userId, project_id: $projectId})
WHERE NOT j:Muted AND coalesce(j.finding_type, '') <> 'js_file'
RETURN j.id AS id, 'JsReconFinding' AS label, 'js_recon' AS source,
       coalesce(j.title, j.finding_type) AS name,
       coalesce(j.severity, 'low') AS severity,
       j.finding_type AS finding_type, j.confidence AS confidence,
       j.detail AS description, j.evidence AS evidence,
       j.package_name AS package_name, j.stale_since AS stale_since,
       j.triage_status AS triage_status, j.triage_source AS triage_source,
       j.triage_evidence_hash AS triage_evidence_hash,
       toString(j.updated_at) AS seen_updated_at,
       coalesce(j.base_url, j.source_url,
                head([(b:BaseURL)-[:HAS_JS_FILE]->(f)-[:HAS_JS_FINDING]->(j) | b.url]),
                '') AS triage_host
""",
    },
    {
        "name": "multiscanner",
        "label": "MultiscannerFinding",
        "query": """
MATCH (tf:MultiscannerFinding {user_id: $userId, project_id: $projectId})
WHERE NOT tf:Muted
RETURN tf.id AS id, 'MultiscannerFinding' AS label,
       coalesce(tf.source, tf.source_type, 'trufflehog') AS source,
       tf.detector_name AS name, coalesce(tf.severity, 'high') AS severity,
       tf.detector_name AS detector_name, tf.detector_name AS secret_type,
       tf.validation_status AS validation_status, tf.validated_at AS validated_at,
       tf.stale_since AS stale_since,
       tf.triage_status AS triage_status, tf.triage_source AS triage_source,
       tf.triage_evidence_hash AS triage_evidence_hash,
       toString(tf.updated_at) AS seen_updated_at,
       coalesce(tf.location, tf.repository, '') AS triage_host
""",
    },
    {
        "name": "github_secrets",
        "label": "GithubSecret",
        "query": """
MATCH (g:GithubSecret {user_id: $userId, project_id: $projectId})
WHERE NOT g:Muted
RETURN g.id AS id, 'GithubSecret' AS label, 'github_hunt' AS source,
       g.secret_type AS name, coalesce(g.severity, 'high') AS severity,
       g.secret_type AS secret_type, g.secret_type AS detector_name,
       g.validation_status AS validation_status, g.stale_since AS stale_since,
       g.repository_public AS repository_public,
       g.triage_status AS triage_status, g.triage_source AS triage_source,
       g.triage_evidence_hash AS triage_evidence_hash,
       toString(g.updated_at) AS seen_updated_at,
       coalesce(g.repository, '') AS triage_host
""",
    },
    {
        "name": "github_files",
        "label": "GithubSensitiveFile",
        "query": """
MATCH (gf:GithubSensitiveFile {user_id: $userId, project_id: $projectId})
WHERE NOT gf:Muted
RETURN gf.id AS id, 'GithubSensitiveFile' AS label, 'github_hunt' AS source,
       coalesce(gf.path, gf.secret_type) AS name,
       coalesce(gf.severity, 'medium') AS severity,
       gf.secret_type AS secret_type, gf.secret_type AS detector_name,
       gf.path AS path, gf.stale_since AS stale_since,
       gf.repository_public AS repository_public,
       gf.triage_status AS triage_status, gf.triage_source AS triage_source,
       gf.triage_evidence_hash AS triage_evidence_hash,
       toString(gf.updated_at) AS seen_updated_at,
       coalesce(gf.repository, '') AS triage_host
""",
    },
    {
        "name": "mal_packages",
        "label": "MalPackageFinding",
        "query": """
MATCH (pkg:Package {user_id: $userId, project_id: $projectId})
      -[:FLAGGED_AS]->(f:MalPackageFinding {user_id: $userId, project_id: $projectId})
WHERE NOT f:Muted
RETURN coalesce(f.finding_id, f.id) AS id, 'MalPackageFinding' AS label,
       coalesce(f.source_tool, 'osv') AS source,
       coalesce(f.title, f.advisory_id) AS name,
       coalesce(f.severity, 'high') AS severity,
       f.verdict AS verdict, f.advisory_id AS advisory_id,
       f.detail AS description, f.soft_error AS soft_error,
       f.stale_since AS stale_since,
       coalesce(pkg.purl, pkg.name) AS package_purl,
       pkg.name AS package_name, pkg.version AS package_version,
       pkg.ecosystem AS ecosystem,
       f.triage_status AS triage_status, f.triage_source AS triage_source,
       f.triage_evidence_hash AS triage_evidence_hash,
       toString(f.updated_at) AS seen_updated_at,
       head([(anchor)-[:DEPENDS_ON]->(pkg) | coalesce(anchor.url, anchor.name)])
         AS triage_host
""",
    },
]


# ===========================================================================
# Reducers: raw rows -> ProjectFacts
# ===========================================================================
def _clean(values) -> set:
    """Non-empty strings from a collect(), with the Nones Cypher leaves in.

    Strip BEFORE filtering: a whitespace-only host would otherwise survive as
    an empty string and then match a finding whose host did not resolve.
    """
    cleaned = {str(v).strip() for v in (values or []) if v is not None}
    return {v for v in cleaned if v and v not in ("[]", "None")}


def _int(value) -> int:
    """A count from a Cypher row. A missing or odd value is 0, never a crash."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def build_project_facts(raw: dict) -> ProjectFacts:
    """Turn the PROJECT_FACT_QUERIES rows into the model's fact sets.

    Every branch tolerates a missing or empty result: a fact set that failed to
    load stays empty, and the model reads that as "unknown", never as "false".
    """
    facts = ProjectFacts()

    for row in raw.get("live_hosts") or []:
        facts.live_hosts |= _clean(row.get("hosts"))
    for row in raw.get("auth_required_hosts") or []:
        facts.auth_required_hosts |= _clean(row.get("hosts"))
    for row in raw.get("origin_exposed_hosts") or []:
        facts.origin_exposed_hosts |= _clean(row.get("hosts"))
    for row in raw.get("cdn_only_hosts") or []:
        facts.cdn_only_hosts |= _clean(row.get("hosts"))
    for row in raw.get("threat_intel_hosts") or []:
        facts.threat_intel_hosts |= _clean(row.get("hosts"))
    for row in raw.get("credential_hosts") or []:
        facts.credential_hosts |= _clean(row.get("hosts"))
    for row in raw.get("injectable_auth_hosts") or []:
        facts.injectable_auth_hosts |= _clean(row.get("hosts"))
    for row in raw.get("gone_hosts") or []:
        facts.gone_hosts |= _clean(row.get("hosts"))

    for row in raw.get("port_hosts") or []:
        host = str(row.get("host") or "").strip()
        if not host:
            continue
        # "active" wins: one active confirmation beats any number of passive
        # sightings, and the order rows arrive in must not decide this.
        if row.get("how") == "active" or facts.port_hosts.get(host) != "active":
            facts.port_hosts[host] = row.get("how") or "active"
        if set(row.get("ports") or []) & {3306, 5432, 6379, 9200, 27017,
                                          1433, 5984, 11211}:
            facts.sensitive_hosts.add(host)

    for row in raw.get("package_exposure") or []:
        package = str(row.get("package") or "").strip()
        if package and row.get("exposure"):
            facts.package_exposure[package] = row["exposure"]

    for row in raw.get("sensitive_hosts") or []:
        host = str(row.get("host") or "").strip()
        if not host:
            continue
        facts.sensitive_hosts.add(host)
        if row.get("login"):
            facts.login_hosts.add(host)

    for row in raw.get("confirmed_exploits") or []:
        facts.proven_cve_ids |= {c.upper() for c in _clean(row.get("cve_ids"))}

    for row in raw.get("proof") or []:
        facts.proven_cve_ids |= {c.upper() for c in _clean(row.get("cve_ids"))}
        facts.proven_finding_ids |= _clean(row.get("finding_ids"))
        hosts = _clean(row.get("hosts"))
        target = str(row.get("target_host") or "").strip()
        if target:
            hosts.add(target)
        facts.compromised_hosts |= hosts
        # X9: the proof itself, so it survives an activation that drops the
        # bridge edges but keeps the chain nodes.
        for host in hosts:
            facts.proof_by_host.setdefault(host, []).append({
                "chain_id": row.get("chain_id"),
                "finding_type": row.get("finding_type"),
            })

    for row in raw.get("detector_labels") or []:
        detector = str(row.get("detector") or "").strip()
        if not detector:
            continue
        real = _int(row.get("real"))
        false_positive = _int(row.get("fp"))
        if real + false_positive:
            facts.detector_labels[detector] = {"real": real, "fp": false_positive}

    # A gone host cannot also be live: the liveness evidence is the stronger
    # statement, and the two queries can disagree across a rescan boundary.
    facts.gone_hosts -= facts.live_hosts
    facts.gone_hosts -= set(facts.port_hosts)

    return facts


def normalise_finding_row(row: dict) -> dict:
    """Tidy one finding row into what `score_model.score` expects.

    Neo4j returns `collect()` results with Nones in them and `coalesce` can
    still produce empty strings. Doing this once here keeps the model free of
    graph-shaped defensiveness.
    """
    row = dict(row or {})
    row["cve_ids"] = sorted({
        str(c).strip().upper() for c in (row.get("cve_ids") or [])
        if c and str(c).strip().upper().startswith("CVE-")
    })
    row["tags"] = [str(t).strip() for t in (row.get("tags") or []) if t]
    row["extracted_results"] = [
        str(x) for x in (row.get("extracted_results") or []) if x
    ]
    for key in ("triage_host", "source", "name", "severity"):
        if row.get(key) is None:
            row[key] = ""
    row["host"] = row.get("triage_host") or ""
    # The package a Vulnerability hangs off is resolved in Cypher; prefer it
    # over a property copy, which several writers leave unset.
    if row.get("vuln_package") and not row.get("package_purl"):
        row["package_purl"] = row["vuln_package"]
    if row.get("vuln_package_version") and not row.get("package_version"):
        row["package_version"] = row["vuln_package_version"]
    return row
