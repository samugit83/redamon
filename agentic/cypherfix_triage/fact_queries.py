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

from .score_model import (AGENT_CONFIDENCE_DEFAULT, PROOF_MIN_AGENT_CONFIDENCE,
                          ProjectFacts, agent_proof_counts)

# ===========================================================================
# Project fact sets
# ===========================================================================
#: The hosts a run skipped (a tripped breaker: the coverage record's `host:port`
#: keys, normalised as circuit_breaker.hostname_of does for the prune), bound
#: to `skipped`. Shared by the two queries that read them.
_SKIPPED_HOSTS = """OPTIONAL MATCH (d:Domain {user_id: $userId, project_id: $projectId})
WITH reduce(acc = [], hs IN collect(d.recon_skipped_hosts) | acc + coalesce(hs, [])) AS keys
WITH [k IN [x IN keys | toLower(trim(toString(x)))] |
      CASE WHEN k STARTS WITH '[' THEN substring(split(k, ']')[0], 1)
           WHEN size(split(k, ':')) = 2 THEN split(k, ':')[0]
           ELSE k END] AS skipped"""

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
        # `passive_only = false` is the port scan's or nmap's mark: it beats the
        # source of a Port a passive provider happened to create first.
        "query": """
MATCH (ip:IP {user_id: $userId, project_id: $projectId})-[:HAS_PORT]->(p:Port)
WHERE toLower(coalesce(p.state, 'open')) = 'open'
RETURN ip.address AS host,
       CASE WHEN p.passive_only = false THEN 'active'
            WHEN toLower(coalesce(p.source, 'nmap')) IN
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
        "name": "ip_ownership",
        "description": "each IP's attribution tag and how many current DNS names point at it",
        # Written by recon's IP attribution step. An IP written before it has
        # neither property and is left out: "not known", never "not the target's".
        "query": """
MATCH (ip:IP {user_id: $userId, project_id: $projectId})
WHERE ip.ownership IS NOT NULL OR ip.current_dns_names IS NOT NULL
RETURN ip.address AS ip, ip.ownership AS ownership,
       ip.current_dns_names AS dns_names, coalesce(ip.ip_mode, false) AS ip_mode
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
        "query": f"""
MATCH (cf:ChainFinding {{user_id: $userId, project_id: $projectId}})
WHERE cf.finding_type IN ['exploit_success', 'access_gained',
                          'privilege_escalation', 'credential_found',
                          'vulnerability_confirmed']
  AND coalesce(toInteger(cf.confidence), {AGENT_CONFIDENCE_DEFAULT}) >= {PROOF_MIN_AGENT_CONFIDENCE}
OPTIONAL MATCH (cf)-[:FINDING_RELATES_CVE]->(c:CVE)
OPTIONAL MATCH (cf)-[:CONFIRMS]->(f)
OPTIONAL MATCH (cf)-[:FOUND_ON]->(t)
RETURN cf.id AS chain_id, cf.finding_type AS finding_type,
       collect(DISTINCT c.id) AS cve_ids,
       collect(DISTINCT coalesce(f.id, f.finding_id)) AS finding_ids,
       collect(DISTINCT coalesce(t.name, t.address, t.url)) AS hosts,
       coalesce(cf.target_host, cf.target_url, '') AS target_host,
       cf.confidence AS confidence
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
        # FFuf files a login path under 'auth'; the other classifiers write
        # 'authentication'.
        "query": """
CALL () {
    MATCH (b:BaseURL {user_id: $userId, project_id: $projectId})-[:HAS_ENDPOINT]->(e:Endpoint)
    WHERE e.is_form = true
       OR toLower(coalesce(e.category, '')) IN ['authentication', 'auth']
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
WHERE (toLower(coalesce(e.category, '')) IN ['authentication', 'auth'] OR e.is_form = true)
  AND EXISTS {
    MATCH (e)-[:HAS_PARAMETER]->(p:Parameter) WHERE p.is_injectable = true
  }
RETURN collect(DISTINCT b.url) AS hosts
""",
    },
    {
        "name": "gone_hosts",
        "description": "no live endpoint, no open port, nothing resolves",
        # RESOLVES_TO runs Subdomain -> IP, so each label reads its own end of
        # it. Only forward DNS counts (no source): Shodan's reverse DNS and the
        # passive sources (Censys, FOFA, OTX, ZoomEye) write the same edge with
        # a source, and a PTR record or an old sighting does not say the host
        # resolves today. A host the run
        # skipped was not re-checked, so its absence proves nothing.
        "query": _SKIPPED_HOSTS + """
MATCH (n {user_id: $userId, project_id: $projectId})
WHERE (n:Subdomain OR n:IP)
  AND NOT EXISTS {
    MATCH (n)-[:HAS_BASE_URL|HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(e:Endpoint)
    WHERE e.is_live = true OR e.status_code IS NOT NULL
  }
  AND NOT EXISTS {
    MATCH (n)-[:HAS_PORT]->(p:Port) WHERE toLower(coalesce(p.state, 'open')) = 'open'
  }
  AND NOT (n:Subdomain AND EXISTS {
    MATCH (n)-[r:RESOLVES_TO]->(:IP) WHERE r.source IS NULL
  })
  AND NOT (n:IP AND EXISTS {
    MATCH (n)<-[r:RESOLVES_TO]-(:Subdomain) WHERE r.source IS NULL
  })
  AND coalesce(n.is_live, false) = false
  AND NOT toLower(coalesce(n.name, n.address, '')) IN skipped
RETURN collect(DISTINCT coalesce(n.name, n.address)) AS hosts
""",
    },
    {
        "name": "skipped_hosts",
        "description": "hosts the run could not re-check (a tripped breaker)",
        "query": _SKIPPED_HOSTS + """
RETURN skipped AS hosts
""",
    },
    {
        "name": "name_ownership",
        "description": "the attribution tags of the IPs each DNS name currently resolves to",
        # Forward DNS only, as in gone_hosts: a PTR answer or a passive sighting
        # does not say the name points there today. An IP no run attributed yet
        # comes back as '' and keeps the name's attribution unknown.
        "query": """
MATCH (s:Subdomain {user_id: $userId, project_id: $projectId})-[r:RESOLVES_TO]->(ip:IP)
WHERE ip.user_id = $userId AND ip.project_id = $projectId
  AND r.source IS NULL
RETURN s.name AS name, collect(DISTINCT coalesce(ip.ownership, '')) AS tags
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
        #
        # Two more filters, both about WHOSE judgement this is:
        # - `triage_verdict_by` must be this user. An imported project keeps
        #   its previous owner's decisions, and those must not teach the
        #   importer's detectors. A decision older than the field counts as
        #   the node's owner's.
        # - only decisions made in the app. An unattended agent's verdicts
        #   over MCP would otherwise retune this user's detectors across every
        #   project (product decision P1).
        "query": """
MATCH (n:Vulnerability|JsReconFinding|Secret|MultiscannerFinding|GithubSecret
       |GithubSensitiveFile|MalPackageFinding|ExploitGvm {user_id: $userId})
WHERE n.triage_source = 'human'
  AND n.triage_status IN ['confirmed', 'likely_noise']
  AND n.triage_detector IS NOT NULL
  AND coalesce(n.triage_verdict_by, n.user_id) = $userId
  AND coalesce(n.triage_verdict_channel, 'app') = 'app'
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
        "id_expr": "v.id",
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
       v.matcher_name AS matcher_name, v.fuzzing_parameter AS fuzzing_parameter,
       v.target_port AS target_port, v.solution_type AS solution_type,
       v.port_confirmed AS port_confirmed, v.control_check AS control_check,
       // A full run rebuilds the IP nodes, and a passive CVE on an IP that left
       // the run is kept until one re-checks it (D1): its port_confirmed is then
       // an earlier run's. Matched as the passive writers link it, by address.
       CASE WHEN coalesce(v.target_ip, '') = '' THEN null
            ELSE EXISTS { MATCH (:IP {address: v.target_ip, user_id: $userId, project_id: $projectId}) }
       END AS target_ip_in_graph,
       v.extracted_results AS extracted_results, v.is_dast_finding AS is_dast_finding,
       v.template_id AS template_id, v.tags AS tags, v.state AS state,
       coalesce(v.oid, v.nvt_oid) AS oid,
       v.verdict AS verdict, v.confidence_tier AS confidence_tier,
       v.takeover_method AS takeover_method, v.cache_impact AS cache_impact,
       // What grouping.group_key splits these sources' fix items on: the cache
       // vector, the takeover provider, the GraphQL check and the AI class.
       v.cache_technique AS cache_technique, v.cache_header AS cache_header,
       v.cache_param AS cache_param, v.takeover_provider AS takeover_provider,
       v.vulnerability_type AS vulnerability_type,
       v.ai_owasp_llm_id AS ai_owasp_llm_id, v.ai_payload_class AS ai_payload_class,
       v.confidence_score AS confidence_score, v.confidence AS confidence,
       v.ai_asr AS ai_asr, v.ai_oracle_kind AS ai_oracle_kind,
       v.introspection_enabled AS introspection_enabled,
       v.raw_request AS raw_request, v.raw_response AS raw_response, v.evidence AS evidence,
       v.package_version AS package_version, v.package_name AS package_name,
       v.purl AS package_purl, v.fixed_version AS fixed_version,
       v.triage_status AS triage_status, v.triage_source AS triage_source,
       v.triage_evidence_hash AS triage_evidence_hash,
       v.validation_status AS validation_status, v.validated_at AS validated_at,
       v.detection_method AS detection_method,
       // A live takeover error page that only leaves the name dangling is not exploitable.
       v.outcome AS outcome,
       // An origin that served the site's own build file byte for byte.
       v.file_match AS file_match,
       // route_exposure's secret_in_response is classed by its detector name.
       v.secret_types AS secret_types,
       // urlscan history: the kind keys its detector (urlscan_leak:{type}:{kind}).
       coalesce(v.link_kind, v.file_kind, v.problem, v.provider, v.family) AS finding_kind,
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
        "id_expr": "ex.id",
        "label": "ExploitGvm",
        "query": """
MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})
WHERE NOT ex:Muted
RETURN ex.id AS id, 'ExploitGvm' AS label, 'gvm' AS source,
       ex.name AS name, coalesce(ex.severity, 'critical') AS severity,
       ex.cvss_vector AS cvss_vector, ex.cvss_score AS cvss_score,
       coalesce(ex.cve_ids, []) AS cve_ids, ex.cisa_kev AS cisa_kev,
       ex.description AS description, ex.qod AS qod, ex.qod_type AS qod_type,
       ex.target_port AS target_port,
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
        "id_expr": "s.id",
        "label": "Secret",
        # js_recon's key_type is the pattern's CATEGORY (cloud, auth...) and
        # secret_type its name. Keyed on the category with no value, every secret
        # of one category on one host fell into one group; the value lets
        # grouping hash it, and the evidence redacts it.
        "query": """
MATCH (s:Secret {user_id: $userId, project_id: $projectId})
WHERE NOT s:Muted
RETURN s.id AS id, 'Secret' AS label, coalesce(s.source, 'js_recon') AS source,
       coalesce(s.secret_type, s.key_type, 'secret') AS name,
       coalesce(s.severity, 'medium') AS severity,
       s.secret_type AS secret_type,
       coalesce(s.secret_type, s.key_type) AS detector_name,
       s.matched_text AS matched_text, s.context AS context,
       s.validation_status AS validation_status, s.validated_at AS validated_at,
       s.validation_info AS validation_info, s.public_client_key AS public_client_key,
       s.detection_method AS detection_method, s.alternate_names AS alternate_names,
       s.stale_since AS stale_since, s.confidence AS confidence,
       s.triage_status AS triage_status, s.triage_source AS triage_source,
       s.triage_evidence_hash AS triage_evidence_hash,
       toString(s.updated_at) AS seen_updated_at,
       // A urlscan Secret hangs off its Subdomain (the org's own name: its
       // Domain), carrying base_url; the parent name covers an older node.
       coalesce(s.base_url,
                head([(bu:BaseURL)-[:HAS_SECRET]->(s) | bu.url]),
                head([(sd)-[:HAS_SECRET]->(s) WHERE sd:Subdomain OR sd:Domain | sd.name]),
                '') AS triage_host
""",
    },
    {
        "name": "js_recon",
        "id_expr": "j.id",
        "label": "JsReconFinding",
        "query": """
MATCH (j:JsReconFinding {user_id: $userId, project_id: $projectId})
WHERE NOT j:Muted AND coalesce(j.finding_type, '') <> 'js_file'
RETURN j.id AS id, 'JsReconFinding' AS label, 'js_recon' AS source,
       coalesce(j.title, j.finding_type) AS name,
       coalesce(j.severity, 'low') AS severity,
       j.finding_type AS finding_type, j.confidence AS confidence,
       j.detail AS description, j.evidence AS evidence, j.control_check AS control_check,
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
        "id_expr": "tf.id",
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
        "id_expr": "g.id",
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
        "id_expr": "gf.id",
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
        "id_expr": "coalesce(f.finding_id, f.id)",
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


def finding_query_by_id(query_def: dict) -> str:
    """One FINDING_QUERIES entry, narrowed to one finding (`$findingId`).

    The same row a run scores, so the evidence an external reviewer is shown
    and hashed is exactly what the built-in reviewer would read. A finding the
    query filters out (muted, a JsRecon `js_file`, a MalPackageFinding with no
    flagged Package) returns nothing: it is not in triage scope.
    """
    query = query_def["query"]
    head, sep, tail = query.partition("\nWHERE ")
    if not sep:                                            # pragma: no cover
        raise ValueError(f"{query_def['name']} has no WHERE to narrow")
    return f"{head}\nWHERE {query_def['id_expr']} = $findingId AND {tail}"


#: The review and decision layers of every non-muted finding of the tenant,
#: joined to the scored rows by (label, id) in Python. Read once per run, after
#: scoring: a review or a verdict written while the run works is re-read again,
#: under the node lock, when the run publishes.
STORED_LAYERS = {
    "name": "stored_layers",
    "query": """
MATCH (n:Vulnerability|JsReconFinding|Secret|MultiscannerFinding|GithubSecret
       |GithubSensitiveFile|MalPackageFinding|ExploitGvm {user_id: $userId, project_id: $projectId})
WHERE NOT n:Muted
RETURN CASE WHEN n:MalPackageFinding THEN coalesce(n.finding_id, n.id) ELSE n.id END AS id,
       [l IN labels(n) WHERE l <> 'Muted'][0] AS label,
       n.triage_status AS triage_status, n.triage_source AS triage_source,
       n.triage_verdict_channel AS triage_verdict_channel,
       n.triage_evidence_hash AS triage_evidence_hash,
       n.triage_ai_verdict AS triage_ai_verdict,
       n.triage_ai_corrections AS triage_ai_corrections,
       n.triage_ai_quote AS triage_ai_quote,
       n.triage_ai_model AS triage_ai_model,
       n.triage_ai_why AS triage_ai_why,
       n.triage_ai_channel AS triage_ai_channel,
       n.triage_ai_by AS triage_ai_by,
       n.triage_ai_evidence_hash AS triage_ai_evidence_hash,
       n.triage_ai_prompt_version AS triage_ai_prompt_version,
       n.triage_fix_lever AS triage_fix_lever,
       n.triage_reason AS triage_reason
""",
}


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
    for row in raw.get("skipped_hosts") or []:
        facts.skipped_hosts |= {h.lower() for h in _clean(row.get("hosts"))}
    for row in raw.get("name_ownership") or []:
        name = str(row.get("name") or "").strip().lower()
        if name:
            facts.name_ownership.setdefault(name, set()).update(
                str(t or "").strip() for t in row.get("tags") or [None])

    for row in raw.get("port_hosts") or []:
        host = str(row.get("host") or "").strip()
        if not host:
            continue
        # "active" wins: one active confirmation beats any number of passive
        # sightings, and the order rows arrive in must not decide this.
        how = row.get("how") or "active"
        if how == "active" or facts.port_hosts.get(host) != "active":
            facts.port_hosts[host] = how
        for port in row.get("ports") or []:
            key = (host, _int(port))
            if key[1] and (how == "active" or facts.port_status.get(key) != "active"):
                facts.port_status[key] = how
        if set(row.get("ports") or []) & {3306, 5432, 6379, 9200, 27017,
                                          1433, 5984, 11211}:
            facts.sensitive_hosts.add(host)

    for row in raw.get("ip_ownership") or []:
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        tag = str(row.get("ownership") or "").strip()
        if tag:
            facts.ip_ownership[ip] = tag
        if tag == "shared_edge":
            facts.shared_edge_hosts.add(ip)
        # An operator-listed IP-mode target has no DNS name by design.
        if row.get("dns_names") is not None and not row.get("ip_mode") and _int(row.get("dns_names")) == 0:
            facts.no_dns_name_hosts.add(ip)

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
        if not agent_proof_counts(row.get("confidence")):
            continue
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
