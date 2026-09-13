"""Hardcoded Cypher queries for the static collection phase of triage.

These are an ENFORCEMENT SITE for mute, not just a data source. They run through
`run_static_query`, which never touches `graph_db.tenant_filter.scope_query`, so
the `&!Muted` exclusion every agent query gets for free is absent here and has to
be written by hand. Without it a triage run re-collects and re-classifies
findings an operator already suppressed, and they reappear in the Findings table.

CVE, MitreData and Capec are shared reference nodes with no tenant keys, so
any per-project label reached THROUGH one (ExploitGvm, Technology) must carry
`{user_id: $userId, project_id: $projectId}` in its own pattern. Without it the
traversal walks out of this project and returns another tenant's rows.

Every query binding a MUTEABLE label (Vulnerability, ExploitGvm, GithubSecret,
GithubSensitiveFile, Secret, JsReconFinding, MultiscannerFinding,
MalPackageFinding) needs `WHERE NOT <var>:Muted`. ChainFinding is EvoGraph
memory, is out of triage scope, and is deliberately left alone.
"""

TRIAGE_QUERIES = [
    {
        "name": "vulnerabilities",
        "phase": "collecting_vulnerabilities",
        "description": "All vulnerabilities with endpoints, parameters, and GVM fields",
        "query": """
MATCH (v:Vulnerability {user_id: $userId, project_id: $projectId})
WHERE NOT v:Muted
OPTIONAL MATCH (v)-[:FOUND_AT]->(e:Endpoint)
OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(p:Parameter)
OPTIONAL MATCH (e)-[:BELONGS_TO]->(b:BaseURL)
RETURN v.id AS vuln_id, v.name AS name, v.severity AS severity,
       v.source AS source, v.category AS category,
       v.cvss_score AS cvss_score, v.description AS description,
       v.matched_at AS matched_at, v.template_id AS template_id,
       v.solution AS solution, v.solution_type AS solution_type,
       v.qod AS qod, v.qod_type AS qod_type,
       v.cisa_kev AS cisa_kev, v.cve_ids AS cve_ids,
       v.remediated AS remediated,
       v.target_ip AS target_ip, v.target_port AS target_port,
       v.target_hostname AS target_hostname,
       collect(DISTINCT {path: e.path, method: e.method, url: b.url}) AS endpoints,
       collect(DISTINCT {name: p.name, type: p.type, is_injectable: p.is_injectable}) AS parameters
""",
    },
    {
        "name": "cve_chains",
        "phase": "collecting_cve_chains",
        "description": "Technology to CVE to CWE to CAPEC chains",
        "query": """
MATCH (t:Technology {user_id: $userId, project_id: $projectId})
      -[:HAS_KNOWN_CVE]->(c:CVE)
OPTIONAL MATCH (c)-[:HAS_CWE]->(m:MitreData)
OPTIONAL MATCH (m)-[:HAS_CAPEC]->(cap:Capec)
OPTIONAL MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})
      -[:EXPLOITED_CVE]->(c)
  WHERE NOT ex:Muted
RETURN t.name AS technology, t.version AS version,
       collect(DISTINCT {cve: c.id, cvss: c.cvss_score, description: c.description}) AS cves,
       collect(DISTINCT m.cwe_id) AS cwes,
       collect(DISTINCT cap.capec_id) AS capecs,
       count(DISTINCT ex) AS exploit_count
""",
    },
    {
        "name": "secrets",
        "phase": "collecting_secrets",
        "description": "GitHub secrets and sensitive files",
        "query": """
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
      -[:HAS_GITHUB_HUNT]->(hunt:GithubHunt)
      -[:HAS_REPOSITORY]->(repo:GithubRepository)
OPTIONAL MATCH (repo)-[:HAS_PATH]->(path:GithubPath)
      -[:CONTAINS_SECRET]->(secret:GithubSecret)
  WHERE NOT secret:Muted
OPTIONAL MATCH (path)-[:CONTAINS_SENSITIVE_FILE]->(sf:GithubSensitiveFile)
  WHERE NOT sf:Muted
RETURN repo.name AS repo, repo.full_name AS full_name,
       collect(DISTINCT {path: path.path, secret_type: secret.secret_type, sample: secret.sample}) AS secrets,
       collect(DISTINCT {path: sf.path, secret_type: sf.secret_type}) AS sensitive_files
""",
    },
    {
        "name": "exploits",
        "phase": "collecting_exploits",
        "description": "Exploitable CVEs with confirmed exploits",
        "query": """
MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})
      -[:EXPLOITED_CVE]->(c:CVE)
WHERE NOT ex:Muted
OPTIONAL MATCH (t:Technology {user_id: $userId, project_id: $projectId})-[:HAS_KNOWN_CVE]->(c)
RETURN c.id AS cve, c.cvss_score AS cvss, c.description AS description,
       collect(DISTINCT t.name) AS affected_technologies,
       collect(DISTINCT {exploit_id: ex.id, source: ex.source}) AS exploits
""",
    },
    {
        "name": "assets",
        "phase": "collecting_assets",
        "description": "Asset context: services, ports, IPs, base URLs",
        "query": """
MATCH (d:Domain {user_id: $userId, project_id: $projectId})
      -[:HAS_SUBDOMAIN]->(s:Subdomain)
      -[:RESOLVES_TO]->(ip:IP)
      -[:HAS_PORT]->(port:Port)
OPTIONAL MATCH (port)-[:RUNS_SERVICE]->(svc:Service)
OPTIONAL MATCH (svc)-[:SERVES_URL]->(b:BaseURL)
RETURN s.name AS subdomain, ip.address AS ip,
       collect(DISTINCT {port: port.number, protocol: port.protocol,
                         service: svc.name, product: svc.product, version: svc.version}) AS services,
       collect(DISTINCT b.url) AS urls
""",
    },
    {
        "name": "chain_findings",
        "phase": "collecting_chain_findings",
        "description": "Attack chain findings from pentesting sessions",
        "query": """
MATCH (cf:ChainFinding {user_id: $userId, project_id: $projectId})
WHERE cf.finding_type IN ['exploit_success', 'credential_found', 'access_gained',
                          'privilege_escalation', 'vulnerability_confirmed']
OPTIONAL MATCH (cf)-[:FOUND_ON]->(target)
  WHERE target:IP OR target:Subdomain
OPTIONAL MATCH (cf)-[:FINDING_RELATES_CVE]->(cve:CVE)
OPTIONAL MATCH (step:ChainStep)-[:PRODUCED]->(cf)
OPTIONAL MATCH (ac:AttackChain)-[:HAS_STEP]->(step)
RETURN cf.finding_id AS finding_id, cf.finding_type AS finding_type,
       cf.severity AS severity, cf.title AS title,
       cf.description AS description, cf.evidence AS evidence,
       cf.confidence AS confidence, cf.phase AS phase,
       cf.target_ip AS target_ip, cf.target_port AS target_port,
       cf.cve_ids AS cve_ids, cf.attack_type AS attack_type,
       labels(target)[0] AS target_type,
       CASE WHEN target:IP THEN target.address ELSE target.name END AS target_value,
       collect(DISTINCT cve.id) AS related_cves,
       ac.chain_id AS chain_id, ac.status AS chain_status,
       ac.attack_path_type AS attack_path_type
""",
    },
    {
        "name": "attack_chains",
        "phase": "collecting_attack_chains",
        "description": "Attack chain session summaries",
        "query": """
MATCH (ac:AttackChain {user_id: $userId, project_id: $projectId})
WHERE ac.status IN ['completed', 'active']
OPTIONAL MATCH (ac)-[:CHAIN_TARGETS]->(target)
OPTIONAL MATCH (ac)-[:HAS_STEP]->(step:ChainStep)-[:PRODUCED]->(cf:ChainFinding)
OPTIONAL MATCH (ac)-[:HAS_STEP]->(fstep:ChainStep)-[:FAILED_WITH]->(fail:ChainFailure)
RETURN ac.chain_id AS chain_id, ac.title AS title,
       ac.objective AS objective, ac.status AS status,
       ac.attack_path_type AS attack_path_type,
       ac.total_steps AS total_steps,
       ac.successful_steps AS successful_steps,
       ac.failed_steps AS failed_steps,
       ac.phases_reached AS phases_reached,
       ac.final_outcome AS final_outcome,
       collect(DISTINCT {type: labels(target)[0],
                         value: CASE WHEN target:IP THEN target.address
                                     WHEN target:Subdomain THEN target.name
                                     WHEN target:CVE THEN target.id
                                     ELSE coalesce(target.name, target.id, 'unknown') END}) AS targets,
       count(DISTINCT cf) AS findings_count,
       count(DISTINCT fail) AS failures_count
""",
    },
    {
        "name": "certificates",
        "phase": "collecting_certificates",
        "description": "TLS certificate findings",
        "query": """
MATCH (cert:Certificate {user_id: $userId, project_id: $projectId})
OPTIONAL MATCH (bu:BaseURL)-[:HAS_CERTIFICATE]->(cert)
OPTIONAL MATCH (ip:IP)-[:HAS_CERTIFICATE]->(cert)
RETURN cert.subject_cn AS subject_cn,
       cert.cert_key AS cert_key,
       cert.fingerprint_sha256 AS fingerprint_sha256,
       cert.issuer AS issuer,
       cert.not_before AS valid_from,
       cert.not_after AS expires,
       cert.san AS san,
       cert.self_signed AS self_signed,
       cert.expired AS expired,
       cert.mismatched AS mismatched,
       cert.source AS source,
       collect(DISTINCT bu.url) AS baseurl_urls,
       collect(DISTINCT ip.address) AS ip_addresses,
       CASE WHEN cert.not_after < datetime() THEN 'expired'
            WHEN cert.not_after < datetime() + duration('P30D') THEN 'expiring_soon'
            ELSE 'valid' END AS cert_status
""",
    },
    {
        "name": "security_checks",
        "phase": "collecting_security_checks",
        "description": "Security check vulnerabilities (missing headers, misconfigs)",
        "query": """
MATCH (v:Vulnerability {user_id: $userId, project_id: $projectId, source: 'security_check'})
WHERE NOT v:Muted
OPTIONAL MATCH (bu:BaseURL)-[:HAS_VULNERABILITY]->(v)
RETURN v.id AS vuln_id, v.name AS name, v.severity AS severity,
       v.description AS description, v.category AS category,
       bu.url AS affected_url
""",
    },
]


# ── Prioritisation scoring queries ────────────────────────────────────────────
#
# One query per finding-bearing label. Each returns a FLAT signal row keyed by
# `id`, consumed by `scoring.score_finding`. Same mute-enforcement contract as
# TRIAGE_QUERIES: run via `run_static_query`, so every muteable var hand-writes
# `WHERE NOT <var>:Muted`.
#
# The Vulnerability query carries the exploitation-proof joins. Proof is matched
# by CVE id (precise) and confirmed exploits by ExploitGvm; a chain finding
# merely FOUND_ON the same host is returned separately as `host_compromised`
# (adjacency, not proof) so it cannot be miscredited to a finding the agent
# actually failed on.
SCORING_QUERIES = [
    {
        "name": "score_vulnerabilities",
        "label": "Vulnerability",
        "query": """
MATCH (v:Vulnerability {user_id: $userId, project_id: $projectId})
WHERE NOT v:Muted
OPTIONAL MATCH (host)-[:HAS_VULNERABILITY]->(v)
OPTIONAL MATCH (v)-[:AFFECTS_PARAMETER]->(p:Parameter)
WITH v, host, collect(DISTINCT p.is_injectable) AS injflags
OPTIONAL MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})-[:EXPLOITED_CVE]->(exc:CVE)
  WHERE exc.id IN coalesce(v.cve_ids, [])
WITH v, host, injflags, count(DISTINCT ex) AS confirmed_exploits
OPTIONAL MATCH (cf:ChainFinding {user_id: $userId, project_id: $projectId})-[:FINDING_RELATES_CVE]->(cvc:CVE)
  WHERE cvc.id IN coalesce(v.cve_ids, [])
WITH v, host, injflags, confirmed_exploits, collect(DISTINCT cf.finding_type) AS chain_proofs
OPTIONAL MATCH (hcf:ChainFinding {user_id: $userId, project_id: $projectId})-[:FOUND_ON]->(host)
  WHERE host IS NOT NULL AND hcf.finding_type IN ['exploit_success','access_gained','privilege_escalation','credential_found']
WITH v, host, injflags, confirmed_exploits, chain_proofs, count(DISTINCT hcf) AS host_compromised
OPTIONAL MATCH (st:ChainStep {user_id: $userId, project_id: $projectId})-[:STEP_TARGETED]->(host)
OPTIONAL MATCH (st)-[:FAILED_WITH]->(fail:ChainFailure {failure_type: 'exploit_failed'})
WITH v, host, injflags, confirmed_exploits, chain_proofs, host_compromised, count(DISTINCT fail) AS exploit_failures
RETURN v.id AS id, 'Vulnerability' AS label, v.source AS source, v.severity AS severity,
       v.cvss_score AS cvss_score, v.cisa_kev AS cisa_kev, v.has_exploit AS has_exploit,
       v.qod AS qod, v.remediated AS remediated, v.matcher_status AS matcher_status,
       v.is_dast_finding AS is_dast_finding, v.name AS name, v.matched_at AS matched_at,
       v.template_id AS template_id,
       coalesce(host.name, host.address, host.url) AS host,
       host.is_cdn AS is_cdn, host.origin_confirmed AS is_origin, host.is_live AS is_live,
       ANY(f IN injflags WHERE f = true) AS injectable,
       chain_proofs, confirmed_exploits, host_compromised, exploit_failures
""",
    },
    {
        "name": "score_exploits",
        "label": "ExploitGvm",
        "query": """
MATCH (ex:ExploitGvm {user_id: $userId, project_id: $projectId})
WHERE NOT ex:Muted
RETURN ex.id AS id, 'ExploitGvm' AS label, 'critical' AS severity,
       ex.cisa_kev AS cisa_kev, ex.name AS name, ex.target_ip AS host,
       1 AS confirmed_exploits
""",
    },
    {
        "name": "score_secrets",
        "label": "Secret",
        "query": """
MATCH (s:Secret {user_id: $userId, project_id: $projectId})
WHERE NOT s:Muted
OPTIONAL MATCH (bu:BaseURL)-[:HAS_SECRET]->(s)
RETURN s.id AS id, 'Secret' AS label, coalesce(s.severity, 'medium') AS severity,
       s.source AS source, s.secret_type AS secret_type,
       s.validation_status AS validation_status, s.key_type AS name,
       coalesce(s.base_url, bu.url) AS host
""",
    },
    {
        "name": "score_js_recon",
        "label": "JsReconFinding",
        "query": """
MATCH (j:JsReconFinding {user_id: $userId, project_id: $projectId})
WHERE NOT j:Muted AND coalesce(j.finding_type, '') <> 'js_file'
RETURN j.id AS id, 'JsReconFinding' AS label, coalesce(j.severity, 'low') AS severity,
       j.confidence AS confidence, coalesce(j.title, j.finding_type) AS name,
       coalesce(j.base_url, j.source_url) AS host
""",
    },
    {
        "name": "score_multiscanner",
        "label": "MultiscannerFinding",
        "query": """
MATCH (tf:MultiscannerFinding {user_id: $userId, project_id: $projectId})
WHERE NOT tf:Muted
RETURN tf.id AS id, 'MultiscannerFinding' AS label, coalesce(tf.severity, 'high') AS severity,
       tf.validation_status AS validation_status, tf.detector_name AS name,
       tf.detector_name AS secret_type, tf.location AS host
""",
    },
    {
        "name": "score_github_secrets",
        "label": "GithubSecret",
        "query": """
MATCH (g:GithubSecret {user_id: $userId, project_id: $projectId})
WHERE NOT g:Muted
RETURN g.id AS id, 'GithubSecret' AS label, coalesce(g.severity, 'high') AS severity,
       g.secret_type AS secret_type, g.secret_type AS name, g.repository AS host
""",
    },
    {
        "name": "score_github_files",
        "label": "GithubSensitiveFile",
        "query": """
MATCH (gf:GithubSensitiveFile {user_id: $userId, project_id: $projectId})
WHERE NOT gf:Muted
RETURN gf.id AS id, 'GithubSensitiveFile' AS label, coalesce(gf.severity, 'medium') AS severity,
       gf.secret_type AS secret_type, coalesce(gf.path, gf.secret_type) AS name,
       gf.repository AS host
""",
    },
    {
        "name": "score_mal_packages",
        "label": "MalPackageFinding",
        "query": """
MATCH (:Package {user_id: $userId, project_id: $projectId})-[:FLAGGED_AS]->(f:MalPackageFinding {user_id: $userId, project_id: $projectId})
WHERE NOT f:Muted
RETURN f.finding_id AS id, 'MalPackageFinding' AS label, coalesce(f.severity, 'high') AS severity,
       f.verdict AS verdict, coalesce(f.title, f.advisory_id) AS name
""",
    },
]
