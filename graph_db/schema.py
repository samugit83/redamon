"""
Neo4j Schema: Constraints and Indexes for RedAmon Graph Database

All DDL statements use IF NOT EXISTS / IF EXISTS guards, making them
fully idempotent — safe to run multiple times without side effects.
"""


# Drop old global constraints that conflict with tenant-scoped ones
DROP_LEGACY_CONSTRAINTS = [
    "DROP CONSTRAINT subdomain_unique IF EXISTS",
    "DROP CONSTRAINT ip_unique IF EXISTS",
    "DROP CONSTRAINT baseurl_unique IF EXISTS",
]

# Uniqueness constraints (tenant-scoped for per-project nodes, global for shared reference nodes)
CONSTRAINTS = [
    "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (d:Domain) REQUIRE (d.name, d.user_id, d.project_id) IS UNIQUE",
    "CREATE CONSTRAINT subdomain_unique IF NOT EXISTS FOR (s:Subdomain) REQUIRE (s.name, s.user_id, s.project_id) IS UNIQUE",
    "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IP) REQUIRE (i.address, i.user_id, i.project_id) IS UNIQUE",
    "CREATE CONSTRAINT baseurl_unique IF NOT EXISTS FOR (u:BaseURL) REQUIRE (u.url, u.user_id, u.project_id) IS UNIQUE",
    "CREATE CONSTRAINT port_unique IF NOT EXISTS FOR (p:Port) REQUIRE (p.number, p.protocol, p.ip_address, p.user_id, p.project_id) IS UNIQUE",
    "CREATE CONSTRAINT service_unique IF NOT EXISTS FOR (svc:Service) REQUIRE (svc.name, svc.port_number, svc.ip_address, svc.user_id, svc.project_id) IS UNIQUE",
    "CREATE CONSTRAINT technology_unique IF NOT EXISTS FOR (t:Technology) REQUIRE (t.name, t.version, t.user_id, t.project_id) IS UNIQUE",
    "CREATE CONSTRAINT endpoint_unique IF NOT EXISTS FOR (e:Endpoint) REQUIRE (e.path, e.method, e.baseurl, e.user_id, e.project_id) IS UNIQUE",
    "CREATE CONSTRAINT parameter_unique IF NOT EXISTS FOR (p:Parameter) REQUIRE (p.name, p.position, p.endpoint_path, p.baseurl, p.user_id, p.project_id) IS UNIQUE",
    "CREATE CONSTRAINT header_unique IF NOT EXISTS FOR (h:Header) REQUIRE (h.name, h.value, h.baseurl, h.user_id, h.project_id) IS UNIQUE",
    "CREATE CONSTRAINT dnsrecord_unique IF NOT EXISTS FOR (dns:DNSRecord) REQUIRE (dns.type, dns.value, dns.subdomain, dns.user_id, dns.project_id) IS UNIQUE",
    "CREATE CONSTRAINT certificate_unique IF NOT EXISTS FOR (c:Certificate) REQUIRE (c.subject_cn, c.user_id, c.project_id) IS UNIQUE",
    "CREATE CONSTRAINT traceroute_unique IF NOT EXISTS FOR (tr:Traceroute) REQUIRE (tr.target_ip, tr.user_id, tr.project_id) IS UNIQUE",
    "CREATE CONSTRAINT cve_unique IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT mitredata_unique IF NOT EXISTS FOR (m:MitreData) REQUIRE m.id IS UNIQUE",
    "CREATE CONSTRAINT capec_unique IF NOT EXISTS FOR (cap:Capec) REQUIRE cap.capec_id IS UNIQUE",
    "CREATE CONSTRAINT vulnerability_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
    "CREATE CONSTRAINT exploit_unique IF NOT EXISTS FOR (e:Exploit) REQUIRE e.id IS UNIQUE",
    "CREATE CONSTRAINT exploitgvm_unique IF NOT EXISTS FOR (e:ExploitGvm) REQUIRE e.id IS UNIQUE",
    # GitHub Secret Hunt constraints
    "CREATE CONSTRAINT githubhunt_unique IF NOT EXISTS FOR (gh:GithubHunt) REQUIRE gh.id IS UNIQUE",
    "CREATE CONSTRAINT githubrepo_unique IF NOT EXISTS FOR (gr:GithubRepository) REQUIRE gr.id IS UNIQUE",
    "CREATE CONSTRAINT githubpath_unique IF NOT EXISTS FOR (gp:GithubPath) REQUIRE gp.id IS UNIQUE",
    "CREATE CONSTRAINT githubsecret_unique IF NOT EXISTS FOR (gs:GithubSecret) REQUIRE gs.id IS UNIQUE",
    "CREATE CONSTRAINT githubsensitivefile_unique IF NOT EXISTS FOR (gsf:GithubSensitiveFile) REQUIRE gsf.id IS UNIQUE",
    # TruffleHog Secret Scanner constraints
    "CREATE CONSTRAINT trufflehogscan_unique IF NOT EXISTS FOR (ts:TrufflehogScan) REQUIRE ts.id IS UNIQUE",
    "CREATE CONSTRAINT trufflehogrepository_unique IF NOT EXISTS FOR (tr:TrufflehogRepository) REQUIRE tr.id IS UNIQUE",
    "CREATE CONSTRAINT trufflehogfinding_unique IF NOT EXISTS FOR (tf:TrufflehogFinding) REQUIRE tf.id IS UNIQUE",
    # JS Recon Scanner constraints
    "CREATE CONSTRAINT jsreconfinding_unique IF NOT EXISTS FOR (jf:JsReconFinding) REQUIRE jf.id IS UNIQUE",
    # Secret constraints
    "CREATE CONSTRAINT secret_unique IF NOT EXISTS FOR (s:Secret) REQUIRE (s.id) IS UNIQUE",
    # External Domain constraints
    "CREATE CONSTRAINT externaldomain_unique IF NOT EXISTS FOR (ed:ExternalDomain) REQUIRE (ed.domain, ed.user_id, ed.project_id) IS UNIQUE",
    # OTX Threat Intelligence constraints
    "CREATE CONSTRAINT threatpulse_unique IF NOT EXISTS FOR (tp:ThreatPulse) REQUIRE (tp.pulse_id, tp.user_id, tp.project_id) IS UNIQUE",
    "CREATE CONSTRAINT malware_unique IF NOT EXISTS FOR (m:Malware) REQUIRE (m.hash, m.user_id, m.project_id) IS UNIQUE",
    # Attack Chain Graph constraints
    "CREATE CONSTRAINT attack_chain_id IF NOT EXISTS FOR (ac:AttackChain) REQUIRE ac.chain_id IS UNIQUE",
    "CREATE CONSTRAINT chain_step_id IF NOT EXISTS FOR (s:ChainStep) REQUIRE s.step_id IS UNIQUE",
    "CREATE CONSTRAINT chain_finding_id IF NOT EXISTS FOR (f:ChainFinding) REQUIRE f.finding_id IS UNIQUE",
    "CREATE CONSTRAINT chain_decision_id IF NOT EXISTS FOR (d:ChainDecision) REQUIRE d.decision_id IS UNIQUE",
    "CREATE CONSTRAINT chain_failure_id IF NOT EXISTS FOR (fl:ChainFailure) REQUIRE fl.failure_id IS UNIQUE",
    # Knowledge Base — base constraint (not tenant-scoped, content is universal)
    "CREATE CONSTRAINT kb_chunk_id IF NOT EXISTS FOR (c:KBChunk) REQUIRE c.chunk_id IS UNIQUE",
    # Partial Recon — user-provided inputs for per-tool partial recon runs
    "CREATE CONSTRAINT userinput_unique IF NOT EXISTS FOR (ui:UserInput) REQUIRE (ui.id) IS UNIQUE",
]

# Tenant composite indexes (one per node type for efficient per-project queries)
TENANT_INDEXES = [
    "CREATE INDEX idx_domain_tenant IF NOT EXISTS FOR (d:Domain) ON (d.user_id, d.project_id)",
    "CREATE INDEX idx_subdomain_tenant IF NOT EXISTS FOR (s:Subdomain) ON (s.user_id, s.project_id)",
    "CREATE INDEX idx_ip_tenant IF NOT EXISTS FOR (i:IP) ON (i.user_id, i.project_id)",
    "CREATE INDEX idx_port_tenant IF NOT EXISTS FOR (p:Port) ON (p.user_id, p.project_id)",
    "CREATE INDEX idx_dnsrecord_tenant IF NOT EXISTS FOR (dns:DNSRecord) ON (dns.user_id, dns.project_id)",
    "CREATE INDEX idx_baseurl_tenant IF NOT EXISTS FOR (u:BaseURL) ON (u.user_id, u.project_id)",
    "CREATE INDEX idx_technology_tenant IF NOT EXISTS FOR (t:Technology) ON (t.user_id, t.project_id)",
    "CREATE INDEX idx_header_tenant IF NOT EXISTS FOR (h:Header) ON (h.user_id, h.project_id)",
    "CREATE INDEX idx_endpoint_tenant IF NOT EXISTS FOR (e:Endpoint) ON (e.user_id, e.project_id)",
    "CREATE INDEX idx_parameter_tenant IF NOT EXISTS FOR (p:Parameter) ON (p.user_id, p.project_id)",
    "CREATE INDEX idx_vulnerability_tenant IF NOT EXISTS FOR (v:Vulnerability) ON (v.user_id, v.project_id)",
    "CREATE INDEX idx_exploit_tenant IF NOT EXISTS FOR (e:Exploit) ON (e.user_id, e.project_id)",
    "CREATE INDEX idx_exploitgvm_tenant IF NOT EXISTS FOR (e:ExploitGvm) ON (e.user_id, e.project_id)",
    # GitHub Secret Hunt tenant indexes
    "CREATE INDEX idx_githubhunt_tenant IF NOT EXISTS FOR (gh:GithubHunt) ON (gh.user_id, gh.project_id)",
    "CREATE INDEX idx_githubrepo_tenant IF NOT EXISTS FOR (gr:GithubRepository) ON (gr.user_id, gr.project_id)",
    "CREATE INDEX idx_githubpath_tenant IF NOT EXISTS FOR (gp:GithubPath) ON (gp.user_id, gp.project_id)",
    "CREATE INDEX idx_githubsecret_tenant IF NOT EXISTS FOR (gs:GithubSecret) ON (gs.user_id, gs.project_id)",
    "CREATE INDEX idx_githubsensitivefile_tenant IF NOT EXISTS FOR (gsf:GithubSensitiveFile) ON (gsf.user_id, gsf.project_id)",
    # TruffleHog Secret Scanner tenant indexes
    "CREATE INDEX idx_trufflehogscan_tenant IF NOT EXISTS FOR (ts:TrufflehogScan) ON (ts.user_id, ts.project_id)",
    "CREATE INDEX idx_trufflehogrepository_tenant IF NOT EXISTS FOR (tr:TrufflehogRepository) ON (tr.user_id, tr.project_id)",
    "CREATE INDEX idx_trufflehogfinding_tenant IF NOT EXISTS FOR (tf:TrufflehogFinding) ON (tf.user_id, tf.project_id)",
    # JS Recon Scanner tenant indexes
    "CREATE INDEX idx_jsreconfinding_tenant IF NOT EXISTS FOR (jf:JsReconFinding) ON (jf.user_id, jf.project_id)",
    # Secret tenant indexes
    "CREATE INDEX idx_secret_tenant IF NOT EXISTS FOR (s:Secret) ON (s.user_id, s.project_id)",
    # External Domain tenant indexes
    "CREATE INDEX idx_externaldomain_tenant IF NOT EXISTS FOR (ed:ExternalDomain) ON (ed.user_id, ed.project_id)",
    # OTX Threat Intelligence tenant indexes
    "CREATE INDEX idx_threatpulse_tenant IF NOT EXISTS FOR (tp:ThreatPulse) ON (tp.user_id, tp.project_id)",
    "CREATE INDEX idx_malware_tenant IF NOT EXISTS FOR (m:Malware) ON (m.user_id, m.project_id)",
    # Attack Chain Graph tenant indexes
    "CREATE INDEX idx_attackchain_tenant IF NOT EXISTS FOR (ac:AttackChain) ON (ac.user_id, ac.project_id)",
    "CREATE INDEX idx_chainstep_tenant IF NOT EXISTS FOR (s:ChainStep) ON (s.user_id, s.project_id)",
    "CREATE INDEX idx_chainfinding_tenant IF NOT EXISTS FOR (f:ChainFinding) ON (f.user_id, f.project_id)",
    "CREATE INDEX idx_chaindecision_tenant IF NOT EXISTS FOR (d:ChainDecision) ON (d.user_id, d.project_id)",
    "CREATE INDEX idx_chainfailure_tenant IF NOT EXISTS FOR (fl:ChainFailure) ON (fl.user_id, fl.project_id)",
    # Partial Recon — UserInput tenant index
    "CREATE INDEX idx_userinput_tenant IF NOT EXISTS FOR (ui:UserInput) ON (ui.user_id, ui.project_id)",
]

# Additional functional indexes
ADDITIONAL_INDEXES = [
    "CREATE INDEX subdomain_name IF NOT EXISTS FOR (s:Subdomain) ON (s.name)",
    "CREATE INDEX idx_subdomain_status IF NOT EXISTS FOR (s:Subdomain) ON (s.status)",
    "CREATE INDEX ip_address IF NOT EXISTS FOR (i:IP) ON (i.address)",
    "CREATE INDEX idx_service_tenant IF NOT EXISTS FOR (svc:Service) ON (svc.user_id, svc.project_id)",
    "CREATE INDEX tech_name IF NOT EXISTS FOR (t:Technology) ON (t.name)",
    "CREATE INDEX tech_name_version IF NOT EXISTS FOR (t:Technology) ON (t.name, t.version)",
    # Vulnerability indexes
    "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
    "CREATE INDEX vuln_category IF NOT EXISTS FOR (v:Vulnerability) ON (v.category)",
    "CREATE INDEX vuln_template IF NOT EXISTS FOR (v:Vulnerability) ON (v.template_id)",
    # Parameter indexes
    "CREATE INDEX param_injectable IF NOT EXISTS FOR (p:Parameter) ON (p.is_injectable)",
    # CVE indexes
    "CREATE INDEX cve_severity IF NOT EXISTS FOR (c:CVE) ON (c.severity)",
    "CREATE INDEX cve_cvss IF NOT EXISTS FOR (c:CVE) ON (c.cvss)",
    "CREATE INDEX idx_cve_tenant IF NOT EXISTS FOR (c:CVE) ON (c.user_id, c.project_id)",
    # MitreData indexes
    "CREATE INDEX idx_mitredata_tenant IF NOT EXISTS FOR (m:MitreData) ON (m.user_id, m.project_id)",
    # Capec indexes
    "CREATE INDEX capec_id IF NOT EXISTS FOR (c:Capec) ON (c.capec_id)",
    "CREATE INDEX idx_capec_tenant IF NOT EXISTS FOR (c:Capec) ON (c.user_id, c.project_id)",
    # Exploit indexes
    "CREATE INDEX idx_exploit_type IF NOT EXISTS FOR (e:Exploit) ON (e.attack_type)",
    # GitHub Secret Hunt indexes
    "CREATE INDEX idx_githubrepo_name IF NOT EXISTS FOR (gr:GithubRepository) ON (gr.name)",
    "CREATE INDEX idx_githubpath_path IF NOT EXISTS FOR (gp:GithubPath) ON (gp.path)",
    "CREATE INDEX idx_githubsecret_secret_type IF NOT EXISTS FOR (gs:GithubSecret) ON (gs.secret_type)",
    # TruffleHog functional indexes
    "CREATE INDEX idx_trufflehogfinding_detector IF NOT EXISTS FOR (tf:TrufflehogFinding) ON (tf.detector_name)",
    "CREATE INDEX idx_trufflehogrepository_name IF NOT EXISTS FOR (tr:TrufflehogRepository) ON (tr.name)",
    # Secret functional indexes
    "CREATE INDEX idx_secret_type IF NOT EXISTS FOR (s:Secret) ON (s.secret_type)",
    "CREATE INDEX idx_secret_severity IF NOT EXISTS FOR (s:Secret) ON (s.severity)",
    "CREATE INDEX idx_secret_source IF NOT EXISTS FOR (s:Secret) ON (s.source)",
    # Attack Chain Graph functional indexes
    "CREATE INDEX idx_chainstep_chain IF NOT EXISTS FOR (s:ChainStep) ON (s.chain_id)",
    "CREATE INDEX idx_chainfinding_type IF NOT EXISTS FOR (f:ChainFinding) ON (f.finding_type)",
    "CREATE INDEX idx_chainfinding_severity IF NOT EXISTS FOR (f:ChainFinding) ON (f.severity)",
    "CREATE INDEX idx_chainfailure_type IF NOT EXISTS FOR (fl:ChainFailure) ON (fl.failure_type)",
    "CREATE INDEX idx_attackchain_status IF NOT EXISTS FOR (ac:AttackChain) ON (ac.status)",
    # Fireteam (multi-agent) attribution indexes. Report queries filter
    # ChainStep/ChainFinding by fireteam_id to assemble per-member sections;
    # without the index those queries scan the full Chain subgraph.
    "CREATE INDEX idx_chainstep_by_fireteam IF NOT EXISTS FOR (s:ChainStep) ON (s.fireteam_id)",
    "CREATE INDEX idx_chainfinding_by_fireteam IF NOT EXISTS FOR (f:ChainFinding) ON (f.fireteam_id)",
]


def init_schema(session):
    """
    Initialize constraints and indexes for the graph schema.

    Safe to call multiple times — all statements use IF NOT EXISTS / IF EXISTS guards.
    """
    for stmt in DROP_LEGACY_CONSTRAINTS:
        try:
            session.run(stmt)
        except Exception:
            pass

    for query in CONSTRAINTS + TENANT_INDEXES + ADDITIONAL_INDEXES:
        try:
            session.run(query)
        except Exception as e:
            # Ignore if constraint/index already exists
            if "already exists" not in str(e).lower():
                print(f"[!][graph-db] Schema warning: {e}")
