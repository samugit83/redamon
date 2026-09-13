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
    # Renamed with the Trufflehog -> Multiscanner labels. Dropped by their OLD
    # names, because a constraint is identified by NAME: recreating it under the
    # new name leaves this one behind, still guarding a label nothing writes.
    "DROP CONSTRAINT trufflehogscan_unique IF EXISTS",
    "DROP CONSTRAINT trufflehogrepository_unique IF EXISTS",
    "DROP CONSTRAINT trufflehogfinding_unique IF EXISTS",
    "DROP CONSTRAINT trufflehogimage_unique IF EXISTS",
    "DROP CONSTRAINT trufflehogmodel_unique IF EXISTS",
    "DROP CONSTRAINT trufflehogbucket_unique IF EXISTS",
    "DROP CONSTRAINT trufflehogendpoint_unique IF EXISTS",
    "DROP INDEX idx_trufflehogscan_tenant IF EXISTS",
    "DROP INDEX idx_trufflehogrepository_tenant IF EXISTS",
    "DROP INDEX idx_trufflehogfinding_tenant IF EXISTS",
    "DROP INDEX idx_trufflehogimage_tenant IF EXISTS",
    "DROP INDEX idx_trufflehogmodel_tenant IF EXISTS",
    "DROP INDEX idx_trufflehogbucket_tenant IF EXISTS",
    "DROP INDEX idx_trufflehogendpoint_tenant IF EXISTS",
    "DROP INDEX idx_trufflehogfinding_detector IF EXISTS",
    "DROP INDEX idx_trufflehogfinding_source IF EXISTS",
    "DROP INDEX idx_trufflehogfinding_validation IF EXISTS",
    "DROP INDEX idx_trufflehogscan_source IF EXISTS",
    "DROP INDEX idx_trufflehogrepository_name IF EXISTS",
    "DROP INDEX idx_trufflehogimage_name IF EXISTS",
    "DROP INDEX idx_trufflehogmodel_name IF EXISTS",
    "DROP INDEX idx_trufflehogbucket_name IF EXISTS",
    "DROP INDEX idx_trufflehogendpoint_name IF EXISTS",
    # Certificate re-key: subject_cn is not a certificate identity (empty on
    # SAN-only certs, non-unique across distinct certs). Dropped by its OLD name
    # so the renamed constraint (certificate_key_unique) can back the new
    # cert_key without a same-name silent no-op. See backfill_cert_key.
    "DROP CONSTRAINT certificate_unique IF EXISTS",

    # ── G2: per-project findings were globally unique by id ──────────────────
    # These labels are per-PROJECT, but their uniqueness was on `id` alone, so
    # one id could exist once in the whole database. Two projects scanning the
    # same target therefore collided, and the collision went one of two ways,
    # both silent:
    #
    #   * an id-only MERGE took the other project's node over, re-pointing it,
    #     so one project's scan mutated another project's graph;
    #   * a tenant-keyed MERGE hit the global constraint, and the writers catch
    #     and swallow that, so the second project's finding was LOST.
    #
    # Recreated below as (id, user_id, project_id), which is strictly weaker:
    # anything valid under the old constraint is valid under the new one, so no
    # data migration is needed for the swap itself. The names must change,
    # because CREATE CONSTRAINT <same name> IF NOT EXISTS is a silent no-op
    # against a database that still has the old one.
    "DROP CONSTRAINT vulnerability_unique IF EXISTS",
    "DROP CONSTRAINT exploitgvm_unique IF EXISTS",
    "DROP CONSTRAINT githubhunt_unique IF EXISTS",
    "DROP CONSTRAINT githubrepo_unique IF EXISTS",
    "DROP CONSTRAINT githubpath_unique IF EXISTS",
    "DROP CONSTRAINT githubsecret_unique IF EXISTS",
    "DROP CONSTRAINT githubsensitivefile_unique IF EXISTS",
    "DROP CONSTRAINT sbomdoc_unique IF EXISTS",
    "DROP CONSTRAINT jsreconfinding_unique IF EXISTS",
    "DROP CONSTRAINT secret_unique IF EXISTS",
    "DROP CONSTRAINT userinput_unique IF EXISTS",
    # K25: the `Exploit` label is constrained but nothing has ever written one.
    "DROP CONSTRAINT exploit_unique IF EXISTS",
    # K25: tenant indexes on the SHARED reference nodes. They have no tenant
    # keys (strip_reference_node_tenant removes any it finds), so these indexed
    # nothing but empty values and cost a write on every CVE upsert.
    "DROP INDEX idx_cve_tenant IF EXISTS",
    "DROP INDEX idx_mitredata_tenant IF EXISTS",
    "DROP INDEX idx_capec_tenant IF EXISTS",
    "DROP INDEX idx_exploit_type IF EXISTS",
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
    # Keyed on cert_key (fingerprint-derived, surrogate fallback), NOT subject_cn.
    # NEW NAME is mandatory: a same-name CREATE IF NOT EXISTS against a DB that
    # still has the old constraint is a silent no-op (see backfill_cert_key).
    #
    # ROLLBACK, written down before anyone needs it at 2am:
    #
    #   DROP CONSTRAINT certificate_key_unique IF EXISTS;
    #   CREATE CONSTRAINT certificate_unique IF NOT EXISTS
    #     FOR (c:Certificate) REQUIRE (c.subject_cn, c.user_id, c.project_id) IS UNIQUE;
    #
    # That recreate FAILS if the re-keyed data already holds two certificates
    # sharing a subject_cn -- which is the entire reason this key exists, so on a
    # real install it is the expected outcome, not the exception. A true rollback
    # therefore also requires deleting the surplus, keeping the most recent
    # updated_at per subject_cn:
    #
    #   MATCH (c:Certificate)
    #   WITH c.subject_cn AS cn, c.user_id AS u, c.project_id AS p, c
    #   ORDER BY c.updated_at DESC          // ORDER BY *before* collect, or the
    #   WITH cn, u, p, collect(c) AS certs  // list order is arbitrary and the
    #   WHERE size(certs) > 1               // survivor is a coin flip
    #   UNWIND certs[1..] AS dup
    #   DETACH DELETE dup
    #
    # The DECISION if that is unacceptable: leave the constraint dropped. An
    # unconstrained Certificate label duplicates on re-scan but loses nothing,
    # whereas deleting certificates to satisfy a rolled-back key is irreversible.
    "CREATE CONSTRAINT certificate_key_unique IF NOT EXISTS FOR (c:Certificate) REQUIRE (c.cert_key, c.user_id, c.project_id) IS UNIQUE",
    "CREATE CONSTRAINT traceroute_unique IF NOT EXISTS FOR (tr:Traceroute) REQUIRE (tr.target_ip, tr.user_id, tr.project_id) IS UNIQUE",
    "CREATE CONSTRAINT cve_unique IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT mitredata_unique IF NOT EXISTS FOR (m:MitreData) REQUIRE m.id IS UNIQUE",
    "CREATE CONSTRAINT capec_unique IF NOT EXISTS FOR (cap:Capec) REQUIRE cap.capec_id IS UNIQUE",
    # ── Per-project findings: keyed on (id, tenant), never on id alone ───────
    # See DROP_LEGACY_CONSTRAINTS above for what an id-only key did to two
    # projects scanning the same target. The `_tenant_unique` suffix is a NEW
    # name on purpose: a same-name CREATE IF NOT EXISTS would silently keep the
    # old, global constraint.
    "CREATE CONSTRAINT vulnerability_tenant_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE (v.id, v.user_id, v.project_id) IS UNIQUE",
    "CREATE CONSTRAINT exploitgvm_tenant_unique IF NOT EXISTS FOR (e:ExploitGvm) REQUIRE (e.id, e.user_id, e.project_id) IS UNIQUE",
    # GitHub Secret Hunt constraints
    "CREATE CONSTRAINT githubhunt_tenant_unique IF NOT EXISTS FOR (gh:GithubHunt) REQUIRE (gh.id, gh.user_id, gh.project_id) IS UNIQUE",
    "CREATE CONSTRAINT githubrepo_tenant_unique IF NOT EXISTS FOR (gr:GithubRepository) REQUIRE (gr.id, gr.user_id, gr.project_id) IS UNIQUE",
    "CREATE CONSTRAINT githubpath_tenant_unique IF NOT EXISTS FOR (gp:GithubPath) REQUIRE (gp.id, gp.user_id, gp.project_id) IS UNIQUE",
    # Supply-chain feature (plan Phase 2/4): Package + MalPackageFinding, shared by L1 + L2.
    "CREATE CONSTRAINT package_unique IF NOT EXISTS FOR (p:Package) REQUIRE (p.purl, p.user_id, p.project_id) IS UNIQUE",
    # Anchor for packages read out of an operator-uploaded SBOM/lockfile.
    "CREATE CONSTRAINT sbomdoc_tenant_unique IF NOT EXISTS FOR (d:SbomDocument) REQUIRE (d.id, d.user_id, d.project_id) IS UNIQUE",
    "CREATE CONSTRAINT malpackagefinding_unique IF NOT EXISTS FOR (mf:MalPackageFinding) REQUIRE (mf.finding_id, mf.user_id, mf.project_id) IS UNIQUE",
    "CREATE CONSTRAINT githubsecret_tenant_unique IF NOT EXISTS FOR (gs:GithubSecret) REQUIRE (gs.id, gs.user_id, gs.project_id) IS UNIQUE",
    "CREATE CONSTRAINT githubsensitivefile_tenant_unique IF NOT EXISTS FOR (gsf:GithubSensitiveFile) REQUIRE (gsf.id, gsf.user_id, gsf.project_id) IS UNIQUE",
    # TruffleHog Secret Scanner constraints. Tenant-scoped (id, user_id,
    # project_id), matching the MERGE key: an id-only constraint plus a project
    # import that re-owns the tenant props WITHOUT rewriting the embedded id left
    # the two disagreeing about who owns the node.
    "CREATE CONSTRAINT multiscannerscan_unique IF NOT EXISTS FOR (ts:MultiscannerScan) REQUIRE (ts.id, ts.user_id, ts.project_id) IS UNIQUE",
    "CREATE CONSTRAINT multiscannerrepository_unique IF NOT EXISTS FOR (tr:MultiscannerRepository) REQUIRE (tr.id, tr.user_id, tr.project_id) IS UNIQUE",
    "CREATE CONSTRAINT multiscannerfinding_unique IF NOT EXISTS FOR (tf:MultiscannerFinding) REQUIRE (tf.id, tf.user_id, tf.project_id) IS UNIQUE",
    # Four asset labels for the non-git sources. Grouped by asset SHAPE, not one
    # per source: the graph renderer draws a node from labels[0] (a single label,
    # unordered by Neo4j), so a node may carry only one.
    "CREATE CONSTRAINT multiscannerimage_unique IF NOT EXISTS FOR (ti:MultiscannerImage) REQUIRE (ti.id, ti.user_id, ti.project_id) IS UNIQUE",
    "CREATE CONSTRAINT multiscannermodel_unique IF NOT EXISTS FOR (tm:MultiscannerModel) REQUIRE (tm.id, tm.user_id, tm.project_id) IS UNIQUE",
    "CREATE CONSTRAINT multiscannerbucket_unique IF NOT EXISTS FOR (tb:MultiscannerBucket) REQUIRE (tb.id, tb.user_id, tb.project_id) IS UNIQUE",
    "CREATE CONSTRAINT multiscannerendpoint_unique IF NOT EXISTS FOR (te:MultiscannerEndpoint) REQUIRE (te.id, te.user_id, te.project_id) IS UNIQUE",
    # JS Recon Scanner constraints
    "CREATE CONSTRAINT jsreconfinding_tenant_unique IF NOT EXISTS FOR (jf:JsReconFinding) REQUIRE (jf.id, jf.user_id, jf.project_id) IS UNIQUE",
    # Secret constraints
    "CREATE CONSTRAINT secret_tenant_unique IF NOT EXISTS FOR (s:Secret) REQUIRE (s.id, s.user_id, s.project_id) IS UNIQUE",
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
    "CREATE CONSTRAINT userinput_tenant_unique IF NOT EXISTS FOR (ui:UserInput) REQUIRE (ui.id, ui.user_id, ui.project_id) IS UNIQUE",
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
    "CREATE INDEX idx_sbomdoc_tenant IF NOT EXISTS FOR (d:SbomDocument) ON (d.user_id, d.project_id)",
    "CREATE INDEX idx_githubpath_tenant IF NOT EXISTS FOR (gp:GithubPath) ON (gp.user_id, gp.project_id)",
    "CREATE INDEX idx_githubsecret_tenant IF NOT EXISTS FOR (gs:GithubSecret) ON (gs.user_id, gs.project_id)",
    "CREATE INDEX idx_githubsensitivefile_tenant IF NOT EXISTS FOR (gsf:GithubSensitiveFile) ON (gsf.user_id, gsf.project_id)",
    # TruffleHog Secret Scanner tenant indexes
    "CREATE INDEX idx_multiscannerscan_tenant IF NOT EXISTS FOR (ts:MultiscannerScan) ON (ts.user_id, ts.project_id)",
    "CREATE INDEX idx_multiscannerrepository_tenant IF NOT EXISTS FOR (tr:MultiscannerRepository) ON (tr.user_id, tr.project_id)",
    "CREATE INDEX idx_multiscannerfinding_tenant IF NOT EXISTS FOR (tf:MultiscannerFinding) ON (tf.user_id, tf.project_id)",
    "CREATE INDEX idx_multiscannerimage_tenant IF NOT EXISTS FOR (ti:MultiscannerImage) ON (ti.user_id, ti.project_id)",
    "CREATE INDEX idx_multiscannermodel_tenant IF NOT EXISTS FOR (tm:MultiscannerModel) ON (tm.user_id, tm.project_id)",
    "CREATE INDEX idx_multiscannerbucket_tenant IF NOT EXISTS FOR (tb:MultiscannerBucket) ON (tb.user_id, tb.project_id)",
    "CREATE INDEX idx_multiscannerendpoint_tenant IF NOT EXISTS FOR (te:MultiscannerEndpoint) ON (te.user_id, te.project_id)",
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
    # These labels used to be backed by an id-only uniqueness constraint, which
    # is also what served "everything in this project" reads. The constraint is
    # now (id, tenant), so the tenant half needs its own index or a per-project
    # scan walks every row in the database.
    "CREATE INDEX idx_traceroute_tenant IF NOT EXISTS FOR (tr:Traceroute) ON (tr.user_id, tr.project_id)",
    "CREATE INDEX idx_package_tenant IF NOT EXISTS FOR (p:Package) ON (p.user_id, p.project_id)",
    "CREATE INDEX idx_malpackagefinding_tenant IF NOT EXISTS FOR (mf:MalPackageFinding) ON (mf.user_id, mf.project_id)",
    "CREATE INDEX idx_sbomdoc_tenant IF NOT EXISTS FOR (d:SbomDocument) ON (d.user_id, d.project_id)",
    # Certificate had no tenant index of its own: the old (subject_cn,...)
    # constraint backed reads. Re-keying to cert_key moves that backing, and
    # readers filtering by project_id alone (sharedInfra, graph-overview) need
    # this on a cert population tlsx is about to grow.
    "CREATE INDEX idx_certificate_tenant IF NOT EXISTS FOR (c:Certificate) ON (c.user_id, c.project_id)",
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
    # K25: CVE, MitreData and Capec are SHARED reference nodes and carry no
    # tenant keys (strip_reference_node_tenant removes any it finds), so a
    # tenant index on them indexed nothing but empty values. Dropped below.
    # Capec indexes
    "CREATE INDEX capec_id IF NOT EXISTS FOR (c:Capec) ON (c.capec_id)",
    # GitHub Secret Hunt indexes
    "CREATE INDEX idx_githubrepo_name IF NOT EXISTS FOR (gr:GithubRepository) ON (gr.name)",
    "CREATE INDEX idx_sbomdoc_name IF NOT EXISTS FOR (d:SbomDocument) ON (d.name)",
    "CREATE INDEX idx_githubpath_path IF NOT EXISTS FOR (gp:GithubPath) ON (gp.path)",
    "CREATE INDEX idx_githubsecret_secret_type IF NOT EXISTS FOR (gs:GithubSecret) ON (gs.secret_type)",
    # TruffleHog functional indexes. The source index carries the scoped clear:
    # every ingest deletes its own source's subgraph first, and that MATCH runs
    # on (user_id, project_id, source).
    "CREATE INDEX idx_multiscannerfinding_detector IF NOT EXISTS FOR (tf:MultiscannerFinding) ON (tf.detector_name)",
    "CREATE INDEX idx_multiscannerfinding_source IF NOT EXISTS FOR (tf:MultiscannerFinding) ON (tf.source)",
    "CREATE INDEX idx_multiscannerfinding_validation IF NOT EXISTS FOR (tf:MultiscannerFinding) ON (tf.validation_status)",
    "CREATE INDEX idx_multiscannerscan_source IF NOT EXISTS FOR (ts:MultiscannerScan) ON (ts.source)",
    "CREATE INDEX idx_multiscannerrepository_name IF NOT EXISTS FOR (tr:MultiscannerRepository) ON (tr.name)",
    "CREATE INDEX idx_multiscannerimage_name IF NOT EXISTS FOR (ti:MultiscannerImage) ON (ti.name)",
    "CREATE INDEX idx_multiscannermodel_name IF NOT EXISTS FOR (tm:MultiscannerModel) ON (tm.name)",
    "CREATE INDEX idx_multiscannerbucket_name IF NOT EXISTS FOR (tb:MultiscannerBucket) ON (tb.name)",
    "CREATE INDEX idx_multiscannerendpoint_name IF NOT EXISTS FOR (te:MultiscannerEndpoint) ON (te.name)",
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
    # Suppressed findings. `Muted` is added ALONGSIDE a finding's own label
    # rather than replacing it (see GRAPH.SCHEMA.md), so this is the only index
    # that can serve the Triage page's Muted table without knowing which kind of
    # finding it is about to list.
    "CREATE INDEX idx_muted_tenant IF NOT EXISTS FOR (n:Muted) ON (n.project_id)",
]



# Nodes written before the Trufflehog -> Multiscanner rename. Relabelled in place
# rather than left behind: every read is by label, so an un-migrated node is not
# "old data", it is invisible - a finished scan whose findings silently vanish
# from the Red Zone and from every report.
LEGACY_LABEL_RENAMES = [
    ("TrufflehogScan", "MultiscannerScan"),
    ("TrufflehogRepository", "MultiscannerRepository"),
    ("TrufflehogFinding", "MultiscannerFinding"),
    ("TrufflehogImage", "MultiscannerImage"),
    ("TrufflehogModel", "MultiscannerModel"),
    ("TrufflehogBucket", "MultiscannerBucket"),
    ("TrufflehogEndpoint", "MultiscannerEndpoint"),
]

LEGACY_REL_RENAMES = [("HAS_TRUFFLEHOG_SCAN", "HAS_MULTISCANNER_SCAN")]


# Set once the rename has fully applied. Without it the migration re-scans every
# label on every Neo4jClient construction - and init_schema runs from
# BaseMixin.__init__, so that is every scan container spawn and every agent graph
# call, forever, at a cost that grows with the size of the graph.
#
# A global reference node: it describes the DATABASE, not a project, so it
# carries no tenant key (see the graph-db-writes ruleset).
MIGRATION_MARKER = "trufflehog-to-multiscanner-v1"

# Relabelling the whole graph in one statement is a single transaction whose size
# is the caller's data. Batched so a large graph cannot exceed the heap and leave
# the rest un-migrated - which would be invisible data, not merely stale data.
MIGRATION_BATCH = 10_000


def _migration_applied(session, marker=MIGRATION_MARKER) -> bool:
    try:
        row = session.run(
            "MATCH (m:RedamonSchemaMigration {id: $id}) RETURN count(m) AS c",
            id=marker).single()
        return bool(row and row["c"])
    except Exception:
        # Unknown state: re-running the migration is idempotent, skipping it is
        # not recoverable, so fail towards doing the work.
        return False


def _mark_migration_applied(session, marker=MIGRATION_MARKER) -> None:
    try:
        session.run(
            "MERGE (m:RedamonSchemaMigration {id: $id}) "
            "ON CREATE SET m.applied_at = datetime()", id=marker)
    except Exception as e:
        print(f"[!][graph-db] could not record migration marker: {e}")


def _run_batched(session, query: str, **params) -> int:
    """Run `query` (which must carry its own LIMIT and RETURN a count) until it
    stops matching. Returns the total touched."""
    total = 0
    while True:
        row = session.run(query, **params).single()
        touched = (row or {}).get("c") or 0
        total += touched
        if not touched:
            return total


def migrate_legacy_labels(session):
    """Move pre-rename nodes and relationships onto the current names.

    A rename does not leave old data stale, it leaves it INVISIBLE: every read is
    by label, so an un-migrated finding disappears from the Red Zone and from
    every report while still sitting in the database.

    Guarded by a marker node, so the steady-state cost is ONE lookup rather than
    a scan per label. The marker is written only after every step succeeded; a
    partial migration therefore retries on the next construction instead of
    silently stopping half-way.

    Runs BEFORE the constraints are created: a uniqueness constraint on the new
    label cannot be satisfied while data still carries the old one.
    """
    if _migration_applied(session):
        return

    ok = True

    for old, new in LEGACY_LABEL_RENAMES:
        try:
            moved = _run_batched(
                session,
                f"MATCH (n:`{old}`) WITH n LIMIT {MIGRATION_BATCH} "
                f"SET n:`{new}` REMOVE n:`{old}` RETURN count(n) AS c")
            if moved:
                print(f"[graph-db] migrated {moved} {old} -> {new}")
        except Exception as e:
            print(f"[!][graph-db] label migration {old} -> {new} failed: {e}")
            ok = False

    # The node id is the MERGE key and carried the old name as a prefix. Left
    # alone, the next scan would MERGE on the NEW prefix and create a second copy
    # of every node beside the migrated one. `scan_id` moves with it, being a
    # foreign key holding the same string.
    for label in (new for _old, new in LEGACY_LABEL_RENAMES):
        for prop in ("id", "scan_id"):
            try:
                if prop == "id":
                    # A node may already hold the migrated id (reachable if a
                    # write lands between the code rename and this migration).
                    # Rewriting it would violate the uniqueness constraint and
                    # abort the statement, leaving everything after it undone.
                    stuck = session.run(
                        f"MATCH (n:`{label}`) WHERE n.id STARTS WITH 'trufflehog-' "
                        f"AND EXISTS {{ MATCH (m:`{label}`) "
                        f"WHERE m.id = 'multiscanner-' + substring(n.id, 11) }} "
                        f"RETURN count(n) AS c").single()
                    if stuck and stuck["c"]:
                        print(f"[!][graph-db] {stuck['c']} legacy {label} node(s) "
                              f"already superseded by a migrated copy; left as-is")
                    _run_batched(
                        session,
                        f"MATCH (n:`{label}`) WHERE n.id STARTS WITH 'trufflehog-' "
                        f"AND NOT EXISTS {{ MATCH (m:`{label}`) "
                        f"WHERE m.id = 'multiscanner-' + substring(n.id, 11) }} "
                        f"WITH n LIMIT {MIGRATION_BATCH} "
                        f"SET n.id = 'multiscanner-' + substring(n.id, 11) "
                        f"RETURN count(n) AS c")
                    continue
                _run_batched(
                    session,
                    f"MATCH (n:`{label}`) WHERE n.{prop} STARTS WITH 'trufflehog-' "
                    f"WITH n LIMIT {MIGRATION_BATCH} "
                    f"SET n.{prop} = 'multiscanner-' + substring(n.{prop}, 11) "
                    f"RETURN count(n) AS c")
            except Exception as e:
                print(f"[!][graph-db] {label}.{prop} prefix migration failed: {e}")
                ok = False

    # A relationship type cannot be renamed in place; it is recreated and the old
    # one deleted. Properties are carried over so nothing is lost.
    for old, new in LEGACY_REL_RENAMES:
        try:
            moved = _run_batched(
                session,
                f"MATCH (a)-[r:`{old}`]->(b) WITH a, r, b LIMIT {MIGRATION_BATCH} "
                f"CREATE (a)-[n:`{new}`]->(b) SET n = properties(r) "
                f"DELETE r RETURN count(r) AS c")
            if moved:
                print(f"[graph-db] migrated {moved} {old} -> {new}")
        except Exception as e:
            print(f"[!][graph-db] relationship migration {old} -> {new} failed: {e}")
            ok = False

    if ok:
        _mark_migration_applied(session)
    else:
        print("[!][graph-db] migration incomplete; it will be retried on the "
              "next connection (no marker written)")



# Every node write now stamps `updated_at`, but nodes written before that do not
# carry it, and several labels never did: Package and MalPackageFinding stamp
# first_seen/last_seen, the attack-chain labels stamp created_at. Those are the
# rows the graph tables render as blank, and on a real graph Package alone is
# the single largest label.
#
# Seeded from whichever write time the node DOES hold, newest-meaning first. A
# node with none of them is left null rather than stamped "now": an invented
# timestamp is worse than an honest blank, because it would claim the node was
# touched by a scan that never saw it.
UPDATED_AT_BACKFILL_MARKER = "backfill-updated-at-v1"
UPDATED_AT_SOURCES = ("last_seen", "created_at", "first_seen")

# Certificate re-key backfill: existing nodes have no cert_key and would escape
# the new uniqueness constraint. Runs in the pre-DDL block (a uniqueness
# constraint on the new key cannot be satisfied while data lacks it) and is
# guarded by a marker so the steady-state cost is one lookup, not a full
# Certificate scan on every client construction.
CERT_KEY_BACKFILL_MARKER = "backfill-cert-key-v1"


def backfill_updated_at(session):
    """Give pre-existing nodes an `updated_at` from their other write time."""
    if _migration_applied(session, UPDATED_AT_BACKFILL_MARKER):
        return

    ok = True
    total = 0
    for prop in UPDATED_AT_SOURCES:
        try:
            moved = _run_batched(
                session,
                f"MATCH (n) WHERE n.updated_at IS NULL AND n.`{prop}` IS NOT NULL "
                f"WITH n LIMIT {MIGRATION_BATCH} "
                f"SET n.updated_at = n.`{prop}` RETURN count(n) AS c")
            total += moved
            if moved:
                print(f"[graph-db] backfilled updated_at on {moved} node(s) from {prop}")
        except Exception as e:
            print(f"[!][graph-db] updated_at backfill from {prop} failed: {e}")
            ok = False

    if ok:
        _mark_migration_applied(session, UPDATED_AT_BACKFILL_MARKER)
        if total:
            print(f"[graph-db] updated_at backfill complete: {total} node(s)")
    else:
        print("[!][graph-db] updated_at backfill incomplete; retried on the "
              "next connection (no marker written)")


# CVE, MitreData and Capec are GLOBAL reference nodes: UNIQUE on their natural
# id, one node per CVE for the whole database, shared by every project that
# finds it. Several writers nevertheless stamped user_id/project_id on them via
# `SET +=`, so the LAST project to touch a CVE became its owner — and every
# project-scoped delete (a recon re-run, a project deletion, a scan-version
# restore) then removed the shared node and every OTHER project's links to it.
#
# Observed live before the fix: 4 CVE nodes stamped with one project were linked
# by INCLUDES_CVE from a second one.
#
# The writers no longer stamp. This strips the stamps already on disk, so the
# project-scoped deletes stop matching them.
# Labels owned by a scanner OTHER than the recon pipeline. A recon re-run wipes
# and rebuilds recon's own view of the target; it must not take these with it.
# Each of these subsystems already has its own scoped clear, run at the head of
# its own ingest — recon was the last one still deleting everything.
#
# ADDING A SCANNER: put its labels here, or the first recon run after it lands
# will delete its findings with no error anywhere.
NON_RECON_LABELS = (
    # GitHub Secret Hunt
    "GithubHunt", "GithubRepository", "GithubPath", "GithubSecret",
    "GithubSensitiveFile",
    # Secret Multiscanner (TruffleHog)
    "MultiscannerScan", "MultiscannerFinding", "MultiscannerRepository",
    "MultiscannerImage", "MultiscannerModel", "MultiscannerBucket",
    "MultiscannerEndpoint",
    # Supply chain
    "Package", "MalPackageFinding", "SbomDocument",
    # Agent attack chains (session state, not recon output)
    "AttackChain", "ChainStep", "ChainFinding", "ChainDecision", "ChainFailure",
    # GVM
    "ExploitGvm", "Traceroute",
    # Knowledge base
    "KBChunk",
)

# `source` values on the labels recon SHARES with another scanner — chiefly
# Vulnerability, which GVM, the supply-chain scanner and the AI attack-surface
# scanner all write into. Nodes carrying one of these belong to that scanner.
# The mirror image of clear_gvm_data, which deletes only `source = 'gvm'`.
NON_RECON_SOURCES = (
    "gvm",                      # GVM
    "osv",                      # supply chain
    "garak", "promptfoo",       # AI attack surface findings
    "ai_attack_target",         # ...and the synthetic target nodes they hang off
)

REFERENCE_TENANT_STRIP_MARKER = "strip-reference-node-tenant-v1"
GLOBAL_REFERENCE_LABELS = ("CVE", "MitreData", "Capec")


def strip_reference_node_tenant(session):
    """Remove user_id/project_id from the global reference labels."""
    if _migration_applied(session, REFERENCE_TENANT_STRIP_MARKER):
        return

    ok = True
    total = 0
    for label in GLOBAL_REFERENCE_LABELS:
        try:
            stripped = _run_batched(
                session,
                f"MATCH (n:`{label}`) "
                f"WHERE n.user_id IS NOT NULL OR n.project_id IS NOT NULL "
                f"WITH n LIMIT {MIGRATION_BATCH} "
                f"REMOVE n.user_id, n.project_id RETURN count(n) AS c")
            total += stripped
            if stripped:
                print(f"[graph-db] unstamped {stripped} {label} node(s)")
        except Exception as e:
            print(f"[!][graph-db] {label} tenant strip failed: {e}")
            ok = False

    if ok:
        _mark_migration_applied(session, REFERENCE_TENANT_STRIP_MARKER)
        if total:
            print(f"[graph-db] reference-node tenant strip complete: {total} node(s)")
    else:
        print("[!][graph-db] reference-node tenant strip incomplete; retried on "
              "the next connection (no marker written)")


def backfill_cert_key(session):
    """Give pre-existing Certificate nodes a cert_key and one fingerprint name.

    Two steps, both idempotent and both careful NOT to touch updated_at (the
    unseen-rows badge counts nodes stamped after the user's watermark; bumping it
    here would light the badge for every existing certificate in every project).

    1. Consolidate the three historical fingerprint spellings
       (sha256_fingerprint from GVM, fingerprint from Censys) onto the single
       name fingerprint_sha256.
    2. Assign a unique legacy cert_key to every node still missing one. The key
       is suffixed with the node id so two certs that once collided on subject_cn
       cannot collide again here and block constraint creation. Legacy rows keep
       this degraded key until their next scan re-MERGEs them on a real key; the
       cert writers reconcile the resulting duplicate by subject_cn.
    """
    if _migration_applied(session, CERT_KEY_BACKFILL_MARKER):
        return

    ok = True
    try:
        moved = _run_batched(
            session,
            "MATCH (c:Certificate) "
            "WHERE c.fingerprint_sha256 IS NULL "
            "AND (c.sha256_fingerprint IS NOT NULL OR c.fingerprint IS NOT NULL) "
            f"WITH c LIMIT {MIGRATION_BATCH} "
            "SET c.fingerprint_sha256 = coalesce(c.sha256_fingerprint, c.fingerprint) "
            "RETURN count(c) AS c")
        if moved:
            print(f"[graph-db] consolidated fingerprint on {moved} certificate(s)")
    except Exception as e:
        print(f"[!][graph-db] certificate fingerprint consolidation failed: {e}")
        ok = False

    try:
        keyed = _run_batched(
            session,
            "MATCH (c:Certificate) WHERE c.cert_key IS NULL "
            f"WITH c LIMIT {MIGRATION_BATCH} "
            "SET c.cert_key = 'legacy:' + coalesce(c.subject_cn, '') + ':' + toString(id(c)) "
            "RETURN count(c) AS c")
        if keyed:
            print(f"[graph-db] backfilled cert_key on {keyed} certificate(s)")
    except Exception as e:
        print(f"[!][graph-db] cert_key backfill failed: {e}")
        ok = False

    if ok:
        _mark_migration_applied(session, CERT_KEY_BACKFILL_MARKER)
    else:
        print("[!][graph-db] cert_key backfill incomplete; retried on the next "
              "connection (no marker written)")


def init_schema(session):
    """
    Initialize constraints and indexes for the graph schema.

    Safe to call multiple times — all statements use IF NOT EXISTS / IF EXISTS guards.
    """
    # Before the DDL: the new constraints cannot be created while data still
    # carries the old labels.
    migrate_legacy_labels(session)
    backfill_updated_at(session)
    strip_reference_node_tenant(session)
    backfill_cert_key(session)

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
