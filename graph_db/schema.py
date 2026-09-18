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

# Uniqueness constraints, GENERATED from the single label-key declaration in
# schema_keys.py. They used to be 45 hand-written strings here, which meant a new
# node label had to be added in two places - the constraint list and the schema
# documentation - and forgetting either failed silently: no error, just a label
# the agent could never query or a MERGE with no uniqueness guarantee.
#
# tests/test_schema_constraints_generated.py asserts the generated statements are
# byte-identical to the frozen originals, so this is a refactor of WHERE the
# declaration lives, never of what the database gets.
#
# The import is INSIDE the function, not at module level. `graph_db/__init__.py`
# imports the client, which imports base_mixin, which imports THIS module - so a
# module-level `from graph_db.schema_keys import ...` re-enters the package while
# schema.py is only partway executed, and `init_schema` (defined further down) is
# not yet bound. The failure surfaces as a confusing
# "cannot import name 'init_schema' from 'graph_db.schema'".


def _sibling(name):
    """A sibling module of graph_db, however this module was loaded.

    Tests load schema.py BY PATH, with neither `graph_db` importable as a
    package nor its directory on sys.path, so both import forms fail there.
    Resolving the sibling file relative to __file__ works in every case: as a
    package member, as a bare module, and as a path-loaded one.
    """
    import importlib

    try:
        return importlib.import_module(f"graph_db.{name}")
    except ImportError:
        pass

    import importlib.util
    import os

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{name}.py")
    spec = importlib.util.spec_from_file_location(f"_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _key_constraints():
    """The label-key declaration, however this module was loaded."""
    try:
        from graph_db.schema_keys import KEY_CONSTRAINTS

        return KEY_CONSTRAINTS
    except ImportError:
        return _sibling("schema_keys").KEY_CONSTRAINTS


def build_constraints() -> list:
    """Render CREATE CONSTRAINT statements from the label-key declaration."""
    out = []
    for k in _key_constraints():
        keys = ", ".join(f"{k['var']}.{p}" for p in k["key_properties"])
        inner = f"({keys})" if len(k["key_properties"]) > 1 else keys
        out.append(
            f"CREATE CONSTRAINT {k['constraint']} IF NOT EXISTS "
            f"FOR ({k['var']}:{k['label']}) REQUIRE {inner} IS UNIQUE"
        )
    return out


def __getattr__(name):
    """Defer CONSTRAINTS until first use (PEP 562).

    Building it at module level would run the schema_keys import during the
    circular-import window described above. Every consumer reads it inside
    init_schema or a test, long after the package has finished loading.
    """
    if name == "CONSTRAINTS":
        value = build_constraints()
        globals()["CONSTRAINTS"] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

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


TECH_IDENTITY_MARKER = "technology-identity-v1"


def consolidate_technology_identity(session):
    """Fold the Technology duplicates written before the writers resolved
    identity (see technology_identity.fold_technology_duplicates).

    A node kept because it holds a relationship type the fold does not know
    does not block the marker: a retry would meet the same edge. Only an error
    leaves the marker unwritten.
    """
    if _migration_applied(session, TECH_IDENTITY_MARKER):
        return

    try:
        stats = _sibling("technology_identity").fold_technology_duplicates(session)
    except Exception as e:
        print(f"[!][graph-db] Technology identity fold incomplete; retried on the "
              f"next connection (no marker written): {e}")
        return

    _mark_migration_applied(session, TECH_IDENTITY_MARKER)
    if stats["folded"] or stats["versioned"]:
        print(f"[graph-db] Technology identity: folded {stats['folded']} duplicate(s), "
              f"gave {stats['versioned']} versionless node(s) version ''")


RESOLVES_TO_DEDUPE_MARKER = "resolves-to-edge-identity-v1"


def dedupe_resolves_to(session):
    """Fold duplicate Subdomain -> IP edges without crossing tenants.

    Older writers put properties inside the relationship MERGE pattern, so
    the same node pair could accumulate one RESOLVES_TO edge per property map.
    Keep one edge per tenant-scoped node pair and union every relationship
    property map into it before deleting the duplicates.
    """
    if _migration_applied(session, RESOLVES_TO_DEDUPE_MARKER):
        return

    try:
        deduped = _run_batched(
            session,
            f"""
            MATCH (s:Subdomain)-[rels:RESOLVES_TO]->(i:IP)
            WHERE s.user_id IS NOT NULL
              AND s.project_id IS NOT NULL
              AND s.user_id = i.user_id
              AND s.project_id = i.project_id
            WITH s, i, collect(rels) AS rels
            WHERE size(rels) > 1
            WITH head(rels) AS keep, tail(rels) AS duplicates
            LIMIT {MIGRATION_BATCH}
            FOREACH (r IN duplicates | SET keep += properties(r))
            FOREACH (r IN duplicates | DELETE r)
            RETURN count(keep) AS c
            """,
        )
        _mark_migration_applied(session, RESOLVES_TO_DEDUPE_MARKER)
        if deduped:
            print(f"[graph-db] folded {deduped} duplicate RESOLVES_TO edge group(s)")
    except Exception as e:
        print(f"[!][graph-db] RESOLVES_TO dedupe incomplete; retried on the next "
              f"connection (no marker written): {e}")


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
    consolidate_technology_identity(session)
    dedupe_resolves_to(session)

    for stmt in DROP_LEGACY_CONSTRAINTS:
        try:
            session.run(stmt)
        except Exception:
            pass

    # build_constraints() rather than the module global: PEP 562 __getattr__
    # only intercepts attribute access from OUTSIDE, so a bare name here would
    # raise NameError.
    for query in build_constraints() + TENANT_INDEXES + ADDITIONAL_INDEXES:
        try:
            session.run(query)
        except Exception as e:
            # Ignore if constraint/index already exists
            if "already exists" not in str(e).lower():
                print(f"[!][graph-db] Schema warning: {e}")
