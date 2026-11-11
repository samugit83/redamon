---
name: graph-db-writes
description: >
  Writing to the Neo4j attack-surface graph in RedAmon: the tenant-isolation
  MERGE key every entity node must carry, where graph methods live (mixins, not
  the client), and the schema places that must be updated together. A MERGE
  missing the tenant key silently merges one project's data into another's.
  Trigger: editing anything under graph_db/mixins/; adding or changing an
  update_graph_from_* method; writing a Cypher MERGE/CREATE that adds a node,
  relationship or property; adding a new node label to the graph.
license: MIT
metadata:
  author: redamon
  version: "1.2.0"
  scope: [root]
  auto_invoke:
    - "Writing to the Neo4j graph or editing a graph_db mixin"
    - "Adding a node label, relationship, or property to the graph schema"
---

## When to Use

- Adding or changing any Cypher that writes nodes/relationships/properties, in a
  `graph_db` mixin or a scan tool that persists to the graph.

For placing a whole new recon tool (which includes its graph write), use
`recon-tool-integration`; this skill is the
graph-write rules it depends on.

---

## Critical Rules

- **NEVER add the tenant key to a reference node, and NEVER omit it from an entity
  node.** Entity nodes (per-project findings) MERGE on
  `{<natural_key>, user_id, project_id}` - the tenant-isolation triple. A MERGE
  missing `user_id`/`project_id` **merges one project's data into another's**,
  silently. Global reference nodes (e.g. `CVE`) key on their natural id **only**
  (`MERGE (c:CVE {id: $cve_id})`); adding tenant keys there fragments shared data.
- **NEVER edit [graph_db/neo4j_client.py](../../graph_db/neo4j_client.py) directly.**
  It is a thin orchestrator that combines the mixins by inheritance. Graph methods
  live in the mixin for their domain (see the table below).
- **NEVER unconditionally `SET` a field another tool owns.** Use `ON CREATE SET`
  for provenance/first-writer fields (e.g. `source`) so a later tool merging the
  same node does not clobber them; use plain `SET` only for this tool's own
  enrichment fields. Reference: the `ON CREATE SET bu.source = 'graphql_scan'` merges in
  [graph_db/mixins/graphql_mixin.py](../../graph_db/mixins/graphql_mixin.py).
- **NEVER collect a field in a tool and not write it to the graph.** Every field
  in the tool's output dict must land on a node property or relationship, or it is
  silent data loss. If it fits no node, map it to the closest property or say why it is dropped.
- **NEVER put a map, or a list of maps, in a property.** Neo4j rejects it, so
  `SET v += $props` fails the whole node write and the mixin's per-finding
  `except` turns that into a silently dropped finding. Flatten first: nuclei's
  `cves` arrive as `{id,cvss,url}` maps and are stored as id strings via
  `nuclei_cve_ids` in [graph_db/mixins/recon/vuln_mixin.py](../../graph_db/mixins/recon/vuln_mixin.py).
- **NEVER delete a finding a person has touched, and NEVER clear findings up
  front.** A scan MERGEs its findings (which refreshes `updated_at`) and
  afterwards prunes the ones it did not touch - ingest-then-prune, never
  clear-then-ingest. A half-failed scan that reported nothing would otherwise
  empty the project, so the CALLER decides whether to prune and only does so
  after an ingest that actually produced findings. Nodes an operator muted and
  ones carrying `triage_source = 'human'` are never deleted, only stamped
  `stale_since`: they hold an operator's mute, verdict and the fix items written
  against them. A mute a node-filter RULE applied (`muted_by` starting `rule:`)
  is not a person's decision and is pruned like any stale finding.
  Reference: `prune_unseen_findings` in
  [graph_db/mixins/base_mixin.py](../../graph_db/mixins/base_mixin.py), and the
  four clears that spare them. A delete that spares muted findings takes the
  node's write lock (`SET n._prune_lock = true REMOVE n._prune_lock`) BEFORE it
  reads `n:Muted`, or a mute committing in between is deleted with the node.
  An external agent's MCP mute keeps the owner's id in `muted_by`, so it is kept
  like a person's; its `muted_channel`/`muted_token` stamp must be REMOVEd by
  every unmute and cleared by every other mute, or a later mute inherits it.
- **NEVER prune a source or host the run could not re-check (circuit breakers).**
  When a data provider was paused or a scan host was skipped, "not seen this run"
  does NOT mean "gone". The caller passes `keep_hosts` (anchored regexes, matched
  against `_KEEP_HOST_FIELDS` with `toStringOrNull`, passed as a Cypher parameter)
  to `prune_unseen_findings`, and skips the prune entirely for a degraded source.
  A finding that names hosts in a list (`source_urls`) is matched on every
  element too (`_KEEP_HOST_LIST_FIELDS`): `toStringOrNull` of a list is null, so
  a list field missing from that tuple keeps nothing. Host names may contain `_`
  (`_dmarc.example.com`); the coverage accumulator and `_KEEP_HOST_CHARS` must
  keep accepting it, or such a host drops out of every note.
  What was cut is recorded on the coverage record of the **org** `Domain` (one per
  registrable domain), merged across the run's groups of that org —
  `recon_coverage_at`, `recon_coverage_gaps` (each entry tagged with its scan
  `root`), `recon_skipped_hosts`, `recon_nuclei_truncated`, `recon_coverage_roots`
  and `recon_coverage_run` (written by `update_graph_coverage` in
  [graph_db/mixins/recon/domain_mixin.py](../../graph_db/mixins/recon/domain_mixin.py),
  one locked unit of work: the first group of a run overwrites, later ones merge).
  They are in the webapp's `VOLATILE_PROPERTIES`, so they never make a `Domain`
  read as "changed" in the Recon Delta.
- **ALWAYS give a new host-bound prune source positive coverage.** Record the
  hosts it actually re-checked with `circuit_breaker.note_checked(source,
  hosts=[...], checks=[...])` (a 09.1 coverage record does it through
  `coverage_stamps.note_rows_checked`): the prune then deletes its findings only
  on those hosts (`prune_unseen_findings(..., only_hosts=, types=)`), so a host
  it never reached keeps its findings even when nobody called `note_degraded`.
  Degraded still wins. Skip it when switched off by configuration, and for a
  source whose findings carry no host field. A host the source's own filter
  dropped before asking (a CDN edge, a private address) was decided, not
  skipped: record it as checked (`note_cve_coverage(considered=...)` in
  [passive_cve_coverage.py](../../recon/helpers/passive_cve_coverage.py) does
  this for the passive CVE lookups). A source that records only some of
  its finding types (`checks=`, as `security_check` does for its DNS and service
  probes) also gets one source-level prune for every other type
  (`_checked_prune_batches` passes `exclude_types=`), so the types it does not
  record still prune as before.
- **NEVER queue a background writer of findings without a `_WRITER_SOURCES`
  row** in [recon/main.py](../../recon/main.py) naming the
  `_PHASE_FINDING_SOURCES` phase whose sources it writes. A finding the write
  did not MERGE keeps last run's `updated_at`, so the prune reads it as gone;
  with the row, a writer that raises, reports an item error, finds Neo4j
  unreachable or is never queued notes those sources degraded
  (`graph write failed (<writer>)`), which wins over `note_checked`. A writer
  of assets only goes in the test's `ASSET_ONLY` instead:
  `recon/tests/test_graph_writer_failures.py` fails a queued writer in neither.
- **NEVER attach to `Domain {name: <scan root>}`.** A writer decides scope and
  attach separately (`graph_db/mixins/recon/scope.py`): `scan_root_for_host` /
  `attach_for_host` say whether a host is in scope, and `org_for_scan_root` names
  the Domain it hangs off. A deeper scan root that is a target is
  `Subdomain {is_scan_root: true}`, never a Domain; only
  `update_graph_from_domain_discovery`, `update_graph_from_ip_recon` and
  `ensure_root_domains` may MERGE a Domain (`tests/test_no_stray_domain_merge.py`).
- **NEVER write an unscoped `MATCH` for an entity node.** Uniqueness is the
  `(id, user_id, project_id)` triple, so a natural id is NOT unique across the
  database and `MATCH (n {id: $id})` can read or write another project's node.
  Every read and write carries `user_id`/`project_id`; agent-facing queries go
  through `scope_query`, never `inject_tenant_filter` alone.
- **ALWAYS reuse an existing node label before inventing one.** Discovered
  hostnames are `Subdomain`, not a new label. Check
  [graph_db/schema_sections.md](../../graph_db/schema_sections.md) first - that
  is the single declaration of every label, property and relationship.
- **ALWAYS declare a new label / relationship / property in ONE place**:
  [graph_db/schema_sections.md](../../graph_db/schema_sections.md), then re-seed
  with `python3 tooling/scripts/seed_schema_catalog.py`. A uniqueness key also
  goes in [graph_db/schema_keys.py](../../graph_db/schema_keys.py), from which
  `schema.py` renders its `CREATE CONSTRAINT` statements.
  Do NOT copy the schema into the prompt or into GRAPH.SCHEMA.md: the prompt
  splices the catalog in at `__GRAPH_SCHEMA__`, and GRAPH.SCHEMA.md deliberately
  no longer lists labels at all. Three copies is what drifted, and four tests
  now fail if you make a fourth.
  Editing or removing a line there fails
  `test_the_composed_document_still_contains_the_baseline` in
  [recon/tests/test_schema_catalog.py](../../recon/tests/test_schema_catalog.py)
  (additions pass: it is a CONTAINS check, so a stale golden file can sit
  unnoticed). Refresh the fixture in the same commit with the command in that
  test's docstring, then read the fixture diff.
  Still update `NODE_COLORS` in
  [webapp/src/app/graph/config/colors.ts](../../webapp/src/app/graph/config/colors.ts),
  which is presentation, not schema.

---

## MERGE: the copy target

```cypher
// entity node - tenant-scoped: the {natural key, user_id, project_id} triple is mandatory
MERGE (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})
  ON CREATE SET bu.source = 'graphql_scan', bu.updated_at = datetime()   // provenance: first writer only
MERGE (e:Endpoint {path: $path, method: 'POST', baseurl: $baseurl, user_id: $user_id, project_id: $project_id})
  ON CREATE SET e.source = 'graphql_scan'
  SET e += $props                                                        // this tool's own enrichment fields
MERGE (bu)-[:HAS_ENDPOINT]->(e)

// reference node - global: natural id only, NO tenant key
MERGE (c:CVE {id: $cve_id})
```

Copied from [graph_db/mixins/graphql_mixin.py](../../graph_db/mixins/graphql_mixin.py).

## Which mixin

| Writing | Mixin |
| --- | --- |
| core recon phases (subdomains, IPs, ports, HTTP, endpoints) | [recon_mixin.py](../../graph_db/mixins/recon_mixin.py) |
| passive OSINT enrichment | [osint_mixin.py](../../graph_db/mixins/osint_mixin.py) |
| secrets / credentials | [secret_mixin.py](../../graph_db/mixins/secret_mixin.py) |
| vuln scan (GVM) | [gvm_mixin.py](../../graph_db/mixins/gvm_mixin.py) |
| GraphQL probes | [graphql_mixin.py](../../graph_db/mixins/graphql_mixin.py) |
| supply-chain packages | [supply_chain_mixin.py](../../graph_db/mixins/supply_chain_mixin.py) |

## Resources

- [graph_db/schema_sections.md](../../graph_db/schema_sections.md) - THE declaration: every label, property and relationship
- [graph_db/schema_keys.py](../../graph_db/schema_keys.py) - each label's uniqueness key; schema.py renders its constraints from it
- [docs/readmes/GRAPH.SCHEMA.md](../../docs/readmes/GRAPH.SCHEMA.md) - the rationale: design principles, tenancy strategy, the Muted label. No longer lists labels
- [graph_db/neo4j_client.py](../../graph_db/neo4j_client.py) - the mixin MRO (do not edit; edit a mixin)
- Related skill: `recon-tool-integration`
