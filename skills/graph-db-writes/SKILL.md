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
  version: "1.0.0"
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
  enrichment fields. Reference: [graph_db/mixins/graphql_mixin.py:189](../../graph_db/mixins/graphql_mixin.py#L189).
- **NEVER collect a field in a tool and not write it to the graph.** Every field
  in the tool's output dict must land on a node property or relationship, or it is
  silent data loss. If it fits no node, map it to the closest property or say why it is dropped.
- **NEVER delete a finding a person has touched, and NEVER clear findings up
  front.** A scan MERGEs its findings (which refreshes `updated_at`) and
  afterwards prunes the ones it did not touch - ingest-then-prune, never
  clear-then-ingest. A half-failed scan that reported nothing would otherwise
  empty the project, so the CALLER decides whether to prune and only does so
  after an ingest that actually produced findings. Muted nodes and ones carrying
  `triage_source = 'human'` are never deleted, only stamped `stale_since`: they
  hold an operator's mute, verdict and the fix items written against them.
  Reference: `prune_unseen_findings` in
  [graph_db/mixins/base_mixin.py](../../graph_db/mixins/base_mixin.py), and the
  four clears that spare them.
- **NEVER write an unscoped `MATCH` for an entity node.** Uniqueness is the
  `(id, user_id, project_id)` triple, so a natural id is NOT unique across the
  database and `MATCH (n {id: $id})` can read or write another project's node.
  Every read and write carries `user_id`/`project_id`; agent-facing queries go
  through `scope_query`, never `inject_tenant_filter` alone.
- **ALWAYS reuse an existing node label before inventing one.** Discovered
  hostnames are `Subdomain`, not a new label. Check [docs/readmes/GRAPH.SCHEMA.md](../../docs/readmes/GRAPH.SCHEMA.md) first.
- **ALWAYS sync the schema when you add a label / relationship / property.** Update
  [docs/readmes/GRAPH.SCHEMA.md](../../docs/readmes/GRAPH.SCHEMA.md), the `TEXT_TO_CYPHER_SYSTEM`
  prompt at [agentic/prompts/base.py:1451](../../agentic/prompts/base.py#L1451)
  (or the agent generates wrong Cypher and cannot see the new data), and
  `NODE_COLORS` in [webapp/src/app/graph/config/colors.ts](../../webapp/src/app/graph/config/colors.ts).

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

- [docs/readmes/GRAPH.SCHEMA.md](../../docs/readmes/GRAPH.SCHEMA.md) - canonical node/relationship schema and MERGE keys
- [graph_db/neo4j_client.py](../../graph_db/neo4j_client.py) - the mixin MRO (do not edit; edit a mixin)
- Related skill: `recon-tool-integration`
