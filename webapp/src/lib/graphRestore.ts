/**
 * Shared Neo4j restore - rebuild a project subgraph from the export/snapshot
 * format `{labels, properties}` + `{startExportId, endExportId, type, properties}`.
 *
 * Extracted from the project import route so version activation (Scan Timeline
 * Section 4A) reuses the exact same, already-proven code path. That is also why
 * snapshots are stored in export fidelity rather than the lossy render shape.
 *
 * Strategy (unchanged from import):
 *   - group nodes by primary label,
 *   - MERGE on the label's uniqueness constraint keys when it has any (avoids
 *     IndexEntryConflictException), CREATE otherwise,
 *   - batch with UNWIND,
 *   - recreate relationships by the temporary `_exportId`, then strip it.
 *
 * Tenancy: `project_id` is ALWAYS stamped from the caller's argument (never taken
 * from the payload), so a restore can only ever write into the target project.
 * Every MERGE also matches on it, and the agent-session nodes get fresh ids
 * (`freshSessionIds`), so a restore never matches a node of another project.
 */
import { createHash, randomUUID } from 'crypto'
import { DateTime, type Session } from 'neo4j-driver'
import { functionalLabel } from '@/lib/scanSnapshot'
import { carriedReferenceEdgesToLinks, isReferenceNode, restoreReferenceLinks } from '@/lib/graphReferenceLinks'

/**
 * Derive a Certificate `cert_key` for a snapshot node that predates the re-key
 * (Phase 0.2). Mirrors graph_db/cert_key.build_cert_key exactly: fingerprint
 * wins, else a surrogate over subject_cn|issuer|not_before|not_after. Without
 * this, activating an old version restores every Certificate with a null key and
 * they collapse into one node (or the restore throws IndexEntryConflict) AFTER
 * clearProjectGraph has already wiped the live graph — irreversible loss.
 */
export function deriveCertKey(props: Record<string, unknown>): string {
  const fp = typeof props.fingerprint_sha256 === 'string' && props.fingerprint_sha256
    ? props.fingerprint_sha256
    : (typeof props.sha256_fingerprint === 'string' ? props.sha256_fingerprint : '')
        || (typeof props.fingerprint === 'string' ? props.fingerprint : '')
  if (fp) return 'sha256:' + fp.trim().toLowerCase()
  const s = (k: string) => (typeof props[k] === 'string' ? (props[k] as string) : '')
  const surrogate = `${s('subject_cn')}|${s('issuer')}|${s('not_before')}|${s('not_after')}`
  return 'surrogate:' + createHash('sha1').update(surrogate).digest('hex').slice(0, 32)
}

export interface RestorableNode {
  labels: string[]
  properties: Record<string, unknown>
  _exportId: string
}

export interface RestorableRelationship {
  startExportId: string
  endExportId: string
  type: string
  properties: Record<string, unknown>
}

export interface RestoreOptions {
  /** Target project. Always stamped onto every restored node. */
  projectId: string
  /** When set, re-owns every node (import). When omitted, each node keeps its own user_id. */
  userId?: string
  nodeBatchSize?: number
  relBatchSize?: number
  /** Link records to the global reference catalogue (graphReferenceLinks.ts); untrusted input. */
  referenceLinks?: readonly unknown[]
  /**
   * The chain id to give each exported one. A chain id is its conversation's session
   * id, which the import renames; without an entry a chain gets a fresh id.
   */
  renamedChainIds?: ReadonlyMap<string, string>
}

export interface RestoreResult {
  nodes: number
  relationships: number
  /** Present when link records were given: those re-linked, and those skipped. */
  referenceLinks?: { restored: number; skipped: number }
}

const DEFAULT_NODE_BATCH = 500
const DEFAULT_REL_BATCH = 500

/**
 * Global reference labels: the public NVD/MITRE catalogue. One node per CVE for
 * the WHOLE database, shared by every project that finds it, so it must never
 * be removed along with a project — doing so deleted other projects' links to
 * it. Kept in step with GLOBAL_REFERENCE_LABELS in graph_db/schema.py.
 */
export const GLOBAL_REFERENCE_LABELS = ['CVE', 'MitreData', 'Capec'] as const

/**
 * Drop reference nodes no project can reach any more.
 *
 * The other half of excluding them from the wipe above, and it must test
 * REACHABILITY rather than degree. The catalogue is internally linked as
 * `CVE -[:HAS_CWE]-> MitreData -[:HAS_CAPEC]-> Capec`, so an unreferenced CVE
 * still holds its CWE and a degree-zero test never fires — the nodes would
 * accumulate forever. Nor is "no non-reference neighbour" enough: that would
 * delete a MitreData whose CVE is still live. Mirrors
 * `_sweep_orphan_reference_nodes` in graph_db/mixins/base_mixin.py.
 */
const REFERENCE_CHAIN_DEPTH = 3

export async function sweepOrphanReferenceNodes(session: Session): Promise<void> {
  const isRef = (v: string) =>
    GLOBAL_REFERENCE_LABELS.map(l => `${v}:\`${l}\``).join(' OR ')
  await session.run(
    `MATCH (n) WHERE (${isRef('n')})
       AND NOT EXISTS {
         MATCH (n)-[*1..${REFERENCE_CHAIN_DEPTH}]-(x) WHERE NOT (${isRef('x')})
       }
     DETACH DELETE n`
  )
}

/**
 * Delete a project's graph. `excludeLabels` keeps nodes that are NOT part of the
 * recon version - notably the AttackChain family, which is agent-session state
 * and must survive a version swap (F1).
 *
 * Global reference nodes are always excluded, then swept if orphaned. A caller
 * that restores a graph next passes `sweep: false` and sweeps after its restore:
 * swept in between, a CVE only this project linked is gone before the restore
 * can link it back.
 */
export async function clearProjectGraph(
  session: Session,
  projectId: string,
  excludeLabels: readonly string[] = [],
  opts: { sweep?: boolean } = {}
): Promise<void> {
  const excluded = [...new Set([...excludeLabels, ...GLOBAL_REFERENCE_LABELS])]
  await session.run(
    `MATCH (n {project_id: $pid})
     WHERE NONE(l IN labels(n) WHERE l IN $excluded)
     DETACH DELETE n`,
    { pid: projectId, excluded }
  )
  if (opts.sweep !== false) await sweepOrphanReferenceNodes(session)
}

/**
 * The id each agent-session label (scanSnapshot SESSION_LABELS) is unique on, ALONE:
 * graph_db/schema_keys.py keys them without the tenant, and the agent refuses to write
 * a chain id another project holds (`_chain_held_elsewhere`). Checked against that file
 * by graphRestore.globalIds.test.ts.
 */
export const SESSION_ID_KEYS: Readonly<Record<string, string>> = {
  AttackChain: 'chain_id',
  ChainStep: 'step_id',
  ChainFinding: 'finding_id',
  ChainDecision: 'decision_id',
  ChainFailure: 'failure_id',
}

/**
 * Give every agent-session node its own new id, in place on `nodes` (copies the
 * caller made). Restored under the exported ids, an import into the database that
 * still holds the source project MERGEd onto the source's chain nodes, re-stamped
 * them into the import, and the import's delete removed them (R-15); without a
 * constraint it left one chain id in two projects, and the agent then refused every
 * write to the source's chain. Each old id maps to one new id, so the `chain_id` a
 * step, finding, decision or failure carries follows its chain. Edges are wired by
 * `_exportId`, which this leaves alone.
 */
function freshSessionIds(
  nodes: ReadonlyArray<{ labels: string[]; properties: Record<string, unknown> }>,
  renamedChainIds: ReadonlyMap<string, string> = new Map()
): void {
  const fresh = new Map<string, string>()
  const remap = (key: string, old: unknown): string => {
    if (typeof old !== 'string' || old === '') return randomUUID()
    const slot = `${key}\u0000${old}`
    let id = fresh.get(slot)
    if (!id) {
      id = (key === 'chain_id' ? renamedChainIds.get(old) : undefined) ?? randomUUID()
      fresh.set(slot, id)
    }
    return id
  }
  for (const node of nodes) {
    const label = node.labels.find(l => l in SESSION_ID_KEYS)
    if (!label) continue
    const key = SESSION_ID_KEYS[label]
    node.properties[key] = remap(key, node.properties[key])
    if (key !== 'chain_id' && typeof node.properties.chain_id === 'string' && node.properties.chain_id) {
      node.properties.chain_id = remap('chain_id', node.properties.chain_id)
    }
  }
}

/** Uniqueness-constraint keys per label, used to choose MERGE vs CREATE. */
async function loadUniqueKeys(session: Session): Promise<Map<string, string[]>> {
  const result = await session.run(
    `SHOW CONSTRAINTS YIELD labelsOrTypes, properties, type
     WHERE type = 'UNIQUENESS'
     RETURN labelsOrTypes[0] AS label, properties`
  )
  const map = new Map<string, string[]>()
  for (const record of result.records) {
    map.set(record.get('label') as string, record.get('properties') as string[])
  }
  return map
}

/**
 * Properties an earlier release wrote and nothing writes any more, per label
 * (`*` = every label). A scan version saved before they were retired, or a
 * project exported then, would bring them back.
 *
 * - every label: OpenAPI declarations stored as JSON (up to 1 MiB per
 *   Endpoint), the Domain import summary and stamp, and a transaction-local lock;
 * - `Domain`: the flat per-run props of the scan-root Domain (§4.11.3). The
 *   Domain is now the org, shared by several scan roots, so one run's
 *   `filtered_mode` or `target` would describe only one of them. Per label on
 *   purpose: `GithubHunt.target` and `MultiscannerScan.target` are live, and an
 *   IP-mode Domain keeps its own `scan_type` and `modules_executed`.
 */
export const RETIRED_NODE_PROPERTIES_BY_LABEL: Readonly<Record<string, readonly string[]>> = {
  '*': ['openapi_declarations', 'openapi_summary', 'openapi_last_import_at', '_openapi_write_lock'],
  Domain: ['target', 'filtered_mode', 'wildcard_mode', 'subdomain_filter', 'modules_executed',
    'anonymous_mode', 'bruteforce_mode', 'scan_type'],
}

/** The retired properties to drop from one node. */
export function retiredPropertiesFor(labels: readonly string[], properties: Record<string, unknown>): string[] {
  const out = [...RETIRED_NODE_PROPERTIES_BY_LABEL['*']]
  if (labels.includes('Domain') && properties.ip_mode !== true) out.push(...RETIRED_NODE_PROPERTIES_BY_LABEL.Domain)
  return out
}

/**
 * Node properties every RedAmon writer stores as a Neo4j DateTime, which the
 * export flattens to `YYYY-MM-DDTHH:MM:SSZ` (graphSerialize.ts). Written back
 * as strings, the recon prune never matched them (R-38): a restored finding was
 * never pruned nor stamped stale. An allowlist, not every `*_at`: `matched_at`
 * is a URL, and js_recon stores `discovered_at` as a string in exactly the
 * exported shape, which a reader may compare as text.
 */
const RESTORED_DATETIME_PROPERTIES: ReadonlySet<string> = new Set([
  'updated_at', 'created_at', 'stale_since', 'muted_at',
  'triaged_at', 'triage_rescored_at', 'triage_ai_at', 'triage_verdict_at',
  'recon_coverage_at', 'js_recon_at', 'nuclei_at', 'http_probed_at', 'anon_status_at',
  'first_seen_at', 'last_seen_at',
  // The hostname selection's (graph_db ip_hostnames_mixin, the webapp's
  // narrowing marker): readers order by it.
  'ip_hostname_evaluated_at',
])

const EXPORTED_DATETIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/

/** A temporal property as the DateTime it was exported from; anything else unchanged. */
export function restoredTemporal(key: string, value: unknown): unknown {
  if (typeof value !== 'string' || !RESTORED_DATETIME_PROPERTIES.has(key)) return value
  const match = EXPORTED_DATETIME.exec(value)
  if (!match) return value
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number)
  // The driver checks each field's range but not the day against its month.
  const parsed = new Date(Date.UTC(year, month - 1, day, hour, minute, second))
  if (parsed.getUTCMonth() !== month - 1 || parsed.getUTCDate() !== day
      || parsed.getUTCHours() !== hour || parsed.getUTCMinutes() !== minute
      || parsed.getUTCSeconds() !== second) {
    return value
  }
  return new DateTime(year, month, day, hour, minute, second, 0, 0)
}

/**
 * Recreate `nodes` + `relationships` for `projectId`. The caller owns clearing
 * (so it can choose what to preserve) and owns the session lifecycle.
 */
export async function restoreGraph(
  session: Session,
  nodes: RestorableNode[],
  relationships: RestorableRelationship[],
  opts: RestoreOptions
): Promise<RestoreResult> {
  if (nodes.length === 0) return { nodes: 0, relationships: 0 }

  const nodeBatchSize = opts.nodeBatchSize ?? DEFAULT_NODE_BATCH
  const relBatchSize = opts.relBatchSize ?? DEFAULT_REL_BATCH
  const uniqueKeyMap = await loadUniqueKeys(session)

  // A catalogue node is keyed on its natural id alone and shared by every
  // tenant: MERGEd from a payload it would take the payload's properties. Only
  // links to it are restored, below, its carried edges included.
  const carried = carriedReferenceEdgesToLinks(nodes, relationships)
  const projectRelationships = carried.relationships
  const links = [...(opts.referenceLinks ?? []), ...carried.referenceLinks]
  const prepared = nodes.filter(node => !isReferenceNode(node.labels)).map(node => {
    const properties: Record<string, unknown> = {
      ...node.properties,
      ...(opts.userId ? { user_id: opts.userId } : {}),
      project_id: opts.projectId,
      _exportId: node._exportId,
    }
    for (const retired of retiredPropertiesFor(node.labels, properties)) delete properties[retired]
    for (const [key, value] of Object.entries(properties)) properties[key] = restoredTemporal(key, value)
    // Pre-re-key snapshots have no cert_key; the uniqueness constraint now
    // requires it. Derive it before MERGE so old certificates do not collapse.
    if (node.labels.includes('Certificate') && !properties.cert_key) {
      properties.cert_key = deriveCertKey(properties)
    }
    return { labels: node.labels, properties }
  })
  freshSessionIds(prepared, opts.renamedChainIds)

  // The project end of every MERGE: a constraint without the tenant (the session
  // labels, an older database's id-only key) would otherwise match another
  // project's node and re-stamp it into this one. With it, the restore makes its
  // own node, or the constraint refuses the write; it never moves one. user_id
  // only when the restore stamps it: activation keeps each node's own, which an
  // old node may lack, and a null key fails the MERGE.
  const tenantKeys = opts.userId ? ['user_id', 'project_id'] : ['project_id']

  // Bucket by the node's FUNCTIONAL label, not labels[0]. A suppressed finding
  // is dual-labelled (`:Vulnerability:Muted`) and Neo4j does not order labels,
  // so labels[0] can come back as `Muted`; uniqueKeyMap would then miss and the
  // node would be recreated through apoc.create.node with NO uniqueness key,
  // duplicating the finding on the next import. The full node.labels array is
  // still what gets written, so `:Muted` itself round-trips intact.
  const byLabel = new Map<string, typeof prepared>()
  for (const node of prepared) {
    const primaryLabel = node.labels.length ? functionalLabel(node.labels) : '__no_label__'
    if (!byLabel.has(primaryLabel)) byLabel.set(primaryLabel, [])
    byLabel.get(primaryLabel)!.push(node)
  }

  for (const [label, labelNodes] of byLabel) {
    const uniqueKeys = uniqueKeyMap.get(label)
    for (let i = 0; i < labelNodes.length; i += nodeBatchSize) {
      const batch = labelNodes.slice(i, i + nodeBatchSize)
      if (uniqueKeys && uniqueKeys.length > 0) {
        const identExpr = [...new Set([...uniqueKeys, ...tenantKeys])]
          .map(k => `\`${k}\`: node.properties.\`${k}\``)
          .join(', ')
        await session.run(
          `UNWIND $nodes AS node
           CALL apoc.merge.node(node.labels, {${identExpr}}, node.properties, node.properties) YIELD node AS n
           RETURN count(n)`,
          { nodes: batch }
        )
      } else {
        await session.run(
          `UNWIND $nodes AS node
           CALL apoc.create.node(node.labels, node.properties) YIELD node AS n
           RETURN count(n)`,
          { nodes: batch }
        )
      }
    }
  }

  if (projectRelationships.length > 0) {
    for (let i = 0; i < projectRelationships.length; i += relBatchSize) {
      const batch = projectRelationships.slice(i, i + relBatchSize)
      await session.run(
        `UNWIND $rels AS rel
         MATCH (a {_exportId: rel.startExportId, project_id: $pid})
         MATCH (b {_exportId: rel.endExportId, project_id: $pid})
         CALL apoc.create.relationship(a, rel.type, rel.properties, b) YIELD rel AS r
         RETURN count(r)`,
        { rels: batch, pid: opts.projectId }
      )
    }
  }

  // Before the strip: links find their project end by its _exportId.
  const referenceLinks = links.length
    ? await restoreReferenceLinks(session, links, opts.projectId, relBatchSize)
    : undefined

  // Strip the temporary correlation id so it never leaks into the graph.
  await session.run(
    'MATCH (n {project_id: $pid}) WHERE n._exportId IS NOT NULL REMOVE n._exportId',
    { pid: opts.projectId }
  )

  return {
    nodes: prepared.length,
    relationships: projectRelationships.length,
    ...(referenceLinks ? { referenceLinks } : {}),
  }
}
