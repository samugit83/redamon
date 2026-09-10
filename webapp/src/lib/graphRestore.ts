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
 */
import type { Session } from 'neo4j-driver'
import { functionalLabel } from '@/lib/scanSnapshot'

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
}

export interface RestoreResult {
  nodes: number
  relationships: number
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
 * Global reference nodes are always excluded, then swept if orphaned.
 */
export async function clearProjectGraph(
  session: Session,
  projectId: string,
  excludeLabels: readonly string[] = []
): Promise<void> {
  const excluded = [...new Set([...excludeLabels, ...GLOBAL_REFERENCE_LABELS])]
  await session.run(
    `MATCH (n {project_id: $pid})
     WHERE NONE(l IN labels(n) WHERE l IN $excluded)
     DETACH DELETE n`,
    { pid: projectId, excluded }
  )
  await sweepOrphanReferenceNodes(session)
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

  const prepared = nodes.map(node => ({
    labels: node.labels,
    properties: {
      ...node.properties,
      ...(opts.userId ? { user_id: opts.userId } : {}),
      project_id: opts.projectId,
      _exportId: node._exportId,
    },
  }))

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
        const identExpr = uniqueKeys
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

  if (relationships.length > 0) {
    for (let i = 0; i < relationships.length; i += relBatchSize) {
      const batch = relationships.slice(i, i + relBatchSize)
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

  // Strip the temporary correlation id so it never leaks into the graph.
  await session.run(
    'MATCH (n {project_id: $pid}) WHERE n._exportId IS NOT NULL REMOVE n._exportId',
    { pid: opts.projectId }
  )

  return { nodes: nodes.length, relationships: relationships.length }
}
