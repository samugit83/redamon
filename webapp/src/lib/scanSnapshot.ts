/**
 * Scan Timeline - snapshot capture / storage / load / render.
 *
 * THE MODEL: the live Neo4j graph IS the current version. A PAST version is a
 * frozen copy of that graph, serialized in the EXPORT (restore-fidelity) format
 * and gzipped into `ScanVersion.snapshot` in Postgres. The Neo4j schema is
 * untouched; nothing is versioned inside the graph.
 *
 * Why export fidelity and not the UI render shape: a snapshot must be restorable
 * back into Neo4j (version activation), so it stores full `{labels, properties}`
 * nodes and `{startExportId, endExportId, type, properties}` relationships - the
 * exact shape `lib/graphRestore.ts` round-trips. The UI `{nodes, links}` shape is
 * DERIVED from it on read (`snapshotToGraphPayload`).
 *
 * Agent session nodes (AttackChain family) are EXCLUDED: a version is recon
 * state, not agent-run state. Chains are conversation-scoped and already purged
 * when their conversation goes away, so snapshotting them would both pollute
 * diffs and let an activation restore dead-session chains.
 */
import { gzipSync, gunzipSync } from 'zlib'
import { randomUUID } from 'crypto'
import prisma from '@/lib/prisma'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { serializeGraphProperties } from '@/lib/graphSerialize'
import { MUTED_LABEL } from '@/lib/graphMute'
import { getNodeName, type FormattedGraphData, type Neo4jNode } from '@/app/api/graph/format'

/** Agent-run (session) labels that are never part of a recon version. */
export const SESSION_LABELS = [
  'AttackChain',
  'ChainStep',
  'ChainFinding',
  'ChainDecision',
  'ChainFailure',
] as const

export interface SnapshotNode {
  labels: string[]
  properties: Record<string, unknown>
  _exportId: string
}

export interface SnapshotRelationship {
  startExportId: string
  endExportId: string
  type: string
  properties: Record<string, unknown>
}

export interface SnapshotPayload {
  nodes: SnapshotNode[]
  relationships: SnapshotRelationship[]
}

export interface CapturedSnapshot extends SnapshotPayload {
  nodeCount: number
  linkCount: number
  /** Per-primary-label node counts, for the Recon Delta scorecard. */
  summary: Record<string, number>
}

/** Hard ceiling on the stored (gzipped) snapshot. Refuse rather than bloat Postgres. */
export function snapshotMaxBytes(): number {
  const raw = parseInt(process.env.SCAN_SNAPSHOT_MAX_BYTES || '', 10)
  return Number.isFinite(raw) && raw > 0 ? raw : 128 * 1024 * 1024
}

/** F5: cap concurrent heavy Neo4j capture/restore windows process-wide. */
function snapshotMaxConcurrency(): number {
  const raw = parseInt(process.env.SCAN_SNAPSHOT_MAX_CONCURRENCY || '', 10)
  return Number.isFinite(raw) && raw > 0 ? raw : 2
}

let running = 0
const waiters: Array<() => void> = []

/**
 * Run `fn` inside the global snapshot semaphore. Capture and activation restore
 * are large Neo4j read/write windows that no admission ledger gates (they spawn
 * no container), so this keeps N cross-project operations from piling onto Neo4j.
 */
export async function withSnapshotSlot<T>(fn: () => Promise<T>): Promise<T> {
  const limit = snapshotMaxConcurrency()
  // `while`, not `if`: a caller arriving in the microtask gap between a release
  // and the woken waiter resuming would otherwise take the free slot, and the
  // waiter would then increment on top of it - two bodies under a cap of one.
  // Re-checking on wake makes the cap hold whatever the arrival interleaving.
  while (running >= limit) {
    await new Promise<void>(resolve => waiters.push(resolve))
  }
  running += 1
  try {
    return await fn()
  } finally {
    running -= 1
    const next = waiters.shift()
    if (next) next()
  }
}

/**
 * Read the project's live recon graph in export fidelity.
 *
 * Same node + relationship queries the project exporter uses, plus the session
 * label exclusion. A relationship is kept only when BOTH endpoints are in the
 * captured node set, so chain→recon edges (and edges to global, project-less
 * enrichment nodes) drop out exactly as they do on export.
 *
 * The caller must guarantee no scan / partial recon / activation is writing the
 * graph (Sections 3.3 and 4A.3 enforce this via the activation lock), otherwise
 * the capture may be of a mid-write graph.
 */
export async function captureGraphSnapshot(projectId: string): Promise<CapturedSnapshot> {
  return withSnapshotSlot(async () => {
    const session = getGraphSession()
    try {
      const nodesResult = await session.run(
        `MATCH (n) WHERE n.project_id = $pid
           AND NONE(l IN labels(n) WHERE l IN $sessionLabels)
         RETURN labels(n) as labels, properties(n) as props, elementId(n) as eid`,
        { pid: projectId, sessionLabels: [...SESSION_LABELS] }
      )

      const elementIdToExportId = new Map<string, string>()
      const summary: Record<string, number> = {}

      const nodes: SnapshotNode[] = nodesResult.records.map(record => {
        const eid = record.get('eid') as string
        const exportId = randomUUID()
        elementIdToExportId.set(eid, exportId)
        const labels = record.get('labels') as string[]
        const primary = functionalLabel(labels)
        summary[primary] = (summary[primary] || 0) + 1
        return {
          labels,
          properties: serializeGraphProperties(record.get('props') as Record<string, unknown>),
          _exportId: exportId,
        }
      })

      const relsResult = await session.run(
        `MATCH (a)-[r]->(b)
         WHERE a.project_id = $pid OR b.project_id = $pid
         RETURN elementId(a) as startId, elementId(b) as endId,
                type(r) as relType, properties(r) as relProps`,
        { pid: projectId }
      )

      const relationships: SnapshotRelationship[] = relsResult.records
        .filter(record =>
          elementIdToExportId.has(record.get('startId') as string) &&
          elementIdToExportId.has(record.get('endId') as string)
        )
        .map(record => ({
          startExportId: elementIdToExportId.get(record.get('startId') as string)!,
          endExportId: elementIdToExportId.get(record.get('endId') as string)!,
          type: record.get('relType') as string,
          properties: serializeGraphProperties((record.get('relProps') as Record<string, unknown>) || {}),
        }))

      return {
        nodes,
        relationships,
        nodeCount: nodes.length,
        linkCount: relationships.length,
        summary,
      }
    } finally {
      await session.close()
    }
  })
}

export function serializeSnapshot(payload: SnapshotPayload): Buffer {
  return gzipSync(Buffer.from(JSON.stringify({
    nodes: payload.nodes,
    relationships: payload.relationships,
  })))
}

export function deserializeSnapshot(buf: Buffer | Uint8Array): SnapshotPayload {
  const parsed = JSON.parse(gunzipSync(Buffer.from(buf)).toString('utf8'))
  return {
    nodes: Array.isArray(parsed?.nodes) ? parsed.nodes : [],
    relationships: Array.isArray(parsed?.relationships) ? parsed.relationships : [],
  }
}

export class SnapshotTooLargeError extends Error {
  constructor(public bytes: number, public max: number) {
    super(`Snapshot too large: ${bytes} bytes (max ${max})`)
    this.name = 'SnapshotTooLargeError'
  }
}

/**
 * Freeze `payload` onto a ScanVersion row: gzip the bytes and record the counts +
 * per-type summary. Never logs snapshot contents (Section 8.5).
 */
export async function storeSnapshot(
  scanVersionId: string,
  payload: CapturedSnapshot
): Promise<{ bytes: number }> {
  const gz = serializeSnapshot(payload)
  const max = snapshotMaxBytes()
  if (gz.length > max) {
    console.error(`[scanTimeline] refusing snapshot for version ${scanVersionId}: ${gz.length} bytes > ${max}`)
    throw new SnapshotTooLargeError(gz.length, max)
  }
  await prisma.scanVersion.update({
    where: { id: scanVersionId },
    data: {
      // Prisma Bytes wants a plain Uint8Array view, not a Node Buffer type.
      snapshot: new Uint8Array(gz),
      nodeCount: payload.nodeCount,
      linkCount: payload.linkCount,
      summary: payload.summary as object,
    },
  })
  console.info(
    `[scanTimeline] stored snapshot version=${scanVersionId} nodes=${payload.nodeCount} ` +
    `links=${payload.linkCount} bytes=${gz.length}`
  )
  return { bytes: gz.length }
}

/** Read + gunzip a past version's payload. Returns null when the row has no bytes. */
export async function loadSnapshot(scanVersionId: string): Promise<SnapshotPayload | null> {
  const row = await prisma.scanVersion.findUnique({
    where: { id: scanVersionId },
    select: { snapshot: true },
  })
  if (!row?.snapshot) return null
  return deserializeSnapshot(row.snapshot as unknown as Buffer)
}

/**
 * Convert a stored snapshot into the UI `{nodes, links}` payload - the same shape
 * `formatGraphRecords` produces for the live graph, so the graph canvas, the
 * clustering and the node/link tables render a past version unchanged.
 *
 * Node ids are the snapshot's stable `_exportId`s (the live path uses Neo4j
 * internal ids); links reference the same ids, so the payload is self-consistent.
 */
/** True when a snapshot node carries the suppressed-finding marker. */
export function snapshotNodeIsMuted(labels: string[]): boolean {
  return labels.includes(MUTED_LABEL)
}

/**
 * A node's real type, ignoring the `Muted` marker.
 *
 * A muted finding is dual-labelled and Neo4j does not order labels, so
 * `labels[0]` can be `Muted` and would mis-type the node. Anything asking "what
 * kind of thing is this" has to go through here.
 */
export function functionalLabel(labels: string[]): string {
  return labels.find(l => l !== MUTED_LABEL) || 'Unknown'
}

/**
 * Render a snapshot as a `{nodes, links}` payload.
 *
 * Muted findings are dropped HERE and not in `captureGraphSnapshot`, and the
 * distinction matters in both directions. This feeds the graph view and the
 * Recon Delta, neither of which may show a suppressed finding -- and in the
 * delta a finding that vanished because somebody muted it would otherwise be
 * reported under `resolvedVulnerabilities`, i.e. as fixed. The STORED snapshot
 * keeps them, so mute still survives export, import and version-activate.
 */
export function snapshotToGraphPayload(snapshot: SnapshotPayload): FormattedGraphData {
  const nodes = snapshot.nodes
    .filter(n => !snapshotNodeIsMuted(n.labels))
    .map(n => ({
      id: n._exportId,
      name: getNodeName({ labels: n.labels, properties: n.properties } as Neo4jNode),
      type: functionalLabel(n.labels),
      properties: n.properties,
    }))
  const known = new Set(nodes.map(n => n.id))
  const links = snapshot.relationships
    .filter(r => known.has(r.startExportId) && known.has(r.endExportId))
    .map(r => ({ source: r.startExportId, target: r.endExportId, type: r.type }))
  return { nodes, links }
}

/** Per-primary-label counts for an already-rendered `{nodes, links}` payload. */
export function summarizeGraphPayload(data: FormattedGraphData): Record<string, number> {
  const summary: Record<string, number> = {}
  for (const n of data.nodes) {
    const t = n.type || 'Unknown'
    summary[t] = (summary[t] || 0) + 1
  }
  return summary
}

/** Human default label for a newly created version. */
export function defaultVersionLabel(seq: number, at: Date = new Date()): string {
  const iso = at.toISOString()
  return `Scan ${seq} - ${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`
}

export interface ScanVersionRow {
  id: string
  seq: number
  label: string
  isCurrent: boolean
  pinned: boolean
  nodeCount: number | null
  linkCount: number | null
  createdAt: Date
}

/**
 * Return the project's current ScanVersion, creating the backfill row for a
 * project that predates the Scan Timeline (its live graph becomes v1).
 *
 * Concurrency: two simultaneous first-uses race on `@@unique([projectId, seq])`;
 * the loser retries the read and gets the winner's row.
 */
export async function ensureCurrentVersion(projectId: string): Promise<ScanVersionRow> {
  const existing = await prisma.scanVersion.findFirst({
    where: { projectId, isCurrent: true },
    select: CURRENT_SELECT,
  })
  if (existing) return existing

  // Some rows exist but none is current (e.g. an activation crashed between the
  // clear and the pointer move): adopt the highest seq rather than minting a
  // duplicate identity for the live graph.
  const orphanLatest = await prisma.scanVersion.findFirst({
    where: { projectId },
    orderBy: { seq: 'desc' },
    select: CURRENT_SELECT,
  })
  if (orphanLatest) {
    await prisma.scanVersion.update({
      where: { id: orphanLatest.id },
      data: { isCurrent: true },
    })
    return { ...orphanLatest, isCurrent: true }
  }

  try {
    return await prisma.scanVersion.create({
      data: {
        projectId,
        seq: 1,
        label: defaultVersionLabel(1),
        isCurrent: true,
        snapshot: null,
      },
      select: CURRENT_SELECT,
    })
  } catch {
    const raced = await prisma.scanVersion.findFirst({
      where: { projectId, isCurrent: true },
      select: CURRENT_SELECT,
    })
    if (raced) return raced
    throw new Error(`Could not establish a current scan version for project ${projectId}`)
  }
}

const CURRENT_SELECT = {
  id: true,
  seq: true,
  label: true,
  isCurrent: true,
  pinned: true,
  nodeCount: true,
  linkCount: true,
  createdAt: true,
} as const
