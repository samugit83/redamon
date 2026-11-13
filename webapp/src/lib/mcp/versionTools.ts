/**
 * The Scan Timeline, read-only.
 *
 * `start_recon` already returns a versionId and says it "consumed a retention
 * slot", yet nothing could list versions, name one, or tell whether the version
 * it had just created still existed: a write tool with no matching read.
 *
 * `compare_scan_versions` is the higher-value half. "What changed since the
 * last scan" is the question the nightly-rescan use case exists to ask, and the
 * one thing an agent genuinely cannot reconstruct for itself, because two
 * 1000-row-capped graph dumps do not diff inside a model's context.
 */
import prisma from '@/lib/prisma'
import { SCOPE_SELECT, currentScanRoots } from '@/lib/scanCoverage'
import { assertMcpProjectAccess, requireScope, type McpProjectToken } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { assertVersionInProject, type OwnedScanVersion } from '@/lib/mcp/childAccess'
import { readProjectActivity } from '@/lib/mcp/activity'
import { computeReconDelta, type ReconDelta } from '@/lib/reconDelta'
import {
  captureGraphSnapshot,
  loadSnapshot,
  snapshotToGraphPayload,
  tryWithSnapshotSlot,
} from '@/lib/scanSnapshot'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

export const VERSIONS_DEFAULT_LIMIT = 20
export const VERSIONS_MAX_LIMIT = 100

/** Per lens. Enough to act on, nowhere near enough to be a data export. */
const SAMPLE_CAP = 10
const SAMPLE_NAME_MAX = 200

/**
 * Every saved version of this project's graph.
 *
 * Deliberately does NOT call `ensureCurrentVersion`, which the browser route
 * uses and which WRITES: it backfills a v1 row for a pre-timeline project and
 * promotes an orphan row to current. A tool annotated `readOnlyHint: true` that
 * mutates state is a lie to every client, so a project with no rows returns an
 * empty list honestly.
 */
export async function listScanVersions(
  ctx: McpContext,
  projectId: string,
  args: { limit?: number } = {}
) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')
  await assertMcpProjectAccess(ctx.token, projectId, 'R')

  const limit = Math.max(
    1,
    Math.min(Math.trunc(args.limit ?? VERSIONS_DEFAULT_LIMIT), VERSIONS_MAX_LIMIT)
  )

  // `octet_length(snapshot)` rather than selecting `snapshot`: the column is a
  // gzipped dump of a whole graph, and the only thing a caller needs to know is
  // whether it is still there.
  const rows = await prisma.$queryRaw<Array<{
    id: string
    seq: number
    label: string
    is_current: boolean
    pinned: boolean
    node_count: number | null
    link_count: number | null
    created_at: Date
    snapshot_bytes: number | null
  }>>`
    SELECT id, seq, label, is_current, pinned, node_count, link_count, created_at,
           octet_length(snapshot) AS snapshot_bytes
    FROM scan_versions
    WHERE project_id = ${projectId}
    ORDER BY seq DESC
    LIMIT ${limit}
  `

  const total = await prisma.scanVersion.count({ where: { projectId } })

  return {
    projectId,
    versions: rows.map(r => ({
      versionId: r.id,
      seq: r.seq,
      label: r.label,
      isCurrent: r.is_current,
      pinned: r.pinned,
      nodeCount: r.node_count,
      linkCount: r.link_count,
      createdAt: r.created_at.toISOString(),
      // The two facts that decide whether this version will still be there
      // later, and whether it can be compared at all.
      hasSnapshot: Number(r.snapshot_bytes ?? 0) > 0,
    })),
    returned: rows.length,
    total,
    ...(rows.length < total ? { truncated: true } : {}),
    notes: [
      'An UNPINNED, non-current version can be trimmed at any time: retention runs on every ' +
        'accepted scan start and every "save current as a version". Pinning is the only way to ' +
        'keep one.',
      'hasSnapshot false means the version cannot be compared. The current version always has ' +
        'no stored snapshot by design - it IS the live graph - so compare against "current".',
    ],
  }
}

// --- comparison -------------------------------------------------------------------

type Side =
  | { kind: 'current' }
  | { kind: 'version'; version: OwnedScanVersion }

interface LoadedSide {
  descriptor: { versionId: string; seq: number | null; label: string }
  data: ReturnType<typeof snapshotToGraphPayload>
}

async function resolveSide(
  token: McpProjectToken,
  projectId: string,
  selector: string | undefined,
  fallbackToNewestPast: boolean
): Promise<Side> {
  const raw = selector?.trim()
  // An EXPLICIT 'current' always means the live graph, on either side. Folding
  // it in with "no selector given" let the `from` side's fallback swallow it,
  // so a caller that asked for the live graph silently got a stored version and
  // a comparison it never requested.
  if (raw === 'current') return { kind: 'current' }
  if (raw) {
    const version = await assertVersionInProject(token, projectId, raw, 'R')
    return { kind: 'version', version }
  }
  if (!fallbackToNewestPast) return { kind: 'current' }

  // The default `from`: the newest version that still HAS bytes. Defaulting to
  // the newest row would usually pick the current one, whose snapshot is null
  // by design, and produce "no stored snapshot" for a no-argument call.
  const [row] = await prisma.$queryRaw<Array<{ id: string }>>`
    SELECT id FROM scan_versions
    WHERE project_id = ${projectId}
      AND is_current = false
      AND octet_length(snapshot) > 0
    ORDER BY seq DESC
    LIMIT 1
  `
  if (!row) {
    throw new McpToolError(
      'This project has no earlier saved version with a stored snapshot, so there is nothing to ' +
      'compare against yet. list_scan_versions shows which versions exist.',
      'not_found'
    )
  }
  const version = await assertVersionInProject(token, projectId, row.id, 'R')
  return { kind: 'version', version }
}

async function loadStoredSide(version: OwnedScanVersion): Promise<LoadedSide> {
  if (version.isCurrent) {
    // The current row's snapshot is null BY DESIGN; saying "empty snapshot"
    // here would send a caller looking for a data problem that does not exist.
    throw new McpToolError(
      `Version ${version.seq} is the current one, which has no stored snapshot because it IS the ` +
      `live graph. Pass "current" for that side instead.`,
      'bad_args'
    )
  }
  const payload = await loadSnapshot(version.id)
  if (!payload) {
    // Retention TOCTOU: a version listed a moment ago can be gone now.
    throw new McpToolError(
      `Version ${version.seq} no longer has a stored snapshot. It may have been trimmed by ` +
      `retention, or had its bytes released when it was activated. Only pinned versions are ` +
      `kept indefinitely.`,
      'not_found'
    )
  }
  return {
    descriptor: { versionId: version.id, seq: version.seq, label: version.label },
    data: snapshotToGraphPayload(payload),
  }
}

const BUSY = (why: string) =>
  new McpToolError(
    `The live graph cannot be compared right now: ${why}. Retry once it is settled, or compare ` +
    `two stored versions instead, which is cheaper and repeatable.`,
    'busy'
  )

/**
 * Capture the live graph, refusing rather than returning a delta computed
 * across a state change.
 *
 * Version activation is not atomic: it clears the project's graph and then
 * restores into it as two separate operations, so for the whole duration of a
 * restore the graph is observably EMPTY. A point-in-time busy check does not
 * protect a read that takes seconds - an activation starting one millisecond
 * after it passes deletes the graph mid-stream, and the result is not an error
 * but a successful delta reporting every node in the project as removed. An
 * agent acts on that as "the attack surface was torn down".
 *
 * Hence check, capture, and check AGAIN: if anything moved, the captured side
 * is discarded.
 */
async function captureCurrentSide(projectId: string): Promise<LoadedSide> {
  const before = await readProjectActivity(projectId)
  if (before.unknown) throw BUSY('whether anything is writing it could not be determined')
  if (before.activating) throw BUSY('a saved version is being activated')
  if (before.scans.length > 0) throw BUSY('a scan is writing it')
  if (before.agentSession || before.triageRun) throw BUSY('an agent session or triage run is writing it')
  if (before.muteRulesApply) throw BUSY('Mute Rules are being applied to it')

  // Non-blocking: queueing here would leave an abandoned waiter that runs a
  // full graph capture nobody is awaiting, holding a slot the UI also needs.
  const slot = await tryWithSnapshotSlot(() => captureGraphSnapshot(projectId))
  if (!slot.acquired) {
    throw new McpToolError(
      'The graph snapshot service is busy with another capture. Try again shortly, or compare ' +
      'two stored versions, which does not need it.',
      'busy'
    )
  }

  const after = await readProjectActivity(projectId)
  if (after.unknown || after.activating || after.scans.length > 0
      || after.agentSession || after.triageRun || after.muteRulesApply) {
    throw BUSY('it started being rewritten while it was being read')
  }

  return {
    descriptor: { versionId: 'current', seq: null, label: 'Current (live graph)' },
    data: snapshotToGraphPayload(slot.value),
  }
}

/**
 * Summarise a delta.
 *
 * The raw `ReconDelta` must NEVER leave this process, for two independent
 * reasons. It leaks secret values: `identityKey` builds a node's key from
 * `IDENTITY_KEYS`, which includes `Secret: [value, file]` and
 * `JsReconFinding: [url, type, value]`, so `key`, `sourceKey` and `targetKey`
 * literally embed secret material, and every added or changed node carries its
 * full property bag. And it is unbounded: nothing caps it, the lens arrays hold
 * the same object references as `addedNodes` so several node types serialise
 * twice, and the only related ceiling anywhere is a 128 MiB GZIPPED store cap.
 *
 * So: counts, per-type scores, and at most a handful of {type, name} samples.
 * No identity keys, no property bags, and no `changes[].from/to` - those carry
 * the raw before-and-after values.
 */
function summariseDelta(delta: ReconDelta) {
  const cap = (list: { type: string; name?: string }[]) =>
    list.slice(0, SAMPLE_CAP).map(n => ({
      type: n.type,
      name: String(n.name ?? '').slice(0, SAMPLE_NAME_MAX),
    }))

  const l = delta.lenses
  return {
    totals: delta.totals,
    scorecard: delta.scorecard,
    // Which finding sources the newer run could not fully re-check (circuit
    // breakers): removed counts below may include skipped work, not real change.
    coverageGaps: delta.coverage?.sources ?? null,
    lenses: {
      newlyExposedPorts: l.newlyExposedPorts.length,
      closedPorts: l.closedPorts.length,
      newVulnerabilities: l.newVulnerabilities.length,
      resolvedVulnerabilities: l.resolvedVulnerabilities.length,
      newCves: l.newCves.length,
      technologyVersionChanges: l.technologyVersionChanges.length,
      certificateChanges: l.certificateChanges.length,
      newParameters: l.newParameters.length,
    },
    samples: {
      newlyExposedPorts: cap(l.newlyExposedPorts),
      newVulnerabilities: cap(l.newVulnerabilities),
      newCves: cap(l.newCves),
      technologyVersionChanges: cap(l.technologyVersionChanges),
    },
    ...(l.newlyExposedPorts.length > SAMPLE_CAP
      || l.newVulnerabilities.length > SAMPLE_CAP
      || l.newCves.length > SAMPLE_CAP
      ? { truncated: true }
      : {}),
  }
}

export async function compareScanVersions(
  ctx: McpContext,
  projectId: string,
  args: { from?: string; to?: string } = {}
) {
  requireScope(ctx.token, 'recon:read')
  // OWNERSHIP FIRST, unlike the per-token buckets elsewhere on this surface.
  // This bucket is keyed per PROJECT, so its counter is shared by every token
  // in the deployment: charging it before proving ownership would let anyone
  // who knows a project id exhaust that project's comparison budget, and the
  // owner would then be refused with a message blaming their own token.
  // `startRecon` checks ownership first for exactly this reason.
  await assertMcpProjectAccess(ctx.token, projectId, 'R')
  // Orders of magnitude heavier than any other read: a stored side is a full
  // Postgres Bytes fetch plus gunzip plus JSON.parse, and a `current` side
  // runs two unbounded Cypher queries.
  enforceRate(ctx, 'compare', projectId, { perProject: true })

  const fromSide = await resolveSide(ctx.token, projectId, args.from, true)
  const toSide = await resolveSide(ctx.token, projectId, args.to, false)

  // Two captures of the same graph buy a guaranteed no-op answer with two of
  // the only two snapshot slots, which the UI and version activation share.
  if (fromSide.kind === 'current' && toSide.kind === 'current') {
    throw new McpToolError(
      'Both sides are the live graph, so this would compare it with itself. Pass a version id ' +
      'from list_scan_versions for one side, or omit both to compare the newest saved version ' +
      'against the live graph.',
      'bad_args'
    )
  }

  const from = fromSide.kind === 'current'
    ? await captureCurrentSide(projectId)
    : await loadStoredSide(fromSide.version)
  const to = toSide.kind === 'current'
    ? await captureCurrentSide(projectId)
    : await loadStoredSide(toSide.version)

  const scope = await prisma.project.findUnique({ where: { id: projectId }, select: SCOPE_SELECT })
  const delta = computeReconDelta(from.data, to.data, {}, scope ? currentScanRoots(scope) : null)

  return {
    projectId,
    from: from.descriptor,
    to: to.descriptor,
    ...summariseDelta(delta),
  }
}
