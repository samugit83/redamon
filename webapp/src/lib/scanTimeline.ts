/**
 * Scan Timeline - full-scan version bookkeeping (server-side).
 *
 * A full scan always wipes and rebuilds the live Neo4j graph, and the live graph
 * IS the current version. So there is no pointer to flip and no completion
 * detection needed for correctness: the only decision is what happens to the
 * graph that is about to be destroyed.
 *
 *   mode = 'new'       keep it. Freeze the current version (capture live graph ->
 *                      gzip -> ScanVersion.snapshot), demote it to a past version,
 *                      and mint the next version as the new current. FAIL CLOSED:
 *                      if the freeze fails we throw and the caller must NOT start
 *                      the scan, so the graph is never lost.
 *   mode = 'overwrite' discard it. No snapshot; the current version row is reused.
 *
 * `ScanJob` rows are the run history the timeline/scheduler tables read.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { readDegradedSourceCount } from '@/lib/scanCoverage'
import {
  captureGraphSnapshot,
  storeSnapshot,
  ensureCurrentVersion,
  defaultVersionLabel,
  type ScanVersionRow,
} from '@/lib/scanSnapshot'

export type ScanMode = 'new' | 'overwrite'
export type ScanTrigger = 'manual' | 'scheduled'

export const SCAN_MODES: ScanMode[] = ['new', 'overwrite']

export function parseScanMode(value: unknown): ScanMode | null {
  return value === 'new' || value === 'overwrite' ? value : null
}

/** Auto-generated labels are refreshed on overwrite; user-renamed ones are kept. */
const AUTO_LABEL = /^Scan \d+ - \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/

export interface PrepareResult {
  /** The version the scan about to start will populate (the new current). */
  currentVersion: ScanVersionRow
  /** The version that was frozen as a past version, if any. */
  frozenVersionId: string | null
  /** Nodes captured into the frozen snapshot (0 when nothing was kept). */
  frozenNodeCount: number
}

export class SnapshotFreezeError extends Error {
  constructor(message: string, public cause?: unknown) {
    super(message)
    this.name = 'SnapshotFreezeError'
  }
}

/**
 * Apply the version-side effects of starting a full scan. MUST be called before
 * the scan is actually started, and its rejection MUST abort the start.
 */
export async function prepareVersionsForFullScan(
  projectId: string,
  mode: ScanMode,
  actorId?: string | null
): Promise<PrepareResult> {
  const current = await ensureCurrentVersion(projectId)

  if (mode === 'overwrite') {
    const label = AUTO_LABEL.test(current.label)
      ? defaultVersionLabel(current.seq)
      : current.label
    const updated = await prisma.scanVersion.update({
      where: { id: current.id },
      data: { label },
      select: VERSION_SELECT,
    })
    await writeAudit({
      actorId: actorId ?? null,
      action: 'scan-version.overwrite',
      targetType: 'scanVersion',
      targetId: current.id,
      before: { seq: current.seq, label: current.label, nodeCount: current.nodeCount },
      after: { seq: current.seq, label, discardedSnapshot: true },
    })
    return { currentVersion: updated, frozenVersionId: null, frozenNodeCount: 0 }
  }

  // mode === 'new': freeze the outgoing graph first. Anything that throws here
  // must propagate - the caller aborts the start rather than risk losing it.
  let captured
  try {
    captured = await captureGraphSnapshot(projectId)
  } catch (err) {
    throw new SnapshotFreezeError(
      'Could not snapshot the current graph, so the scan was not started (no data was lost). ' +
      (err instanceof Error ? err.message : String(err)),
      err
    )
  }

  // An empty live graph has nothing worth keeping: reuse the current version
  // rather than filling the timeline with empty snapshots.
  if (captured.nodeCount === 0) {
    return { currentVersion: current, frozenVersionId: null, frozenNodeCount: 0 }
  }

  try {
    await storeSnapshot(current.id, captured)
  } catch (err) {
    throw new SnapshotFreezeError(
      'Could not store the snapshot of the current graph, so the scan was not started ' +
      '(no data was lost). ' + (err instanceof Error ? err.message : String(err)),
      err
    )
  }

  const created = await rotateToNextVersion(projectId, current.id)

  // Retention is deliberately NOT run here. It deletes the oldest unpinned
  // versions, and a start the orchestrator goes on to refuse must not cost the
  // user a saved version. `startFullScan` calls applyRetentionSafe only after
  // the start is accepted (mcp_plan.md P0-2).
  return {
    currentVersion: created,
    frozenVersionId: current.id,
    frozenNodeCount: captured.nodeCount,
  }
}

/**
 * Undo `prepareVersionsForFullScan` after a start the orchestrator refused.
 *
 * Only meaningful for `mode: 'new'` that actually rotated (`frozenVersionId`
 * set). The live graph is never touched by the freeze, so deleting the empty
 * new version and making the frozen one current again returns the timeline to
 * its prior state. Without this, an external agent retrying a 403 in a loop
 * mints a version and stores a duplicate snapshot on every attempt.
 *
 * Never throws: a start has already failed, and failing to tidy up must not
 * replace that error with a less useful one.
 */
export async function rollbackPreparedVersions(
  projectId: string,
  prepared: PrepareResult
): Promise<boolean> {
  const frozenId = prepared.frozenVersionId
  if (!frozenId) return false

  try {
    await prisma.$transaction(async tx => {
      await tx.scanVersion.delete({ where: { id: prepared.currentVersion.id } })
      await tx.scanVersion.update({
        where: { id: frozenId },
        // nodeCount/linkCount are left as the freeze measured them: the live
        // graph was never touched, so those numbers describe it accurately.
        // Only the snapshot bytes (and the demotion) are undone.
        data: { isCurrent: true, snapshot: null },
      })
    })
    return true
  } catch (err) {
    console.error(
      `[scanTimeline] could not roll back the prepared version for project ${projectId} ` +
      '(the timeline keeps an extra empty version):',
      err
    )
    return false
  }
}

/** Prisma's unique-constraint violation. */
function isSeqCollision(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === 'P2002'
}

const ROTATE_ATTEMPTS = 4

/**
 * Demote `demoteVersionId` and open the next version, atomically.
 *
 * Two writers can read the same max(seq) and both try to create seq+1 (a
 * double-clicked Start, or a scan racing "save current as a version"). The
 * `@@unique([projectId, seq])` constraint is what keeps version numbering from
 * forking - but the loser used to surface as a 500 AFTER its snapshot had already
 * been frozen. Retrying with a recomputed seq turns that race into a queue.
 */
export async function rotateToNextVersion(
  projectId: string,
  demoteVersionId: string
): Promise<ScanVersionRow> {
  let lastError: unknown
  for (let attempt = 0; attempt < ROTATE_ATTEMPTS; attempt++) {
    const nextSeq = await nextVersionSeq(projectId)
    try {
      return await prisma.$transaction(async tx => {
        await tx.scanVersion.update({ where: { id: demoteVersionId }, data: { isCurrent: false } })
        return tx.scanVersion.create({
          data: {
            projectId,
            seq: nextSeq,
            label: defaultVersionLabel(nextSeq),
            isCurrent: true,
            snapshot: null,
          },
          select: VERSION_SELECT,
        })
      })
    } catch (err) {
      if (!isSeqCollision(err)) throw err
      lastError = err
      console.warn(
        `[scanTimeline] version seq ${nextSeq} was taken by a concurrent writer for project ` +
        `${projectId}; retrying (${attempt + 1}/${ROTATE_ATTEMPTS})`
      )
    }
  }
  throw lastError
}

export async function nextVersionSeq(projectId: string): Promise<number> {
  const top = await prisma.scanVersion.findFirst({
    where: { projectId },
    orderBy: { seq: 'desc' },
    select: { seq: true },
  })
  return (top?.seq ?? 0) + 1
}

export interface CreateScanJobInput {
  projectId: string
  versionId?: string | null
  trigger: ScanTrigger
  mode: ScanMode | null
  status?: string
  initiatedByUserId?: string | null
  scheduleId?: string | null
  ramReason?: string | null
  /** Defaults to full_recon, which is what every ScanJob used to be. */
  kind?: string
  /** Only for kinds that run several times per project at once. */
  runId?: string
  /** The sha256 of the scan-steering settings this run started with. */
  settingsHash?: string | null
  /** Which authorization permitted it, from the project's current record. */
  authorizationId?: string | null
  /** The project roots the run covers, as the orchestrator returned them. */
  targets?: string[]
  /** digestScopeDocument of the RoE text in force when the run started. */
  roeTextSha256?: string | null
}

export async function createScanJob(input: CreateScanJobInput): Promise<{ id: string }> {
  const status = input.status ?? 'running'
  return prisma.scanJob.create({
    data: {
      projectId: input.projectId,
      versionId: input.versionId ?? null,
      kind: input.kind ?? 'full_recon',
      runId: input.runId ?? '',
      trigger: input.trigger,
      mode: input.mode,
      status,
      initiatedByUserId: input.initiatedByUserId ?? null,
      scheduleId: input.scheduleId ?? null,
      ramReason: input.ramReason ?? null,
      settingsHash: input.settingsHash ?? null,
      authorizationId: input.authorizationId ?? null,
      targets: input.targets ?? [],
      roeTextSha256: input.roeTextSha256 ?? null,
      startedAt: status === 'running' ? new Date() : null,
    },
    select: { id: true },
  })
}

/**
 * Record a non-full-recon scan that the orchestrator just accepted.
 *
 * Deliberately never throws: history is a side effect of starting a scan, and a
 * failure to write it must not fail the start the operator asked for.
 */
export async function recordScanStart(input: {
  projectId: string
  kind: string
  runId?: string
  initiatedByUserId?: string | null
  scheduleId?: string | null
  /** The roots the run covers (partial recon reports them). */
  targets?: string[]
  /** Read before the orchestrator was called, so a replace cannot misattribute the run. */
  roeTextSha256?: string | null
}): Promise<void> {
  try {
    await createScanJob({
      projectId: input.projectId,
      versionId: null,
      kind: input.kind,
      runId: input.runId ?? '',
      targets: input.targets ?? [],
      roeTextSha256: input.roeTextSha256 ?? null,
      // These kinds do not version the graph, so there is no mode to record.
      trigger: input.scheduleId ? 'scheduled' : 'manual',
      mode: null,
      initiatedByUserId: input.initiatedByUserId ?? null,
      scheduleId: input.scheduleId ?? null,
    })
  } catch (err) {
    console.error(`[scanTimeline] could not record ${input.kind} start (continuing):`, err)
  }
}

/**
 * Close out the project's open ScanJob from an observed orchestrator status.
 *
 * The orchestrator owns scan liveness; we only mirror terminal states onto the
 * history row. Non-terminal states ('starting', 'running', 'paused', 'stopping')
 * are left alone. Best-effort: this runs inside a status poll and must never
 * break it.
 */
export async function reconcileScanJobStatus(
  projectId: string,
  reconStatus: string | undefined | null,
  opts: { kind?: string; runId?: string } = {}
): Promise<void> {
  const kind = opts.kind ?? 'full_recon'
  const mapped =
    reconStatus === 'completed' ? 'completed'
    : reconStatus === 'error' ? 'failed'
    : reconStatus === 'idle' ? 'canceled'
    : null
  if (!mapped) return

  try {
    // C-1: only ever close out a GENUINELY running job. A 'queued' row has no
    // container, so the orchestrator reports 'idle', which this function maps to
    // 'canceled' -- an ordinary browser status poll would then silently cancel a
    // queued scan just by looking at the page. The JobQueue row is the pending
    // record; a ScanJob exists only for an attempt that really started.
    const open = await prisma.scanJob.findFirst({
      // Scoped to the kind (and, where several can run at once, the run): closing
      // "the project's open job" from a GVM poll would otherwise end the full
      // recon's history row instead of GVM's.
      where: {
        projectId,
        kind,
        status: { in: ['running'] },
        ...(opts.runId ? { runId: opts.runId } : {}),
      },
      orderBy: { createdAt: 'desc' },
      select: { id: true, versionId: true },
    })
    if (!open) return

    const nodeCount = open.versionId
      ? (await prisma.scanVersion.findUnique({
          where: { id: open.versionId },
          select: { nodeCount: true },
        }))?.nodeCount ?? null
      : null

    // Stamp how many finding sources this run could not fully re-check, read
    // from the graph coverage record (the only reliable carrier). full_recon
    // only; null on any other kind or when coverage is unknown.
    const degradedSources =
      kind === 'full_recon' && mapped === 'completed'
        ? await readDegradedSourceCount(projectId)
        : null

    await prisma.scanJob.update({
      where: { id: open.id },
      data: { status: mapped, finishedAt: new Date(), nodeCount, degradedSources },
    })

    // Scheduled-scan change pipeline: diff vs the previous completed run and
    // fan out to webhooks. Best-effort — never breaks the status poll.
    if (mapped === 'completed' && kind === 'full_recon') {
      try {
        const { trackCompletedScan } = await import('./scanChangeTracker')
        await trackCompletedScan(open.id)
      } catch (err) {
        console.error('[scanTimeline] change tracking failed (continuing):', err)
      }
    }
  } catch (err) {
    console.error('[scanTimeline] scan-job reconcile failed (continuing):', err)
  }
}

/**
 * Close out the run-keyed kinds (partial_recon, ai_attack) from the one list poll
 * the UI already makes, instead of a status call per run.
 *
 * Only an explicitly TERMINAL live status closes a row. A run that has simply
 * disappeared from the orchestrator's list is left alone: it also disappears when
 * the orchestrator restarts, and calling that "completed" would invent an outcome.
 * Such a row stays `running` until something else reconciles it.
 */
export async function reconcileRunScanJobs(
  projectId: string,
  kind: string,
  runs: unknown
): Promise<void> {
  if (!Array.isArray(runs) || runs.length === 0) return
  try {
    const open = await prisma.scanJob.findMany({
      where: { projectId, kind, status: 'running' },
      select: { id: true, runId: true },
    })
    if (open.length === 0) return

    const liveStatus = new Map<string, string>()
    for (const r of runs) {
      const run = r as { run_id?: unknown; status?: unknown }
      if (typeof run?.run_id === 'string' && typeof run?.status === 'string') {
        liveStatus.set(run.run_id, run.status)
      }
    }

    await Promise.all(open.map(row => {
      const status = row.runId ? liveStatus.get(row.runId) : undefined
      const mapped =
        status === 'completed' ? 'completed'
        : status === 'error' ? 'failed'
        : null
      if (!mapped) return Promise.resolve()
      return prisma.scanJob.update({
        where: { id: row.id },
        data: { status: mapped, finishedAt: new Date() },
      })
    }))
  } catch (err) {
    console.error(`[scanTimeline] ${kind} run reconcile failed (continuing):`, err)
  }
}

export const VERSION_SELECT = {
  id: true,
  seq: true,
  label: true,
  isCurrent: true,
  pinned: true,
  nodeCount: true,
  linkCount: true,
  createdAt: true,
} as const
