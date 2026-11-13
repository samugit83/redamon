/**
 * Scan Queue - the Activity view data (plan Phase 5). The canonical surface for
 * queue state. Tenancy: the caller sees THEIR OWN rows in full, and everyone
 * else's in-flight work only as an anonymised aggregate count. Also returns the
 * orchestrator ledger snapshot so the UI can show why the queue is waiting.
 *
 * "Running" is a union of three sources, because no single one sees every scan:
 *   1. JobQueue rows in running/dispatching - only work the QUEUE started.
 *   2. ScanJob rows - every scan that started, except a supply_chain_repo batch item.
 *   3. GET /system/active-scans on the orchestrator - every kind, but in-memory,
 *      so it is empty for scans that predate the orchestrator's last restart.
 * Deduplicated on kind|projectId|runId, preferring the source that carries the
 * most identity: a queue row (has cancel/re-confirm) > a ScanJob > a live entry.
 *
 * With sharing in force (step 4.5) "own rows" are also every job and scan of a project the
 * caller sees, a shared one included, each naming who started it (`initiator`: id and name,
 * null when no person did: a schedule, the agent, a live entry); the anonymous count is their
 * complement, and `sharedProjectIds` names the listed projects the caller does not own, so the
 * view counts them apart from the caller's own (step 4.11). Not in force, the rows and their shape
 * are the ones before.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'
import { jobQueueScope, sharedProjectIds, visibleProjects } from '@/lib/authz/visibleProjects'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, withRouteErrors } from '@/lib/routeErrors'

export const runtime = 'nodejs'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const RECENT_LIMIT = 20

type Row = {
  id: string
  projectId: string
  kind: string
  status: string
  priority: number
  attempts: number
  blockedCode: string
  blockedReason: string
  error: string
  envelopeBytes: bigint
  enqueuedAt: Date
  startedAt: Date | null
  finishedAt: Date | null
  scanJobId: string | null
  runId: string
  /** Who queued it: selected only with sharing in force. */
  userId?: string
  project: { name: string } | null
}

interface Initiator { id: string; name: string | null }

/** Who started a row, by account id; null when no person did. Present only with sharing in force. */
type People = (userId: string | null | undefined) => Initiator | null

function initiatorField(people: People | null, userId: string | null | undefined) {
  return people ? { initiator: people(userId) } : {}
}

function serialize(r: Row, people: People | null) {
  return {
    id: r.id,
    projectId: r.projectId,
    projectName: r.project?.name ?? '',
    kind: r.kind,
    status: r.status,
    priority: r.priority,
    attempts: r.attempts,
    blockedCode: r.blockedCode,
    blockedReason: r.blockedReason,
    error: r.error,
    detail: '',
    envelopeBytes: Number(r.envelopeBytes),
    enqueuedAt: r.enqueuedAt.toISOString(),
    startedAt: r.startedAt ? r.startedAt.toISOString() : null,
    finishedAt: r.finishedAt ? r.finishedAt.toISOString() : null,
    // 'queue' rows are cancellable through /api/job-queue/{id}; 'scan' rows are a
    // running scan that was never queued, so the UI must not offer queue actions.
    source: 'queue' as const,
    ...initiatorField(people, r.userId),
  }
}

/**
 * A scan started straight from its Start button never becomes a JobQueue row (the
 * queue's producers are the refusal modal, the scheduler and the batch), so the
 * queue alone cannot see it. Every kind now writes a ScanJob at start, so this is
 * the durable record - it survives an orchestrator restart, which the live source
 * does not.
 */
type ScanRow = {
  id: string
  projectId: string
  kind: string
  runId: string
  startedAt: Date | null
  createdAt: Date
  /** Selected only with sharing in force. */
  initiatedByUserId?: string | null
  project: { name: string } | null
}

function serializeScan(s: ScanRow, people: People | null) {
  return {
    id: s.id,
    projectId: s.projectId,
    projectName: s.project?.name ?? '',
    kind: s.kind,
    status: 'running',
    priority: 0,
    attempts: 0,
    blockedCode: '',
    blockedReason: '',
    error: '',
    detail: '',
    envelopeBytes: 0,
    enqueuedAt: s.createdAt.toISOString(),
    startedAt: s.startedAt ? s.startedAt.toISOString() : null,
    finishedAt: null,
    source: 'scan' as const,
    ...initiatorField(people, s.initiatedByUserId),
  }
}

/** A scan the orchestrator is holding right now, of any kind. */
interface LiveScan {
  kind: string
  project_id: string
  run_id: string
  tool_id: string
  status: string
  started_at: string | null
}

function serializeLive(s: LiveScan, projectName: string, people: People | null) {
  return {
    id: `${s.kind}:${s.project_id}:${s.run_id}`,
    projectId: s.project_id,
    projectName,
    kind: s.kind,
    status: s.status,
    priority: 0,
    attempts: 0,
    blockedCode: '',
    blockedReason: '',
    error: '',
    // Which tool this run is: several partial recons in one project are otherwise
    // indistinguishable rows.
    detail: s.tool_id || '',
    envelopeBytes: 0,
    enqueuedAt: s.started_at ?? '',
    startedAt: s.started_at,
    finishedAt: null,
    source: 'live' as const,
    ...initiatorField(people, null),
  }
}

/** Identity of an in-flight scan across the three sources. partial_recon and
 *  ai_attack can have several concurrent runs in one project, so the run id is
 *  part of the key when there is one.
 *
 *  A per-repo batch item (`supply_chain_repo`) runs in the SAME container/state as
 *  a single supply-chain scan, so the orchestrator's live source reports it as
 *  `supply_chain`. Collapse the two to one family here or the same running scan is
 *  listed twice: once from its `supply_chain_repo` queue row and once from the
 *  `supply_chain` live entry. Safe: per-project serialization (C-12) means a
 *  project never has a single and a repo supply-chain scan running at once. */
function dedupKind(kind: string): string {
  return kind === 'supply_chain_repo' ? 'supply_chain' : kind
}
function runKey(kind: string, projectId: string, runId = ''): string {
  const k = dedupKind(kind)
  return runId ? `${k}|${projectId}|${runId}` : `${k}|${projectId}`
}

const SELECT = {
  id: true, projectId: true, kind: true, status: true, priority: true, attempts: true,
  blockedCode: true, blockedReason: true, error: true, envelopeBytes: true,
  enqueuedAt: true, startedAt: true, finishedAt: true, scanJobId: true, runId: true,
  project: { select: { name: true } },
} as const

const SCAN_SELECT = {
  id: true, projectId: true, kind: true, runId: true, startedAt: true, createdAt: true,
  project: { select: { name: true } },
} as const

const SELECT_WITH_INITIATOR = { ...SELECT, userId: true } as const
const SCAN_SELECT_WITH_INITIATOR = { ...SCAN_SELECT, initiatedByUserId: true } as const

/** The names of the accounts that started the listed rows, in one read. */
async function peopleOf(ids: Array<string | null | undefined>): Promise<People> {
  const wanted = [...new Set(ids.filter((id): id is string => typeof id === 'string' && id !== ''))]
  const rows = wanted.length === 0 ? [] : await prisma.user.findMany({
    where: { id: { in: wanted } },
    select: { id: true, name: true },
  })
  const names = new Map(rows.map(u => [u.id, u.name]))
  return (userId) => (userId ? { id: userId, name: names.get(userId) ?? null } : null)
}

export const GET = withRouteErrors('Could not load scan activity', async (_request: NextRequest) => {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff

  try {
    // One filter for every read below, so they agree on what "mine" is.
    const visible = await visibleProjects(eff)
    const mineWhere = visible.where
    const queueScope = jobQueueScope(eff, visible)
    const select = visible.withShares ? SELECT_WITH_INITIATOR : SELECT
    const [
      mine, recent, othersActive, othersNeedsReview, runningScans, othersRunningScans,
      myProjects, liveScans,
    ] = await Promise.all([
      prisma.jobQueue.findMany({
        where: { ...queueScope.mine, status: { in: ['running', 'dispatching', 'queued', 'needs_review'] } },
        orderBy: [{ priority: 'desc' }, { enqueuedAt: 'asc' }],
        select,
      }),
      prisma.jobQueue.findMany({
        where: { ...queueScope.mine, status: { in: ['done', 'failed', 'canceled'] } },
        orderBy: { finishedAt: 'desc' },
        take: RECENT_LIMIT,
        select,
      }),
      prisma.jobQueue.groupBy({
        // Grouped by the ScanJob a row started, so a dispatched scan already
        // counted from its ScanJob is not counted again from its queue row.
        by: ['status', 'scanJobId'],
        where: { ...queueScope.others, status: { in: ['running', 'dispatching', 'queued'] } },
        _count: { _all: true },
      }),
      prisma.jobQueue.count({
        where: { ...queueScope.others, status: 'needs_review' },
      }),
      // Scoped by the projects the operator sees, not by initiator: a scan the agent
      // or a schedule started has no initiator, and it is still this operator's scan.
      prisma.scanJob.findMany({
        where: { status: 'running', project: mineWhere },
        orderBy: { startedAt: 'desc' },
        select: visible.withShares ? SCAN_SELECT_WITH_INITIATOR : SCAN_SELECT,
      }),
      prisma.scanJob.count({
        where: { status: 'running', project: { NOT: mineWhere } },
      }),
      // Which projects are mine, so a live scan can be attributed without a second
      // round trip per row.
      prisma.project.findMany({
        where: mineWhere,
        select: visible.withShares ? { id: true, name: true, userId: true } : { id: true, name: true },
      }),
      // Every kind the orchestrator is holding right now. Best effort: if it is
      // unreachable the DB sources still answer.
      (async (): Promise<LiveScan[]> => {
        try {
          const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/system/active-scans`, { method: 'GET' })
          if (!res.ok) return []
          const body = await res.json()
          return Array.isArray(body?.scans) ? body.scans as LiveScan[] : []
        } catch {
          return []
        }
      })(),
    ])

    const people = visible.withShares
      ? await peopleOf([
        ...mine.map(r => (r as Row).userId), ...recent.map(r => (r as Row).userId),
        ...runningScans.map(s => (s as ScanRow).initiatedByUserId),
      ])
      : null
    const queued = mine.filter(r => r.status === 'queued').map(r => serialize(r, people))
    const needsReview = mine.filter(r => r.status === 'needs_review').map(r => serialize(r, people))

    const projectNames = new Map(myProjects.map(p => [p.id, p.name]))

    // Union the three running sources, richest identity first.
    //
    // `seen` holds exact keys. `pending` counts rows claimed WITHOUT a run id (a
    // queue row between dispatch and recording its run id, and every ScanJob):
    // the live entry for such a scan carries a run id the DB row does not have
    // yet, so it can only be matched on kind+project. It is a counter, not a flag,
    // so a project genuinely running two partial recons still lists both.
    const seen = new Set<string>()
    const pending = new Map<string, number>()
    const claim = (kind: string, projectId: string, runId = '') => {
      seen.add(runKey(kind, projectId, runId))
      if (!runId) {
        const k = runKey(kind, projectId)
        pending.set(k, (pending.get(k) ?? 0) + 1)
      }
    }

    const queueRunning = mine.filter(r => r.status === 'running' || r.status === 'dispatching')
    for (const r of queueRunning) claim(r.kind, r.projectId, r.runId)

    // A ScanJob row is closed to a terminal state only by a per-project status poll
    // (a browser viewing that project) or the reaper's queue reconcile. A scan that
    // STOPPED or finished with nobody viewing leaves a phantom 'running' ScanJob, so
    // the queue would show a scan that is not actually running. Drop such phantoms
    // using the orchestrator's live set as the source of truth — but ONLY when it is
    // authoritative and only past a start grace, so neither an orchestrator restart
    // (live momentarily empty) nor a scan that just started (not yet in the live
    // set) is ever wrongly hidden.
    const LIVE_FILTER_GRACE_MS = 90_000
    const liveKeys = new Set<string>()
    for (const s of liveScans) {
      liveKeys.add(runKey(s.kind, s.project_id, s.run_id))
      liveKeys.add(runKey(s.kind, s.project_id))
    }
    const liveAuthoritative = liveScans.length > 0
    const nowMs = Date.now()
    const isLiveScanJob = (s: ScanRow): boolean => {
      if (!liveAuthoritative) return true                       // can't tell -> keep (restart-safe)
      if (s.startedAt && nowMs - s.startedAt.getTime() < LIVE_FILTER_GRACE_MS) return true  // may not be in live yet
      const key = s.runId ? runKey(s.kind, s.projectId, s.runId) : runKey(s.kind, s.projectId)
      return liveKeys.has(key)
    }

    // A queue row that reached dispatch carries the ScanJob it started, so the two
    // sources would otherwise list the same scan twice.
    const claimedScanJobs = new Set(queueRunning.map(r => r.scanJobId).filter((v): v is string => !!v))
    const freeScans = runningScans.filter(s => !claimedScanJobs.has(s.id) && isLiveScanJob(s))
    for (const s of freeScans) claim(s.kind, s.projectId, s.runId)

    const freeLive = liveScans.filter(s => {
      if (!projectNames.has(s.project_id)) return false        // not mine: an anonymous count
      if (seen.has(runKey(s.kind, s.project_id, s.run_id))) return false
      const k = runKey(s.kind, s.project_id)
      const waiting = pending.get(k) ?? 0
      if (waiting > 0) { pending.set(k, waiting - 1); return false }
      return true
    })

    const running = [
      ...queueRunning.map(r => serialize(r, people)),
      ...freeScans.map(s => serializeScan(s, people)),
      ...freeLive.map(s => serializeLive(s, projectNames.get(s.project_id) ?? '', people)),
    ]

    // Everyone else's in-flight work, as one anonymised number. Counted from the DB
    // only: every scan that started writes a ScanJob, whether a button or the
    // queue started it, except a supply_chain_repo batch item, and a queue row
    // records the ScanJob it started when it goes `running`. So a queue row
    // counts only while it has none: dispatching, supply_chain_repo, or a start
    // whose history write failed. The live source is not consulted here -
    // without per-project rows there is no key to de-duplicate it against.
    const othersAgg = {
      queued: 0,
      running: othersRunningScans,
      needsReview: othersNeedsReview,
    }
    for (const g of othersActive) {
      const n = g._count._all
      if (g.status === 'queued') othersAgg.queued += n
      else if (!g.scanJobId) othersAgg.running += n
    }

    // Best-effort ledger snapshot from the orchestrator (drives the "waiting for
    // memory/capacity" hint). Never fails the request.
    let ledger: unknown = null
    try {
      const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/system/stats`, { method: 'GET' })
      if (res.ok) ledger = await res.json()
    } catch {
      /* orchestrator unreachable: the queue view still renders */
    }

    return NextResponse.json({
      mine: { running, queued, needsReview, recent: recent.map(r => serialize(r, people)) },
      others: othersAgg,
      ledger,
      ...(visible.withShares ? { sharedProjectIds: sharedProjectIds(eff, visible, myProjects) } : {}),
    })
  } catch (error) {
    return internalError(error, 'Could not load scan activity', { log: '[jobQueue] system/jobs failed' })
  }
})
