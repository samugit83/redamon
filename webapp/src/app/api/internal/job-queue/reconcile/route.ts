/**
 * Scan Queue - close out finished 'running' jobs (plan Phase 2, C-6). Internal-key
 * only. The orchestrator reaper posts the set of projectIds that currently have a
 * live scan container, so a job that finished with every browser tab closed is
 * still marked terminal (job completion must never depend on a browser being open).
 *
 * Two things are reconciled from the same authoritative signal:
 *   1. `JobQueue` 'running' rows (the queue's own bookkeeping).
 *   2. `ScanJob` 'running' history rows for the one-per-project scan kinds. These
 *      are otherwise closed ONLY by a per-project status poll (a browser viewing
 *      that project), so a scheduled scan that finishes with nobody watching leaves
 *      its row stuck at 'running' - and a 15-minute schedule then piles up a stack
 *      of stuck rows that LOOKS like many parallel scans. Closing them here, every
 *      reaper tick, makes run history tell the truth without a browser open.
 *
 * Fail-safe: a row is only closed when its project is NOT in the active set AND it
 * has been running past a short grace window, so a container that has not yet
 * appeared in the live set right after dispatch is never closed prematurely. The
 * run-keyed kinds (partial recon, trufflehog, AI attack) go by their own run in the
 * orchestrator's listing instead, since one project runs several at once.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { readDegradedSourceCount } from '@/lib/scanCoverage'
import { orchestratorFetch } from '@/lib/orchestrator'

export const runtime = 'nodejs'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

// A just-dispatched container may take a beat to appear in the orchestrator's live
// run set; do not close a running row younger than this.
const RECONCILE_GRACE_MS = 90_000

// Never touch more than this many stale ScanJobs per tick, so an initial backlog
// (many historically-stuck rows) drains over a few ticks instead of one burst of
// orchestrator status fetches. Steady state is ~0-1 per tick.
const MAX_SCANJOBS_PER_TICK = 25

// Kinds that write ONE ScanJob per project (so a project-granular "is anything live
// here?" signal is enough to call a row stale) AND can end with no browser open.
// Deliberately excluded:
//   - partial_recon / trufflehog / ai_attack: run-keyed (several concurrent runs
//     per project, one per SOURCE for trufflehog). Here they would force-cancel
//     all but the newest row per (project, kind) while those containers still
//     ran. They get the run-granular sweep below.
//   - supply_chain_repo: only ever queue-dispatched, and dispatchStart records no
//     ScanJob for it - its history lives in the JobQueue, closed by the queue
//     reconcile above.
const ONE_PER_PROJECT_KINDS = ['full_recon', 'supply_chain', 'gvm', 'github_hunt']

// Kinds whose rows are keyed by run id, and the orchestrator listing of every run
// of the kind for a project. Partial recon's lives under /recon, and AI attack's
// under /ai-attack-surface, not a segment named after the kind.
const RUN_LIST_PATH: Record<string, (projectId: string) => string> = {
  trufflehog: p => `/trufflehog/${p}/all`,
  partial_recon: p => `/recon/${p}/partial/all`,
  ai_attack: p => `/ai-attack-surface/${p}/all`,
}

// Listed statuses that mean the run is still going: its row is left running.
const LIVE_RUN_STATUSES = new Set(['starting', 'running', 'stopping', 'paused'])

// The orchestrator status path for each swept kind.
const STATUS_PATH: Record<string, string> = {
  full_recon: 'recon',
  supply_chain: 'supply-chain',
  gvm: 'gvm',
  github_hunt: 'github-hunt',
}

/**
 * Every run's status for a run-keyed kind, keyed by run id, or null when the
 * listing cannot be read.
 *
 * Reads the /all listing rather than a project-level status: with N runs in
 * parallel, one status describes one of them and the other N-1 would be closed
 * from the wrong run's outcome.
 */
async function fetchRunStatuses(kind: string, projectId: string): Promise<Map<string, string> | null> {
  const path = RUN_LIST_PATH[kind]
  if (!path) return null
  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}${path(projectId)}`, { method: 'GET' })
    if (!res.ok) return null
    const body = await res.json().catch(() => null)
    if (!Array.isArray(body?.runs)) return null
    const out = new Map<string, string>()
    for (const run of body.runs as { run_id?: unknown; status?: unknown }[]) {
      if (typeof run?.run_id === 'string' && typeof run?.status === 'string') {
        out.set(run.run_id, run.status)
      }
    }
    return out
  } catch {
    return null
  }
}

/**
 * The status to close a run-keyed row with, or null to leave it running.
 *
 * A run the listing reports as ended is closed at once, however young the row:
 * the orchestrator drops an ended run from its listing about a minute later,
 * after which only "over, outcome unknown" can be said. A run the listing no
 * longer has is over once its row is past the grace (a stopped run leaves at
 * once). An unreadable listing says nothing about a project that still has a
 * live run; for an idle project the run is over and only its outcome is unknown.
 */
function runRowOutcome(
  listing: Map<string, string> | null,
  runId: string,
  pastGrace: boolean,
  projectActive: boolean,
): string | null {
  const status = runId && listing ? listing.get(runId) : undefined
  if (status === 'completed') return 'completed'
  if (status === 'error') return 'failed'
  if (status && LIVE_RUN_STATUSES.has(status)) return null
  if (!pastGrace) return null
  if (!listing && projectActive) return null
  return 'canceled'
}

/**
 * The orchestrator's current status for a project's scan of `kind`, or undefined if
 * it cannot be read. The caller treats undefined as "over but unconfirmed" and
 * records the row as canceled rather than leaving it stuck at 'running': the
 * project is already known idle (not in the reaper's active set, past the grace),
 * so the scan is over regardless - only its outcome label is uncertain.
 */
async function fetchScanStatus(kind: string, projectId: string): Promise<string | undefined> {
  const seg = STATUS_PATH[kind]
  if (!seg) return undefined
  try {
    const res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/${seg}/${projectId}/status`, { method: 'GET' })
    if (!res.ok) return undefined
    const body = await res.json().catch(() => null)
    return typeof body?.status === 'string' ? body.status : undefined
  } catch {
    return undefined
  }
}

export async function POST(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  try {
    const body = await request.json().catch(() => ({}))
    const activeProjects: string[] = Array.isArray(body?.activeProjects)
      ? body.activeProjects.filter((p: unknown): p is string => typeof p === 'string')
      : []
    const activeSet = new Set(activeProjects)

    const cutoff = new Date(Date.now() - RECONCILE_GRACE_MS)
    const running = await prisma.jobQueue.findMany({
      where: { status: 'running' },
      select: { id: true, projectId: true, startedAt: true },
    })

    const toClose = running.filter(
      r => !activeSet.has(r.projectId) && (r.startedAt == null || r.startedAt <= cutoff),
    )

    let closed = 0
    for (const r of toClose) {
      // The ScanJob history row (linked via scanJobId) carries the real
      // completed/failed outcome; the queue row only needs to leave 'running'.
      await prisma.jobQueue
        .updateMany({
          where: { id: r.id, status: 'running' },
          data: { status: 'done', finishedAt: new Date() },
        })
        .then(res => { closed += res.count })
        .catch(() => {})
    }

    // Close stuck one-per-project ScanJob rows. Ordered newest-first within each
    // (project, kind) group so that, per group, the newest row takes the
    // orchestrator's real outcome (completed / failed / canceled-if-forgotten) and
    // any older rows - superseded runs that start_recon force-replaced - are
    // recorded as canceled rather than left stuck at 'running'.
    // Exclude active projects IN the query (not just after), so genuinely-running
    // scans never consume the per-tick budget and starve the stale rows behind them.
    // The post-filter is a cheap defense-in-depth backstop for the same invariant.
    const staleScans = (await prisma.scanJob.findMany({
      where: {
        status: 'running',
        kind: { in: ONE_PER_PROJECT_KINDS },
        OR: [{ startedAt: null }, { startedAt: { lte: cutoff } }],
        ...(activeProjects.length ? { projectId: { notIn: activeProjects } } : {}),
      },
      orderBy: [{ projectId: 'asc' }, { kind: 'asc' }, { startedAt: 'desc' }],
      take: MAX_SCANJOBS_PER_TICK,
      select: { id: true, projectId: true, kind: true },
    })).filter(s => !activeSet.has(s.projectId))

    let scansClosed = 0
    const groupSeen = new Set<string>()
    for (const s of staleScans) {
      const gk = `${s.projectId}|${s.kind}`
      let outcome: string
      if (!groupSeen.has(gk)) {
        groupSeen.add(gk)
        const status = await fetchScanStatus(s.kind, s.projectId)
        outcome = status === 'completed' ? 'completed' : status === 'error' ? 'failed' : 'canceled'
      } else {
        outcome = 'canceled' // an older, superseded run for the same project+kind
      }
      // Stamp degraded-source coverage from the graph, full_recon completions
      // only (the same rule as the status-poll close path).
      const degradedSources =
        s.kind === 'full_recon' && outcome === 'completed'
          ? await readDegradedSourceCount(s.projectId)
          : null
      await prisma.scanJob
        .updateMany({
          where: { id: s.id, status: 'running' },
          data: { status: outcome, finishedAt: new Date(), degradedSources },
        })
        .then(res => { scansClosed += res.count })
        .catch(() => {})
    }

    // Run-granular sweep for the run-keyed kinds. Each row is closed from ITS
    // OWN run's status in the /all listing, so parallel runs do not cancel one
    // another (runRowOutcome). No grace in the queries: a short run's listed
    // outcome must be read before the orchestrator drops it. Idle projects are
    // swept in their own budget, so live runs never starve their stuck rows; an
    // active project's rows are read too, or one long partial run would keep
    // its finished siblings `running` until it ended.
    const runKeyed = { status: 'running', kind: { in: Object.keys(RUN_LIST_PATH) } }
    const runSelect = { id: true, projectId: true, kind: true, runId: true, startedAt: true }
    const staleRuns = [
      ...(await prisma.scanJob.findMany({
        where: { ...runKeyed, ...(activeProjects.length ? { projectId: { notIn: activeProjects } } : {}) },
        orderBy: [{ projectId: 'asc' }, { kind: 'asc' }],
        take: MAX_SCANJOBS_PER_TICK,
        select: runSelect,
      })).filter(s => !activeSet.has(s.projectId)),
      ...(activeProjects.length
        ? await prisma.scanJob.findMany({
            where: { ...runKeyed, projectId: { in: activeProjects } },
            orderBy: [{ startedAt: 'asc' }],
            take: MAX_SCANJOBS_PER_TICK,
            select: runSelect,
          })
        : []),
    ]

    const runStatusCache = new Map<string, Map<string, string> | null>()
    for (const s of staleRuns) {
      const cacheKey = `${s.projectId}|${s.kind}`
      if (!runStatusCache.has(cacheKey)) {
        runStatusCache.set(cacheKey, await fetchRunStatuses(s.kind, s.projectId))
      }
      const pastGrace = s.startedAt == null || s.startedAt <= cutoff
      const outcome = runRowOutcome(
        runStatusCache.get(cacheKey) ?? null, s.runId, pastGrace, activeSet.has(s.projectId))
      if (!outcome) continue
      await prisma.scanJob
        .updateMany({
          where: { id: s.id, status: 'running' },
          data: { status: outcome, finishedAt: new Date() },
        })
        .then(res => { scansClosed += res.count })
        .catch(() => {})
    }

    return NextResponse.json({ ok: true, closed, running: running.length, scansClosed })
  } catch (error) {
    console.error('[jobQueue] reconcile failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
