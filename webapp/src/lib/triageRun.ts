/**
 * The lifecycle of a triage run, shared by the five internal routes.
 *
 * A triage run used to exist only in the agent's memory. Nothing else in the
 * product could see one, so version activation, version save, the delta
 * preview, project import and project delete could all swap or delete the graph
 * while a run was halfway through reading it — and then the run would publish
 * its results onto a graph that no longer matched.
 *
 * `TriageRun` makes the run a row. Three rules follow from that:
 *
 * 1. **The agent authorises before it works.** The run is created through an
 *    internal route that re-checks ownership STRICTLY, ignoring the log-only
 *    `ACCESS_ENFORCE=0` mode, so a ticket minted in observe-mode cannot start a
 *    run on somebody else's project.
 * 2. **A stale heartbeat stops blocking.** A crashed agent must not hold a
 *    project forever, so a run that has not checked in for ten minutes no
 *    longer counts as live, and the next create marks it failed.
 * 3. **Publishing is a conditional transition.** `running -> publishing` uses
 *    the same atomic `updateMany` pattern as the activation lock, so a run that
 *    lost its claim writes nothing at all rather than writing half of it.
 */
import prisma from '@/lib/prisma'
import { isActivationInProgress } from '@/lib/activationLock'

/** Statuses in which a run still intends to write. */
export const LIVE_TRIAGE_STATUSES = ['running', 'publishing'] as const

export const TRIAGE_STATUSES = [
  'running', 'publishing', 'completed', 'completed_partial', 'failed', 'stopped',
] as const

export type TriageStatus = (typeof TRIAGE_STATUSES)[number]

/**
 * How long a run may go without a heartbeat before it stops blocking guards.
 * Ten minutes is a deliberate trade: long enough that a slow LLM batch or a
 * paused container is not mistaken for a crash, short enough that an operator
 * is not locked out of activation for the rest of the day.
 */
export function triageHeartbeatTtlMs(): number {
  const configured = Number(process.env.TRIAGE_HEARTBEAT_TTL_MS)
  return Number.isFinite(configured) && configured > 0 ? configured : 10 * 60 * 1000
}

export function heartbeatIsStale(heartbeatAt: Date | null, now = Date.now()): boolean {
  if (!heartbeatAt) return true
  return now - heartbeatAt.getTime() > triageHeartbeatTtlMs()
}

export interface LiveRun {
  id: string
  status: string
  startedAt: Date
  actorUserId: string
  model: string
}

/**
 * The run currently holding this project, or null.
 *
 * Runs whose heartbeat has gone stale are reported as failed here rather than
 * returned, so one call both answers the question and cleans up after a crashed
 * agent. Sweeping is best-effort: failing to mark a dead run must not make the
 * caller believe a live one exists.
 */
export async function findLiveTriageRun(projectId: string): Promise<LiveRun | null> {
  const candidates = await prisma.triageRun.findMany({
    where: { projectId, status: { in: [...LIVE_TRIAGE_STATUSES] } },
    orderBy: { startedAt: 'desc' },
    select: {
      id: true, status: true, startedAt: true, heartbeatAt: true,
      actorUserId: true, model: true,
    },
  })

  const now = Date.now()
  const live = candidates.filter((run) => !heartbeatIsStale(run.heartbeatAt, now))
  const dead = candidates.filter((run) => heartbeatIsStale(run.heartbeatAt, now))

  if (dead.length > 0) {
    try {
      await prisma.triageRun.updateMany({
        where: { id: { in: dead.map((run) => run.id) } },
        data: { status: 'failed', errorClass: 'agent_lost', finishedAt: new Date() },
      })
    } catch (e) {
      console.error('[triageRun] could not mark a lost run failed:', e)
    }
  }

  if (live.length === 0) return null
  const [run] = live
  return {
    id: run.id, status: run.status, startedAt: run.startedAt,
    actorUserId: run.actorUserId, model: run.model,
  }
}

export interface StartRefusal {
  reason: string
  /** So the UI can offer Stop on the run that is in the way. */
  runId?: string
}

/**
 * Everything that must be true before a run may start.
 *
 * FAIL CLOSED throughout: a check that cannot be answered refuses the run. A
 * refused run costs the operator one button press; a run that starts against a
 * graph somebody else is replacing costs them the results.
 */
export async function refuseTriageStart(
  projectId: string,
  actorUserId: string,
): Promise<StartRefusal | null> {
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { id: true, userId: true },
  })
  // A project that does not exist and one owned by somebody else are the same
  // answer, so this cannot be used to enumerate project ids.
  if (!project || project.userId !== actorUserId) {
    return { reason: 'Not found' }
  }

  if (await isActivationInProgress(projectId)) {
    return { reason: 'A version activation is in progress for this project.' }
  }

  const live = await findLiveTriageRun(projectId)
  if (live) {
    return {
      reason: 'A triage run is already in progress for this project.',
      runId: live.id,
    }
  }

  return null
}

/**
 * Move a run from `running` to `publishing`, or refuse.
 *
 * The conditional `updateMany` is the whole point: two callers cannot both see
 * `running` and both proceed. A run that does not win writes nothing, which is
 * what keeps a publish atomic across Neo4j and Postgres without a distributed
 * transaction.
 */
export async function claimPublish(
  runId: string,
): Promise<{ ok: true } | { ok: false; reason: string; errorClass: string }> {
  const run = await prisma.triageRun.findUnique({
    where: { id: runId },
    select: { id: true, projectId: true, status: true, heartbeatAt: true },
  })
  if (!run) return { ok: false, reason: 'Unknown run', errorClass: 'unknown_run' }

  if (run.status !== 'running') {
    return {
      ok: false,
      reason: `The run is ${run.status}, not running.`,
      errorClass: 'publish_refused',
    }
  }
  if (heartbeatIsStale(run.heartbeatAt)) {
    return {
      ok: false,
      reason: 'The run stopped checking in.',
      errorClass: 'agent_lost',
    }
  }
  if (await isActivationInProgress(run.projectId)) {
    return {
      ok: false,
      reason: 'A version activation started while the run was working.',
      errorClass: 'publish_refused',
    }
  }

  const claimed = await prisma.triageRun.updateMany({
    where: { id: runId, status: 'running' },
    data: { status: 'publishing' },
  })
  if (claimed.count === 0) {
    return {
      ok: false,
      reason: 'The run was no longer running.',
      errorClass: 'publish_refused',
    }
  }
  return { ok: true }
}
