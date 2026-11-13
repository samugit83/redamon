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
 *    internal route that re-checks ownership STRICTLY, so a ticket cannot start
 *    a run on somebody else's project.
 * 2. **A stale heartbeat stops blocking.** A crashed agent must not hold a
 *    project forever, so a run that has not checked in for ten minutes no
 *    longer counts as live, and the next create marks it failed.
 * 3. **Publishing is a conditional transition.** `running -> publishing` uses
 *    the same atomic `updateMany` pattern as the activation lock, so a run that
 *    lost its claim writes nothing at all rather than writing half of it.
 */
import prisma from '@/lib/prisma'
import { isActivationInProgress } from '@/lib/activationLock'
import { meetsLevel, projectAccess } from '@/lib/authz/projectAccess'
import { PERMISSIONS } from '@/lib/authz/permissions'
import { MCP_RUN_COOLDOWN_MS, MCP_RUNS_PER_DAY } from '@/lib/triage/limits'

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
  /** `app` or `mcp`. Absent from a row created before the column existed. */
  trigger?: string
  tokenId?: string | null
  phase?: string
  progress?: number
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
      actorUserId: true, model: true, trigger: true, tokenId: true,
      phase: true, progress: true,
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
    trigger: run.trigger, tokenId: run.tokenId, phase: run.phase, progress: run.progress,
  }
}

/** The runs a status view lists, newest first. Counts and codes only. */
export async function latestTriageRuns(projectId: string, take = 5) {
  return prisma.triageRun.findMany({
    where: { projectId },
    orderBy: { startedAt: 'desc' },
    take,
    select: {
      id: true, status: true, startedAt: true, finishedAt: true, model: true,
      summary: true, errorClass: true, trigger: true,
    },
  })
}

/**
 * The newest run whose results the board shows: the latest completed one.
 * An imported project has no runs, and its findings still carry the run id
 * that ranked them, so the caller falls back to that (`latestRunIdFrom`).
 */
/** A run whose results reached the board. */
export const PUBLISHED_TRIAGE_STATUSES = ['completed', 'completed_partial'] as const

export async function latestPublishedRunId(projectId: string): Promise<string | null> {
  const run = await prisma.triageRun.findFirst({
    where: { projectId, status: { in: [...PUBLISHED_TRIAGE_STATUSES] } },
    orderBy: { startedAt: 'desc' },
    select: { id: true },
  })
  return run?.id ?? null
}

/** The run id of the most recently triaged finding: an imported project's "latest run". */
export function latestRunIdFrom(
  findings: Array<{ triage_run_id?: unknown; triaged_at?: unknown }>,
): string | null {
  let best: { id: string; at: string } | null = null
  for (const f of findings) {
    const id = typeof f.triage_run_id === 'string' ? f.triage_run_id : ''
    const at = typeof f.triaged_at === 'string' ? f.triaged_at : ''
    if (!id || !at) continue
    if (!best || at > best.at) best = { id, at }
  }
  return best?.id ?? null
}

export { MCP_RUN_COOLDOWN_MS, MCP_RUNS_PER_DAY }

export interface McpRunBudget {
  runsToday: number
  /** When the next MCP start is allowed, or null when it is allowed now. */
  nextAllowedAt: Date | null
  reason: 'cooldown' | 'daily_cap' | null
}

/**
 * Where a project stands against the MCP cooldown and daily cap, counted from
 * its `TriageRun` rows with `trigger = 'mcp'`, across every token.
 *
 * The cooldown runs from the previous MCP-started run's `finishedAt`, or its
 * last heartbeat when it never finished. Throws on a read error: the caller
 * refuses the start (fail closed).
 */
export async function mcpRunBudget(projectId: string, now = Date.now()): Promise<McpRunBudget> {
  const dayAgo = new Date(now - 24 * 60 * 60 * 1000)
  const [today, last] = await Promise.all([
    prisma.triageRun.findMany({
      where: { projectId, trigger: 'mcp', startedAt: { gte: dayAgo } },
      orderBy: { startedAt: 'asc' },
      select: { startedAt: true },
    }),
    prisma.triageRun.findFirst({
      where: { projectId, trigger: 'mcp' },
      orderBy: { startedAt: 'desc' },
      select: { finishedAt: true, heartbeatAt: true, startedAt: true, errorClass: true },
    }),
  ])

  let nextAllowedAt: Date | null = null
  let reason: McpRunBudget['reason'] = null
  if (last) {
    // A lost run's `finishedAt` is when the loss was NOTICED, which can be
    // hours later; it stopped at its last heartbeat.
    const endedAt = last.errorClass === 'agent_lost'
      ? last.heartbeatAt
      : (last.finishedAt ?? last.heartbeatAt ?? last.startedAt)
    const ended = endedAt.getTime()
    if (now < ended + MCP_RUN_COOLDOWN_MS) {
      nextAllowedAt = new Date(ended + MCP_RUN_COOLDOWN_MS)
      reason = 'cooldown'
    }
  }
  if (today.length >= MCP_RUNS_PER_DAY) {
    // The window reopens when the oldest run in it is a day old.
    const reopens = new Date(today[today.length - MCP_RUNS_PER_DAY].startedAt.getTime()
                             + 24 * 60 * 60 * 1000)
    if (!nextAllowedAt || reopens > nextAllowedAt) nextAllowedAt = reopens
    reason = 'daily_cap'
  }
  return { runsToday: today.length, nextAllowedAt, reason }
}

/** How many finished rows a project keeps at least, whatever their age. */
export const TRIAGE_RUN_KEEP_NEWEST = 50
/** Finished rows younger than this are never trimmed. */
export const TRIAGE_RUN_KEEP_MS = 24 * 60 * 60 * 1000

/**
 * Trim a project's finished runs, never anything still in use (C11).
 *
 * A row is deleted only when ALL hold: it started more than a day ago, it is
 * not among the newest 50, it is not the newest published run (the board's
 * "latest run" and the remediations read it), and it is not live. The MCP
 * cooldown and daily cap read the last day only, so trimming older rows
 * cannot reopen them. Best-effort: never throws.
 */
export async function trimTriageRuns(projectId: string, now = Date.now()): Promise<number> {
  try {
    const [newest, newestPublished] = await Promise.all([
      prisma.triageRun.findMany({
        where: { projectId },
        orderBy: { startedAt: 'desc' },
        take: TRIAGE_RUN_KEEP_NEWEST,
        select: { id: true },
      }),
      // The board's "latest run": partial runs published too.
      prisma.triageRun.findFirst({
        where: { projectId, status: { in: [...PUBLISHED_TRIAGE_STATUSES] } },
        orderBy: { startedAt: 'desc' },
        select: { id: true },
      }),
    ])
    const keep = new Set(newest.map((r) => r.id))
    if (newestPublished) keep.add(newestPublished.id)
    const deleted = await prisma.triageRun.deleteMany({
      where: {
        projectId,
        startedAt: { lt: new Date(now - TRIAGE_RUN_KEEP_MS) },
        status: { notIn: [...LIVE_TRIAGE_STATUSES] },
        id: { notIn: [...keep] },
      },
    })
    return deleted.count
  } catch (e) {
    console.error('[triageRun] could not trim finished runs:', e)
    return 0
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
  // A project that does not exist and one the actor cannot see are the same
  // answer, so this cannot be used to enumerate project ids. The actor is the
  // person the run is for, who may be a collaborator (step 5.3: the agent sends
  // the ticket's `sub`, while the run reads the owner's graph): their access must
  // reach `triage:run`'s level, as the ticket route and the MCP start asked of the
  // permission itself. Below that level a run never starts.
  const access = await projectAccess({ userId: actorUserId }, projectId)
  const level = PERMISSIONS['triage:run'].level
  if (!access || level === null || !meetsLevel(access, level)) {
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
