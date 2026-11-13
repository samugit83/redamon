/**
 * Losing access stops the person's live work (step 5.9; SH-11, SH-12, SH-41, OQ-13): the one path
 * every reduction of access takes once its change has committed. A ticket is checked only when its
 * socket opens and a queued or scheduled scan only when it fires, so the change alone would leave a
 * run, a terminal or a triage run going on access that is gone.
 *
 * `onAccessReduced(projectId, userId, reason)` plays the reason's plan (PLANS):
 * - on one project (a share revoked, left, expired, force-revoked or narrowed; the owner's consent
 *   withdrawn): the person's agent runs there stop (`/agent-sessions/stop-for`), their sockets there
 *   close (`/ws/close` with the project, which also reaches an admin's act-as sockets as them), their
 *   queued scans that have not started are cancelled and their schedules paused when they may no
 *   longer start them (the same check the queue and the scheduler make when the work fires, so a
 *   narrowing that keeps Run scans cancels nothing), and a live triage run they started is stopped;
 * - on the account: a disable keeps what step 2.3 did (runs stopped, every socket closed with scope
 *   `account`, the account's own impersonations ended; its deferred work is skipped while it is
 *   disabled and resumes after an enable); a session-version bump closes every socket (`account`)
 *   and ends the impersonations; a capability removal does the project plan on every project of the
 *   person, sockets with scope `account` because its callers raise the session version too; a
 *   deletion does that too; a device session's revoke and a lost legacy terminal grant close sockets
 *   with the default scope (the terminal ones only for the grant).
 * Scans already running finish (OQ-13). The person's MCP tokens fail on their next call (every MCP
 * tool asks projectAccess() and can() per call); an Agent in the Loop driver's step leases end with
 * the run they belong to; open pages follow the stale-access poll.
 *
 * Each step is best effort and never throws: a failure is logged `[rbac] revocation step failed
 * step=<name>` (beside the helper's own `[rbac] socket-close failed` / `[rbac] agent-stop failed`)
 * and reported in the answer, and the change that called it stands. Calling it twice, or twice at
 * once, stops nothing twice: each job and schedule is changed by an update conditional on its state,
 * in one transaction with its audit row (`job_queue.cancelled`, `scan_schedule.paused`), and only the
 * update that changed it writes the row and tells the owner.
 */
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { closeAgentSockets } from '@/lib/agentSockets'
import { AgentUnreachableError, agentFetch } from '@/lib/agentFetch'
import { safeErrorCode } from '@/lib/routeErrors'
import { WS_SOCKETS, type WsSocket } from '@/lib/wsTicket'
import { findLiveTriageRun, LIVE_TRIAGE_STATUSES } from '@/lib/triageRun'
import { stopRun } from '@/lib/triage/actions'
import { endOpenImpersonationsQuietly } from './actAs'
import { now } from './clock'
import { rbacFlags } from './flags'
import { queuedJobPermissions } from './queuedJobPermissions'
import { actorScanRefusal, actorScanRefusalReason, noticeSchedulePaused, type ActorScanRefusal } from './scanActor'

/** What ended the person's access to one project. */
export type ProjectReduction =
  | 'share_revoked' | 'share_left' | 'share_expired' | 'share_force_revoked' | 'share_reduced' | 'consent_withdrawn'

/** What ended or narrowed the account's access everywhere. */
export type AccountReduction =
  | 'account_disabled' | 'account_deleted' | 'capability_removed'
  | 'sessions_revoked' | 'credentials_reset' | 'reset_link_used' | 'root_transferred'
  | 'device_session_revoked' | 'terminal_grant_removed'

export type AccessReducedReason = ProjectReduction | AccountReduction

export type RevocationStep = 'stop_runs' | 'close_sockets' | 'cancel_queued_scans' | 'pause_schedules' | 'stop_triage_run'

export type Counted<K extends string> = { [P in K]: number } | { error: string }

export interface LiveWorkStopped {
  /** Absent when the plan stops no run. */
  runs?: Counted<'stopped'>
  sockets: Counted<'closed'>
  /** Absent when the plan leaves deferred work to its own check (a disable, a sign-out). */
  scans?: Counted<'cancelled'>
  schedules?: Counted<'paused'>
  triage?: Counted<'stopped'>
  /** The steps that failed, each logged. */
  failed: RevocationStep[]
}

/** The agent part as the account routes have always answered it (`agent: {runs?, sockets}`). */
export interface AgentWorkEnded {
  runs?: Counted<'stopped'>
  sockets: Counted<'closed'>
}

interface Plan {
  stopRuns: boolean
  closeScope: 'access' | 'account'
  kinds: readonly WsSocket[]
  deferredScans: boolean
  triage: boolean
  /** The account's own impersonations as an admin end: every caller that ends its sessions. */
  endImpersonations: boolean
}

const PROJECT: Plan = { stopRuns: true, closeScope: 'access', kinds: WS_SOCKETS, deferredScans: true, triage: true, endImpersonations: false }
const SESSIONS: Plan = { stopRuns: false, closeScope: 'account', kinds: WS_SOCKETS, deferredScans: false, triage: false, endImpersonations: true }

export const PLANS: Readonly<Record<AccessReducedReason, Readonly<Plan>>> = Object.freeze({
  share_revoked: PROJECT,
  share_left: PROJECT,
  share_expired: PROJECT,
  share_force_revoked: PROJECT,
  share_reduced: PROJECT,
  consent_withdrawn: PROJECT,
  account_disabled: { ...SESSIONS, stopRuns: true },
  // The user DELETE ends a deleted admin's impersonations itself, closing what they opened.
  account_deleted: { stopRuns: true, closeScope: 'account', kinds: WS_SOCKETS, deferredScans: true, triage: true, endImpersonations: false },
  capability_removed: { stopRuns: true, closeScope: 'account', kinds: WS_SOCKETS, deferredScans: true, triage: true, endImpersonations: true },
  sessions_revoked: SESSIONS,
  credentials_reset: SESSIONS,
  reset_link_used: SESSIONS,
  root_transferred: SESSIONS,
  device_session_revoked: { ...SESSIONS, closeScope: 'access', endImpersonations: false },
  terminal_grant_removed: { ...SESSIONS, closeScope: 'access', kinds: ['kali-terminal'], endImpersonations: false },
})

const AGENT_TIMEOUT_MS = 10_000
const NOT_STARTED = ['queued', 'needs_review']
const ACCESS_PAUSE_REASON = 'actor_no_access'
const LEVEL_RANK: Record<string, number> = { read: 1, write: 2 }
const TOGGLES = ['rawData', 'runScans', 'useAgent', 'exploit', 'manage'] as const

type ShareGrant = { access: string } & Partial<Record<(typeof TOGGLES)[number], boolean>>

/** Whether a share change narrows what it gives: a lower level, or a toggle turned off. */
export function isAccessReduction(before: ShareGrant, after: ShareGrant): boolean {
  if ((LEVEL_RANK[after.access] ?? 0) < (LEVEL_RANK[before.access] ?? 0)) return true
  return TOGGLES.some((t) => before[t] === true && after[t] !== true)
}

/** The agent part of a result, in the shape the account routes answer. */
export function agentWorkOf(stopped: LiveWorkStopped): AgentWorkEnded {
  return { ...(stopped.runs ? { runs: stopped.runs } : {}), sockets: stopped.sockets }
}

/**
 * Stops the account's agent runs, on these projects only when named. Never throws; a failure is
 * logged `[rbac] agent-stop failed` and answered. An empty list names nothing, so nothing is asked.
 */
export async function stopAgentRuns(userId: string, projectIds?: readonly string[]): Promise<Counted<'stopped'>> {
  if (projectIds && projectIds.length === 0) return { stopped: 0 }
  const failed = (reason: string) => {
    console.error(`[rbac] agent-stop failed user=${userId}${projectIds ? ` projects=${projectIds.join(',')}` : ''}: ${reason}`)
    return { error: reason }
  }
  let res: Response
  try {
    res = await agentFetch('/agent-sessions/stop-for', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(projectIds ? { user_id: userId, project_ids: projectIds } : { user_id: userId }),
    }, { timeoutMs: AGENT_TIMEOUT_MS })
  } catch (err) {
    return failed(err instanceof AgentUnreachableError ? 'agent_unreachable' : safeErrorCode(err))
  }
  if (!res.ok) return failed(`agent_http_${res.status}`)
  const body = await res.json().catch(() => null) as { stopped?: unknown } | null
  return { stopped: typeof body?.stopped === 'number' ? body.stopped : 0 }
}

/**
 * Whether the person may still start each deferred scan, asked once per project and permission
 * list: the dispatch's and the scheduler's own check (scanActor.ts), read fresh.
 */
function refusalCheck(userId: string) {
  const seen = new Map<string, Promise<ActorScanRefusal | null>>()
  return (projectId: string, permissions: ReturnType<typeof queuedJobPermissions>) => {
    const key = `${projectId}|${permissions.join(',')}`
    let pending = seen.get(key)
    if (!pending) {
      pending = actorScanRefusal(userId, projectId, permissions)
      seen.set(key, pending)
    }
    return pending
  }
}

async function cancelQueuedScans(
  userId: string, projectId: string | null, reason: AccessReducedReason, refused: ReturnType<typeof refusalCheck>,
): Promise<number> {
  const jobs = await prisma.jobQueue.findMany({
    where: { userId, status: { in: NOT_STARTED }, ...(projectId ? { projectId } : {}) },
    select: { id: true, projectId: true, kind: true, payload: true },
  })
  let cancelled = 0
  for (const job of jobs) {
    const refusal = await refused(job.projectId, queuedJobPermissions(job.kind, job.payload))
    if (!refusal) continue
    const blocked = reason === 'consent_withdrawn'
      ? { code: 'owner_consent_withdrawn', text: "The project's owner withdrew the consent to spend their credentials." }
      : { code: ACCESS_PAUSE_REASON, text: actorScanRefusalReason(refusal, 'queued') }
    const done = await auditedTransaction(prisma, async (tx) => {
      const { count } = await tx.jobQueue.updateMany({
        where: { id: job.id, userId, status: { in: NOT_STARTED } },
        data: { status: 'canceled', blockedCode: blocked.code, blockedReason: blocked.text, finishedAt: now() },
      })
      if (count !== 1) return false
      await writeAuditTx(tx, {
        actorId: null,
        projectId: job.projectId,
        action: 'job_queue.cancelled',
        targetType: 'jobQueue',
        targetId: job.id,
        after: {
          reason: blocked.code, projectId: job.projectId, kind: job.kind, userId,
          permission: refusal.permission, refusal: refusal.reason, revocation: reason,
        },
        source: 'system',
      })
      return true
    })
    if (done) cancelled += 1
  }
  return cancelled
}

async function pauseSchedules(
  userId: string, projectId: string | null, reason: AccessReducedReason, refused: ReturnType<typeof refusalCheck>,
): Promise<number> {
  const schedules = await prisma.scanSchedule.findMany({
    where: { userId, enabled: true, ...(projectId ? { projectId } : {}) },
    select: { id: true, projectId: true, label: true, scanMode: true },
  })
  let paused = 0
  for (const schedule of schedules) {
    const refusal = await refused(schedule.projectId, queuedJobPermissions('full_recon', { mode: schedule.scanMode }))
    if (!refusal) continue
    const done = await auditedTransaction(prisma, async (tx) => {
      // Only while it still runs as this person: a confirmation since the read made someone else its actor.
      const { count } = await tx.scanSchedule.updateMany({
        where: { id: schedule.id, userId, enabled: true },
        data: { enabled: false, pausedReason: ACCESS_PAUSE_REASON },
      })
      if (count !== 1) return false
      await writeAuditTx(tx, {
        actorId: null,
        projectId: schedule.projectId,
        action: 'scan_schedule.paused',
        targetType: 'scanSchedule',
        targetId: schedule.id,
        after: {
          reason: ACCESS_PAUSE_REASON, projectId: schedule.projectId, userId,
          permission: refusal.permission, refusal: refusal.reason, revocation: reason,
        },
        source: 'system',
      })
      return true
    })
    if (!done) continue
    paused += 1
    await noticeSchedulePaused({ projectId: schedule.projectId, scheduleId: schedule.id, label: schedule.label, actorUserId: userId })
  }
  return paused
}

async function stopTriageRuns(userId: string, projectId: string | null, ownerId: string | undefined): Promise<number> {
  const projectIds = projectId
    ? [projectId]
    : [...new Set((await prisma.triageRun.findMany({
      where: { actorUserId: userId, status: { in: [...LIVE_TRIAGE_STATUSES] } },
      select: { projectId: true },
    })).map((r) => r.projectId))]
  let stopped = 0
  for (const pid of projectIds) {
    const live = await findLiveTriageRun(pid)
    if (!live || live.actorUserId !== userId) continue
    // The agent keys a triage run by the project's owner, the tenant.
    const owner = pid === projectId && ownerId
      ? ownerId
      : (await prisma.project.findUnique({ where: { id: pid }, select: { userId: true } }))?.userId
    if (!owner) continue
    if ((await stopRun({ userId: owner, projectId: pid }, 'app')).stopped) stopped += 1
  }
  return stopped
}

/**
 * Stops what `userId` still runs on access that `reason` ended: on `projectId`, or on the whole
 * account for an account reason (`projectId` null). `ownerId` spares a read when the caller knows
 * the project's owner. Never throws.
 */
export async function onAccessReduced(projectId: string, userId: string, reason: ProjectReduction, opts?: { ownerId?: string }): Promise<LiveWorkStopped>
export async function onAccessReduced(projectId: null, userId: string, reason: AccountReduction, opts?: { ownerId?: string }): Promise<LiveWorkStopped>
export async function onAccessReduced(
  projectId: string | null, userId: string, reason: AccessReducedReason, { ownerId }: { ownerId?: string } = {},
): Promise<LiveWorkStopped> {
  const plan = PLANS[reason]
  const out: LiveWorkStopped = { sockets: { closed: 0 }, failed: [] }
  const where = `reason=${reason} user=${userId} project=${projectId ?? '-'}`
  const fail = (step: RevocationStep, code: string) => {
    console.error(`[rbac] revocation step failed step=${step} ${where}: ${code}`)
    out.failed.push(step)
    return { error: code }
  }
  async function attempt<K extends string>(step: RevocationStep, key: K, run: () => Promise<number>): Promise<Counted<K>> {
    try {
      return { [key]: await run() } as Counted<K>
    } catch (err) {
      return fail(step, safeErrorCode(err))
    }
  }

  if (plan.endImpersonations && rbacFlags().permissions) {
    await endOpenImpersonationsQuietly(userId, 'invalidated', { closeSockets: false })
  }
  if (plan.stopRuns) {
    out.runs = await stopAgentRuns(userId, projectId ? [projectId] : undefined)
    if ('error' in out.runs) fail('stop_runs', out.runs.error)
  }
  const close = await closeAgentSockets({
    userId, ...(projectId ? { projectId } : {}), kinds: [...plan.kinds], scope: plan.closeScope,
  })
  out.sockets = close.ok ? { closed: close.closed } : fail('close_sockets', close.reason)
  if (plan.deferredScans) {
    const refused = refusalCheck(userId)
    out.scans = await attempt('cancel_queued_scans', 'cancelled', () => cancelQueuedScans(userId, projectId, reason, refused))
    out.schedules = await attempt('pause_schedules', 'paused', () => pauseSchedules(userId, projectId, reason, refused))
  }
  if (plan.triage) out.triage = await attempt('stop_triage_run', 'stopped', () => stopTriageRuns(userId, projectId, ownerId))

  const n = (c: Counted<string> | undefined) => (c && !('error' in c) ? Object.values(c)[0] : 0)
  const total = n(out.runs) + n(out.sockets) + n(out.scans) + n(out.schedules) + n(out.triage)
  if (total > 0) {
    console.info(
      `[rbac] revocation ${where} runs=${n(out.runs)} sockets=${n(out.sockets)} scans=${n(out.scans)} `
      + `schedules=${n(out.schedules)} triage=${n(out.triage)}${out.failed.length ? ` failed=${out.failed.join(',')}` : ''}`,
    )
  }
  return out
}
