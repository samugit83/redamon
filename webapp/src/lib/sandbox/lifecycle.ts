/**
 * What a change of access does to the per-user Kali sandboxes (group 1, B.7, B.10; TD-17, TD-27;
 * docs/readmes/README.KALI_SANDBOX.md): the hooks that access loss (lib/authz/revocation.ts), project
 * deletion (lib/projectTeardown.ts) and the emergency stop call, over the gateway (gateway.ts).
 *
 * - access changed → each person's instances outside their fresh lists stop (own and act-as views); a
 *   person left with no allowed project is stopped (`last_project_deleted`);
 * - an account's end → both views stop, always sent, so `account_deleted` also removes the person's
 *   output folders when nothing runs (OQ-G1-8);
 * - a project deleted → every instance mounting it stops, before its folder is purged;
 * - the emergency stop → every sandbox, or the presser's own.
 *
 * No answer from the orchestrator is a failure: access was lost and nobody could check it was stopped.
 *
 * A hook never throws and never holds the change for long: it answers within LIFECYCLE_DEADLINE_MS
 * with a count or a code, for the caller to record. A stop that failed (the orchestrator down, or
 * slower than the deadline) is kept and retried in the background, and at once when a later hook
 * reaches the orchestrator: otherwise an instance adopted after an orchestrator restart would keep a
 * lost project mounted until it idles out, or for 8 hours under a hold. Each retry reads access again.
 * A hook past its deadline visits nobody more: the kept retries do the rest.
 *
 * The backstop (`reconcileRunningSandboxes`, run by every RBAC sweep, lib/authz/expirySweep.ts, every
 * RBAC_SWEEP_INTERVAL: 300 s by default) checks again every person with a running sandbox, so what
 * no hook saw converges within one sweep period: a sharing-policy change or a switch rolled back at
 * restart (shares read as Read), an override or a share that expired lazily, a capability lost to a
 * role change, a kept retry that a webapp restart forgot. It also turns off the tunnel of a person
 * who no longer holds platform:tunnels, and sends again the `account_deleted` stop of an account
 * deleted in the last DELETION_RESEND_WINDOW_MS that this process never saw done (a webapp restart
 * forgets its kept stops, and only that stop removes a deleted person's output folders when nothing
 * runs). It visits at most BACKSTOP_MAX_PEOPLE people per sweep, starting after the last one it
 * reached, so a long list is covered over several sweeps rather than the same head each time.
 *
 * The warm-up of the ws-ticket mint is here too, coalesced per person and view: every ticket mint
 * would otherwise start one background `ensure`, with its access reads.
 *
 * Server-side only.
 */
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { auditActor } from '@/lib/auditActor'
import { logValue, safeErrorCode, upstreamFailure } from '@/lib/routeErrors'
import { ERR_INVALID_PROJECT_ID, ERR_INVALID_USER_ID, ERR_USER_REFUSED, type StopReason } from './contract'
import {
  assertSandboxUser, listRunningSandboxes, sandboxProjectsFor, sandboxStatus, stopAllSandboxes, stopProjectSandboxes,
  stopSandbox, touchSandbox, type SandboxActor,
} from './gateway'
import { OrchestratorUnreachable, SandboxError, orchestratorReconcile, validProjectId, validUserId } from './orchestratorClient'
import { loadPrincipal } from '@/lib/authz/principal'

/** How long a hook may hold the change that called it before it answers `sandbox_timeout`. */
export const LIFECYCLE_DEADLINE_MS = 15_000
/** After a warm-up, the same person and view are not warmed up again for this long. */
export const WARM_UP_COOLDOWN_MS = 30_000
/** People the backstop checks per sweep; the rest wait for the next one. */
export const BACKSTOP_MAX_PEOPLE = 200
/** How far back the backstop looks for account deletions whose sandbox stop this process may have lost. */
export const DELETION_RESEND_WINDOW_MS = 7 * 86_400_000
/** Deletion stops sent again per sweep; the rest wait for the next one. */
export const DELETION_RESEND_MAX = 50
/** The audit action of an account deletion (app/api/users/[id]/route.ts). */
const USER_DELETE_ACTION = 'user.delete'
const MAX_DELETIONS_REMEMBERED = 10_000
const RETRY_FIRST_MS = 30_000
const RETRY_MAX_MS = 600_000
const MAX_PENDING = 1_000
const MAX_WARM_UP_KEYS = 10_000
const TIMEOUT = 'sandbox_timeout'
/** Codes the orchestrator would answer again on a retry. */
const PERMANENT = new Set([ERR_INVALID_PROJECT_ID, ERR_INVALID_USER_ID, 'invalid_reason'])

/** What stopped, or why it could not be done (with what stopped before). */
export type SandboxHookOutcome =
  | { stopped: number }
  | { error: string; stopped: number }

/** The stop reasons of an account that can no longer have a sandbox. */
export type AccountEndReason = Extract<StopReason, 'account_disabled' | 'account_deleted' | 'access_lost'>

/**
 * `again`: a lower-ranked keep was refused while this one was held, so its success must reconcile
 * once more. `at`: when the account's change happened (epoch ms), which decides what a retried stop
 * still has to stop.
 */
type Pending = (
  | { kind: 'reconcile'; userId: string; actor: SandboxActor }
  | { kind: 'stop'; userId: string; reason: AccountEndReason; actor: SandboxActor; at: number }
  | { kind: 'project'; projectId: string; actor: SandboxActor }
) & { again?: boolean }

function codeOf(err: unknown): string {
  if (err instanceof SandboxError) return err.code
  if (err instanceof OrchestratorUnreachable) return upstreamFailure('orchestrator', err.cause_, '').body.code
  return safeErrorCode(err)
}

/** The actor the caller named; none named: the person signed in to this request, or the system outside one. */
async function actorOf(given: SandboxActor | undefined): Promise<SandboxActor> {
  if (given !== undefined) return given
  try {
    const actor = await auditActor()
    return actor.actorId ? actor : null
  } catch {
    return null
  }
}

async function withDeadline<T>(work: Promise<T>, onTimeout: () => T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(onTimeout()), LIFECYCLE_DEADLINE_MS)
  })
  try {
    return await Promise.race([work, late])
  } finally {
    clearTimeout(timer)
  }
}

// ---- the kept stops and their retry ----

const pending = new Map<string, Pending>()
let retryTimer: ReturnType<typeof setTimeout> | null = null
let retryDelay = RETRY_FIRST_MS
let retrying: Promise<void> | null = null

const keyOf = (item: Pending): string => (item.kind === 'project' ? `project:${item.projectId}` : `user:${item.userId}`)
/** A deletion outranks any other stop of the person, and a stop outranks a reconcile. */
const rank = (item: Pending): number => (item.kind === 'stop' ? (item.reason === 'account_deleted' ? 2 : 1) : 0)

function keep(item: Pending, code: string): void {
  if (PERMANENT.has(code)) return
  const key = keyOf(item)
  const held = pending.get(key)
  if (held && rank(held) > rank(item)) {
    held.again = true
    return
  }
  if (!held && pending.size >= MAX_PENDING) {
    console.warn(`[sandbox] retry list full; ${logValue(key, 100)} is not retried`)
    return
  }
  pending.set(key, item)
  scheduleRetry(retryDelay)
}

function scheduleRetry(delayMs: number): void {
  if (pending.size === 0) return
  if (retryTimer && delayMs > 0) return
  if (retryTimer) clearTimeout(retryTimer)
  retryTimer = setTimeout(() => {
    retryTimer = null
    void retryPendingSandboxStops()
  }, delayMs)
  // A kept stop must never keep the process alive on its own.
  ;(retryTimer as unknown as { unref?: () => void }).unref?.()
}

/** A hook reached the orchestrator: anything kept is retried now rather than at its back-off. */
function orchestratorAnswered(): void {
  retryDelay = RETRY_FIRST_MS
  if (pending.size > 0 && !retrying) scheduleRetry(0)
}

/**
 * Whether the person still has an instance that started at or before `at` (epoch ms): one the
 * change was meant to stop. An instance without a start time counts as one. Throws when the
 * orchestrator cannot say, so the stop is kept.
 */
async function startedBefore(userId: string, at: number): Promise<boolean> {
  const { instances } = await sandboxStatus(userId)
  return instances.some((i) => typeof i.created_at !== 'number' || i.created_at * 1000 <= at)
}

async function runPending(item: Pending): Promise<void> {
  if (item.kind === 'project') {
    const outcome = await stopProjectSandboxes(item.projectId, 'project_deleted', item.actor)
    if (!outcome.ok) throw new SandboxError(502, outcome.code)
    return
  }
  if (item.kind === 'stop' && item.reason !== 'account_deleted') {
    // The stop was due when the change happened, whatever the account is now: a reset or a revoked
    // sign-in leaves a sandbox that may hold someone else's work, a capability removal or a disable
    // one that ran on access now gone. So an instance from before the change stops, even when the
    // account came back since; one started after it ran on the access then in force and is only
    // reconciled. An account still refused stops whole (it cannot have started anything since).
    let refused = false
    try {
      await assertSandboxUser(item.userId)
    } catch (err) {
      if (!(err instanceof SandboxError && err.code === ERR_USER_REFUSED)) throw err
      refused = true
    }
    if (refused || await startedBefore(item.userId, item.at)) {
      await stopSandbox(item.userId, item.reason, item.actor)
      return
    }
    await reconcilePerson(item.userId, item.actor)
    return
  }
  if (item.kind === 'stop') {
    await stopSandbox(item.userId, item.reason, item.actor)
    deletionStopDone(item.userId)
    return
  }
  await reconcilePerson(item.userId, item.actor)
}

const attempt = (work: Promise<unknown>): Promise<string | null> =>
  withDeadline<string | null>(work.then(() => null, codeOf), () => TIMEOUT)

/** One pass over the kept stops; the timer calls it. Concurrent calls share the pass in flight. */
export function retryPendingSandboxStops(): Promise<void> {
  retrying ??= retryRound().finally(() => { retrying = null })
  return retrying
}

async function retryRound(): Promise<void> {
  if (pending.size === 0) return
  for (const [key, first] of [...pending]) {
    let item = first
    let code = await attempt(runPending(item))
    if (code === null && item.again && item.kind !== 'project' && pending.get(key) === item) {
      // The keep refused meanwhile may need lists this pass read before its change: once more, fresh.
      item = { kind: 'reconcile', userId: item.userId, actor: item.actor }
      pending.set(key, item)
      code = await attempt(reconcilePerson(item.userId, item.actor))
    }
    if (pending.get(key) !== item) continue
    if (code === null || PERMANENT.has(code)) {
      pending.delete(key)
    } else {
      console.warn(`[sandbox] kept stop still not done for ${logValue(key, 100)}: ${code}`)
    }
  }
  if (pending.size > 0) retryLater()
  else retryDelay = RETRY_FIRST_MS
}

function retryLater(): void {
  retryDelay = Math.min(retryDelay * 2, RETRY_MAX_MS)
  scheduleRetry(retryDelay)
}

// ---- the hooks ----

async function auditReconcileStop(actor: SandboxActor, userId: string, stopped: number): Promise<void> {
  // The row the gateway's own reconcile writes; here because that one swallows its failures.
  await writeAudit({
    ...(actor ?? { actorId: null, onBehalfOfUserId: null, actorEmail: null }),
    action: 'sandbox.stopped',
    targetType: 'user',
    targetId: userId,
    after: { reason: 'access_lost', stopped },
    source: 'system',
  })
}

/** Stops the person's instances outside their fresh lists; with no project left, the rest too. Throws. */
async function reconcilePerson(userId: string, actor: SandboxActor): Promise<number> {
  const projects = await sandboxProjectsFor(userId)
  const actAsProjects = await sandboxProjectsFor(userId, { actingAs: true })
  let stopped = await orchestratorReconcile(userId, projects, actAsProjects)
  if (stopped > 0) await auditReconcileStop(actor, userId, stopped)
  if (projects.length === 0) stopped += await stopSandbox(userId, 'last_project_deleted', actor)
  return stopped
}

/**
 * The persons whose access changed (a share revoked, narrowed, left or expired, consent withdrawn, a
 * project deleted): each one's instances outside their fresh own and act-as lists stop; nothing is
 * started. `actor`: who caused the change (null: the system); omitted, the person signed in.
 */
export async function sandboxAccessChanged(userIds: readonly string[], actor?: SandboxActor): Promise<SandboxHookOutcome> {
  const people = [...new Set(userIds)].filter((id) => validUserId(id))
  if (people.length === 0) return { stopped: 0 }
  const done = new Set<string>()
  let late = false
  let who: SandboxActor = null
  const work = (async (): Promise<SandboxHookOutcome> => {
    const by = await actorOf(actor)
    who = by
    let stopped = 0
    let error: string | null = null
    for (const userId of people) {
      if (late) break
      try {
        stopped += await reconcilePerson(userId, by)
      } catch (err) {
        const code = codeOf(err)
        error ??= code
        console.warn(`[sandbox] access-loss stop not done for ${logValue(userId, 80)}: ${code}`)
        keep({ kind: 'reconcile', userId, actor: by }, code)
      }
      done.add(userId)
    }
    if (late) return { error: TIMEOUT, stopped }
    if (error === null) {
      orchestratorAnswered()
      return { stopped }
    }
    return { error, stopped }
  })()
  return withDeadline(work, () => {
    late = true
    for (const userId of people) if (!done.has(userId)) keep({ kind: 'reconcile', userId, actor: who }, TIMEOUT)
    console.warn(`[sandbox] access-loss stop not done in time for ${people.length - done.size} person(s)`)
    return { error: TIMEOUT, stopped: 0 }
  })
}

/** An account that can no longer have a sandbox: both views stop, sent even when nothing runs. */
export function sandboxAccountEnded(userId: string, reason: AccountEndReason, actor?: SandboxActor): Promise<SandboxHookOutcome> {
  return sandboxAccountsEnded([userId], reason, actor)
}

/**
 * Several accounts that can no longer have a sandbox (a capability removed from a set, the accounts
 * after a batch the agent refused): each one's both views stop, one by one under one deadline.
 */
export async function sandboxAccountsEnded(userIds: readonly string[], reason: AccountEndReason, actor?: SandboxActor): Promise<SandboxHookOutcome> {
  const people = [...new Set(userIds)].filter((id) => validUserId(id))
  if (people.length === 0) return { stopped: 0 }
  const at = Date.now()
  const done = new Set<string>()
  let late = false
  let who: SandboxActor = null
  const keepStop = (userId: string, code: string) => keep({ kind: 'stop', userId, reason, actor: who, at }, code)
  const work = (async (): Promise<SandboxHookOutcome> => {
    who = await actorOf(actor)
    let stopped = 0
    let error: string | null = null
    for (const userId of people) {
      if (late) break
      try {
        stopped += await stopSandbox(userId, reason, who)
        if (reason === 'account_deleted') deletionStopDone(userId)
      } catch (err) {
        const code = codeOf(err)
        error ??= code
        console.warn(`[sandbox] ${reason} stop not done for ${logValue(userId, 80)}: ${code}`)
        keepStop(userId, code)
      }
      done.add(userId)
    }
    if (late) return { error: TIMEOUT, stopped }
    if (error === null) {
      orchestratorAnswered()
      return { stopped }
    }
    return { error, stopped }
  })()
  return withDeadline(work, () => {
    late = true
    for (const userId of people) if (!done.has(userId)) keepStop(userId, TIMEOUT)
    console.warn(`[sandbox] ${reason} stop not done in time for ${people.length - done.size} person(s)`)
    return { error: TIMEOUT, stopped: 0 }
  })
}

/** A project being deleted: every instance mounting it stops, before its folder is purged (TD-27). */
export async function sandboxProjectDeleted(projectId: string, actor?: SandboxActor): Promise<SandboxHookOutcome> {
  // The gateway never puts an id the contract refuses in a mount list: no instance can hold it.
  if (!validProjectId(projectId)) return { stopped: 0 }
  let who: SandboxActor = null
  const fail = (code: string): SandboxHookOutcome => {
    console.warn(`[sandbox] project stop not done for ${logValue(projectId, 80)}: ${code}`)
    keep({ kind: 'project', projectId, actor: who }, code)
    return { error: code, stopped: 0 }
  }
  const work = (async (): Promise<SandboxHookOutcome> => {
    who = await actorOf(actor)
    const outcome = await stopProjectSandboxes(projectId, 'project_deleted', who)
    if (!outcome.ok) return fail(outcome.code)
    orchestratorAnswered()
    return { stopped: outcome.stopped }
  })()
  return withDeadline(work, () => fail(TIMEOUT))
}

/**
 * The emergency stop: every sandbox (`all`), or both views of the presser (`own`). Never kept for a
 * retry: a stop-all minutes later would stop sandboxes started after the emergency.
 */
export async function sandboxEmergencyStop(
  target: { scope: 'all' } | { scope: 'own'; userId: string }, actor: SandboxActor,
): Promise<SandboxHookOutcome> {
  const work = (async (): Promise<SandboxHookOutcome> => {
    try {
      const stopped = target.scope === 'all'
        ? await stopAllSandboxes('emergency', actor)
        : await stopSandbox(target.userId, 'emergency', actor)
      orchestratorAnswered()
      return { stopped }
    } catch (err) {
      const code = codeOf(err)
      console.warn(`[sandbox] emergency stop not done (${target.scope}): ${code}`)
      return { error: code, stopped: 0 }
    }
  })()
  return withDeadline(work, () => ({ error: TIMEOUT, stopped: 0 }))
}

/** Null when the account may still have a sandbox; else the stop reason its refusal maps to. */
async function accountRefusal(userId: string): Promise<AccountEndReason | null> {
  try {
    await assertSandboxUser(userId)
    return null
  } catch (err) {
    if (!(err instanceof SandboxError && err.code === ERR_USER_REFUSED)) throw err
  }
  const principal = await loadPrincipal(userId, { fresh: true })
  if (!principal) return 'account_deleted'
  return principal.status === 'disabled' ? 'account_disabled' : 'access_lost'
}

// ---- the backstop ----

/** The deletions whose `account_deleted` stop this process saw done (or sent again). */
const deletionStopsDone = new Set<string>()
/** The last person the previous sweep reached: the next one starts after them. */
let backstopCursor: string | null = null

function deletionStopDone(userId: string): void {
  if (deletionStopsDone.size >= MAX_DELETIONS_REMEMBERED) deletionStopsDone.clear()
  deletionStopsDone.add(userId)
}

/**
 * The `account_deleted` stops this process may have lost: accounts deleted in the last
 * DELETION_RESEND_WINDOW_MS (their `user.delete` audit row, inside the audit retention floor), whose
 * stop it never saw done and does not keep. Each is sent again only once its account row is gone, so
 * an account that exists is never sent a stop that removes its output folders. A stop that fails is
 * kept, as the deletion's own would have been. Throws when the reads fail.
 */
async function resendLostDeletionStops(actor: SandboxActor): Promise<number> {
  const rows = await prisma.auditLog.findMany({
    where: { action: USER_DELETE_ACTION, createdAt: { gte: new Date(Date.now() - DELETION_RESEND_WINDOW_MS) } },
    select: { targetId: true },
    orderBy: { createdAt: 'desc' },
    take: 1_000,
  })
  const candidates = [...new Set(rows.map((r) => r.targetId))]
    .filter((id): id is string => validUserId(id) && !deletionStopsDone.has(id) && !pending.has(`user:${id}`))
    .slice(0, DELETION_RESEND_MAX)
  if (candidates.length === 0) return 0
  const alive = new Set((await prisma.user.findMany({ where: { id: { in: candidates } }, select: { id: true } })).map((u) => u.id))
  let stopped = 0
  for (const userId of candidates) {
    if (alive.has(userId)) {
      deletionStopDone(userId)
      continue
    }
    try {
      stopped += await stopSandbox(userId, 'account_deleted', actor)
      deletionStopDone(userId)
    } catch (err) {
      const code = codeOf(err)
      console.warn(`[sandbox] lost account_deleted stop not done for ${logValue(userId, 80)}: ${code}`)
      keep({ kind: 'stop', userId, reason: 'account_deleted', actor, at: Date.now() }, code)
    }
  }
  return stopped
}

/** The people to visit this sweep: sorted, starting after the last one reached, wrapping round. */
function backstopPeople(running: Array<{ user_id: string }>): string[] {
  const all = [...new Set(running.map((s) => s.user_id))].filter((id) => validUserId(id)).sort()
  const start = backstopCursor === null ? 0 : all.findIndex((id) => id > backstopCursor!)
  const from = start < 0 ? 0 : start
  return [...all.slice(from), ...all.slice(0, from)].slice(0, BACKSTOP_MAX_PEOPLE)
}

/** A tunnel left up by a person who lost platform:tunnels goes off (loaded lazily: settings effects pull the agent client). */
async function tunnelOffIfNotHeld(userId: string): Promise<boolean> {
  const { enforceTunnelPermission } = await import('@/lib/sharedSettingsEffects')
  return (await enforceTunnelPermission(userId)).turnedOff
}

/**
 * The backstop, run by every RBAC sweep (as the system) and right after a change of Root's sharing
 * policy (with Root as `actor`): each person with a running sandbox (at most BACKSTOP_MAX_PEOPLE, one
 * by one under the deadline, from after the last person the previous sweep reached) is checked again.
 * An account refused now is stopped with its reason (`account_deleted` also removes its output
 * folders); any other is reconciled with its fresh own and act-as lists, and loses a tunnel it no
 * longer holds platform:tunnels for. The lost deletion stops are sent first. Never throws; the log
 * line carries counts only.
 */
export async function reconcileRunningSandboxes(actor: SandboxActor = null): Promise<SandboxHookOutcome> {
  let late = false
  let visited = 0
  let stopped = 0
  let failed = 0
  let tunnelsOff = 0
  const work = (async (): Promise<SandboxHookOutcome> => {
    let error: string | null = null
    try {
      stopped += await resendLostDeletionStops(actor)
    } catch (err) {
      failed += 1
      error = codeOf(err)
    }
    let running: Awaited<ReturnType<typeof listRunningSandboxes>>
    try {
      running = await listRunningSandboxes()
    } catch (err) {
      const code = codeOf(err)
      console.warn(`[sandbox] backstop not done: ${code}`)
      return { error: code, stopped }
    }
    for (const userId of backstopPeople(running.sandboxes)) {
      if (late) break
      visited += 1
      backstopCursor = userId
      try {
        const refused = await accountRefusal(userId)
        stopped += refused ? await stopSandbox(userId, refused, actor) : await reconcilePerson(userId, actor)
        if (!refused && await tunnelOffIfNotHeld(userId)) tunnelsOff += 1
      } catch (err) {
        failed += 1
        error ??= codeOf(err)
      }
    }
    if (late) return { error: TIMEOUT, stopped }
    const counts = `people=${visited} stopped=${stopped}${tunnelsOff ? ` tunnels_off=${tunnelsOff}` : ''}`
    if (failed > 0) console.warn(`[sandbox] backstop ${counts} failed=${failed}`)
    else if (stopped > 0 || tunnelsOff > 0) console.info(`[sandbox] backstop ${counts}`)
    return error === null ? { stopped } : { error, stopped }
  })()
  return withDeadline(work, () => {
    late = true
    console.warn(`[sandbox] backstop not done in time: people=${visited} stopped=${stopped} failed=${failed}`)
    return { error: TIMEOUT, stopped }
  })
}

// ---- the warm-up ----

const warmUps = new Map<string, { inFlight: boolean; at: number }>()

/**
 * The ws-ticket warm-up (`touchSandbox`), at most one per person and view at a time and none within
 * WARM_UP_COOLDOWN_MS of the last: a socket that reconnects in a loop must not start one ensure, with
 * its access reads, per ticket. Never throws.
 */
export async function warmUpSandbox(userId: string, opts: { actingAs: boolean; actor: SandboxActor }): Promise<void> {
  const key = `${opts.actingAs ? 'act_as' : 'own'}:${userId}`
  const seen = warmUps.get(key)
  if (seen && (seen.inFlight || Date.now() - seen.at < WARM_UP_COOLDOWN_MS)) return
  if (!seen && warmUps.size >= MAX_WARM_UP_KEYS) {
    for (const [k, v] of warmUps) if (!v.inFlight && Date.now() - v.at >= WARM_UP_COOLDOWN_MS) warmUps.delete(k)
    if (warmUps.size >= MAX_WARM_UP_KEYS) return
  }
  warmUps.set(key, { inFlight: true, at: Date.now() })
  try {
    await touchSandbox(userId, { actingAs: opts.actingAs, actor: opts.actor })
  } catch {
    // touchSandbox logs and swallows its own failures; nothing more to say here.
  } finally {
    warmUps.set(key, { inFlight: false, at: Date.now() })
  }
}

/** Tests only: the kept stops, without their actors. */
export function pendingSandboxStopsForTests(): Array<{ key: string; kind: Pending['kind']; reason?: AccountEndReason }> {
  return [...pending].map(([key, item]) => ({ key, kind: item.kind, ...(item.kind === 'stop' ? { reason: item.reason } : {}) }))
}

/** Tests only: the retry pass in flight, if any. */
export function sandboxRetryIdleForTests(): Promise<void> {
  return retrying ?? Promise.resolve()
}

/** Tests only: forget the kept stops, the retry timer and the warm-ups. */
export function resetSandboxLifecycleForTests(): void {
  pending.clear()
  if (retryTimer) clearTimeout(retryTimer)
  retryTimer = null
  retryDelay = RETRY_FIRST_MS
  retrying = null
  warmUps.clear()
  deletionStopsDone.clear()
  backstopCursor = null
}
