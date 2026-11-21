/**
 * The webapp side of the per-user Kali sandboxes (group 1, B.10; docs/readmes/README.KALI_SANDBOX.md):
 * which project folders a person's sandbox mounts, who may have one, and the calls that start, lease
 * and stop sandboxes at the orchestrator (orchestratorClient.ts) and forget them at the agent
 * (agentCalls.ts). The agent reaches it through the four internal routes under
 * /api/internal/agent/sandbox/; the ws-ticket route warms a sandbox up; access loss, deletion and the
 * operations view stop them.
 *
 * The mount list (T5, I9) is decided here and only here, from the authorization library: the
 * person's own projects, plus the projects shared with them whose access now holds Use AI agent or
 * Exploitation & shells (`projectAccess` read fresh, so the owner's consent, the share's expiry and
 * the person's account are today's). Under act-as, what act-as access allows: a share reads as Read
 * there, so the member's own projects only (TD-26). The agent's project id is a hint, never a grant:
 * one outside the list is refused. Nothing is cached: every call reads access again.
 *
 * A stop can overtake a start (R2-F7): the webapp reads the list, an access loss commits and its
 * stop runs, then the start arrives at the orchestrator with the old list. So after every start this
 * call caused (`fresh`), access is read again: an account refused now stops the person's sandboxes;
 * a project no longer allowed is reconciled away and the start retried once on the new list. Any
 * loss that commits after that re-read has its own stop arrive after the start. A start the
 * orchestrator reused (not fresh) needs no re-read: its own `ensure` stopped every instance outside
 * the list it was sent.
 *
 * The webapp never invents a mode for an `ensure`: it answers a mode only when the orchestrator
 * named it in that call. Each `ensure` asks the mode first: shared mode (while the switch is off)
 * answers `{mode: "shared"}` before the person and project checks, so shared mode stays exactly as
 * today; per-user mode runs them, and a refusal is a 403, never shared. An orchestrator out of reach,
 * or answering outside the contract (a crash, a wrong key, a route it lacks), is 503
 * `orchestrator_unavailable`, and the agent applies its own last-answered mode (TD-6): shared stays
 * shared through an outage, per-user fails closed. One owner for that decision.
 *
 * Server-side only.
 */
import { createHash } from 'node:crypto'
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAudit, type AuditEntry } from '@/lib/audit'
import type { AuditActor } from '@/lib/auditActor'
import { internalError, logValue, safeErrorCode, upstreamFailure, upstreamFailureResponse } from '@/lib/routeErrors'
import { loadPrincipal } from '@/lib/authz/principal'
import { resolveCapabilities } from '@/lib/authz/capabilities'
import type { PermissionId, ProjectLevel } from '@/lib/authz/permissions'
import { meetsLevel, projectAccess } from '@/lib/authz/projectAccess'
import { ownedProjectsWhere, sharedProjectIds, visibleProjects } from '@/lib/authz/visibleProjects'
import {
  ERR_INVALID_PROJECT_ID, ERR_INVALID_USER_ID, ERR_PROJECT_REFUSED, ERR_START_FAILED, ERR_USER_REFUSED,
  type EnsureAnswer, type LeaseAnswer, type LeaseKind, type SandboxListAnswer, type SandboxMode, type SandboxState,
  type SandboxStatusAnswer, type SandboxView, type StopReason,
} from './contract'
import {
  BAD_ANSWER, ORCHESTRATOR_ERROR, OrchestratorUnreachable, ROUTES_MISSING, SandboxError, isLeaseKind, isStopReason,
  orchestratorEnsure, orchestratorLease, orchestratorList, orchestratorMode, orchestratorReconcile, orchestratorRelease,
  orchestratorStatus, orchestratorStopAll, orchestratorStopProject, orchestratorStopUser, validInstance, validLeaseId,
  validProjectId, validUserId,
} from './orchestratorClient'

/** An ensure (or the agent's list) the orchestrator gave no answer to: the agent decides from its own last mode. */
export const ORCHESTRATOR_UNAVAILABLE = 'orchestrator_unavailable'
import { dropSandboxClient } from './agentCalls'

/** Who an audit row names: the person whose work caused it, or the admin who pressed the stop; null = the system. */
export type SandboxActor = AuditActor | null

/** Holding one of these at all is what makes an account a sandbox user (B.10). */
const SANDBOX_PERMISSIONS: readonly PermissionId[] = ['agent:chat', 'agent:kali_exec', 'platform:kali_terminal']
/** A shared project is mounted when the person's access reaches Use AI agent or Exploitation & shells on it. */
const SANDBOX_LEVELS: readonly ProjectLevel[] = ['W+A', 'W+X']
/** A start whose access changed under it is retried once; a second change fails it. */
const MAX_START_ATTEMPTS = 2
const MODE_CACHE_MS = 30_000
const LOG_EVERY_MS = 60_000

const lastLogged = new Map<string, number>()

/** A warning that repeats with every request (an outage, a refused warm-up): once a minute per key. */
function warnAtMostEveryMinute(key: string, line: string): void {
  const last = lastLogged.get(key)
  if (last !== undefined && Date.now() - last < LOG_EVERY_MS) return
  lastLogged.set(key, Date.now())
  console.warn(line)
}

function checkUserId(userId: string): void {
  if (!validUserId(userId)) throw new SandboxError(400, ERR_INVALID_USER_ID)
}

function checkReason(reason: StopReason): void {
  if (!isStopReason(reason)) throw new SandboxError(400, 'invalid_reason')
}

/** The code a caller logs or returns for a failure: the contract's, the transport's, or the error's class. */
function failureCode(err: unknown): string {
  if (err instanceof SandboxError) return err.code
  if (err instanceof OrchestratorUnreachable) return upstreamFailure('orchestrator', err.cause_, '').body.code
  return safeErrorCode(err)
}

/** The orchestrator's `redamon.sandbox.projects` label: 16 hex of the SHA-256 of the sorted ids joined by newlines. */
function projectsHash(projectIds: readonly string[]): string {
  return createHash('sha256').update([...new Set(projectIds)].sort().join('\n')).digest('hex').slice(0, 16)
}

const unmountable = new Set<string>()

/** A stored id the orchestrator would refuse (`PROJECT_ID_RE`) is left out of the list, logged once. */
function mountable(projectId: string): boolean {
  if (validProjectId(projectId)) return true
  if (!unmountable.has(projectId)) {
    unmountable.add(projectId)
    console.warn(`[sandbox] project ${logValue(projectId, 80)} has an id the sandbox contract refuses; it is never mounted`)
  }
  return false
}

/**
 * The project folders the person's sandbox mounts, sorted: their own projects and, with sharing in
 * force, the shared ones whose access reaches Use AI agent or Exploitation & shells. `actingAs`: the
 * list of the `act_as` view (an admin acting as the person), where a share is Read. Read fresh.
 */
export async function sandboxProjectsFor(userId: string, { actingAs = false }: { actingAs?: boolean } = {}): Promise<string[]> {
  checkUserId(userId)
  const subject = { userId }
  const owned = await prisma.project.findMany({ where: ownedProjectsWhere(subject), select: { id: true } })
  const visible = await visibleProjects(subject)
  const candidates = visible.withShares
    ? sharedProjectIds(subject, visible, await prisma.project.findMany({ where: visible.where, select: { id: true, userId: true } }))
    : []
  const allowed: string[] = owned.map((p) => p.id)
  // One at a time: each is a few fresh reads, and a person with many shares must not take the pool.
  for (const projectId of candidates) {
    const access = await projectAccess(subject, projectId, { fresh: true, ...(actingAs ? { actingAs: true } : {}) })
    if (access && SANDBOX_LEVELS.some((level) => meetsLevel(access, level))) allowed.push(projectId)
  }
  return [...new Set(allowed)].filter(mountable).sort()
}

/** Null when the account may have a sandbox now (read fresh), else the stop reason its refusal maps to. */
async function sandboxUserRefusal(userId: string): Promise<StopReason | null> {
  const principal = await loadPrincipal(userId, { fresh: true })
  if (!principal) return 'account_deleted'
  if (principal.status === 'disabled') return 'account_disabled'
  if (principal.status !== 'active') return 'access_lost'
  const capabilities = await resolveCapabilities(principal, { fresh: true })
  return SANDBOX_PERMISSIONS.some((p) => capabilities.has(p)) ? null : 'access_lost'
}

/** The account exists, is active and holds agent:chat, agent:kali_exec or platform:kali_terminal; else 403 `sandbox_user_refused`. */
export async function assertSandboxUser(userId: string): Promise<void> {
  checkUserId(userId)
  if (await sandboxUserRefusal(userId)) throw new SandboxError(403, ERR_USER_REFUSED)
}

let modeCache: { mode: SandboxMode; at: number } | null = null
// The last mode the orchestrator named, kept until it names another. It only decides whether the
// warm-up starts anything; it never becomes an ensure's answer.
let lastSeenMode: SandboxMode | null = null

function seeMode(mode: SandboxMode): void {
  lastSeenMode = mode
  modeCache = { mode, at: Date.now() }
}

const routesMissing = (err: unknown): boolean => err instanceof SandboxError && err.code === ROUTES_MISSING

/**
 * The orchestrator's mode for what people are shown, cached 30 s (`fresh`: asked now). An
 * orchestrator without the sandbox routes runs only the shared container, so it shows as shared;
 * that guess is never kept as the mode the orchestrator named.
 */
export async function sandboxMode({ fresh = false }: { fresh?: boolean } = {}): Promise<SandboxMode> {
  if (!fresh && modeCache && Date.now() - modeCache.at < MODE_CACHE_MS) return modeCache.mode
  try {
    const mode = await orchestratorMode()
    seeMode(mode)
    return mode
  } catch (err) {
    if (!routesMissing(err)) throw err
    modeCache = { mode: 'shared', at: Date.now() }
    return 'shared'
  }
}

/** The orchestrator gave no answer at all: out of reach, or one outside the contract. */
function noAnswer(err: unknown): boolean {
  return err instanceof OrchestratorUnreachable
    || (err instanceof SandboxError && (err.code === ORCHESTRATOR_ERROR || err.code === BAD_ANSWER || err.code === ROUTES_MISSING))
}

function unavailable(err: unknown): SandboxError {
  warnAtMostEveryMinute(`unavailable:${failureCode(err)}`, `[sandbox] the orchestrator gave no answer: ${failureCode(err)}`)
  return new SandboxError(503, ORCHESTRATOR_UNAVAILABLE)
}

export interface EnsureOptions {
  /** The project the agent's work is on: a hint checked against the list, never added to it. */
  needProject?: string | null
  /** Wait until the sandbox is healthy (default true). */
  wait?: boolean
  /** The warm-up: start in the background, take no lease, wait for nothing. */
  touch?: boolean
  /** The admin acting as the person: the `act_as` view and its list. */
  actingAs?: boolean
  /** Who the `sandbox.started` row names; by default the person (own view) or the system on the person's behalf (act_as). */
  actor?: SandboxActor
}

/**
 * The person's sandbox for the agent. The orchestrator's mode is asked first: shared mode answers
 * shared before any check. In per-user mode it is refused (403) unless the account may have one and
 * the project hint is in the list; then the orchestrator's answer (running, starting, or shared). A
 * start this call caused writes `sandbox.started` and, on the own view, turns the person's tunnels
 * off (B.16). No answer from the orchestrator, at any step, is 503 `orchestrator_unavailable`.
 */
export async function ensureSandbox(userId: string, opts: EnsureOptions = {}): Promise<EnsureAnswer> {
  try {
    return await ensureAttempt(userId, opts, 1)
  } catch (err) {
    throw noAnswer(err) ? unavailable(err) : err
  }
}

async function ensureAttempt(userId: string, opts: EnsureOptions, attempt: number): Promise<EnsureAnswer> {
  checkUserId(userId)
  const needProject = opts.needProject ?? null
  if (needProject !== null && !validProjectId(needProject)) throw new SandboxError(400, ERR_INVALID_PROJECT_ID)
  const actingAs = opts.actingAs === true
  const touch = opts.touch === true
  const view: SandboxView = actingAs ? 'act_as' : 'own'

  // The mode first, asked in this call: in shared mode nobody gets a sandbox of their own, so the
  // person and project checks below would refuse work the shared container does today (a set with
  // triage:run but no agent permission, act-as on a share).
  const mode = await orchestratorMode()
  seeMode(mode)
  if (mode === 'shared') return { mode: 'shared' }

  if (await sandboxUserRefusal(userId)) throw new SandboxError(403, ERR_USER_REFUSED)
  const projects = await sandboxProjectsFor(userId, { actingAs })
  if (needProject !== null && !projects.includes(needProject)) throw new SandboxError(403, ERR_PROJECT_REFUSED)

  const answer = await orchestratorEnsure({
    user_id: userId, view, projects, need_project: needProject, wait: touch ? false : opts.wait !== false, touch,
  })
  seeMode(answer.mode)
  if (answer.mode !== 'per_user' || !answer.fresh) return answer

  await recordStart(userId, view, answer.instance, projects, opts.actor ?? null)
  return (await recheckAfterStart(userId, opts, projects, attempt)) ?? answer
}

/** Null when access still covers the list the start was sent; otherwise the start is undone (and retried once). */
async function recheckAfterStart(userId: string, opts: EnsureOptions, sent: string[], attempt: number): Promise<EnsureAnswer | null> {
  const refused = await sandboxUserRefusal(userId)
  if (refused) {
    await stopSandbox(userId, refused, null)
    throw new SandboxError(403, ERR_USER_REFUSED)
  }
  const now = await sandboxProjectsFor(userId, { actingAs: opts.actingAs === true })
  if (sent.every((p) => now.includes(p))) return null
  await reconcileOne(userId, null)
  const needProject = opts.needProject ?? null
  if (needProject !== null && !now.includes(needProject)) throw new SandboxError(403, ERR_PROJECT_REFUSED)
  if (attempt >= MAX_START_ATTEMPTS) throw new SandboxError(503, ERR_START_FAILED)
  return ensureAttempt(userId, opts, attempt + 1)
}

function startActor(actor: SandboxActor, userId: string, view: SandboxView): AuditActor {
  if (actor) return actor
  return view === 'own'
    ? { actorId: userId, onBehalfOfUserId: null, actorEmail: null }
    : { actorId: null, onBehalfOfUserId: userId, actorEmail: null }
}

async function recordStart(userId: string, view: SandboxView, instance: string, projects: string[], actor: SandboxActor): Promise<void> {
  if (view === 'own') {
    try {
      await prisma.userSettings.updateMany({ where: { userId, tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    } catch (err) {
      // A fresh sandbox whose tunnels could not be turned off is not handed out: stopped, so the
      // next ensure starts it fresh and turns them off then (B.16: never brought back silently).
      await orchestratorStopUser(userId, 'start_failed').catch(() => 0)
      throw err
    }
  }
  await writeAudit({
    ...startActor(actor, userId, view),
    action: 'sandbox.started',
    targetType: 'user',
    targetId: userId,
    after: { view, instance, projectsHash: projectsHash(projects) },
    source: 'system',
  })
}

async function auditStop(actor: SandboxActor, target: Pick<AuditEntry, 'targetType' | 'targetId' | 'projectId'>, reason: StopReason, stopped: number): Promise<void> {
  await writeAudit({
    ...(actor ?? { actorId: null, onBehalfOfUserId: null, actorEmail: null }),
    action: 'sandbox.stopped',
    ...target,
    after: { reason, stopped },
    source: 'system',
  })
}

/**
 * The warm-up (the ws-ticket mint): `ensureSandbox` with `touch`, never awaited by its caller and
 * never throwing. Quiet until an orchestrator answer has named per-user mode. A failure is logged
 * by its code, once a minute at most per code; a refused warm-up shows the person nothing.
 */
export async function touchSandbox(userId: string, opts: { actingAs?: boolean; actor?: SandboxActor } = {}): Promise<void> {
  try {
    if (lastSeenMode !== 'per_user') return
    await ensureSandbox(userId, { touch: true, actingAs: opts.actingAs === true, actor: opts.actor ?? null })
  } catch (err) {
    const code = failureCode(err)
    warnAtMostEveryMinute(`touch:${code}`, `[sandbox] warm-up not done: ${code}`)
  }
}

async function reconcileOne(userId: string, actor: SandboxActor): Promise<number> {
  checkUserId(userId)
  const projects = await sandboxProjectsFor(userId)
  const actAsProjects = await sandboxProjectsFor(userId, { actingAs: true })
  const stopped = await orchestratorReconcile(userId, projects, actAsProjects)
  if (stopped > 0) await auditStop(actor, { targetType: 'user', targetId: userId }, 'access_lost', stopped)
  return stopped
}

/**
 * After an access change: each person's instances outside their fresh lists (own and act-as) are
 * stopped; nothing is started. Best effort: a failure is logged and the next person goes on.
 * Returns how many instances stopped.
 */
export async function reconcileSandbox(userIds: readonly string[], actor: SandboxActor = null): Promise<number> {
  let total = 0
  for (const userId of new Set(userIds)) {
    try {
      total += await reconcileOne(userId, actor)
    } catch (err) {
      console.warn(`[sandbox] reconcile not done for ${logValue(userId, 80)}: ${failureCode(err)}`)
    }
  }
  return total
}

/** Stops both views of the person, then forgets them at the agent; one `sandbox.stopped` row when any stopped. */
export async function stopSandbox(userId: string, reason: StopReason, actor: SandboxActor): Promise<number> {
  checkUserId(userId)
  checkReason(reason)
  const stopped = await orchestratorStopUser(userId, reason)
  if (stopped > 0) {
    await dropSandboxClient(userId)
    await auditStop(actor, { targetType: 'user', targetId: userId }, reason, stopped)
  }
  return stopped
}

/** Stops every sandbox (the emergency stop), then forgets each person at the agent. */
export async function stopAllSandboxes(reason: StopReason, actor: SandboxActor): Promise<number> {
  checkReason(reason)
  // Read before the stop: afterwards the orchestrator no longer knows whose clients to drop.
  const before = await orchestratorList().catch((err: unknown) => {
    console.warn(`[sandbox] the list before stop-all was not read: ${failureCode(err)}`)
    return null
  })
  const stopped = await orchestratorStopAll(reason)
  if (stopped > 0) {
    const people = [...new Set((before?.sandboxes ?? []).map((s) => s.user_id))]
    await Promise.all(people.map((userId) => dropSandboxClient(userId)))
    await auditStop(actor, { targetType: 'instance', targetId: null }, reason, stopped)
  }
  return stopped
}

export type StopOutcome = { ok: true; stopped: number } | { ok: false; code: string }

/** Stops every instance that mounts the project (before its folder is purged, TD-27). Never throws: the caller records the outcome. */
export async function stopProjectSandboxes(projectId: string, reason: StopReason, actor: SandboxActor): Promise<StopOutcome> {
  if (!validProjectId(projectId)) return { ok: false, code: ERR_INVALID_PROJECT_ID }
  if (!isStopReason(reason)) return { ok: false, code: 'invalid_reason' }
  try {
    const stopped = await orchestratorStopProject(projectId, reason)
    if (stopped > 0) await auditStop(actor, { targetType: 'project', targetId: projectId, projectId }, reason, stopped)
    return { ok: true, stopped }
  } catch (err) {
    const code = failureCode(err)
    console.warn(`[sandbox] stop-project not done: ${code}`)
    return { ok: false, code }
  }
}

/** The person's instances (no token): state, stop time, warning. */
export async function sandboxStatus(userId: string): Promise<SandboxStatusAnswer> {
  checkUserId(userId)
  try {
    const status = await orchestratorStatus(userId)
    seeMode(status.mode)
    return status
  } catch (err) {
    if (routesMissing(err)) return { mode: 'shared', instances: [] }
    throw err
  }
}

export interface OperationsSandbox {
  user_id: string
  view: SandboxView
  instance: string
  state: SandboxState
  projects_hash?: string
  created_at?: number
  last_used?: number
  stop_at?: number | null
}

/** Every running sandbox for the admin Operations view, without hosts or tokens. */
export async function listSandboxes(): Promise<{ mode: SandboxMode; sandboxes: OperationsSandbox[] }> {
  let list: SandboxListAnswer
  try {
    list = await orchestratorList()
  } catch (err) {
    if (routesMissing(err)) return { mode: 'shared', sandboxes: [] }
    throw err
  }
  seeMode(list.mode)
  const people = [...new Set(list.sandboxes.map((s) => s.user_id))]
  const statuses = new Map(await Promise.all(people.map(async (userId) => {
    const status = await orchestratorStatus(userId).catch(() => null)
    return [userId, status?.instances ?? []] as const
  })))
  const sandboxes = list.sandboxes.map((s) => {
    const detail = statuses.get(s.user_id)?.find((i) => i.instance === s.instance)
    return {
      user_id: s.user_id, view: s.view, instance: s.instance, state: s.state,
      ...(detail ? { projects_hash: detail.projects_hash, created_at: detail.created_at, last_used: detail.last_used, stop_at: detail.stop_at } : {}),
    }
  })
  return { mode: list.mode, sandboxes }
}

/** The agent's list (internal route only): every running sandbox WITH its host and token, for its fan-out. */
export async function agentSandboxList(): Promise<SandboxListAnswer> {
  try {
    const list = await orchestratorList()
    seeMode(list.mode)
    return list
  } catch (err) {
    // The agent reads a mode from this list too: a missing route is no answer, never "shared".
    if (routesMissing(err)) throw unavailable(err)
    throw err
  }
}

/** Takes or renews a lease after re-reading the account: a disabled or stripped account's renewals stop. */
export async function leaseSandbox(userId: string, lease: { instance: string; leaseId: string; kind: LeaseKind }): Promise<LeaseAnswer> {
  checkUserId(userId)
  if (!validInstance(lease.instance) || !validLeaseId(lease.leaseId) || !isLeaseKind(lease.kind)) {
    throw new SandboxError(400, 'invalid_sandbox_request')
  }
  await assertSandboxUser(userId)
  return orchestratorLease(userId, { instance: lease.instance, lease_id: lease.leaseId, kind: lease.kind })
}

/** Releases a lease; never refused for the account (a release only lets a sandbox stop sooner). */
export async function releaseSandboxLease(userId: string, leaseId: string): Promise<void> {
  checkUserId(userId)
  if (!validLeaseId(leaseId)) throw new SandboxError(400, 'invalid_sandbox_request')
  await orchestratorRelease(userId, leaseId)
}

/** 202 for a start that did not wait, 200 otherwise. */
export function ensureStatus(answer: EnsureAnswer): 200 | 202 {
  return answer.mode === 'per_user' && answer.state === 'starting' ? 202 : 200
}

/**
 * An internal route's answer for a failure: the contract's code and status (a memory or count
 * refusal as the governor payload with its code, as the orchestrator gives it, B.6), the orchestrator
 * out of reach as 503/504, anything else a coded 500. Never the error's text.
 */
export function sandboxFailureResponse(err: unknown, message: string): NextResponse {
  if (err instanceof SandboxError) {
    if (err.limit) return NextResponse.json({ ...err.limit, code: err.code }, { status: err.status })
    return NextResponse.json({ error: message, code: err.code }, { status: err.status })
  }
  if (err instanceof OrchestratorUnreachable) return upstreamFailureResponse('orchestrator', err.cause_, message)
  return internalError(err, message)
}

/** Tests only: forget the mode, the warnings' times and the logged ids. */
export function resetSandboxGatewayForTests(): void {
  modeCache = null
  lastSeenMode = null
  lastLogged.clear()
  unmountable.clear()
}
