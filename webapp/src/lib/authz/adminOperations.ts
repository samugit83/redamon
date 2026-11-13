/**
 * The admin console's operations view (step 6.5; GV-06, GV-18): what runs on the instance right
 * now, whoever started it, for whoever holds platform:operations. Server only.
 *
 * Read from the sources that already know, and from no new store:
 *   - scans: the queue (`JobQueue`, running, dispatching, queued, needs_review), the scans that
 *     started (`ScanJob` running) and what the orchestrator holds (`GET /system/active-scans`), the
 *     three sources api/system/jobs merges, merged the same way; the actor is the one step 5.5
 *     records (the queue row's user, the ScanJob's initiator, the orchestrator's `actor_user_id`);
 *   - agent runs: the agent's `GET /agent-sessions/all` (master key), each session with its person,
 *     project and whether a run is active, and the admin behind an act-as run;
 *   - triage runs: `TriageRun` rows still running or publishing whose heartbeat is fresh;
 *   - shell sessions: the agent's session list, each tied to its project through the chat that
 *     opened it (`Conversation.sessionId`, the 1.13 mapping).
 * Each outside source is best effort: one that does not answer is reported by its code and the
 * rest still render. Names and ids only: no target, no address, no chat title, no project content,
 * and listing writes no audit row.
 *
 * Stopping one agent run (`stopAgentRun`) is the per-run half of the emergency stop: it needs the
 * permission that already stops every user's runs (platform:emergency_stop through sharedTools.ts,
 * its escape hatch included), is audited `agent.run_stop` with the run's project, and is never
 * refused for anything the run is doing.
 */
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { orchestratorFetch } from '@/lib/orchestrator'
import { upstreamErrorResponse, upstreamFailure } from '@/lib/routeErrors'
import { LIVE_TRIAGE_STATUSES, heartbeatIsStale } from '@/lib/triageRun'
import type { Session } from '@/lib/session'
import { now } from './clock'
import { forbiddenResponse } from './guards'
import { personAuditEntry } from './permissionAdmin'
import { loadPrincipal } from './principal'
import { sharedToolAccess } from './sharedTools'

/** Each outside read gives up after this long, so one hung service cannot hold the view. */
const SOURCE_TIMEOUT_MS = 8_000
/** A scan that started this recently may not be in the orchestrator's live set yet (system/jobs). */
const LIVE_FILTER_GRACE_MS = 90_000
const RUNNING_LIMIT = 500
const QUEUED_LIMIT = 200
const TRIAGE_LIMIT = 200

export interface OpsPerson {
  id: string
  /** Null for an account with no name, or one deleted since. */
  name: string | null
}

export interface OpsProject {
  id: string
  /** Null when the project is gone (deleted while the run was still listed). */
  name: string | null
  owner: OpsPerson | null
}

export type SourceState = { ok: true } | { ok: false; code: string }

export interface OpsScan {
  key: string
  kind: string
  status: string
  /** `queue`: started or held by the queue; `scan`: a ScanJob nobody queued; `live`: only the orchestrator knows it. */
  source: 'queue' | 'scan' | 'live'
  project: OpsProject
  /** Who the scan acts as (step 5.5); null when no person started it (a schedule before 5.5, an adopted run). */
  actor: OpsPerson | null
  /** The tool of a partial recon or the source of a TruffleHog run: otherwise identical rows. */
  detail: string
  startedAt: string | null
  enqueuedAt: string | null
  blockedCode: string
  blockedReason: string
}

export interface OpsAgentRun {
  key: string
  sessionId: string
  project: OpsProject
  /** The session's person: whose run it is (the ticket's subject). */
  actor: OpsPerson
  /** The administrator who started it acting as `actor`, when one did. */
  realActor: OpsPerson | null
  running: boolean
  /** Whether a browser tab holds the session's socket now. */
  connected: boolean
}

export interface OpsTriageRun {
  id: string
  project: OpsProject
  actor: OpsPerson
  realActor: OpsPerson | null
  status: string
  /** `app` (a person's tab) or `mcp` (an external agent). */
  trigger: string
  phase: string
  progress: number
  startedAt: string
  heartbeatAt: string
}

export interface OpsShell {
  key: string
  id: string
  kind: 'session' | 'listener'
  type: string
  /** Null when no chat is known to have opened it. */
  project: OpsProject | null
  /** The person whose chat opened it. */
  person: OpsPerson | null
}

export interface OperationsView {
  generatedAt: string
  /** Decided by the server; the stop route decides again. */
  actions: { stopRuns: boolean }
  agentRuns: { state: SourceState; runs: OpsAgentRun[] }
  scans: { orchestrator: SourceState; running: OpsScan[]; queued: OpsScan[]; queuedTotal: number }
  triageRuns: OpsTriageRun[]
  shells: { state: SourceState; sessions: OpsShell[]; jobs: number }
}

// ---------------------------------------------------------------------------------------------
// Scans: the three sources, merged as api/system/jobs merges them.

export interface QueueScanRow {
  id: string
  projectId: string
  userId: string
  kind: string
  status: string
  runId: string
  scanJobId: string | null
  blockedCode: string
  blockedReason: string
  enqueuedAt: Date
  startedAt: Date | null
}

export interface ScanJobRow {
  id: string
  projectId: string
  kind: string
  runId: string
  initiatedByUserId: string | null
  startedAt: Date | null
  createdAt: Date
}

export interface LiveScan {
  kind: string
  project_id: string
  run_id: string
  tool_id: string
  status: string
  started_at: string | null
  actor_user_id: string | null
}

/** A scan before its project and people are resolved. */
export interface MergedScan {
  key: string
  kind: string
  status: string
  source: OpsScan['source']
  projectId: string
  actorId: string | null
  detail: string
  startedAt: string | null
  enqueuedAt: string | null
  blockedCode: string
  blockedReason: string
}

/** A per-repo supply-chain batch item runs in the single scan's container, which reports it as `supply_chain`. */
function dedupKind(kind: string): string {
  return kind === 'supply_chain_repo' ? 'supply_chain' : kind
}

function runKey(kind: string, projectId: string, runId = ''): string {
  const k = dedupKind(kind)
  return runId ? `${k}|${projectId}|${runId}` : `${k}|${projectId}`
}

const iso = (d: Date | null): string | null => (d ? d.toISOString() : null)

/**
 * The running scans, each once, richest identity first: a queue row, then a ScanJob the queue did
 * not start, then a scan only the orchestrator holds. A ScanJob left `running` by a scan that ended
 * with nobody watching is dropped when the orchestrator's set is known (not empty) and the scan is
 * past the start grace. A row without a run id claims the next live entry of its kind and project,
 * as a counter, so a project really running two partial recons still lists both.
 */
export function mergeRunningScans(
  queue: readonly QueueScanRow[],
  scanJobs: readonly ScanJobRow[],
  live: readonly LiveScan[],
  nowMs: number,
): MergedScan[] {
  const seen = new Set<string>()
  const pending = new Map<string, number>()
  const claim = (kind: string, projectId: string, runId = '') => {
    seen.add(runKey(kind, projectId, runId))
    if (!runId) {
      const k = runKey(kind, projectId)
      pending.set(k, (pending.get(k) ?? 0) + 1)
    }
  }

  const running = queue.filter((r) => r.status === 'running' || r.status === 'dispatching')
  for (const r of running) claim(r.kind, r.projectId, r.runId)

  const liveKeys = new Set<string>()
  for (const s of live) {
    liveKeys.add(runKey(s.kind, s.project_id, s.run_id))
    liveKeys.add(runKey(s.kind, s.project_id))
  }
  const liveKnown = live.length > 0
  const stillRunning = (s: ScanJobRow): boolean => {
    if (!liveKnown) return true
    if (s.startedAt && nowMs - s.startedAt.getTime() < LIVE_FILTER_GRACE_MS) return true
    return liveKeys.has(s.runId ? runKey(s.kind, s.projectId, s.runId) : runKey(s.kind, s.projectId))
  }
  const claimedJobs = new Set(running.map((r) => r.scanJobId).filter((id): id is string => !!id))
  const freeJobs = scanJobs.filter((s) => !claimedJobs.has(s.id) && stillRunning(s))
  for (const s of freeJobs) claim(s.kind, s.projectId, s.runId)

  const freeLive = live.filter((s) => {
    if (seen.has(runKey(s.kind, s.project_id, s.run_id))) return false
    const k = runKey(s.kind, s.project_id)
    const waiting = pending.get(k) ?? 0
    if (waiting > 0) { pending.set(k, waiting - 1); return false }
    return true
  })

  return [
    ...running.map((r): MergedScan => ({
      key: `queue:${r.id}`, kind: r.kind, status: r.status, source: 'queue', projectId: r.projectId, actorId: r.userId || null,
      detail: '', startedAt: iso(r.startedAt), enqueuedAt: iso(r.enqueuedAt), blockedCode: r.blockedCode, blockedReason: r.blockedReason,
    })),
    ...freeJobs.map((s): MergedScan => ({
      key: `scan:${s.id}`, kind: s.kind, status: 'running', source: 'scan', projectId: s.projectId, actorId: s.initiatedByUserId,
      detail: '', startedAt: iso(s.startedAt), enqueuedAt: iso(s.createdAt), blockedCode: '', blockedReason: '',
    })),
    ...freeLive.map((s): MergedScan => ({
      key: `live:${s.kind}:${s.project_id}:${s.run_id}`, kind: s.kind, status: s.status, source: 'live', projectId: s.project_id,
      actorId: s.actor_user_id, detail: s.tool_id, startedAt: s.started_at, enqueuedAt: s.started_at, blockedCode: '', blockedReason: '',
    })),
  ]
}

function queuedScan(r: QueueScanRow): MergedScan {
  return {
    key: `queue:${r.id}`, kind: r.kind, status: r.status, source: 'queue', projectId: r.projectId, actorId: r.userId || null,
    detail: '', startedAt: null, enqueuedAt: iso(r.enqueuedAt), blockedCode: r.blockedCode, blockedReason: r.blockedReason,
  }
}

// ---------------------------------------------------------------------------------------------
// The outside sources. Each answers its rows or the code that says why it could not.

type Fetched<T> = { ok: true; value: T } | { ok: false; code: string }

const str = (v: unknown): string => (typeof v === 'string' ? v : '')
const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

/**
 * A safe code for an agent answer that is not 2xx: 404 is an agent older than this view, 503 one still
 * starting or without its master key (the fail-closed guard), 401/403 one that refused the webapp's key.
 */
function agentStatusCode(status: number): string {
  if (status === 404) return 'agent_route_missing'
  if (status === 503) return 'agent_not_ready'
  if (status === 401 || status === 403) return 'agent_refused'
  return 'agent_error'
}

async function agentRead(path: string): Promise<Fetched<unknown>> {
  try {
    const res = await agentFetch(path, { method: 'GET', cache: 'no-store' }, { timeoutMs: SOURCE_TIMEOUT_MS })
    if (!res.ok) return { ok: false, code: agentStatusCode(res.status) }
    return { ok: true, value: await res.json() }
  } catch (err) {
    const cause = err instanceof AgentUnreachableError ? err.cause_ : err
    return { ok: false, code: upstreamFailure('agent', cause, '').body.code }
  }
}

async function liveScans(): Promise<Fetched<LiveScan[]>> {
  const base = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
  try {
    const res = await orchestratorFetch(`${base}/system/active-scans`, { method: 'GET' }, { timeoutMs: SOURCE_TIMEOUT_MS })
    if (!res.ok) return { ok: false, code: 'orchestrator_error' }
    const body = await res.json()
    const scans = isRecord(body) && Array.isArray(body.scans) ? body.scans : []
    return {
      ok: true,
      value: scans.filter(isRecord).filter((s) => str(s.kind) && str(s.project_id)).map((s) => ({
        kind: str(s.kind), project_id: str(s.project_id), run_id: str(s.run_id), tool_id: str(s.tool_id), status: str(s.status),
        started_at: str(s.started_at) || null, actor_user_id: str(s.actor_user_id) || null,
      })),
    }
  } catch (err) {
    return { ok: false, code: upstreamFailure('orchestrator', err, '').body.code }
  }
}

interface AgentSession {
  userId: string
  projectId: string
  sessionId: string
  running: boolean
  connected: boolean
  actorId: string | null
}

/** The agent's `GET /agent-sessions/all`: `{sessions: [{user_id, project_id, session_id, running, connected, actor_id}]}`. */
function agentSessionsOf(body: unknown): AgentSession[] {
  const rows = isRecord(body) && Array.isArray(body.sessions) ? body.sessions : []
  return rows.filter(isRecord).filter((r) => str(r.user_id) && str(r.project_id) && str(r.session_id)).map((r) => ({
    userId: str(r.user_id), projectId: str(r.project_id), sessionId: str(r.session_id),
    running: r.running === true, connected: r.connected === true, actorId: str(r.actor_id) || null,
  }))
}

interface ShellRow {
  id: string
  kind: OpsShell['kind']
  type: string
  chat: string | null
}

/** The agent's `GET /sessions`: only the id, the kind and the chat of each; never its target or connection. */
function shellsOf(body: unknown): { rows: ShellRow[]; jobs: number } {
  const p = isRecord(body) ? body : {}
  const list = (value: unknown, kind: OpsShell['kind']): ShellRow[] => (Array.isArray(value) ? value : [])
    .filter(isRecord)
    .filter((r) => r.id !== undefined && r.id !== null && String(r.id) !== '')
    .map((r) => ({ id: String(r.id), kind, type: str(r.type) || 'unknown', chat: str(r.chat_session_id) || null }))
  return { rows: [...list(p.sessions, 'session'), ...list(p.non_msf_sessions, 'listener')], jobs: Array.isArray(p.jobs) ? p.jobs.length : 0 }
}

// ---------------------------------------------------------------------------------------------
// The view.

const QUEUE_SELECT = {
  id: true, projectId: true, userId: true, kind: true, status: true, runId: true, scanJobId: true,
  blockedCode: true, blockedReason: true, enqueuedAt: true, startedAt: true,
} as const

export async function readOperations(session: Session): Promise<OperationsView> {
  const principal = await loadPrincipal(session.userId)
  const [stop, runningQueue, queued, queuedTotal, scanJobs, triage, live, agentAnswer, shellAnswer] = await Promise.all([
    principal ? sharedToolAccess(principal, 'emergency_stop_all', { record: false }) : null,
    prisma.jobQueue.findMany({
      where: { status: { in: ['running', 'dispatching'] } }, orderBy: { startedAt: 'desc' }, take: RUNNING_LIMIT, select: QUEUE_SELECT,
    }),
    prisma.jobQueue.findMany({
      where: { status: { in: ['queued', 'needs_review'] } },
      orderBy: [{ priority: 'desc' }, { enqueuedAt: 'asc' }], take: QUEUED_LIMIT, select: QUEUE_SELECT,
    }),
    prisma.jobQueue.count({ where: { status: { in: ['queued', 'needs_review'] } } }),
    prisma.scanJob.findMany({
      where: { status: 'running' }, orderBy: { startedAt: 'desc' }, take: RUNNING_LIMIT,
      select: { id: true, projectId: true, kind: true, runId: true, initiatedByUserId: true, startedAt: true, createdAt: true },
    }),
    prisma.triageRun.findMany({
      where: { status: { in: [...LIVE_TRIAGE_STATUSES] } }, orderBy: { startedAt: 'desc' }, take: TRIAGE_LIMIT,
      select: {
        id: true, projectId: true, actorUserId: true, realActorUserId: true, status: true, trigger: true, phase: true,
        progress: true, startedAt: true, heartbeatAt: true,
      },
    }),
    liveScans(),
    agentRead('/agent-sessions/all'),
    agentRead('/sessions'),
  ])

  const at = now()
  const scans = mergeRunningScans(runningQueue, scanJobs, live.ok ? live.value : [], at.getTime())
  const waiting = queued.map(queuedScan)
  // A stale heartbeat is a crashed run; findLiveTriageRun marks it failed, this read-only view only leaves it out.
  const triageRuns = triage.filter((r) => !heartbeatIsStale(r.heartbeatAt, at.getTime()))
  const sessions = agentAnswer.ok ? agentSessionsOf(agentAnswer.value) : []
  const shells = shellAnswer.ok ? shellsOf(shellAnswer.value) : { rows: [], jobs: 0 }

  const chats = [...new Set(shells.rows.map((s) => s.chat).filter((c): c is string => !!c))]
  const conversations = chats.length === 0 ? [] : await prisma.conversation.findMany({
    where: { sessionId: { in: chats } }, select: { sessionId: true, projectId: true, userId: true },
  })
  const chatOf = new Map(conversations.map((c) => [c.sessionId, c]))

  const projectIds = new Set<string>([
    ...scans.map((s) => s.projectId), ...waiting.map((s) => s.projectId), ...triageRuns.map((r) => r.projectId),
    ...sessions.map((s) => s.projectId), ...conversations.map((c) => c.projectId),
  ])
  const projectRows = projectIds.size === 0 ? [] : await prisma.project.findMany({
    where: { id: { in: [...projectIds] } }, select: { id: true, name: true, userId: true },
  })
  const personIds = new Set<string>([
    ...projectRows.map((p) => p.userId),
    ...[...scans, ...waiting].map((s) => s.actorId),
    ...triageRuns.flatMap((r) => [r.actorUserId, r.realActorUserId]),
    ...sessions.flatMap((s) => [s.userId, s.actorId]),
    ...conversations.map((c) => c.userId),
  ].filter((id): id is string => !!id))
  const userRows = personIds.size === 0 ? [] : await prisma.user.findMany({
    where: { id: { in: [...personIds] } }, select: { id: true, name: true },
  })

  const names = new Map(userRows.map((u) => [u.id, u.name ?? null]))
  const person = (id: string): OpsPerson => ({ id, name: names.get(id) ?? null })
  const maybePerson = (id: string | null | undefined): OpsPerson | null => (id ? person(id) : null)
  const projects = new Map(projectRows.map((p) => [p.id, p]))
  const project = (id: string): OpsProject => {
    const row = projects.get(id)
    return row ? { id, name: row.name, owner: person(row.userId) } : { id, name: null, owner: null }
  }
  const scanOf = (s: MergedScan): OpsScan => {
    const { projectId, actorId, ...rest } = s
    return { ...rest, project: project(projectId), actor: maybePerson(actorId) }
  }

  return {
    generatedAt: at.toISOString(),
    actions: { stopRuns: stop?.allowed === true },
    agentRuns: {
      state: agentAnswer.ok ? { ok: true } : { ok: false, code: agentAnswer.code },
      runs: sessions
        .map((s): OpsAgentRun => ({
          key: `${s.userId}:${s.projectId}:${s.sessionId}`, sessionId: s.sessionId, project: project(s.projectId),
          actor: person(s.userId), realActor: s.actorId && s.actorId !== s.userId ? person(s.actorId) : null,
          running: s.running, connected: s.connected,
        }))
        .sort((a, b) => Number(b.running) - Number(a.running) || a.key.localeCompare(b.key)),
    },
    scans: {
      orchestrator: live.ok ? { ok: true } : { ok: false, code: live.code },
      running: scans.map(scanOf),
      queued: waiting.map(scanOf),
      queuedTotal,
    },
    triageRuns: triageRuns.map((r) => ({
      id: r.id, project: project(r.projectId), actor: person(r.actorUserId),
      realActor: r.realActorUserId && r.realActorUserId !== r.actorUserId ? person(r.realActorUserId) : null,
      status: r.status, trigger: r.trigger, phase: r.phase, progress: r.progress,
      startedAt: r.startedAt.toISOString(), heartbeatAt: r.heartbeatAt.toISOString(),
    })),
    shells: {
      state: shellAnswer.ok ? { ok: true } : { ok: false, code: shellAnswer.code },
      sessions: shells.rows.map((s): OpsShell => {
        const chat = s.chat ? chatOf.get(s.chat) : undefined
        return {
          key: `${s.kind}:${s.id}`, id: s.id, kind: s.kind, type: s.type,
          project: chat ? project(chat.projectId) : null, person: chat ? person(chat.userId) : null,
        }
      }),
      jobs: shells.jobs,
    },
  }
}

// ---------------------------------------------------------------------------------------------
// Stopping one agent run.

export interface RunTarget {
  userId: string
  projectId: string
  sessionId: string
}

export interface TargetProblem {
  error: string
  code: 'invalid_target'
  field: keyof RunTarget
}

// The agent keys a run `user:project:session` and splits on the first two colons, so a colon in the
// user or the project would name another key.
const KEY_PART = /^[^:\s]{1,200}$/
const SESSION_PART = /^\S{1,200}$/

/** The run a stop names, from the request body; a bad field answers 400 naming it. */
export function parseRunTarget(body: Record<string, unknown>): RunTarget | TargetProblem {
  const fields: Array<[keyof RunTarget, RegExp]> = [['userId', KEY_PART], ['projectId', KEY_PART], ['sessionId', SESSION_PART]]
  for (const [field, shape] of fields) {
    const value = body[field]
    if (typeof value !== 'string' || !shape.test(value)) {
      return { error: `The run to stop needs a valid ${field}.`, code: 'invalid_target', field }
    }
  }
  return { userId: body.userId as string, projectId: body.projectId as string, sessionId: body.sessionId as string }
}

const STOP_FAILED = 'Could not stop the agent run'

/**
 * Stops one agent run of any person: the signed-in person must hold platform:emergency_stop (read
 * fresh, and counted as a use of the escape hatch when that is how it is held). Audited only when a
 * run stopped (`stopped: true`); a run already over answers `stopped: false` and writes nothing, so
 * pressing twice records one stop. The row is written after the stop, as `agent.emergency_stop` is:
 * a safety stop is never held back by the audit table, and a failed write is logged by writeAudit.
 */
export async function stopAgentRun(request: NextRequest, session: Session, target: RunTarget): Promise<NextResponse> {
  const principal = await loadPrincipal(session.userId, { fresh: true })
  const access = principal ? await sharedToolAccess(principal, 'emergency_stop_all') : null
  if (!access?.allowed) return forbiddenResponse('platform:emergency_stop')

  let res: Response
  try {
    res = await agentFetch('/agent-session/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: target.userId, project_id: target.projectId, session_id: target.sessionId }),
    })
  } catch (err) {
    const failure = upstreamFailure('agent', err instanceof AgentUnreachableError ? err.cause_ : err, STOP_FAILED)
    console.error(`[rbac] operations run stop failed actor=${session.userId} project=${target.projectId} code=${failure.body.code}`)
    return NextResponse.json(failure.body, { status: failure.status })
  }
  if (!res.ok) {
    console.error(`[rbac] operations run stop failed actor=${session.userId} project=${target.projectId} code=agent_error status=${res.status}`)
    return upstreamErrorResponse('agent', res, STOP_FAILED, { status: 502 })
  }
  const body: unknown = await res.json().catch(() => null)
  const stopped = isRecord(body) && body.stopped === true
  if (stopped) {
    await writeAudit(await personAuditEntry(request, session, {
      action: 'agent.run_stop',
      targetType: 'agent_session',
      targetId: target.sessionId,
      projectId: target.projectId,
      permission: 'platform:emergency_stop',
      after: { userId: target.userId, via: access.via },
    }))
  }
  return NextResponse.json({ stopped })
}
