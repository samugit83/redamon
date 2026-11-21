/**
 * Typed calls to the recon orchestrator's sandbox routes (group 1, B.9;
 * docs/readmes/README.KALI_SANDBOX.md), through `orchestratorFetch`, which adds the orchestrator
 * key. The gateway (gateway.ts) is the only caller: it decides who and which folders, this file only
 * speaks the protocol.
 *
 * Answers are cut to the contract's keys, so nothing the orchestrator adds later reaches the agent or
 * a browser unreviewed. An error keeps its code only when it is one of the contract's (a FastAPI
 * `{detail: {code}}` or a bare `{code}`); anything else is a 502 `orchestrator_error`, never the
 * body's text, which can quote a traceback. A mode is only ever one the orchestrator named: a 404
 * without a code (a route this orchestrator does not have yet) is `orchestrator_error` for `ensure`
 * and `sandbox_routes_missing` for the mode, the statuses and the list, never "shared". It is "no
 * sandbox" for the stops and the reconcile, which then have nothing to stop.
 *
 * Only `ensure` with `wait` (and not `touch`) gets the long timeout, above the orchestrator's own
 * start timeout (B.15); every other call keeps `orchestratorFetch`'s default.
 *
 * Server-side only.
 */
import { orchestratorFetch } from '@/lib/orchestrator'
import {
  ENSURE_RUNNING_KEYS, ENSURE_STARTING_KEYS, ERR_DRAINING, ERR_HARD, ERR_IMAGE_MISSING, ERR_INVALID_PROJECT_ID,
  ERR_INVALID_USER_ID, ERR_INVALID_VIEW, ERR_NOT_RUNNING, ERR_PROJECT_REFUSED, ERR_RAM, ERR_START_FAILED,
  ERR_START_TIMEOUT, ERR_UNKNOWN_INSTANCE, ERR_USER_REFUSED, LEASE_KINDS, MODES, ORCHESTRATOR_ENSURE_TIMEOUT_S,
  ROUTE_ENSURE, ROUTE_LEASE, ROUTE_LEASES, ROUTE_LIST, ROUTE_MODE, ROUTE_RECONCILE, ROUTE_STATUS, ROUTE_STOP_ALL,
  ROUTE_STOP_PROJECT, ROUTE_STOP_USER, STATES, STOP_REASONS, VIEWS,
  type EnsureAnswer, type EnsureRequest, type LeaseAnswer, type LeaseKind, type LeaseRequest, type SandboxInstanceStatus,
  type SandboxLimit, type SandboxListAnswer, type SandboxListEntry, type SandboxMode, type SandboxStatusAnswer, type StopReason,
} from './contract'

// The contract's id rules (USER_ID_RE, PROJECT_ID_RE, INSTANCE_RE, RESERVED_USER_IDS and the Windows
// device names of recon_orchestrator/sandbox_contract.py). The TypeScript copy holds no patterns, so
// they live here; gateway.test.ts holds the sources equal to the Python copy's.
export const USER_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/
export const PROJECT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/
export const INSTANCE_PATTERN = /^[0-9a-f]{6}$/
export const RESERVED_USER_IDS: readonly string[] = Object.freeze(['ensure', 'mode', 'stop-all', 'stop-project'])
const WINDOWS_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  ...Array.from({ length: 10 }, (_, i) => `COM${i}`),
  ...Array.from({ length: 10 }, (_, i) => `LPT${i}`),
])
// The lease id is a UUID the agent picks (B.8).
const LEASE_ID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

export const validUserId = (v: unknown): v is string =>
  typeof v === 'string' && USER_ID_PATTERN.test(v) && !RESERVED_USER_IDS.includes(v)
export const validProjectId = (v: unknown): v is string =>
  typeof v === 'string' && PROJECT_ID_PATTERN.test(v) && !WINDOWS_DEVICE_NAMES.has(v.toUpperCase())
export const validInstance = (v: unknown): v is string => typeof v === 'string' && INSTANCE_PATTERN.test(v)
export const validLeaseId = (v: unknown): v is string => typeof v === 'string' && LEASE_ID_PATTERN.test(v)
export const isLeaseKind = (v: unknown): v is LeaseKind => typeof v === 'string' && (LEASE_KINDS as readonly string[]).includes(v)
export const isStopReason = (v: unknown): v is StopReason => typeof v === 'string' && (STOP_REASONS as readonly string[]).includes(v)

/** A refusal or failure with the contract's code, and the governor's payload on a 409 memory/count refusal. */
export class SandboxError extends Error {
  constructor(readonly status: number, readonly code: string, readonly limit: SandboxLimit | null = null) {
    super(`sandbox ${code} (${status})`)
    this.name = 'SandboxError'
  }
}

/** The orchestrator could not be reached (refused, DNS, timeout): no answer at all. */
export class OrchestratorUnreachable extends Error {
  constructor(readonly cause_: unknown) {
    super('the recon orchestrator could not be reached')
    this.name = 'OrchestratorUnreachable'
  }
}

const CONTRACT_CODES: ReadonlySet<string> = new Set([
  ERR_INVALID_PROJECT_ID, ERR_INVALID_USER_ID, ERR_INVALID_VIEW, ERR_IMAGE_MISSING, ERR_START_FAILED, ERR_START_TIMEOUT,
  ERR_UNKNOWN_INSTANCE, ERR_NOT_RUNNING, ERR_DRAINING, ERR_RAM, ERR_HARD, ERR_USER_REFUSED, ERR_PROJECT_REFUSED,
])
const LIMIT_KEYS = ['admitted', 'limitType', 'resource', 'current', 'ceiling', 'settingName', 'detail'] as const
/** The orchestrator answered outside the contract (a crash, a wrong key, a proxy's page). */
export const ORCHESTRATOR_ERROR = 'orchestrator_error'
/** A 200 the contract does not describe. */
export const BAD_ANSWER = 'orchestrator_bad_answer'
/** The orchestrator predates the sandbox routes: it named no mode. */
export const ROUTES_MISSING = 'sandbox_routes_missing'

type Json = Record<string, unknown>
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v)

function base(): string {
  return process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
}

/** The route with its `{user_id}` / `{lease_id}` filled; every value was validated by the caller. */
function url(route: string, params: Record<string, string> = {}): string {
  return base() + route.replace(/\{(\w+)\}/g, (_m, name: string) => encodeURIComponent(params[name]))
}

async function call(target: string, init: RequestInit, timeoutMs?: number): Promise<{ res: Response; body: unknown }> {
  let res: Response
  try {
    res = timeoutMs === undefined ? await orchestratorFetch(target, init) : await orchestratorFetch(target, init, { timeoutMs })
  } catch (err) {
    throw new OrchestratorUnreachable(err)
  }
  const body = res.status === 204 ? null : await res.json().catch(() => null)
  return { res, body }
}

const post = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

/** The `{code, ...}` of an error answer, bare or FastAPI's `{detail: {...}}`. */
function errorDetail(body: unknown): Json | null {
  if (!isObject(body)) return null
  if (isObject(body.detail)) return body.detail
  return typeof body.code === 'string' ? body : null
}

/** A 404 naming no code: the route is not there (an orchestrator older than the sandbox routes). */
function routeMissing(res: Response, body: unknown): boolean {
  return res.status === 404 && typeof errorDetail(body)?.code !== 'string'
}

function failure(res: Response, body: unknown): SandboxError {
  const detail = errorDetail(body)
  const code = typeof detail?.code === 'string' ? detail.code : null
  if (!code || !CONTRACT_CODES.has(code)) return new SandboxError(502, ORCHESTRATOR_ERROR)
  if (res.status === 409 && (code === ERR_RAM || code === ERR_HARD)) {
    const limit = Object.fromEntries(LIMIT_KEYS.filter((k) => k in detail!).map((k) => [k, detail![k]])) as unknown as SandboxLimit
    return new SandboxError(409, code, limit)
  }
  return new SandboxError(res.status, code)
}

function pick(source: Json, keys: readonly string[]): Json {
  return Object.fromEntries(keys.filter((k) => k in source).map((k) => [k, source[k]]))
}

function badAnswer(): SandboxError {
  return new SandboxError(502, BAD_ANSWER)
}

function ensureAnswer(res: Response, body: unknown): EnsureAnswer {
  if (!isObject(body)) throw badAnswer()
  if (res.status === 200 && body.mode === 'shared') return { mode: 'shared' }
  if (body.mode !== 'per_user' || !validInstance(body.instance) || typeof body.fresh !== 'boolean') throw badAnswer()
  if (res.status === 202 && body.state === 'starting') return pick(body, ENSURE_STARTING_KEYS) as unknown as EnsureAnswer
  if (res.status !== 200 || body.state !== 'running') throw badAnswer()
  const answer = pick(body, ENSURE_RUNNING_KEYS)
  const complete = ENSURE_RUNNING_KEYS.every((k) => k in answer)
  if (!complete || typeof answer.token !== 'string' || typeof answer.tunnel_token !== 'string' || typeof answer.host !== 'string'
    || !(VIEWS as readonly unknown[]).includes(answer.view) || !Array.isArray(answer.projects) || !isObject(answer.ports)) {
    throw badAnswer()
  }
  return answer as unknown as EnsureAnswer
}

/** POST /sandboxes/ensure. Throws SandboxError (a refusal or a failed start) or OrchestratorUnreachable. */
export async function orchestratorEnsure(req: EnsureRequest): Promise<EnsureAnswer> {
  const waits = req.wait && !req.touch
  const { res, body } = await call(url(ROUTE_ENSURE), post(req), waits ? ORCHESTRATOR_ENSURE_TIMEOUT_S * 1000 : undefined)
  if (res.status === 200 || res.status === 202) return ensureAnswer(res, body)
  throw failure(res, body)
}

/** POST /sandboxes/{user_id}/leases: take or renew. */
export async function orchestratorLease(userId: string, req: LeaseRequest): Promise<LeaseAnswer> {
  const { res, body } = await call(url(ROUTE_LEASES, { user_id: userId }), post(req))
  if (res.ok && isObject(body) && typeof body.expires_at === 'number' && (STATES as readonly unknown[]).includes(body.state)) {
    return pick(body, ['expires_at', 'state', 'stop_at', 'warn']) as unknown as LeaseAnswer
  }
  if (res.ok) throw badAnswer()
  if (routeMissing(res, body)) throw new SandboxError(404, ERR_UNKNOWN_INSTANCE)
  throw failure(res, body)
}

/** DELETE /sandboxes/{user_id}/leases/{lease_id}. */
export async function orchestratorRelease(userId: string, leaseId: string): Promise<void> {
  const { res, body } = await call(url(ROUTE_LEASE, { user_id: userId, lease_id: leaseId }), { method: 'DELETE' })
  if (res.ok || routeMissing(res, body)) return
  throw failure(res, body)
}

function stoppedCount(res: Response, body: unknown): number {
  if (res.ok) {
    if (isObject(body) && Number.isInteger(body.stopped) && (body.stopped as number) >= 0) return body.stopped as number
    throw badAnswer()
  }
  if (routeMissing(res, body)) return 0
  throw failure(res, body)
}

/** POST /sandboxes/{user_id}/reconcile: stops the instances outside the lists; starts nothing. */
export async function orchestratorReconcile(userId: string, projects: string[], actAsProjects: string[]): Promise<number> {
  const { res, body } = await call(url(ROUTE_RECONCILE, { user_id: userId }), post({ projects, act_as_projects: actAsProjects }))
  return stoppedCount(res, body)
}

/** POST /sandboxes/{user_id}/stop: both views. */
export async function orchestratorStopUser(userId: string, reason: StopReason): Promise<number> {
  const { res, body } = await call(url(ROUTE_STOP_USER, { user_id: userId }), post({ reason }))
  return stoppedCount(res, body)
}

/** POST /sandboxes/stop-project: every instance of every person that mounts the project. */
export async function orchestratorStopProject(projectId: string, reason: StopReason): Promise<number> {
  const { res, body } = await call(url(ROUTE_STOP_PROJECT), post({ project_id: projectId, reason }))
  return stoppedCount(res, body)
}

/** POST /sandboxes/stop-all. */
export async function orchestratorStopAll(reason: StopReason): Promise<number> {
  const { res, body } = await call(url(ROUTE_STOP_ALL), post({ reason }))
  return stoppedCount(res, body)
}

const isMode = (v: unknown): v is SandboxMode => (MODES as readonly unknown[]).includes(v)
const STATUS_KEYS = [
  'instance', 'view', 'state', 'projects_hash', 'created_at', 'last_used', 'lease_kinds', 'stop_at', 'stop_reason', 'warn', 'reverse_port',
] as const
const LIST_KEYS = ['user_id', 'view', 'instance', 'host', 'token', 'state'] as const

/** GET /sandboxes/{user_id}: the person's instances, never a token. */
export async function orchestratorStatus(userId: string): Promise<SandboxStatusAnswer> {
  const { res, body } = await call(url(ROUTE_STATUS, { user_id: userId }), { method: 'GET' })
  if (routeMissing(res, body)) throw new SandboxError(404, ROUTES_MISSING)
  if (!res.ok) throw failure(res, body)
  if (!isObject(body) || !isMode(body.mode) || !Array.isArray(body.instances)) throw badAnswer()
  const instances = body.instances.filter(isObject).map((i) => pick(i, STATUS_KEYS) as unknown as SandboxInstanceStatus)
  return { mode: body.mode, instances }
}

/** GET /sandboxes: every running sandbox, WITH its host and token (the agent's fan-out list). */
export async function orchestratorList(): Promise<SandboxListAnswer> {
  const { res, body } = await call(url(ROUTE_LIST), { method: 'GET' })
  if (routeMissing(res, body)) throw new SandboxError(404, ROUTES_MISSING)
  if (!res.ok) throw failure(res, body)
  if (!isObject(body) || !isMode(body.mode) || !Array.isArray(body.sandboxes)) throw badAnswer()
  const sandboxes = body.sandboxes
    .filter((s): s is Json => isObject(s) && validUserId(s.user_id) && validInstance(s.instance))
    .map((s) => pick(s, LIST_KEYS) as unknown as SandboxListEntry)
  return { mode: body.mode, sandboxes }
}

/** GET /sandboxes/mode. */
export async function orchestratorMode(): Promise<SandboxMode> {
  const { res, body } = await call(url(ROUTE_MODE), { method: 'GET' })
  if (routeMissing(res, body)) throw new SandboxError(404, ROUTES_MISSING)
  if (!res.ok) throw failure(res, body)
  if (!isObject(body) || !isMode(body.mode)) throw badAnswer()
  return body.mode
}
