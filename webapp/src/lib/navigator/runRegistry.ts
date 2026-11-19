/**
 * AI Navigator's live runs (plan §7.5): who a run reads for, on which project, from which login,
 * and the abort controller of its stream. The tool callbacks resolve their credential here, and
 * every revocation, stop and switch ends runs here.
 *
 * Stored on `globalThis` under a Symbol.for key: Next.js loads a module once per server bundle, so
 * one process holds several copies of it, and a module-level Map would let the messages route and
 * the internal tool route see different registries (flags.ts keeps its warnings the same way).
 * The webapp runs as a single replica, which the MCP rate limiter also relies on; a second replica
 * would need this to move to a shared store.
 *
 * A reservation is taken and checked in one synchronous step, so two sends from two tabs cannot
 * both pass while the later awaits run. Entries, reservations included, expire after
 * RUN_EXPIRY_S, so a crashed stream cannot hold a slot; an expired entry's credential stops
 * resolving with it.
 */
import { randomBytes, randomUUID } from 'node:crypto'
import {
  CREDENTIAL_BYTES,
  MAX_RUNS_PER_PERSON,
  MAX_RUNS_PER_PERSON_PROJECT,
  RUN_EXPIRY_S,
} from './constants'
import { hashCredential } from './credentialHash'

/** The login a run started from (§7.3 step 5), never taken from a request body. */
export interface RunLogin {
  /** The signed-in account (under act-as, the admin) and the session version its token carried. */
  userId: string
  sessionVersion: number
  deviceSessionId: string | null
  actAsStartId: string | null
}

export interface NavigatorRun {
  runId: string
  personId: string
  projectId: string
  /** The admin acting as `personId`, when one is. */
  actorId: string | null
  threadId: string | null
  /** The project's owner when the run started; a tool call refuses once it differs. */
  tenantId: string | null
  startedAt: number
  abort: AbortController
  toolCalls: number
  credentialHash: string | null
  login: RunLogin | null
  state: 'reserved' | 'live'
}

export type ReserveAnswer = { ok: true; runId: string } | { ok: false; code: 'busy' }

export interface CompleteInput {
  threadId: string
  tenantId: string
  actorId: string | null
  login: RunLogin
}

type StopNotifier = (runId: string) => void

interface Store {
  runs: Map<string, NavigatorRun>
  byHash: Map<string, string>
  notifyStop: StopNotifier | null
}

const KEY = Symbol.for('redamon.navigator.runs')
type Global = typeof globalThis & { [KEY]?: Store }

function store(): Store {
  const g = globalThis as Global
  if (!g[KEY]) g[KEY] = { runs: new Map(), byHash: new Map(), notifyStop: null }
  return g[KEY]!
}

/**
 * Tells the agent to cancel a run, best effort: the abort of the stream's fetch is what the agent
 * sees first (a disconnect); this covers an agent that has not noticed yet. Loaded lazily so the
 * registry stays importable where agentFetch is not (tests, the edge).
 */
function defaultNotifyStop(runId: string): void {
  void import('@/lib/agentFetch')
    .then(({ agentFetch }) =>
      agentFetch('/navigator/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id: runId }),
      }, { timeoutMs: 5000 }),
    )
    .catch(() => {
      console.warn(`[navigator] stop not delivered run=${runId}`)
    })
}

/** Tests replace the agent call; null restores it. */
export function setStopNotifierForTests(fn: StopNotifier | null): void {
  store().notifyStop = fn
}

function expired(run: NavigatorRun, now: number): boolean {
  return now - run.startedAt > RUN_EXPIRY_S * 1000
}

function drop(run: NavigatorRun): void {
  const s = store()
  s.runs.delete(run.runId)
  if (run.credentialHash) s.byHash.delete(run.credentialHash)
}

function sweep(now = Date.now()): void {
  for (const run of store().runs.values()) {
    if (expired(run, now)) {
      run.abort.abort()
      drop(run)
    }
  }
}

function abortRun(run: NavigatorRun): void {
  drop(run)
  if (!run.abort.signal.aborted) run.abort.abort()
  if (run.state === 'live') (store().notifyStop ?? defaultNotifyStop)(run.runId)
}

function abortWhere(match: (run: NavigatorRun) => boolean): number {
  sweep()
  let n = 0
  for (const run of [...store().runs.values()]) {
    if (match(run)) {
      abortRun(run)
      n += 1
    }
  }
  return n
}

export interface ReserveInput {
  personId: string
  projectId: string
  /**
   * The acting admin and the login, known when the route reserves: a reservation carries them so a
   * device revoke or the act-as end that lands before complete() ends it too.
   */
  actorId?: string | null
  login?: RunLogin | null
}

export interface NavigatorRunRegistry {
  reserve(input: ReserveInput): ReserveAnswer
  complete(runId: string, input: CompleteInput): string | null
  release(runId: string): void
  get(runId: string): NavigatorRun | null
  byCredentialHash(hash: string): NavigatorRun | null
  end(runId: string): void
  liveForThread(threadId: string): NavigatorRun | null
  liveThreadIds(): Set<string>
  countFor(personId: string): number
  countAll(): number
  abortFor(input: { personId: string; projectIds?: readonly string[] }): number
  abortProject(projectId: string): number
  abortThread(threadId: string): number
  abortDeviceSession(sid: string): number
  abortActAs(input: { startId: string | null; adminId: string; targetUserId: string }): number
  abortActor(adminId: string): number
  abortAll(): number
}

const registry: NavigatorRunRegistry = {
  reserve({ personId, projectId, actorId = null, login = null }) {
    sweep()
    const mine = [...store().runs.values()].filter((r) => r.personId === personId)
    if (mine.length >= MAX_RUNS_PER_PERSON) return { ok: false, code: 'busy' }
    if (mine.filter((r) => r.projectId === projectId).length >= MAX_RUNS_PER_PERSON_PROJECT) return { ok: false, code: 'busy' }
    const runId = randomUUID()
    store().runs.set(runId, {
      runId, personId, projectId, actorId, threadId: null, tenantId: null, startedAt: Date.now(),
      abort: new AbortController(), toolCalls: 0, credentialHash: null, login: login ? { ...login } : null, state: 'reserved',
    })
    return { ok: true, runId }
  },

  complete(runId, { threadId, tenantId, actorId, login }) {
    const run = store().runs.get(runId)
    if (!run || run.state !== 'reserved' || run.abort.signal.aborted) return null
    const token = randomBytes(CREDENTIAL_BYTES).toString('base64url')
    const hash = hashCredential(token)
    Object.assign(run, { threadId, tenantId, actorId, login: { ...login }, credentialHash: hash, state: 'live' as const })
    store().byHash.set(hash, runId)
    return token
  },

  release(runId) {
    const run = store().runs.get(runId)
    if (run) drop(run)
  },

  get(runId) {
    sweep()
    return store().runs.get(runId) ?? null
  },

  byCredentialHash(hash) {
    sweep()
    const runId = store().byHash.get(hash)
    const run = runId ? store().runs.get(runId) : undefined
    return run && run.state === 'live' && !run.abort.signal.aborted ? run : null
  },

  end(runId) {
    const run = store().runs.get(runId)
    if (run) drop(run)
  },

  liveForThread(threadId) {
    sweep()
    for (const run of store().runs.values()) if (run.threadId === threadId) return run
    return null
  },

  liveThreadIds() {
    sweep()
    return new Set([...store().runs.values()].flatMap((r) => (r.threadId ? [r.threadId] : [])))
  },

  countFor(personId) {
    sweep()
    return [...store().runs.values()].filter((r) => r.personId === personId).length
  },

  countAll() {
    sweep()
    return store().runs.size
  },

  abortFor({ personId, projectIds }) {
    return abortWhere((r) => r.personId === personId && (!projectIds || projectIds.includes(r.projectId)))
  },
  abortProject(projectId) {
    return abortWhere((r) => r.projectId === projectId)
  },
  abortThread(threadId) {
    return abortWhere((r) => r.threadId === threadId)
  },
  abortDeviceSession(sid) {
    return abortWhere((r) => r.login?.deviceSessionId === sid)
  },
  abortActAs({ startId, adminId, targetUserId }) {
    return abortWhere((r) => r.actorId === adminId && r.personId === targetUserId
      && (startId === null || r.login?.actAsStartId === startId))
  },
  abortActor(adminId) {
    return abortWhere((r) => r.actorId === adminId)
  },
  abortAll() {
    return abortWhere(() => true)
  },
}

export function navigatorRuns(): NavigatorRunRegistry {
  return registry
}

/** Empties the store; tests only. */
export function clearNavigatorRunsForTests(): void {
  const s = store()
  s.runs.clear()
  s.byHash.clear()
}
