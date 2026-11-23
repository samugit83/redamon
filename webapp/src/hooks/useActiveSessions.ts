'use client'

import { useState, useEffect, useCallback, useRef, useContext } from 'react'
import type { MsfSession, MsfJob, NonMsfSession, SessionInteractResult, SessionsData } from '@/lib/websocket-types'
import { ApiError, readApiError, toApiError } from '@/lib/apiError'
import { useCan, useRbacFlags } from '@/hooks/useCan'
import { AuthContext } from '@/providers/authContext'

export type SessionsAccess = 'pending' | 'allowed' | 'refused'

/**
 * Whether the shell-sessions list may be asked for: GET /api/agent/sessions asks agent:sessions with
 * no project (step 3.9). 'refused' only with RBAC_PERMISSIONS_ENABLED on and the permission missing
 * from /api/auth/me's set; 'pending' while that answer is read, since the switch is unknown until
 * then. With the switch off, or with no AuthProvider above, 'allowed', as before the switch (DV-30).
 * Which sessions the list holds stays the server's rule (1.13), so nothing else is gated here.
 */
export function useSessionsAccess(): SessionsAccess {
  const authLoading = useContext(AuthContext)?.isLoading ?? false
  const flags = useRbacFlags()
  const held = useCan('agent:sessions')
  if (authLoading) return 'pending'
  return flags?.permissions === true && !held ? 'refused' : 'allowed'
}

/**
 * A session or job to drive: its number and the Kali sandbox instance it runs in (every console
 * numbers from 1; group 1, TD-11). A row without an instance is no drive target (the route answers
 * 400 `sandbox_required`).
 */
export interface SessionRef {
  id: number
  sandbox?: string | null
}

/** The key of a row: (sandbox, number), so two sandboxes' session 1 are two rows. */
export function sessionRowKey(row: { id: number | string; sandbox?: string | null }): string {
  return `${row.sandbox ?? ''}:${row.id}`
}

function refOf(target: number | SessionRef): SessionRef {
  return typeof target === 'number' ? { id: target, sandbox: null } : target
}

/**
 * A row as the lists show it. `listedAt` (ms): the last answer that listed it. `staleSince` (ms) marks
 * a row kept from an earlier answer because its sandbox did not answer this one: when an answer first
 * left it out.
 */
export type ShownRow<T> = T & { listedAt?: number; staleSince?: number }

export interface ShownSessionLists {
  sessions: ShownRow<MsfSession>[]
  jobs: ShownRow<MsfJob>[]
  nonMsfSessions: ShownRow<NonMsfSession>[]
}

export const NO_SESSION_ROWS: ShownSessionLists = { sessions: [], jobs: [], nonMsfSessions: [] }

/**
 * How long after an answer last listed it a row may still be shown while its sandbox does not answer.
 * The session manager answers the list from its cache while a command holds the console, so a sandbox
 * silent through a minute of polls is down or overloaded, not busy with a command; past that its last
 * rows say nothing about now.
 */
export const STALE_ROW_MAX_MS = 60_000

/** GET /api/agent/sessions's answer, as far as the lists read it. */
type SessionsAnswer = Partial<Record<'sessions' | 'jobs' | 'non_msf_sessions' | 'unavailable_count' | 'unavailable', unknown>>

/** How many sandboxes the agent could not ask; 0 for a missing or malformed count. */
export function unavailableCountOf(answer: SessionsAnswer): number {
  const n = answer.unavailable_count
  return typeof n === 'number' && Number.isSafeInteger(n) && n > 0 ? n : 0
}

/** A list of the answer, each row stamped `listedAt`. A row's fields come from its sandbox: its own marks are dropped. */
function rowsOf<T>(value: unknown, now: number): ShownRow<T>[] {
  if (!Array.isArray(value)) return []
  return value
    .filter((row): row is Record<string, unknown> => !!row && typeof row === 'object')
    .map(({ staleSince: _planted, listedAt: _plantedToo, ...own }) => ({ ...own, listedAt: now }) as ShownRow<T>)
}

function instanceOf(row: { sandbox?: unknown }): string | null {
  return typeof row.sandbox === 'string' && row.sandbox ? row.sandbox : null
}

/**
 * The lists to show after `answer`, given those `shown` before (group 1, S16b).
 *
 * The agent asks every sandbox with a short budget each and answers without the rows of one that
 * did not answer: replacing the lists would drop the very row someone is typing into. So a row shown
 * before is kept, marked `staleSince`, when its sandbox (a tagged instance; never a row without one)
 * lists nothing in this answer and the answer names it in `unavailable`. The
 * webapp names to each viewer only the silent instances that could hold rows that viewer may see
 * (agentSessionsAccess `visibleSessions`); a count without names keeps nothing.
 *
 * A kept row goes once its sandbox answers again, or STALE_ROW_MAX_MS after an answer last listed it
 * (failed reads in between count against it). No row is ever added.
 */
export function nextSessionLists(shown: ShownSessionLists, answer: SessionsAnswer, now: number): ShownSessionLists {
  const live: ShownSessionLists = {
    sessions: rowsOf<MsfSession>(answer.sessions, now),
    jobs: rowsOf<MsfJob>(answer.jobs, now),
    nonMsfSessions: rowsOf<NonMsfSession>(answer.non_msf_sessions, now),
  }
  if (unavailableCountOf(answer) === 0 || !Array.isArray(answer.unavailable)) return live
  const named = new Set(answer.unavailable.filter((i): i is string => typeof i === 'string'))
  const everyRow = (lists: ShownSessionLists): ShownRow<{ sandbox?: unknown }>[] =>
    [...lists.sessions, ...lists.jobs, ...lists.nonMsfSessions]
  const answered = new Set(everyRow(live).map(instanceOf))
  const keepable = (row: ShownRow<{ sandbox?: unknown }>) =>
    instanceOf(row) !== null && typeof row.listedAt === 'number' && now - row.listedAt < STALE_ROW_MAX_MS
  const keepFrom = new Set<string>()
  for (const row of everyRow(shown)) {
    const instance = instanceOf(row)
    if (instance !== null && keepable(row) && named.has(instance) && !answered.has(instance)) keepFrom.add(instance)
  }
  if (keepFrom.size === 0) return live
  const withKept = <T extends { sandbox?: string }>(before: ShownRow<T>[], listed: ShownRow<T>[]): ShownRow<T>[] => {
    const kept = before
      .filter(row => keepable(row) && keepFrom.has(instanceOf(row) ?? ''))
      .map(row => ({ ...row, staleSince: row.staleSince ?? now }))
    return kept.length ? [...listed, ...kept] : listed
  }
  return {
    sessions: withKept(shown.sessions, live.sessions),
    jobs: withKept(shown.jobs, live.jobs),
    nonMsfSessions: withKept(shown.nonMsfSessions, live.nonMsfSessions),
  }
}

/** `nextSessionLists` over the answer's own shape, for a reader that keeps the last answer (Insights). */
export function withKeptRows(before: SessionsData | undefined, answer: SessionsData, now: number): SessionsData {
  const shown = before
    ? { sessions: before.sessions ?? [], jobs: before.jobs ?? [], nonMsfSessions: before.non_msf_sessions ?? [] }
    : NO_SESSION_ROWS
  const lists = nextSessionLists(shown, answer, now)
  return { ...answer, sessions: lists.sessions, jobs: lists.jobs, non_msf_sessions: lists.nonMsfSessions }
}

/**
 * Whose rows the lists hold: the signed-in account and the account it acts as. A kept row never
 * outlives it, so an act-as switch never shows the rows read for the other account.
 */
export function useSessionsViewerKey(): string {
  const user = useContext(AuthContext)?.user
  return `${user?.id ?? ''}:${user?.actingAs?.id ?? ''}`
}

/**
 * A kill the Kali console did not run: the session manager answers 200 `{busy: true}` when a running
 * command holds the console past the kill's wait. The session or job is still alive.
 */
async function throwIfConsoleBusy(resp: Response, what: string): Promise<void> {
  const body: unknown = await resp.json().catch(() => null)
  if (body && typeof body === 'object' && (body as { busy?: unknown }).busy === true) {
    throw new ApiError({ reason: `${what}: the Kali console is busy with another command, try again`, status: resp.status, code: 'console_busy' })
  }
}

/**
 * A drive nobody answered in time: the agent's 504 (passed on as 502 with `upstreamStatus` 504) or
 * the webapp's own timeout. The session manager may still run it, so it must not read as "not done".
 */
export function noAnswerInTime(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 504 || err.upstreamStatus === 504)
}

async function driveFailure(resp: Response, fallback: string, noAnswer: string): Promise<ApiError> {
  const err = await readApiError(resp, fallback)
  if (!noAnswerInTime(err)) return err
  return new ApiError({ reason: noAnswer, status: err.status, code: err.code, upstreamStatus: err.upstreamStatus })
}

/** The webapp route of a drive, naming the row's instance when it has one. The id is encoded: it comes from a sandbox. */
function drivePath(kind: 'sessions' | 'jobs', ref: SessionRef, action: 'interact' | 'kill'): string {
  const path = `/api/agent/${kind}/${encodeURIComponent(String(ref.id))}/${action}`
  return ref.sandbox ? `${path}?sandbox=${encodeURIComponent(ref.sandbox)}` : path
}

interface UseActiveSessionsOptions {
  enabled?: boolean
  fastPoll?: boolean // 3s when true, 10s when false
}

interface UseActiveSessionsReturn {
  /** A row kept from an earlier answer (its sandbox did not answer) carries `staleSince`. */
  sessions: ShownRow<MsfSession>[]
  jobs: ShownRow<MsfJob>[]
  nonMsfSessions: ShownRow<NonMsfSession>[]
  /** How many sandboxes the agent could not ask: their sessions are missing, but for rows kept from before. */
  unavailableCount: number
  agentBusy: boolean
  isLoading: boolean
  error: string | null
  totalCount: number
  /** The person may not use shell sessions (useSessionsAccess): nothing is asked, the lists are empty. */
  refused: boolean
  interactWithSession: (session: number | SessionRef, command: string) => Promise<SessionInteractResult>
  /** Rejects with an ApiError when the kill failed; the row is back in the list by then. */
  killSession: (session: number | SessionRef) => Promise<void>
  /** Rejects with an ApiError when the kill failed; the row is back in the list by then. */
  killJob: (job: number | SessionRef) => Promise<void>
  refetch: () => Promise<void>
}

const FAST_INTERVAL = 3000
const SLOW_INTERVAL = 10000

export function useActiveSessions({
  enabled = true,
  fastPoll = false,
}: UseActiveSessionsOptions = {}): UseActiveSessionsReturn {
  const viewer = useSessionsViewerKey()
  // The lists and the viewer they were read for (kept rows never pass to another viewer).
  const [shown, setShown] = useState<{ viewer: string; lists: ShownSessionLists }>(() => ({ viewer, lists: NO_SESSION_ROWS }))
  const viewerRef = useRef(viewer)
  useEffect(() => { viewerRef.current = viewer }, [viewer])
  const [unavailableCount, setUnavailableCount] = useState(0)
  const [agentBusy, setAgentBusy] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  // Track killed sessions/jobs (by sessionRowKey) so polls don't re-add them
  const killedSessionsRef = useRef<Set<string>>(new Set())
  const killedJobsRef = useRef<Set<string>>(new Set())
  const access = useSessionsAccess()
  const refused = access === 'refused'
  const active = enabled && access === 'allowed'

  // An act-as switch can take agent:sessions away mid-page: the rows read before are not this set's.
  useEffect(() => {
    if (!refused) return
    setShown(prev => ({ viewer: prev.viewer, lists: NO_SESSION_ROWS }))
    setUnavailableCount(0)
    setAgentBusy(false)
    setError(null)
  }, [refused])

  const fetchSessions = useCallback(async () => {
    const askedFor = viewerRef.current
    try {
      const resp = await fetch('/api/agent/sessions', { cache: 'no-store' })
      if (!resp.ok) {
        throw await readApiError(resp, 'Failed to fetch sessions')
      }
      const data = await resp.json()
      const liveSessions: MsfSession[] = Array.isArray(data.sessions) ? data.sessions : []
      const liveJobs: MsfJob[] = Array.isArray(data.jobs) ? data.jobs : []
      // Clear killed keys that are truly gone from the server
      for (const key of killedSessionsRef.current) {
        if (!liveSessions.some(s => sessionRowKey(s) === key)) killedSessionsRef.current.delete(key)
      }
      for (const key of killedJobsRef.current) {
        if (!liveJobs.some(j => sessionRowKey(j) === key)) killedJobsRef.current.delete(key)
      }
      const pendingSessions = new Set(killedSessionsRef.current)
      const pendingJobs = new Set(killedJobsRef.current)
      const now = Date.now()
      setShown(prev => {
        const lists = nextSessionLists(prev.viewer === askedFor ? prev.lists : NO_SESSION_ROWS, data, now)
        // Filter out sessions/jobs that are pending kill
        return {
          viewer: askedFor,
          lists: {
            ...lists,
            sessions: lists.sessions.filter(s => !pendingSessions.has(sessionRowKey(s))),
            jobs: lists.jobs.filter(j => !pendingJobs.has(sessionRowKey(j))),
          },
        }
      })
      setUnavailableCount(unavailableCountOf(data))
      setAgentBusy(data.agent_busy || false)
      setError(null)
    } catch (err) {
      // Don't clear sessions on transient errors - keep showing last known state
      setError(toApiError(err, 'Failed to fetch sessions').message)
    }
  }, [])

  const interactWithSession = useCallback(async (session: number | SessionRef, command: string): Promise<SessionInteractResult> => {
    try {
      const resp = await fetch(drivePath('sessions', refOf(session), 'interact'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      })
      if (!resp.ok) {
        throw await driveFailure(resp, 'Failed to interact with session',
          'No answer in time: the command may still be running in the session; check before sending it again')
      }
      return await resp.json()
    } catch (err) {
      return { busy: false, output: `[ERROR] ${toApiError(err, 'Failed to interact with session').message}` }
    }
  }, [])

  // A failed kill puts the row back (the session is still alive) and rejects,
  // so the caller can say why; it used to stay hidden from every later poll.
  const killSession = useCallback(async (session: number | SessionRef) => {
    const ref = refOf(session)
    const key = sessionRowKey(ref)
    // Mark as killed immediately so polls don't re-add it
    killedSessionsRef.current.add(key)
    setShown(prev => ({ ...prev, lists: { ...prev.lists, sessions: prev.lists.sessions.filter(s => sessionRowKey(s) !== key) } }))
    try {
      const resp = await fetch(drivePath('sessions', ref, 'kill'), { method: 'POST' })
      if (!resp.ok) throw await driveFailure(resp, `Failed to kill session ${ref.id}`, `Session ${ref.id}: no answer in time; the kill may still complete`)
      await throwIfConsoleBusy(resp, `Session ${ref.id} was not killed`)
    } catch (err) {
      killedSessionsRef.current.delete(key)
      await fetchSessions()
      throw toApiError(err, `Failed to kill session ${ref.id}`)
    }
  }, [fetchSessions])

  const killJob = useCallback(async (job: number | SessionRef) => {
    const ref = refOf(job)
    const key = sessionRowKey(ref)
    // Mark as killed immediately so polls don't re-add it
    killedJobsRef.current.add(key)
    setShown(prev => ({ ...prev, lists: { ...prev.lists, jobs: prev.lists.jobs.filter(j => sessionRowKey(j) !== key) } }))
    try {
      const resp = await fetch(drivePath('jobs', ref, 'kill'), { method: 'POST' })
      if (!resp.ok) throw await driveFailure(resp, `Failed to kill job ${ref.id}`, `Job ${ref.id}: no answer in time; the stop may still complete`)
      await throwIfConsoleBusy(resp, `Job ${ref.id} was not stopped`)
    } catch (err) {
      killedJobsRef.current.delete(key)
      await fetchSessions()
      throw toApiError(err, `Failed to kill job ${ref.id}`)
    }
  }, [fetchSessions])

  // Initial fetch
  useEffect(() => {
    if (!active) return
    setIsLoading(true)
    fetchSessions().finally(() => setIsLoading(false))
  }, [active, fetchSessions])

  // Smart polling
  useEffect(() => {
    if (!active) return

    if (pollingRef.current) {
      clearInterval(pollingRef.current)
    }

    const interval = fastPoll ? FAST_INTERVAL : SLOW_INTERVAL
    pollingRef.current = setInterval(fetchSessions, interval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [active, fastPoll, fetchSessions])

  const { sessions, jobs, nonMsfSessions } = shown.lists
  const totalCount = sessions.length + nonMsfSessions.length

  return {
    sessions,
    jobs,
    nonMsfSessions,
    unavailableCount,
    agentBusy,
    isLoading: isLoading || (enabled && access === 'pending'),
    error,
    totalCount,
    refused,
    interactWithSession,
    killSession,
    killJob,
    refetch: fetchSessions,
  }
}

export default useActiveSessions
