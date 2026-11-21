'use client'

import { useState, useEffect, useCallback, useRef, useContext } from 'react'
import type { MsfSession, MsfJob, NonMsfSession, SessionInteractResult } from '@/lib/websocket-types'
import { readApiError, toApiError } from '@/lib/apiError'
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
 * A session or job to drive: its number and, with per-user Kali sandboxes, the instance it runs in
 * (every console numbers from 1; group 1, TD-11). No instance: the shared container's row.
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
  sessions: MsfSession[]
  jobs: MsfJob[]
  nonMsfSessions: NonMsfSession[]
  /** How many sandboxes the agent could not ask: their sessions are missing from the lists. */
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
  const [sessions, setSessions] = useState<MsfSession[]>([])
  const [jobs, setJobs] = useState<MsfJob[]>([])
  const [nonMsfSessions, setNonMsfSessions] = useState<NonMsfSession[]>([])
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
    setSessions([])
    setJobs([])
    setNonMsfSessions([])
    setUnavailableCount(0)
    setAgentBusy(false)
    setError(null)
  }, [refused])

  const fetchSessions = useCallback(async () => {
    try {
      const resp = await fetch('/api/agent/sessions', { cache: 'no-store' })
      if (!resp.ok) {
        throw await readApiError(resp, 'Failed to fetch sessions')
      }
      const data = await resp.json()
      const liveSessions: MsfSession[] = data.sessions || []
      const liveJobs: MsfJob[] = data.jobs || []
      // Clear killed keys that are truly gone from the server
      for (const key of killedSessionsRef.current) {
        if (!liveSessions.some(s => sessionRowKey(s) === key)) killedSessionsRef.current.delete(key)
      }
      for (const key of killedJobsRef.current) {
        if (!liveJobs.some(j => sessionRowKey(j) === key)) killedJobsRef.current.delete(key)
      }
      // Filter out sessions/jobs that are pending kill
      setSessions(liveSessions.filter(s => !killedSessionsRef.current.has(sessionRowKey(s))))
      setJobs(liveJobs.filter(j => !killedJobsRef.current.has(sessionRowKey(j))))
      setNonMsfSessions(data.non_msf_sessions || [])
      const unavailable = data.unavailable_count
      setUnavailableCount(Number.isSafeInteger(unavailable) && unavailable > 0 ? unavailable : 0)
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
        throw await readApiError(resp, 'Failed to interact with session')
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
    setSessions(prev => prev.filter(s => sessionRowKey(s) !== key))
    try {
      const resp = await fetch(drivePath('sessions', ref, 'kill'), { method: 'POST' })
      if (!resp.ok) throw await readApiError(resp, `Failed to kill session ${ref.id}`)
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
    setJobs(prev => prev.filter(j => sessionRowKey(j) !== key))
    try {
      const resp = await fetch(drivePath('jobs', ref, 'kill'), { method: 'POST' })
      if (!resp.ok) throw await readApiError(resp, `Failed to kill job ${ref.id}`)
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
