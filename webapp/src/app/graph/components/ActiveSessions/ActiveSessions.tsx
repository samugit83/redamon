'use client'

import { useState, useCallback, memo } from 'react'
import { Terminal, AlertCircle, Clock, Plug } from 'lucide-react'
import type { MsfSession, MsfJob, NonMsfSession, SessionInteractResult } from '@/lib/websocket-types'
import { useToast } from '@/components/ui'
import { errorMessage } from '@/lib/apiError'
import { partialAnswerLine } from '@/lib/sandbox/contract'
import { reversePortLine } from '@/lib/sandbox/reversePort'
import { noAnswerInTime, sessionRowKey, useSessionsAccess, type SessionRef, type ShownRow } from '@/hooks/useActiveSessions'
import { ForbiddenNotice } from '@/components/auth/ForbiddenNotice'
import { SessionCard, NonMsfCard, JobCard } from './SessionCard'
import { SessionTerminal } from './SessionTerminal'
import { stopWarningText } from './useSandboxStopWarning'
import { useSandboxStatus } from './useSandboxStatus'
import styles from './ActiveSessions.module.css'

interface ActiveSessionsProps {
  /** A row kept from an earlier answer (its sandbox did not answer the last read) carries `staleSince`. */
  sessions: ShownRow<MsfSession>[]
  jobs: ShownRow<MsfJob>[]
  nonMsfSessions: ShownRow<NonMsfSession>[]
  /** The sandbox instances whose console runs a command of the agent now: the terminal warns for its own row's. */
  busyInstances: readonly string[]
  isLoading: boolean
  projectId: string
  /** A session or job is the pair (sandbox instance, number): every per-user sandbox numbers from 1. */
  onInteract: (session: SessionRef, command: string) => Promise<SessionInteractResult>
  onKillSession: (session: SessionRef) => Promise<void>
  onKillJob: (job: SessionRef) => Promise<void>
  /** Why the list could not be refreshed (the agent is down, the route failed). */
  error?: string | null
  /** How many sandboxes the agent could not ask: their sessions are missing from the lists. */
  unavailable?: number
}

const refOf = (row: { id: number; sandbox?: string }): SessionRef => ({ id: row.id, sandbox: row.sandbox ?? null })

/** Whose sandbox and which project a row is, as named to a holder of every session; null for anyone else. */
export function rowOwnerText(row: { person_label?: string; project_label?: string } | undefined): string | null {
  const parts = [row?.person_label, row?.project_label].filter((p): p is string => typeof p === 'string' && p !== '')
  return parts.length ? parts.join(' · ') : null
}

export const ActiveSessions = memo(function ActiveSessions({
  sessions,
  jobs,
  nonMsfSessions,
  busyInstances,
  isLoading,
  projectId,
  onInteract,
  onKillSession,
  onKillJob,
  error = null,
  unavailable = 0,
}: ActiveSessionsProps) {
  const [selected, setSelected] = useState<SessionRef | null>(null)
  // The rows whose kill is pending: the hook hides a row as its kill starts, so it is not "ended" yet.
  const [killing, setKilling] = useState<ReadonlySet<string>>(() => new Set())
  const toast = useToast()
  const refused = useSessionsAccess() === 'refused'
  const { stopAt, reversePort } = useSandboxStatus(!refused)
  const portLine = reversePortLine(reversePort)

  const selectedKey = selected ? sessionRowKey(selected) : null
  const selectedSession = selectedKey === null ? undefined : sessions.find(s => sessionRowKey(s) === selectedKey)
  const selectedKilling = selectedKey !== null && killing.has(selectedKey)
  const selectedBusy = !!selected?.sandbox && busyInstances.includes(selected.sandbox)
  // A complete answer (no sandbox left out, no error) that no longer lists the selected row: it ended.
  const selectedEnded = selected !== null && selectedSession === undefined && unavailable === 0 && !error && !selectedKilling
  const totalSessions = sessions.length + nonMsfSessions.length

  const handleKill = useCallback(async (target: SessionRef) => {
    const key = sessionRowKey(target)
    setKilling(prev => new Set(prev).add(key))
    try {
      await onKillSession(target)
    } catch (err) {
      // No answer in time: the kill may still have happened, so it is not "not killed".
      toast.error(errorMessage(err, `Failed to kill session ${target.id}`), noAnswerInTime(err) ? 'Kill not confirmed' : 'Session not killed')
      return
    } finally {
      setKilling(prev => {
        const next = new Set(prev)
        next.delete(key)
        return next
      })
    }
    setSelected(current => (current && sessionRowKey(current) === key ? null : current))
  }, [onKillSession, toast])

  const handleKillJob = useCallback(async (target: SessionRef) => {
    try {
      await onKillJob(target)
    } catch (err) {
      toast.error(errorMessage(err, `Failed to kill job ${target.id}`), noAnswerInTime(err) ? 'Stop not confirmed' : 'Job not stopped')
    }
  }, [onKillJob, toast])

  // The terminal types into the selected row's own sandbox.
  const interactSelected = useCallback(
    (sessionId: number, command: string) => onInteract({ id: sessionId, sandbox: selected?.sandbox ?? null }, command),
    [onInteract, selected],
  )

  if (refused) {
    return (
      <div className={styles.emptyState}>
        <ForbiddenNotice permission="agent:sessions" />
      </div>
    )
  }

  // Loading state
  if (isLoading) {
    return (
      <div className={styles.loading}>
        <div className={styles.spinner} />
        Loading sessions...
      </div>
    )
  }

  const notices = (
    <>
      {portLine !== null && (
        <div className={styles.reversePort} data-testid="sessions-reverse-port">
          <Plug size={12} />
          <span>{portLine}</span>
        </div>
      )}
      {stopAt !== null && (
        <div className={styles.stopWarning} role="status">
          <Clock size={12} />
          <span>{stopWarningText(stopAt)}</span>
        </div>
      )}
      {unavailable > 0 && (
        <div className={styles.partialAnswer} role="status">
          <AlertCircle size={12} />
          <span>{partialAnswerLine(unavailable)}</span>
        </div>
      )}
    </>
  )

  const nothingListed = totalSessions === 0 && jobs.length === 0
  // The terminal holds its output in its own state, so while a row is selected it stays mounted, even
  // when a read lists nothing (a busy sandbox left out, a failed read): the empty states below would
  // unmount it and lose the answer of a command in flight.
  const showEmpty = nothingListed && selected === null

  // An unreachable agent is not "no sessions": say what failed instead.
  if (showEmpty && error) {
    return (
      <div className={styles.emptyState} role="alert">
        <AlertCircle size={40} className={styles.emptyIcon} />
        <p className={styles.emptyTitle}>Could not load sessions</p>
        <p className={styles.emptyText}>{error}</p>
      </div>
    )
  }

  // Empty state - no sessions at all
  if (showEmpty) {
    return (
      <div className={styles.emptyState}>
        {notices}
        <Terminal size={40} className={styles.emptyIcon} />
        <p className={styles.emptyTitle}>No Reverse Shells</p>
        <p className={styles.emptyText}>
          Sessions appear here when the agent establishes connections -
          reverse shells, meterpreter sessions, bind shells, and listeners.
        </p>
      </div>
    )
  }

  return (
    <div className={styles.container}>
      {/* Left panel - session list */}
      <div className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <span className={styles.sidebarTitle}>
            Sessions
            <span className={styles.count}>{totalSessions}</span>
          </span>
        </div>

        {notices}

        {error && (
          <div className={styles.listError} role="alert">
            <AlertCircle size={12} />
            <span>Not refreshed: {error}</span>
          </div>
        )}

        <div className={styles.sidebarBody}>
          {nothingListed && (
            <div className={styles.nothingListed}>
              <span>No sessions listed.</span>
              <button type="button" className={styles.closeTerminal} onClick={() => setSelected(null)}>
                Close terminal
              </button>
            </div>
          )}

          {/* Metasploit sessions */}
          {sessions.length > 0 && (
            <>
              <p className={styles.sectionLabel}>Metasploit</p>
              {sessions.map(s => (
                <SessionCard
                  key={sessionRowKey(s)}
                  session={s}
                  isSelected={selectedKey === sessionRowKey(s)}
                  onSelect={() => setSelected(refOf(s))}
                  onKill={() => handleKill(refOf(s))}
                />
              ))}
            </>
          )}

          {/* Non-MSF sessions */}
          {nonMsfSessions.length > 0 && (
            <>
              {sessions.length > 0 && <div className={styles.divider} />}
              <p className={styles.sectionLabel}>Other</p>
              {nonMsfSessions.map(s => (
                <NonMsfCard
                  key={sessionRowKey(s)}
                  session={s}
                  isSelected={false}
                  onSelect={() => {}}
                />
              ))}
            </>
          )}

          {/* Background jobs */}
          {jobs.length > 0 && (
            <>
              <div className={styles.divider} />
              <p className={styles.sectionLabel}>
                Background Jobs ({jobs.length})
              </p>
              {jobs.map(j => (
                <JobCard
                  key={sessionRowKey(j)}
                  job={j}
                  onKill={() => handleKillJob(refOf(j))}
                />
              ))}
            </>
          )}
        </div>
      </div>

      {/* Right panel - terminal */}
      <div className={styles.main}>
        <SessionTerminal
          sessionId={selected?.id ?? null}
          sessionKey={selectedKey}
          sessionType={selectedSession?.type || 'shell'}
          agentBusy={selectedBusy}
          owner={rowOwnerText(selectedSession)}
          projectId={projectId}
          onInteract={interactSelected}
          ended={selectedEnded}
          killing={selectedKilling}
        />
      </div>
    </div>
  )
})
