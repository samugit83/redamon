'use client'

import { useState, useCallback, memo } from 'react'
import { Terminal, AlertCircle, Clock } from 'lucide-react'
import type { MsfSession, MsfJob, NonMsfSession, SessionInteractResult } from '@/lib/websocket-types'
import { useToast } from '@/components/ui'
import { errorMessage } from '@/lib/apiError'
import { partialAnswerLine } from '@/lib/sandbox/contract'
import { sessionRowKey, useSessionsAccess, type SessionRef } from '@/hooks/useActiveSessions'
import { ForbiddenNotice } from '@/components/auth/ForbiddenNotice'
import { SessionCard, NonMsfCard, JobCard } from './SessionCard'
import { SessionTerminal } from './SessionTerminal'
import { stopWarningText, useSandboxStopWarning } from './useSandboxStopWarning'
import styles from './ActiveSessions.module.css'

interface ActiveSessionsProps {
  sessions: MsfSession[]
  jobs: MsfJob[]
  nonMsfSessions: NonMsfSession[]
  agentBusy: boolean
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

export const ActiveSessions = memo(function ActiveSessions({
  sessions,
  jobs,
  nonMsfSessions,
  agentBusy,
  isLoading,
  projectId,
  onInteract,
  onKillSession,
  onKillJob,
  error = null,
  unavailable = 0,
}: ActiveSessionsProps) {
  const [selected, setSelected] = useState<SessionRef | null>(null)
  const toast = useToast()
  const refused = useSessionsAccess() === 'refused'
  const stopAt = useSandboxStopWarning(!refused)

  const selectedKey = selected ? sessionRowKey(selected) : null
  const selectedSession = selectedKey === null ? undefined : sessions.find(s => sessionRowKey(s) === selectedKey)
  const totalSessions = sessions.length + nonMsfSessions.length

  const handleKill = useCallback(async (target: SessionRef) => {
    try {
      await onKillSession(target)
    } catch (err) {
      toast.error(errorMessage(err, `Failed to kill session ${target.id}`), 'Session not killed')
      return
    }
    setSelected(current => (current && sessionRowKey(current) === sessionRowKey(target) ? null : current))
  }, [onKillSession, toast])

  const handleKillJob = useCallback(async (target: SessionRef) => {
    try {
      await onKillJob(target)
    } catch (err) {
      toast.error(errorMessage(err, `Failed to kill job ${target.id}`), 'Job not stopped')
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

  // An unreachable agent is not "no sessions": say what failed instead.
  if (totalSessions === 0 && jobs.length === 0 && error) {
    return (
      <div className={styles.emptyState} role="alert">
        <AlertCircle size={40} className={styles.emptyIcon} />
        <p className={styles.emptyTitle}>Could not load sessions</p>
        <p className={styles.emptyText}>{error}</p>
      </div>
    )
  }

  // Empty state - no sessions at all
  if (totalSessions === 0 && jobs.length === 0) {
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
          agentBusy={agentBusy}
          projectId={projectId}
          onInteract={interactSelected}
        />
      </div>
    </div>
  )
})
