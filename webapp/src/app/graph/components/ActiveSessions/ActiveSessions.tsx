'use client'

import { useState, useCallback, memo } from 'react'
import { Terminal, AlertCircle } from 'lucide-react'
import type { MsfSession, MsfJob, NonMsfSession, SessionInteractResult } from '@/lib/websocket-types'
import { useToast } from '@/components/ui'
import { errorMessage } from '@/lib/apiError'
import { useSessionsAccess } from '@/hooks/useActiveSessions'
import { ForbiddenNotice } from '@/components/auth/ForbiddenNotice'
import { SessionCard, NonMsfCard, JobCard } from './SessionCard'
import { SessionTerminal } from './SessionTerminal'
import styles from './ActiveSessions.module.css'

interface ActiveSessionsProps {
  sessions: MsfSession[]
  jobs: MsfJob[]
  nonMsfSessions: NonMsfSession[]
  agentBusy: boolean
  isLoading: boolean
  projectId: string
  onInteract: (sessionId: number, command: string) => Promise<SessionInteractResult>
  onKillSession: (sessionId: number) => Promise<void>
  onKillJob: (jobId: number) => Promise<void>
  /** Why the list could not be refreshed (the agent is down, the route failed). */
  error?: string | null
}

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
}: ActiveSessionsProps) {
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null)
  const toast = useToast()
  const refused = useSessionsAccess() === 'refused'

  const selectedSession = sessions.find(s => s.id === selectedSessionId)
  const totalSessions = sessions.length + nonMsfSessions.length

  const handleKill = useCallback(async (id: number) => {
    try {
      await onKillSession(id)
    } catch (err) {
      toast.error(errorMessage(err, `Failed to kill session ${id}`), 'Session not killed')
      return
    }
    if (selectedSessionId === id) {
      setSelectedSessionId(null)
    }
  }, [onKillSession, selectedSessionId, toast])

  const handleKillJob = useCallback(async (id: number) => {
    try {
      await onKillJob(id)
    } catch (err) {
      toast.error(errorMessage(err, `Failed to kill job ${id}`), 'Job not stopped')
    }
  }, [onKillJob, toast])

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
                  key={s.id}
                  session={s}
                  isSelected={selectedSessionId === s.id}
                  onSelect={() => setSelectedSessionId(s.id)}
                  onKill={() => handleKill(s.id)}
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
                  key={s.id}
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
                  key={j.id}
                  job={j}
                  onKill={() => handleKillJob(j.id)}
                />
              ))}
            </>
          )}
        </div>
      </div>

      {/* Right panel - terminal */}
      <div className={styles.main}>
        <SessionTerminal
          sessionId={selectedSessionId}
          sessionType={selectedSession?.type || 'shell'}
          agentBusy={agentBusy}
          projectId={projectId}
          onInteract={onInteract}
        />
      </div>
    </div>
  )
})
