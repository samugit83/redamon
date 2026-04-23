'use client'

import { useState, useCallback, memo } from 'react'
import { Terminal } from 'lucide-react'
import type { MsfSession, MsfJob, NonMsfSession, SessionInteractResult } from '@/lib/websocket-types'
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
}: ActiveSessionsProps) {
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null)

  const selectedSession = sessions.find(s => s.id === selectedSessionId)
  const totalSessions = sessions.length + nonMsfSessions.length

  const handleKill = useCallback(async (id: number) => {
    await onKillSession(id)
    if (selectedSessionId === id) {
      setSelectedSessionId(null)
    }
  }, [onKillSession, selectedSessionId])

  // Loading state
  if (isLoading) {
    return (
      <div className={styles.loading}>
        <div className={styles.spinner} />
        Loading sessions...
      </div>
    )
  }

  // Empty state — no sessions at all
  if (totalSessions === 0 && jobs.length === 0) {
    return (
      <div className={styles.emptyState}>
        <Terminal size={40} className={styles.emptyIcon} />
        <p className={styles.emptyTitle}>No Reverse Shells</p>
        <p className={styles.emptyText}>
          Sessions appear here when the agent establishes connections —
          reverse shells, meterpreter sessions, bind shells, and listeners.
        </p>
      </div>
    )
  }

  return (
    <div className={styles.container}>
      {/* Left panel — session list */}
      <div className={styles.sidebar}>
        <div className={styles.sidebarHeader}>
          <span className={styles.sidebarTitle}>
            Sessions
            <span className={styles.count}>{totalSessions}</span>
          </span>
        </div>

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
                  onKill={() => onKillJob(j.id)}
                />
              ))}
            </>
          )}
        </div>
      </div>

      {/* Right panel — terminal */}
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
