'use client'

import { memo, useState, useCallback } from 'react'
import { Monitor, Globe, MessageSquare, Skull, Square, Loader2 } from 'lucide-react'
import type { MsfSession, MsfJob, NonMsfSession } from '@/lib/websocket-types'
import { sessionRowKey } from '@/hooks/useActiveSessions'
import styles from './SessionCard.module.css'

/** The Kali sandbox instance a row runs in, when the agent named one (per-user sandboxes). */
function SandboxTag({ sandbox }: { sandbox?: string }) {
  if (!sandbox) return null
  return <span className={styles.sandboxTag} title="Kali sandbox instance">{sandbox}</span>
}

// ── Session card ──

interface SessionCardProps {
  session: MsfSession
  isSelected: boolean
  onSelect: () => void
  onKill: () => void
}

export const SessionCard = memo(function SessionCard({
  session,
  isSelected,
  onSelect,
  onKill,
}: SessionCardProps) {
  const isMeterpreter = session.type === 'meterpreter'
  const [killing, setKilling] = useState(false)

  const handleKill = useCallback(async (e: React.MouseEvent) => {
    e.stopPropagation()
    setKilling(true)
    try { await onKill() } finally { setKilling(false) }
  }, [onKill])

  return (
    <div
      className={`${styles.card} ${isSelected ? styles.cardSelected : ''}`}
      onClick={onSelect}
      data-session-key={sessionRowKey(session)}
    >
      <div className={styles.cardHeader}>
        <span className={styles.sessionId}>#{session.id}</span>
        <SandboxTag sandbox={session.sandbox} />
        <span className={`${styles.typeBadge} ${isMeterpreter ? styles.meterpreter : styles.shell}`}>
          {isMeterpreter ? 'meterpreter' : 'shell'}
        </span>
      </div>

      <div className={styles.meta}>
        {session.info && (
          <div className={styles.metaRow}>
            <Monitor size={11} />
            <span className={styles.metaValue}>{session.info}</span>
          </div>
        )}
        {session.connection && (
          <div className={styles.metaRow}>
            <Globe size={11} />
            <span className={styles.metaValue}>{session.connection}</span>
          </div>
        )}
        {session.chat_session_id && (
          <div className={styles.metaRow}>
            <MessageSquare size={11} />
            <span className={styles.chatLink} title={session.chat_session_id}>
              {session.chat_session_id.slice(0, 12)}...
            </span>
          </div>
        )}
      </div>

      <div className={styles.actions}>
        <button
          className={`${styles.actionBtn} ${styles.killBtn} ${killing ? styles.loading : ''}`}
          onClick={handleKill}
          disabled={killing}
          title="Kill session"
        >
          {killing ? <Loader2 size={11} className={styles.spinner} /> : <Skull size={11} />}
          {killing ? 'Killing...' : 'Kill'}
        </button>
      </div>
    </div>
  )
})

// ── Non-MSF session card ──

interface NonMsfCardProps {
  session: NonMsfSession
  isSelected: boolean
  onSelect: () => void
}

export const NonMsfCard = memo(function NonMsfCard({
  session,
  isSelected,
  onSelect,
}: NonMsfCardProps) {
  return (
    <div
      className={`${styles.card} ${isSelected ? styles.cardSelected : ''}`}
      onClick={onSelect}
    >
      <div className={styles.cardHeader}>
        <span className={styles.sessionId}>{session.id}</span>
        <SandboxTag sandbox={session.sandbox} />
        <span className={`${styles.typeBadge} ${styles.listener}`}>
          {session.tool || session.type}
        </span>
      </div>
      {session.command && (
        <div className={styles.meta}>
          <div className={styles.metaRow}>
            <Monitor size={11} />
            <span className={styles.metaValue}>{session.command}</span>
          </div>
        </div>
      )}
    </div>
  )
})

// ── Job card ──

interface JobCardProps {
  job: MsfJob
  onKill: () => void
}

export const JobCard = memo(function JobCard({ job, onKill }: JobCardProps) {
  const [stopping, setStopping] = useState(false)

  const handleStop = useCallback(async () => {
    setStopping(true)
    try { await onKill() } finally { setStopping(false) }
  }, [onKill])

  return (
    <div className={styles.jobCard} data-session-key={sessionRowKey(job)}>
      <div className={styles.jobInfo}>
        <span className={styles.jobName}>{job.name}</span>
        <SandboxTag sandbox={job.sandbox} />
        {job.port > 0 && (
          <span className={styles.jobMeta}>:{job.port}</span>
        )}
      </div>
      <button
        className={`${styles.actionBtn} ${styles.killBtn} ${stopping ? styles.loading : ''}`}
        onClick={handleStop}
        disabled={stopping}
        title="Stop job"
      >
        {stopping ? <Loader2 size={10} className={styles.spinner} /> : <Square size={10} />}
        {stopping ? 'Stopping...' : 'Stop'}
      </button>
    </div>
  )
})
