/**
 * Fireteam Card
 *
 * Top-level card for a fireteam deployment. Header shows the deployment
 * rationale, live or final status, and aggregate stats. Body is a grid of
 * FireteamMemberCard, one per specialist the parent agent dispatched.
 */

'use client'

import { useState } from 'react'
import {
  Users, ChevronDown, ChevronRight, Loader2, CheckCircle2, XCircle,
  Hourglass, Ban, AlertTriangle,
} from 'lucide-react'
import styles from './FireteamCard.module.css'
import { FireteamMemberCard } from './FireteamMemberCard'
import type { FireteamItem } from './types'

interface FireteamCardProps {
  item: FireteamItem
  missingApiKeys?: Set<string>
  onAddApiKey?: (toolId: string) => void
  onToolConfirmation?: (itemId: string, decision: 'approve' | 'reject') => void
  toolConfirmationDisabled?: boolean
  /** Cancel a single running tool inside one of this fireteam's members. */
  onToolStop?: (itemId: string) => void
}

function headerIcon(status: FireteamItem['status']) {
  switch (status) {
    case 'running':
      return <Loader2 size={14} className={`${styles.icon} ${styles.spinner}`} />
    case 'completed':
      return <CheckCircle2 size={14} className={`${styles.icon} ${styles.iconSuccess}`} />
    case 'timeout':
      return <Hourglass size={14} className={`${styles.icon} ${styles.iconError}`} />
    case 'failed':
      return <XCircle size={14} className={`${styles.icon} ${styles.iconError}`} />
    case 'cancelled':
      return <Ban size={14} className={`${styles.icon} ${styles.iconMuted}`} />
    default:
      return <AlertTriangle size={14} className={`${styles.icon} ${styles.iconWarn}`} />
  }
}

export function FireteamCard({ item, missingApiKeys, onAddApiKey, onToolConfirmation, toolConfirmationDisabled, onToolStop }: FireteamCardProps) {
  const [expanded, setExpanded] = useState(true)
  const counts = item.status_counts ?? {}
  const countStrs: string[] = []
  if (counts.success) countStrs.push(`${counts.success} ok`)
  if (counts.timeout) countStrs.push(`${counts.timeout} timeout`)
  if (counts.error) countStrs.push(`${counts.error} error`)
  if (counts.cancelled) countStrs.push(`${counts.cancelled} cancel`)
  if (counts.needs_confirmation) countStrs.push(`${counts.needs_confirmation} approval`)

  return (
    <div className={`${styles.card} ${styles[`status_${item.status}`] || ''}`}>
      <button type="button" className={styles.header} onClick={() => setExpanded(v => !v)}>
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <Users size={14} className={styles.teamIcon} />
        <span className={styles.title}>
          Fireteam · step {item.iteration} · {item.members.length} specialists
        </span>
        {headerIcon(item.status)}
        <span className={styles.statusLabel}>{item.status}</span>
        <span className={styles.meta}>
          {countStrs.join(' · ')}
          {item.wall_clock_seconds !== undefined && ` · ${item.wall_clock_seconds.toFixed(1)}s`}
        </span>
      </button>

      {expanded && (
        <div className={styles.body}>
          {item.plan_rationale && (
            <div className={styles.rationale}>{item.plan_rationale}</div>
          )}
          <div className={styles.grid}>
            {item.members.map(m => (
              <FireteamMemberCard
                key={m.member_id}
                member={m}
                missingApiKeys={missingApiKeys}
                onAddApiKey={onAddApiKey}
                onToolConfirmation={onToolConfirmation}
                toolConfirmationDisabled={toolConfirmationDisabled}
                onToolStop={onToolStop}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
