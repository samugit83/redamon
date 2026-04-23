/**
 * Fireteam Member Card
 *
 * One panel per member inside a FireteamCard. Shows the member's name,
 * skills, live status, and their streamed tool calls + nested plan waves.
 */

'use client'

import { useState } from 'react'
import {
  ChevronDown, ChevronRight, Loader2, CheckCircle2, XCircle, AlertTriangle,
  Ban, Clock, Hourglass, UserCheck,
} from 'lucide-react'
import styles from './FireteamMemberCard.module.css'
import { ToolExecutionCard } from './ToolExecutionCard'
import { PlanWaveCard } from './PlanWaveCard'
import { formatTokenCount } from '@/lib/formatTokens'
import type { FireteamMemberPanel } from './types'

interface FireteamMemberCardProps {
  member: FireteamMemberPanel
  missingApiKeys?: Set<string>
  onAddApiKey?: (toolId: string) => void
  onToolConfirmation?: (itemId: string, decision: 'approve' | 'reject') => void
  toolConfirmationDisabled?: boolean
  /** Cancel a single running tool inside this member's tool list or nested plan waves. */
  onToolStop?: (itemId: string) => void
}

function statusIcon(status: FireteamMemberPanel['status']) {
  switch (status) {
    case 'running':
      return <Loader2 size={14} className={`${styles.statusIcon} ${styles.spinner}`} />
    case 'success':
      return <CheckCircle2 size={14} className={`${styles.statusIcon} ${styles.iconSuccess}`} />
    case 'partial':
      return <AlertTriangle size={14} className={`${styles.statusIcon} ${styles.iconWarn}`} />
    case 'error':
      return <XCircle size={14} className={`${styles.statusIcon} ${styles.iconError}`} />
    case 'timeout':
      return <Hourglass size={14} className={`${styles.statusIcon} ${styles.iconError}`} />
    case 'cancelled':
      return <Ban size={14} className={`${styles.statusIcon} ${styles.iconMuted}`} />
    case 'needs_confirmation':
      return <UserCheck size={14} className={`${styles.statusIcon} ${styles.iconWarn}`} />
    default:
      return <Clock size={14} className={styles.statusIcon} />
  }
}

export function FireteamMemberCard({ member, missingApiKeys, onAddApiKey, onToolConfirmation, toolConfirmationDisabled, onToolStop }: FireteamMemberCardProps) {
  const [expanded, setExpanded] = useState(false)
  const [expandedTools, setExpandedTools] = useState<Set<string>>(new Set())
  const [collapsedWaves, setCollapsedWaves] = useState<Set<string>>(new Set())

  const toggleWaveExpand = (waveId: string) => {
    setCollapsedWaves(prev => {
      const s = new Set(prev)
      if (s.has(waveId)) s.delete(waveId)
      else s.add(waveId)
      return s
    })
  }

  const toggleToolExpand = (toolId: string) => {
    setExpandedTools(prev => {
      const s = new Set(prev)
      if (s.has(toolId)) s.delete(toolId)
      else s.add(toolId)
      return s
    })
  }

  const toolCount = member.tools.length + member.planWaves.reduce((n, w) => n + w.tools.length, 0)
  const cls = [styles.card, styles[`status_${member.status}`] || ''].filter(Boolean).join(' ')

  // Sub-step: live counter while running, final count when finished.
  // `latest_iteration` streams in via FIRETEAM_THINKING; `iterations_used`
  // lands at FIRETEAM_MEMBER_COMPLETED. Fall back across them so the card
  // always shows the most accurate number.
  const subStep = member.status === 'running'
    ? (member.latest_iteration ?? member.iterations_used ?? 0)
    : (member.iterations_used ?? member.latest_iteration ?? 0)
  const subStepLabel = member.max_iterations
    ? `sub-step ${subStep} (max ${member.max_iterations})`
    : `sub-step ${subStep}`

  return (
    <div className={cls}>
      <button type="button" className={styles.header} onClick={() => setExpanded(v => !v)}>
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span className={styles.name}>{member.name}</span>
        {statusIcon(member.status)}
        <span className={styles.status}>{member.status}</span>
        <span className={styles.meta}>
          {subStep > 0 && <>{subStepLabel} · </>}
          {(member.input_tokens_used > 0 || member.output_tokens_used > 0) ? (
            <>in {formatTokenCount(member.input_tokens_used)} · out {formatTokenCount(member.output_tokens_used)} · </>
          ) : member.tokens_used > 0 ? (
            <>{formatTokenCount(member.tokens_used)} tok · </>
          ) : null}
          {toolCount} tools
          {member.findings_count > 0 && <> · {member.findings_count} findings</>}
        </span>
      </button>

      {expanded && (
        <div className={styles.body}>
          <div className={styles.taskLine}>{member.task}</div>
          {member.latest_thought && member.status === 'running' && (
            <div className={styles.thought}>{member.latest_thought}</div>
          )}
          {member.skills.length > 0 && (
            <div className={styles.skills}>
              {member.skills.map(s => (
                <span key={s} className={styles.skillChip}>{s}</span>
              ))}
            </div>
          )}
          {member.error_message && (
            <div className={styles.error}>Error: {member.error_message}</div>
          )}
          {member.completion_reason && member.status !== 'success' && (
            <div className={styles.completionReason}>Reason: {member.completion_reason}</div>
          )}
          {member.planWaves.length > 0 && (
            <div className={styles.waves}>
              {member.planWaves.map(w => (
                <PlanWaveCard
                  key={w.id}
                  item={w}
                  isExpanded={!collapsedWaves.has(w.id)}
                  onToggleExpand={() => toggleWaveExpand(w.id)}
                  missingApiKeys={missingApiKeys}
                  onAddApiKey={onAddApiKey}
                  onApprove={
                    w.status === 'pending_approval' && onToolConfirmation
                      ? () => onToolConfirmation(w.id, 'approve')
                      : undefined
                  }
                  onReject={
                    w.status === 'pending_approval' && onToolConfirmation
                      ? () => onToolConfirmation(w.id, 'reject')
                      : undefined
                  }
                  confirmationDisabled={toolConfirmationDisabled}
                  onToolStop={onToolStop}
                />
              ))}
            </div>
          )}
          {member.tools.length > 0 && (
            <div className={styles.tools}>
              {member.tools.map(t => (
                <ToolExecutionCard
                  key={t.id}
                  item={t}
                  isExpanded={expandedTools.has(t.id)}
                  onToggleExpand={() => toggleToolExpand(t.id)}
                  missingApiKey={missingApiKeys?.has(t.tool_name) ?? false}
                  onAddApiKey={onAddApiKey ? () => onAddApiKey(t.tool_name) : undefined}
                  onStop={onToolStop ? () => onToolStop(t.id) : undefined}
                />
              ))}
            </div>
          )}
          {toolCount === 0 && member.status === 'running' && !member.latest_thought && (
            <div className={styles.empty}>Deployed, reasoning…</div>
          )}
        </div>
      )}
    </div>
  )
}
