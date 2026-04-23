'use client'

import { useState } from 'react'
import { Loader2, Terminal, Square, X } from 'lucide-react'
import { WORKFLOW_TOOLS } from '@/components/projects/ProjectForm/WorkflowView/workflowDefinition'
import type { PartialReconState } from '@/lib/recon-types'
import styles from './PartialReconBadges.module.css'

interface PartialReconBadgesProps {
  activePartialRecons: PartialReconState[]
  activeLogsRunId?: string | null
  onToggleLogs: (runId: string) => void
  onStop: (runId: string) => void
  /** Max individual badges before grouping into dropdown */
  maxVisible?: number
}

export function PartialReconBadges({
  activePartialRecons,
  activeLogsRunId,
  onToggleLogs,
  onStop,
  maxVisible = 3,
}: PartialReconBadgesProps) {
  const [isOverflowOpen, setIsOverflowOpen] = useState(false)

  if (activePartialRecons.length === 0) return null

  // Individual badges
  if (activePartialRecons.length <= maxVisible) {
    return (
      <>
        {activePartialRecons.map(run => (
          <BadgeItem
            key={run.run_id}
            run={run}
            isLogsActive={activeLogsRunId === run.run_id}
            onToggleLogs={onToggleLogs}
            onStop={onStop}
          />
        ))}
      </>
    )
  }

  // Grouped dropdown
  return (
    <span className={styles.badgeGroup} style={{ position: 'relative' }}>
      <span className={styles.badge} style={{ cursor: 'pointer' }} onClick={() => setIsOverflowOpen(prev => !prev)}>
        <Loader2 size={12} className={styles.spinner} />
        <span>{activePartialRecons.length} Partial Recons</span>
      </span>
      {isOverflowOpen && (
        <div className={styles.overflow}>
          <div className={styles.overflowHeader}>
            <span>{activePartialRecons.length} Partial Recons</span>
            <button type="button" onClick={() => setIsOverflowOpen(false)} className={styles.overflowClose}>
              <X size={14} />
            </button>
          </div>
          <div className={styles.overflowList}>
            {activePartialRecons.map(run => {
              const isBusy = run.status === 'running' || run.status === 'starting'
              const isStopping = run.status === 'stopping'
              return (
                <div key={run.run_id} className={styles.overflowItem}>
                  <span className={styles.overflowLabel}>
                    {isBusy && <Loader2 size={12} className={styles.spinner} />}
                    {WORKFLOW_TOOLS.find(t => t.id === run.tool_id)?.label || run.tool_id}
                  </span>
                  <div className={styles.overflowActions}>
                    <button
                      type="button"
                      onClick={() => { onToggleLogs(run.run_id); setIsOverflowOpen(false) }}
                      className={`${styles.badgeBtn} ${activeLogsRunId === run.run_id ? styles.badgeBtnActive : ''}`}
                      title="View Logs"
                    >
                      <Terminal size={13} />
                    </button>
                    <button
                      type="button"
                      onClick={() => onStop(run.run_id)}
                      disabled={isStopping}
                      className={styles.badgeBtn}
                      title="Stop"
                    >
                      <Square size={13} />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </span>
  )
}

function BadgeItem({
  run,
  isLogsActive,
  onToggleLogs,
  onStop,
}: {
  run: PartialReconState
  isLogsActive: boolean
  onToggleLogs: (runId: string) => void
  onStop: (runId: string) => void
}) {
  const isBusy = run.status === 'running' || run.status === 'starting'
  const isStopping = run.status === 'stopping'

  return (
    <span className={styles.badgeGroup}>
      <span className={styles.badge}>
        {isBusy && <Loader2 size={12} className={styles.spinner} />}
        <span>{WORKFLOW_TOOLS.find(t => t.id === run.tool_id)?.label || run.tool_id}</span>
      </span>
      <button
        type="button"
        className={`${styles.badgeBtn} ${isLogsActive ? styles.badgeBtnActive : ''}`}
        onClick={() => onToggleLogs(run.run_id)}
        title="View Logs"
      >
        <Terminal size={12} />
      </button>
      <button
        type="button"
        className={styles.badgeBtn}
        disabled={isStopping}
        onClick={() => onStop(run.run_id)}
        title="Stop"
      >
        <Square size={12} />
      </button>
    </span>
  )
}
