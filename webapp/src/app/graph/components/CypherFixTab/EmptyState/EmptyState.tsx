'use client'

import { Shield, Scan, ArrowDown, Brain } from 'lucide-react'
import { TriageRunButton } from '@/components/triage/TriageRunButton'
import styles from './EmptyState.module.css'

interface EmptyStateProps {
  onStartTriage: () => void
  projectId: string | null
}

export function EmptyState({ onStartTriage, projectId }: EmptyStateProps) {
  return (
    <div className={styles.wrapper}>
      <div className={styles.card}>
        <div className={styles.iconWrapper}>
          <Shield size={48} strokeWidth={1.5} />
        </div>
        <h2 className={styles.title}>No Remediations Yet</h2>
        <p className={styles.description}>
          A triage run scores every finding in the graph, groups the ones that
          share a fix, and writes one fix item per group. The same run also
          produces the Priority Board&apos;s order, so both pages agree.
        </p>
        <div className={styles.steps}>
          <div className={styles.step}>
            <Scan size={16} />
            <span>Score every finding from the graph</span>
          </div>
          <ArrowDown size={14} className={styles.arrow} />
          <div className={styles.step}>
            <Brain size={16} />
            <span>Group by fix, review the evidence</span>
          </div>
          <ArrowDown size={14} className={styles.arrow} />
          <div className={styles.step}>
            <Shield size={16} />
            <span>One fix item per group</span>
          </div>
        </div>
        <TriageRunButton
          projectId={projectId}
          onConfirm={onStartTriage}
          className={styles.startButton}
        />
      </div>
    </div>
  )
}
