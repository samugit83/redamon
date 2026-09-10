'use client'

import { memo } from 'react'
import { Loader2, CheckCircle, AlertCircle, X, Brain } from 'lucide-react'
import type { TriagePhase, TriageFindingPayload } from '@/lib/cypherfix-types'
import styles from './TriageProgress.module.css'

export const PHASE_LABELS: Record<TriagePhase, string> = {
  collecting_vulnerabilities: 'Collecting vulnerabilities',
  collecting_cve_chains: 'Mapping CVE chains',
  collecting_secrets: 'Scanning for secrets',
  collecting_exploits: 'Finding exploits',
  collecting_assets: 'Mapping assets',
  collecting_chain_findings: 'Analyzing attack chains',
  collecting_attack_chains: 'Loading chain summaries',
  collecting_certificates: 'Checking certificates',
  collecting_security_checks: 'Reviewing security checks',
  classifying: 'AI classifying real vs noise',
  correlating: 'AI correlating findings',
  prioritizing: 'Scoring & ranking findings',
  generating_remediations: 'Generating remediations',
  saving: 'Saving results',
}

interface TriageProgressProps {
  isVisible: boolean
  phase: TriagePhase | null
  progress: number
  findings: TriageFindingPayload[]
  thinking: string
  error: string | null
  status: string
  /** Feature name for the header, e.g. "Priority Board". Defaults to the CypherFix
   *  wording so the CypherFix page is unchanged. */
  title?: string
  onClose: () => void
  onStop: () => void
}

export const TriageProgress = memo(function TriageProgress({
  isVisible,
  phase,
  progress,
  findings,
  thinking,
  error,
  status,
  title = 'Vulnerability Triage',
  onClose,
  onStop,
}: TriageProgressProps) {
  if (!isVisible) return null

  const isRunning = status === 'running' || status === 'connecting'
  const isCompleted = status === 'completed'
  const isError = status === 'error'
  const phaseLabel = phase ? PHASE_LABELS[phase] || phase : 'Initializing...'

  return (
    <div className={styles.overlay}>
      <div className={styles.card}>
        {/* Header */}
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            {isRunning && <Loader2 size={16} className={styles.spinner} />}
            {isCompleted && <CheckCircle size={16} className={styles.successIcon} />}
            {isError && <AlertCircle size={16} className={styles.errorIcon} />}
            <span className={styles.headerTitle}>
              {isCompleted ? `${title} complete` : isError ? `${title} failed` : title}
            </span>
          </div>
          <div className={styles.headerRight}>
            {isRunning && (
              <button className={styles.stopBtn} onClick={onStop}>Stop</button>
            )}
            {(isCompleted || isError) && (
              <button className={styles.closeBtn} onClick={onClose}>
                <X size={14} />
              </button>
            )}
          </div>
        </div>

        {/* Progress */}
        <div className={styles.progressSection}>
          <div className={styles.progressBar}>
            <div
              className={styles.progressFill}
              style={{ width: `${Math.min(progress, 100)}%` }}
            />
          </div>
          <div className={styles.phaseLabel}>{phaseLabel}</div>
        </div>

        {/* Error */}
        {error && (
          <div className={styles.errorBox}>
            <AlertCircle size={14} />
            {error}
          </div>
        )}

        {/* Thinking */}
        {thinking && isRunning && (
          <div className={styles.thinkingSection}>
            <Brain size={12} className={styles.thinkingIcon} />
            <span className={styles.thinkingText}>
              {thinking.length > 200 ? thinking.slice(-200) + '...' : thinking}
            </span>
          </div>
        )}

        {/* Live findings */}
        {findings.length > 0 && (
          <div className={styles.findingsSection}>
            <div className={styles.findingsHeader}>
              Findings: {findings.length}
            </div>
            <div className={styles.findingsList}>
              {findings.slice(-6).map((f, i) => (
                <div key={i} className={styles.findingItem}>
                  <span className={`${styles.findingSeverity} ${styles[`sev_${f.severity}`]}`}>
                    {f.severity}
                  </span>
                  <span className={styles.findingTitle}>{f.title}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Completed summary */}
        {isCompleted && (
          <div className={styles.completedSection}>
            <p>Generated {findings.length} remediation items.</p>
            <button className={styles.viewBtn} onClick={onClose}>
              View Dashboard
            </button>
          </div>
        )}
      </div>
    </div>
  )
})
