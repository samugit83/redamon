'use client'

import { useCallback, useMemo } from 'react'
import { ArrowLeft, Loader2 } from 'lucide-react'
import { ActivityLog } from './ActivityLog'
import { useCypherFixCodeFixWS } from '@/hooks/useCypherFixCodeFixWS'
import { useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { featureModelMessage } from '@/lib/llmFeatures'
import type { Remediation } from '@/lib/cypherfix-types'
import styles from './DiffViewer.module.css'

interface DiffViewerProps {
  remediation: Remediation
  projectId: string
  userId: string
  onBack: () => void
  onRefresh: () => void
}

export function DiffViewer({
  remediation,
  projectId,
  userId,
  onBack,
  onRefresh,
}: DiffViewerProps) {
  const codefix = useCypherFixCodeFixWS({
    userId,
    projectId,
    onComplete: () => {
      onRefresh()
    },
  })

  const { ensureFeatureModel } = useFeatureModelGate()

  // CodeFix runs on the user's own CodeFix model; without one the agent
  // refuses the run, so it is asked for before the socket is opened.
  const handleStart = useCallback(async () => {
    if (!(await ensureFeatureModel('codefix'))) return
    codefix.startFix(remediation.id)
  }, [codefix, remediation.id, ensureFeatureModel])

  // The agent can still answer model_required (the model was cleared in
  // another tab after the check above): pick one and start again.
  const handleChooseModel = useCallback(async () => {
    if (!(await ensureFeatureModel('codefix', { force: true }))) return
    codefix.startFix(remediation.id)
  }, [codefix, remediation.id, ensureFeatureModel])

  const handleAccept = useCallback((blockId: string) => {
    codefix.sendBlockDecision(blockId, 'accept')
  }, [codefix])

  const handleReject = useCallback((blockId: string, reason?: string) => {
    codefix.sendBlockDecision(blockId, 'reject', reason)
  }, [codefix])

  // Stats
  const blockStats = useMemo(() => {
    const accepted = codefix.diffBlocks.filter(b => b.status === 'accepted').length
    const rejected = codefix.diffBlocks.filter(b => b.status === 'rejected').length
    const pending = codefix.diffBlocks.filter(b => b.status === 'pending').length
    return { total: codefix.diffBlocks.length, accepted, rejected, pending }
  }, [codefix.diffBlocks])

  const isRunning = codefix.status === 'running' || codefix.status === 'awaiting_approval'
  const isProcessing = codefix.status === 'running'
  const isStopping = codefix.status === 'stopping'
  const isIdle = codefix.status === 'disconnected' || codefix.status === 'connected'
  const lastEntry = codefix.activityLog[codefix.activityLog.length - 1]
  const showConnectionError = codefix.status === 'error' && codefix.errorCode !== 'model_required'
    && !!codefix.error && !(lastEntry?.type === 'error' && lastEntry.message === codefix.error)
  // The agent asks the webapp at push time whether the person may still push, and refuses when
  // the check does not answer (the owner too): the session has ended, the approved changes are
  // on the remediation, so the way to push them is a new run.
  const pushCheckUnavailable = codefix.errorCode === 'decision_check_unavailable'
    && (codefix.status === 'error' || codefix.status === 'completed')

  return (
    <div className={styles.viewer}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <button className={styles.backBtn} onClick={onBack}>
            <ArrowLeft size={14} />
            Back
          </button>
          <span className={styles.remTitle}>{remediation.title}</span>
        </div>
        <div className={styles.headerRight}>
          {blockStats.total > 0 && (
            <span className={styles.statsLabel}>
              {blockStats.accepted} accepted, {blockStats.rejected} rejected, {blockStats.pending} pending
            </span>
          )}
          {isStopping && (
            <span className={styles.stoppingLabel}>
              <Loader2 size={14} className={styles.spinner} />
              Stopping...
            </span>
          )}
          {isRunning && (
            <button className={styles.stopBtn} onClick={codefix.stopFix}>
              Stop
            </button>
          )}
        </div>
      </div>

      {/* Processing indicator */}
      {isProcessing && (
        <div className={styles.processingBar}>
          <Loader2 size={14} className={styles.spinner} />
          Processing...
        </div>
      )}

      {/* Content */}
      <div className={styles.content}>
        {/* Idle state - show start button (first time or after stop) */}
        {isIdle && codefix.activityLog.length === 0 && (
          <div className={styles.idleState}>
            <p>Ready to start the CodeFix agent for this remediation.</p>
            <button className={styles.startBtn} onClick={() => void handleStart()}>
              Start CodeFix
            </button>
          </div>
        )}

        {/* Activity log - chronological history of all events */}
        {codefix.activityLog.length > 0 && (
          <ActivityLog
            entries={codefix.activityLog}
            diffBlocks={codefix.diffBlocks}
            onAcceptBlock={handleAccept}
            onRejectBlock={handleReject}
          />
        )}

        {/* A refused ticket or a closed socket is not an agent event, so the
            log does not show it; an agent's own error is its last entry. */}
        {showConnectionError && (
          <div className={styles.idleState}>
            <p role="alert">{codefix.error}</p>
            <button className={styles.startBtn} onClick={() => void handleStart()}>
              Try again
            </button>
          </div>
        )}

        {pushCheckUnavailable && (
          <div className={styles.idleState}>
            <p role="alert">
              RedAmon could not confirm your permission to push this fix, so nothing was pushed. The approved
              changes are saved on the remediation: try again in a moment.
            </p>
            <button className={styles.startBtn} onClick={() => void handleStart()}>
              Start the fix again
            </button>
          </div>
        )}

        {codefix.status === 'error' && codefix.errorCode === 'model_required' && (
          <div className={styles.idleState}>
            <p>{featureModelMessage('model_required')}: CodeFix has no model to run on.</p>
            <button className={styles.startBtn} onClick={() => void handleChooseModel()}>
              Choose a model and start
            </button>
          </div>
        )}

        {/* Restart / Go to Remediations - shown when idle after a previous run */}
        {isIdle && codefix.activityLog.length > 0 && (
          <div className={styles.idleState}>
            <button className={styles.startBtn} onClick={() => void handleStart()}>
              Restart CodeFix
            </button>
            <button className={styles.secondaryBtn} onClick={onBack}>
              Go to Remediations
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
