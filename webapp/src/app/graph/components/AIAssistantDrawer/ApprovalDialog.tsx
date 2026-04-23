'use client'

import React from 'react'
import { AlertCircle, ShieldAlert } from 'lucide-react'
import type { ApprovalRequestPayload } from '@/lib/websocket-types'
import styles from './AIAssistantDrawer.module.css'

interface ApprovalDialogProps {
  awaitingApproval: boolean
  approvalRequest: ApprovalRequestPayload | null
  modificationText: string
  isLoading: boolean
  setModificationText: (v: string) => void
  handleApproval: (decision: 'approve' | 'modify' | 'abort') => void
}

export function ApprovalDialog({
  awaitingApproval,
  approvalRequest,
  modificationText,
  isLoading,
  setModificationText,
  handleApproval,
}: ApprovalDialogProps) {
  if (!awaitingApproval || !approvalRequest) return null

  return (
    <div className={styles.approvalDialog}>
      <div className={styles.approvalHeader}>
        <AlertCircle size={16} />
        <span>Phase Transition Request</span>
      </div>
      <div className={styles.approvalContent}>
        <p className={styles.approvalTransition}>
          <span className={styles.approvalFrom}>{approvalRequest.from_phase}</span>
          <span className={styles.approvalArrow}>→</span>
          <span className={styles.approvalTo}>{approvalRequest.to_phase}</span>
        </p>

        <div className={styles.approvalDisclaimer}>
          <ShieldAlert size={16} className={styles.approvalDisclaimerIcon} />
          <p className={styles.approvalDisclaimerText}>
            This transition will enable <strong>active operations</strong> against the target.
            By approving, you confirm that you <strong>own the target</strong> or have{' '}
            <strong>explicit written permission</strong> from the owner.
            Unauthorized activity is illegal and may result in criminal penalties.
          </p>
        </div>

        <p className={styles.approvalReason}>{approvalRequest.reason}</p>

        {approvalRequest.planned_actions.length > 0 && (
          <div className={styles.approvalSection}>
            <strong>Planned Actions:</strong>
            <ul>
              {approvalRequest.planned_actions.map((action, i) => (
                <li key={i}>{action}</li>
              ))}
            </ul>
          </div>
        )}

        {approvalRequest.risks.length > 0 && (
          <div className={styles.approvalSection}>
            <strong>Risks:</strong>
            <ul>
              {approvalRequest.risks.map((risk, i) => (
                <li key={i}>{risk}</li>
              ))}
            </ul>
          </div>
        )}

        <textarea
          className={styles.modificationInput}
          placeholder="Optional: provide modification feedback..."
          value={modificationText}
          onChange={(e) => setModificationText(e.target.value)}
        />
      </div>
      <div className={styles.approvalActions}>
        <button
          className={`${styles.approvalButton} ${styles.approvalButtonApprove}`}
          onClick={() => handleApproval('approve')}
          disabled={isLoading}
        >
          Approve
        </button>
        <button
          className={`${styles.approvalButton} ${styles.approvalButtonModify}`}
          onClick={() => handleApproval('modify')}
          disabled={isLoading || !modificationText.trim()}
        >
          Modify
        </button>
        <button
          className={`${styles.approvalButton} ${styles.approvalButtonAbort}`}
          onClick={() => handleApproval('abort')}
          disabled={isLoading}
        >
          Abort
        </button>
      </div>
    </div>
  )
}
