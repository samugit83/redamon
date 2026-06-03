'use client'

import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ShieldAlert, Play, Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui'
import styles from './ReconConfirmModal.module.css'

interface GraphStats {
  totalNodes: number
  nodesByType: Record<string, number>
}

interface ReconConfirmModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: (deleteGraph: boolean) => void
  projectName: string
  targetDomain: string
  ipMode?: boolean
  targetIps?: string[]
  stats: GraphStats | null
  isLoading: boolean
}

export function ReconConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  projectName,
  targetDomain,
  ipMode,
  targetIps,
  stats,
  isLoading,
}: ReconConfirmModalProps) {
  const [deleteGraph, setDeleteGraph] = useState(false)
  const targetDisplay = ipMode && targetIps?.length
    ? targetIps.slice(0, 5).join(', ') + (targetIps.length > 5 ? ` (+${targetIps.length - 5} more)` : '')
    : targetDomain
  const existingStats = stats && stats.totalNodes > 0 ? stats : null
  const hasExistingData = existingStats !== null
  const targetIpsKey = useMemo(() => targetIps?.join('\0') ?? '', [targetIps])

  useEffect(() => {
    if (isOpen || !hasExistingData) {
      setDeleteGraph(false)
    }
  }, [isOpen, projectName, targetDomain, ipMode, targetIpsKey, hasExistingData])

  const handleConfirm = () => {
    onConfirm(deleteGraph && hasExistingData)
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Start Reconnaissance"
      size="default"
    >
      <div className={styles.content}>
        <div className={styles.info}>
          <p className={styles.projectInfo}>
            <strong>Project:</strong> {projectName}
          </p>
          <p className={styles.projectInfo}>
            <strong>Target:</strong> {targetDisplay}
          </p>
        </div>

        <div className={styles.disclaimer}>
          <ShieldAlert size={18} className={styles.disclaimerIcon} />
          <div className={styles.disclaimerContent}>
            <p className={styles.disclaimerTitle}>Authorization Required</p>
            <p className={styles.disclaimerText}>
              Reconnaissance actively scans and probes the target system. This operation
              may trigger security alerts and can be considered intrusive.
              By proceeding, you confirm that you <strong>own the target</strong> or have{' '}
              <strong>explicit written permission</strong> from the owner to perform this scan.
              Unauthorized scanning is illegal and may result in criminal penalties.
            </p>
          </div>
        </div>

        {hasExistingData ? (
          <div className={deleteGraph ? styles.warning : styles.retentionNotice}>
            <AlertTriangle size={20} className={styles.warningIcon} />
            <div className={styles.warningContent}>
              <p className={styles.warningTitle}>Existing Data Found</p>
              <p className={styles.warningText}>
                {deleteGraph ? (
                  <>
                    Starting a new reconnaissance will <strong>delete all existing graph data</strong> and
                    replace it with fresh scan results.
                  </>
                ) : (
                  <>
                    Existing graph data will be retained. New reconnaissance results will be added to
                    the current <strong>{existingStats.totalNodes}</strong> graph nodes.
                  </>
                )}
              </p>
              <div className={styles.stats}>
                {Object.entries(existingStats.nodesByType).map(([type, count]) => (
                  <span key={type} className={styles.statBadge}>
                    {type}: {count}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className={styles.ready}>
            <p>No existing data found. Ready to start reconnaissance.</p>
            <p className={styles.readyNote}>
              This will scan <strong>{targetDisplay}</strong> and populate the graph database
              with discovered subdomains, ports, services, and vulnerabilities.
            </p>
          </div>
        )}

        {hasExistingData && (
          <label className={styles.toggleRow}>
            <input
              type="checkbox"
              checked={deleteGraph}
              onChange={(event) => setDeleteGraph(event.target.checked)}
              disabled={isLoading}
            />
            <span>Delete existing graph before starting</span>
          </label>
        )}

        <div className={styles.actions}>
          <button
            className={styles.cancelButton}
            onClick={onClose}
            disabled={isLoading}
          >
            Cancel
          </button>
          <button
            className={styles.confirmButton}
            onClick={handleConfirm}
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                <span>Starting...</span>
              </>
            ) : (
              <>
                <Play size={14} />
                <span>{deleteGraph && hasExistingData ? 'Delete & Start' : 'Start Recon'}</span>
              </>
            )}
          </button>
        </div>
      </div>
    </Modal>
  )
}

export default ReconConfirmModal
