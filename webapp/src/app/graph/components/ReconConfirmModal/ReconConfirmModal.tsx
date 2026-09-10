'use client'

import { useState, useEffect } from 'react'
import { AlertTriangle, ShieldAlert, Play, Loader2, History, Trash2 } from 'lucide-react'
import { Modal } from '@/components/ui'
import type { ScanMode } from '@/hooks/useReconStatus'
import styles from './ReconConfirmModal.module.css'

interface GraphStats {
  totalNodes: number
  nodesByType: Record<string, number>
}

interface ReconConfirmModalProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: (mode: ScanMode) => void
  projectName: string
  targetDomain: string
  ipMode?: boolean
  targetIps?: string[]
  /** Domain batch: the derived group roots, in run order. */
  batchDomains?: string[]
  stats: GraphStats | null
  isLoading: boolean
  /** Label of the version the current graph would be saved as (Scan Timeline). */
  currentVersionLabel?: string | null
}

export function ReconConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  projectName,
  targetDomain,
  ipMode,
  targetIps,
  batchDomains,
  stats,
  isLoading,
  currentVersionLabel,
}: ReconConfirmModalProps) {
  // This dialog guards a destructive action, so it must never show a blank
  // target. A Domain-batch project has no targetDomain: name its groups instead.
  const targetDisplay = ipMode && targetIps?.length
    ? targetIps.slice(0, 5).join(', ') + (targetIps.length > 5 ? ` (+${targetIps.length - 5} more)` : '')
    : batchDomains?.length
      ? `${batchDomains.length} domain${batchDomains.length === 1 ? '' : 's'}: `
        + batchDomains.slice(0, 5).join(', ')
        + (batchDomains.length > 5 ? ` (+${batchDomains.length - 5} more)` : '')
      : targetDomain
  const hasExistingData = stats && stats.totalNodes > 0

  // Scan Timeline (Section 3.2): a second-or-later scan asks what to do with the
  // graph it is about to rebuild. Default is the non-destructive choice.
  const [scanMode, setScanMode] = useState<ScanMode>('new')
  useEffect(() => {
    if (isOpen) setScanMode('new')
  }, [isOpen])

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
          <>
            <div className={styles.warning}>
              <AlertTriangle size={20} className={styles.warningIcon} />
              <div className={styles.warningContent}>
                <p className={styles.warningTitle}>Existing Data Found</p>
                <p className={styles.warningText}>
                  This project has <strong>{stats.totalNodes}</strong> nodes in the graph database.
                  The scan rebuilds the live graph from scratch - choose whether to keep the
                  current graph as a saved version first.
                </p>
                <div className={styles.stats}>
                  {Object.entries(stats.nodesByType).map(([type, count]) => (
                    <span key={type} className={styles.statBadge}>
                      {type}: {count}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className={styles.modeChoice} role="radiogroup" aria-label="What to do with the current graph">
              <label
                className={`${styles.modeOption} ${scanMode === 'new' ? styles.modeOptionActive : ''}`}
              >
                <input
                  type="radio"
                  name="scanMode"
                  value="new"
                  checked={scanMode === 'new'}
                  onChange={() => setScanMode('new')}
                  disabled={isLoading}
                />
                <History size={16} className={styles.modeIcon} />
                <span className={styles.modeText}>
                  <span className={styles.modeTitle}>Create a new version (recommended)</span>
                  <span className={styles.modeDesc}>
                    Save the current graph
                    {currentVersionLabel ? ` as “${currentVersionLabel}”` : ' as a previous version'},
                    then scan. You can view, compare and re-activate it later.
                  </span>
                </span>
              </label>

              <label
                className={`${styles.modeOption} ${scanMode === 'overwrite' ? styles.modeOptionActive : ''}`}
              >
                <input
                  type="radio"
                  name="scanMode"
                  value="overwrite"
                  checked={scanMode === 'overwrite'}
                  onChange={() => setScanMode('overwrite')}
                  disabled={isLoading}
                />
                <Trash2 size={16} className={styles.modeIconDanger} />
                <span className={styles.modeText}>
                  <span className={styles.modeTitle}>Overwrite current version</span>
                  <span className={styles.modeDesc}>
                    Discard the current graph without saving it. This cannot be undone.
                  </span>
                </span>
              </label>
            </div>
          </>
        ) : (
          <div className={styles.ready}>
            <p>No existing data found. Ready to start reconnaissance.</p>
            <p className={styles.readyNote}>
              This will scan <strong>{targetDisplay}</strong> and populate the graph database
              with discovered subdomains, ports, services, and vulnerabilities.
            </p>
          </div>
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
            onClick={() => onConfirm(hasExistingData ? scanMode : 'new')}
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
                <span>
                  {!hasExistingData
                    ? 'Start Recon'
                    : scanMode === 'new'
                      ? 'Save Version & Start'
                      : 'Discard & Start'}
                </span>
              </>
            )}
          </button>
        </div>
      </div>
    </Modal>
  )
}

export default ReconConfirmModal
