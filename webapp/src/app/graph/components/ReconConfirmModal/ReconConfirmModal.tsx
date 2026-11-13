'use client'

import { useState, useEffect } from 'react'
import { AlertTriangle, ShieldAlert, Play, Loader2, History, Trash2 } from 'lucide-react'
import { Modal } from '@/components/ui'
import type { ScanMode } from '@/hooks/useReconStatus'
import { type ScopeGroup, groupLabel, ipHostnameModeOf } from '@/lib/scopeGroups'
import { IP_HOSTNAME_SECTION_LABEL, ipHostnameModeLabel } from '@/lib/ipHostnameModeLabels'
import { useOptionalProject } from '@/providers/ProjectProvider'
import { useRefusal } from '@/hooks/useRefusal'
import { RefusalNotice } from '@/components/auth/ForbiddenNotice'
import styles from './ReconConfirmModal.module.css'

/** What the dialog says about an IP project's hostname policy. */
export interface ConfirmHostnamePolicy {
  ipHostnameMode?: string | null
  ipHostnameInclude?: readonly string[] | null
  ipHostnameExclude?: readonly string[] | null
}

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
  /** Domain batch: the derived scope groups, in run order. */
  batchGroups?: ScopeGroup[]
  stats: GraphStats | null
  isLoading: boolean
  /** Label of the version the current graph would be saved as (Scan Timeline). */
  currentVersionLabel?: string | null
  /** IP mode: the saved hostname policy; read from the current project when not passed. */
  hostnamePolicy?: ConfirmHostnamePolicy
}

export function ReconConfirmModal({
  isOpen,
  onClose,
  onConfirm,
  projectName,
  targetDomain,
  ipMode,
  targetIps,
  batchGroups,
  stats,
  isLoading,
  currentVersionLabel,
  hostnamePolicy,
}: ReconConfirmModalProps) {
  // The graph page opens this dialog for its current project, whose summary
  // carries the saved policy; absent (an older read) says nothing rather than
  // guessing "IP only".
  const contextProject = useOptionalProject()?.currentProject
  const policy = hostnamePolicy ?? contextProject ?? undefined
  const hostnameMode = ipMode && typeof policy?.ipHostnameMode === 'string'
    ? ipHostnameModeOf(policy.ipHostnameMode)
    : null
  // This dialog guards a destructive action, so it must never show a blank
  // target. A Domain-batch project has no targetDomain: name its groups instead.
  // An enumerated group discovers hosts this list never names, so the group
  // count alone understates the run by orders of magnitude; this is the last
  // screen before it starts.
  const enumerated = (batchGroups ?? []).filter(g => g.mode === 'enumerate').length
  const targetDisplay = ipMode && targetIps?.length
    ? targetIps.slice(0, 5).join(', ') + (targetIps.length > 5 ? ` (+${targetIps.length - 5} more)` : '')
    : batchGroups?.length
      ? `${batchGroups.length} scope group${batchGroups.length === 1 ? '' : 's'}: `
        + batchGroups.slice(0, 5).map(groupLabel).join('; ')
        + (batchGroups.length > 5 ? ` (+${batchGroups.length - 5} more)` : '')
        + (enumerated > 0
            ? ` — ${enumerated} enumerated group${enumerated === 1 ? '' : 's'} (may take hours)`
            : '')
      : targetDomain
  const hasExistingData = stats && stats.totalNodes > 0

  // Scan Timeline (Section 3.2): a second-or-later scan asks what to do with the
  // graph it is about to rebuild. Default is the non-destructive choice.
  const [scanMode, setScanMode] = useState<ScanMode>('new')
  useEffect(() => {
    if (isOpen) setScanMode('new')
  }, [isOpen])
  // The start route asks recon:overwrite on top of recon:scan for this mode (route manifest).
  const overwriteRefusal = useRefusal('recon:overwrite')
  const overwriteRefused = overwriteRefusal !== null
  useEffect(() => {
    if (overwriteRefused) setScanMode('new')
  }, [overwriteRefused])

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
          {hostnameMode && (
            <p className={styles.projectInfo} data-testid="recon-confirm-hostname-mode">
              <strong>{IP_HOSTNAME_SECTION_LABEL}:</strong> {ipHostnameModeLabel(hostnameMode)}
              {hostnameMode === 'record_filter' && (
                ` (include ${(policy?.ipHostnameInclude ?? []).length}, exclude ${(policy?.ipHostnameExclude ?? []).length})`
              )}
            </p>
          )}
        </div>

        {hostnameMode === 'scan_all' && (
          <div className={styles.disclaimer} role="note" data-testid="recon-confirm-scan-all">
            <ShieldAlert size={18} className={styles.disclaimerIcon} />
            <div className={styles.disclaimerContent}>
              <p className={styles.disclaimerTitle}>Every hostname found on these IPs will be scanned</p>
              <p className={styles.disclaimerText}>
                Including sites you may not own (shared hosting). CDN edge addresses are always
                skipped. Use this only for servers that are entirely yours.
              </p>
            </div>
          </div>
        )}

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
                title={overwriteRefusal?.text}
              >
                <input
                  type="radio"
                  name="scanMode"
                  value="overwrite"
                  checked={scanMode === 'overwrite'}
                  onChange={() => { if (!overwriteRefused) setScanMode('overwrite') }}
                  disabled={isLoading || overwriteRefused}
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
            {overwriteRefusal && <RefusalNotice refusal={overwriteRefusal} />}
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
