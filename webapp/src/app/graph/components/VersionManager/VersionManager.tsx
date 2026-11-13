'use client'

import { useState, useCallback } from 'react'
import { Loader2, Pin, PinOff, Trash2, Pencil, Play, Save, Check, X } from 'lucide-react'
import { Modal, useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import type { ReconStatus } from '@/lib/recon-types'
import { readApiError, toApiError, type ApiError } from '@/lib/apiError'
import type { ScanVersionSummary } from '../../hooks/useScanVersions'
import styles from './VersionManager.module.css'
import { useRefusal } from '@/hooks/useRefusal'
import { UpdatedAtCell } from '../RedZoneTables/updatedAt'

interface VersionManagerProps {
  isOpen: boolean
  onClose: () => void
  projectId: string
  versions: ScanVersionSummary[]
  /** Re-fetch the version list after any mutation. */
  onChanged: () => void
  /** Called after a successful activation so the page can reload the live graph. */
  onActivated?: (versionId: string) => void
  /** Currently viewed version (null = the active one). */
  selectedVersionId: string | null
  onSelectVersion: (versionId: string | null) => void
  /** Live recon status, so the active row says whether a scan is writing to it. */
  liveScanStatus?: ReconStatus
}

/** What a running/paused recon means for the row that is the live graph. */
function liveScanBadge(status: ReconStatus | undefined): { text: string; busy: boolean } | null {
  switch (status) {
    case 'starting':
      return { text: 'Starting', busy: true }
    case 'running':
      return { text: 'Running', busy: true }
    case 'pausing':
      return { text: 'Pausing', busy: false }
    case 'paused':
      return { text: 'Paused', busy: false }
    case 'stopping':
      return { text: 'Stopping', busy: false }
    default:
      return null
  }
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}

/**
 * A lost answer or a gateway timeout says nothing about whether the server
 * finished: an activation in particular can still be swapping the graph.
 */
function outcomeUnknown(err: ApiError): boolean {
  return err.status === 0 || err.status === 502 || err.status === 504
}

function formatBytes(n: number): string {
  if (!n) return '-'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

/**
 * Scan Timeline - Version Manager (Section 5 + 4A.5).
 *
 * The one place that distinguishes VIEW (just look at a snapshot) from ACTIVATE
 * (make it the graph the agent and every analytics panel work on). Activate is a
 * destructive-confirm action, and is offered only for versions that carry
 * restorable bytes.
 */
export function VersionManager({
  isOpen,
  onClose,
  projectId,
  versions,
  onChanged,
  onActivated,
  selectedVersionId,
  onSelectVersion,
  liveScanStatus,
}: VersionManagerProps) {
  // Save, activate, rename and pin ask scan:versions; delete scan:versions_delete (route manifest). A
  // read share views versions only (step 4.11): the rest says whose read access it is.
  const versionsRefusal = useRefusal('scan:versions', projectId)?.text ?? null
  const deleteRefusal = useRefusal('scan:versions_delete', projectId)?.text ?? null
  const liveBadge = liveScanBadge(liveScanStatus)
  const { alertError, dangerConfirm } = useAlertModal()
  const toast = useToast()
  const [busyId, setBusyId] = useState<string | null>(null)
  const [savingCurrent, setSavingCurrent] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [draftLabel, setDraftLabel] = useState('')

  const call = useCallback(async (
    path: string,
    init: RequestInit,
    failure: string,
    unknownOutcome?: string,
  ): Promise<Record<string, unknown> | null> => {
    let err: ApiError
    try {
      const res = await fetch(path, {
        headers: { 'Content-Type': 'application/json' },
        ...init,
      })
      if (res.ok) return await res.json().catch(() => ({}))
      err = await readApiError(res, failure)
    } catch (thrown) {
      err = toApiError(thrown, failure)
    }
    if (unknownOutcome && outcomeUnknown(err)) {
      // The list may already show the result; reload it before the person retries.
      onChanged()
      alertError(`${err.message}\n\n${unknownOutcome}`, failure)
    } else {
      alertError(err.message, failure)
    }
    return null
  }, [alertError, onChanged])

  const startRename = (v: ScanVersionSummary) => {
    setEditingId(v.id)
    setDraftLabel(v.label)
  }

  const commitRename = async (v: ScanVersionSummary) => {
    const label = draftLabel.trim()
    setEditingId(null)
    if (!label || label === v.label) return
    setBusyId(v.id)
    try {
      const ok = await call(
        `/api/projects/${projectId}/versions/${v.id}`,
        { method: 'PATCH', body: JSON.stringify({ label }) },
        'Could not rename the version'
      )
      if (ok) onChanged()
    } finally {
      setBusyId(null)
    }
  }

  const togglePin = async (v: ScanVersionSummary) => {
    setBusyId(v.id)
    try {
      const ok = await call(
        `/api/projects/${projectId}/versions/${v.id}`,
        { method: 'PATCH', body: JSON.stringify({ pinned: !v.pinned }) },
        'Could not update the version'
      )
      if (ok) onChanged()
    } finally {
      setBusyId(null)
    }
  }

  const remove = async (v: ScanVersionSummary) => {
    const confirmed = await dangerConfirm(
      `Delete “${v.label}”? Its saved snapshot (${formatBytes(v.snapshotBytes)}) is removed permanently and cannot be recovered.`,
      'Delete version'
    )
    if (!confirmed) return
    setBusyId(v.id)
    try {
      const ok = await call(
        `/api/projects/${projectId}/versions/${v.id}`,
        { method: 'DELETE' },
        'Could not delete the version'
      )
      if (ok) {
        if (selectedVersionId === v.id) onSelectVersion(null)
        toast.info('Version deleted')
        onChanged()
      }
    } finally {
      setBusyId(null)
    }
  }

  const activate = async (v: ScanVersionSummary) => {
    const confirmed = await dangerConfirm(
      `This will save the current graph as a version and load “${v.label}” as the working graph the agent uses. ` +
      'Only the recon graph is swapped - GVM/secret scan output, remediations, reports and captured traffic stay ' +
      'project-level and still reflect the latest scan.',
      'Activate version'
    )
    if (!confirmed) return
    setBusyId(v.id)
    try {
      const ok = await call(
        `/api/projects/${projectId}/versions/${v.id}/activate`,
        { method: 'POST', body: '{}' },
        'Could not activate the version',
        'No answer came back, so the activation may still be running or may already have finished. ' +
          'Check the list, refreshed now, before activating again.',
      )
      if (ok) {
        toast.info(`“${v.label}” is now the active version`)
        onSelectVersion(null)
        onChanged()
        onActivated?.(v.id)
      }
    } finally {
      setBusyId(null)
    }
  }

  const saveCurrent = async () => {
    setSavingCurrent(true)
    try {
      const ok = await call(
        `/api/projects/${projectId}/versions`,
        { method: 'POST', body: '{}' },
        'Could not save the current graph as a version'
      )
      if (ok) {
        toast.info('Current graph saved as a version')
        onChanged()
      }
    } finally {
      setSavingCurrent(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Scan versions"
      size="full"
      className={styles.modal}
      headerActions={<WikiInfoButton target="VersionManager" title="Open the Version Manager wiki page" />}
    >
      <div className={styles.content}>
        <div className={styles.intro}>
          <p>
            Each version is a point-in-time snapshot of this project&apos;s recon graph.
            <strong> View</strong> renders a snapshot read-only; <strong>Activate</strong> makes it the live
            graph the agent, RedZone analytics and partial recon work on.
          </p>
          <button className={styles.saveCurrent} onClick={saveCurrent} disabled={savingCurrent || !!versionsRefusal}
            title={versionsRefusal ?? undefined}>
            {savingCurrent ? <Loader2 size={13} className={styles.spinner} /> : <Save size={13} />}
            <span>Save current graph as a version</span>
          </button>
        </div>

        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>#</th>
                <th>Label</th>
                <th className={styles.num}>Nodes</th>
                <th className={styles.num}>Snapshot</th>
                <th>Created</th>
                <th>State</th>
                <th className={styles.actionsCol}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {versions.map(v => {
                const busy = busyId === v.id
                const viewing = selectedVersionId ? selectedVersionId === v.id : v.isCurrent
                return (
                  <tr key={v.id} className={viewing ? styles.rowViewing : undefined}>
                    <td>v{v.seq}</td>
                    <td className={styles.labelCell}>
                      {editingId === v.id ? (
                        <span className={styles.renameRow}>
                          <input
                            className={styles.renameInput}
                            value={draftLabel}
                            autoFocus
                            maxLength={120}
                            onChange={e => setDraftLabel(e.target.value)}
                            onKeyDown={e => {
                              if (e.key === 'Enter') commitRename(v)
                              if (e.key === 'Escape') setEditingId(null)
                            }}
                          />
                          <button className={styles.iconBtn} title="Save" onClick={() => commitRename(v)}>
                            <Check size={13} />
                          </button>
                          <button className={styles.iconBtn} title="Cancel" onClick={() => setEditingId(null)}>
                            <X size={13} />
                          </button>
                        </span>
                      ) : (
                        <span className={styles.labelStack}>
                          <span className={styles.label}>{v.label}</span>
                          <span className={styles.created}>{formatDate(v.createdAt)}</span>
                        </span>
                      )}
                    </td>
                    <td className={styles.num}>{v.nodeCount?.toLocaleString() ?? '-'}</td>
                    <td className={`${styles.num} ${styles.muted}`}>
                      {v.isCurrent ? 'live' : formatBytes(v.snapshotBytes)}
                    </td>
                    <td><UpdatedAtCell value={v.createdAt} /></td>
                    <td>
                      {v.isCurrent && liveBadge && (
                        <span
                          className={liveBadge.busy ? styles.runningBadge : styles.busyBadge}
                          title={`A recon scan is ${liveBadge.text.toLowerCase()} on this version`}
                        >
                          {liveBadge.busy && <span className={styles.runningDot} />}
                          {liveBadge.text}
                        </span>
                      )}
                      {v.isCurrent && <span className={styles.activeBadge}>Active</span>}
                      {v.pinned && <span className={styles.pinBadge}>Pinned</span>}
                      {!v.isCurrent && !v.activatable && (
                        <span className={styles.warnBadge} title="No stored snapshot - this version cannot be activated">
                          No snapshot
                        </span>
                      )}
                      {typeof v.degradedSources === 'number' && v.degradedSources > 0 && (
                        <span className={styles.warnBadge}
                          title="Some finding sources could not be fully re-checked when this version was scanned">
                          partial — {v.degradedSources} source{v.degradedSources === 1 ? '' : 's'} skipped
                        </span>
                      )}
                    </td>
                    <td className={styles.actionsCol}>
                      <div className={styles.actions}>
                        <button
                          className={styles.actionBtn}
                          onClick={() => onSelectVersion(v.isCurrent ? null : v.id)}
                          disabled={busy || (!v.isCurrent && !v.activatable)}
                          title={!v.isCurrent && !v.activatable ? 'No stored snapshot to view' : 'View this version (read-only)'}
                        >
                          View
                        </button>
                        <button
                          className={styles.actionBtn}
                          onClick={() => activate(v)}
                          disabled={busy || v.isCurrent || !v.activatable || !!versionsRefusal}
                          title={
                            versionsRefusal ? versionsRefusal
                              : v.isCurrent ? 'Already the active version'
                              : !v.activatable ? 'This version has no stored snapshot, so it cannot be activated'
                              : 'Make this the live graph'
                          }
                        >
                          {busy ? <Loader2 size={12} className={styles.spinner} /> : <Play size={12} />}
                          <span>Activate</span>
                        </button>
                        <button
                          className={styles.actionBtn}
                          onClick={() => startRename(v)}
                          disabled={busy || !!versionsRefusal}
                          title={versionsRefusal ?? 'Rename'}
                        >
                          <Pencil size={12} />
                          <span>Rename</span>
                        </button>
                        <button
                          className={styles.actionBtn}
                          onClick={() => togglePin(v)}
                          disabled={busy || !!versionsRefusal}
                          title={versionsRefusal ? versionsRefusal : v.pinned ? 'Unpin (allow automatic cleanup)' : 'Pin (protect from automatic cleanup)'}
                        >
                          {v.pinned ? <PinOff size={12} /> : <Pin size={12} />}
                          <span>{v.pinned ? 'Unpin' : 'Pin'}</span>
                        </button>
                        <button
                          className={`${styles.actionBtn} ${styles.dangerBtn}`}
                          onClick={() => remove(v)}
                          disabled={busy || v.isCurrent || v.pinned || !!deleteRefusal}
                          title={
                            deleteRefusal ? deleteRefusal
                              : v.isCurrent ? 'The current version is the live graph and cannot be deleted'
                              : v.pinned ? 'Unpin it first'
                              : 'Delete this version and its snapshot'
                          }
                        >
                          <Trash2 size={12} />
                          <span>Delete</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </Modal>
  )
}

export default VersionManager
