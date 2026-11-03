'use client'

import {
  File as FileIcon,
  Folder as FolderIcon,
  FileArchive as ArchiveIcon,
  Link2 as LinkIcon,
  X,
  XCircle,
} from 'lucide-react'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'
import { isGithubFamilyHost } from '@/lib/workspaceImport/githubHosts'
import { isActive, type Transfer, type TransferKind } from './useTransfers'
import { formatBytes, phaseLabel, stopReasonLabel } from './transferMessages'
import styles from './FileSystemDrawer.module.css'

export interface TransfersPanelProps {
  transfers: readonly Transfer[]
  onCancel: (t: Transfer) => void
  onDismiss: (t: Transfer) => void
  /** Called when the user clicks "Saved as …" on a finished transfer. */
  onOpen: (t: Transfer) => void
}

function KindIcon({ kind }: { kind: TransferKind }) {
  if (kind === 'folder') return <FolderIcon size={12} />
  if (kind === 'archive') return <ArchiveIcon size={12} />
  if (kind === 'import') return <LinkIcon size={12} />
  return <FileIcon size={12} />
}

// The GitHub failures a token can fix: a private repository, the hourly limit, a refused token.
const TOKEN_FAILURES = new Set(['not_found', 'rate_limited', 'auth_failed'])

function needsGithubToken(t: Transfer): boolean {
  if (t.kind !== 'import' || !t.errorCode || !TOKEN_FAILURES.has(t.errorCode)) return false
  return isGithubFamilyHost(t.sourceHost) || (t.sourceKind ?? '').startsWith('github-')
}

function stateLabel(t: Transfer): string {
  if (t.waiting) return 'Waiting for the server…'
  if (t.status === 'queued') return 'Queued'
  if (t.status === 'uploading') return 'Uploading'
  return phaseLabel(t.phase)
}

/** Fraction done (null when unknown) and the numbers beside the bar. */
function progressOf(t: Transfer): { fraction: number | null; detail: string } {
  if (t.status !== 'processing') {
    const fraction = t.totalBytes > 0 ? t.sentBytes / t.totalBytes : null
    return { fraction, detail: `${formatBytes(t.sentBytes)} / ${formatBytes(t.totalBytes)}` }
  }
  const parts: string[] = []
  if (typeof t.pages === 'number') {
    // A crawl has no known total: counts only.
    parts.push(`${t.pages} page${t.pages === 1 ? '' : 's'}`, `${t.assets ?? 0} asset${t.assets === 1 ? '' : 's'}`)
    if (typeof t.bytes === 'number') parts.push(formatBytes(t.bytes))
    return { fraction: null, detail: parts.join(' · ') }
  }
  if (typeof t.files === 'number') parts.push(`${t.files} file${t.files === 1 ? '' : 's'}`)
  if (typeof t.bytes === 'number') {
    parts.push(t.jobTotalBytes ? `${formatBytes(t.bytes)} / ${formatBytes(t.jobTotalBytes)}` : formatBytes(t.bytes))
  }
  const fraction = typeof t.bytes === 'number' && t.jobTotalBytes ? t.bytes / t.jobTotalBytes : null
  return { fraction, detail: parts.join(' · ') }
}

function TransferRow({ t, onCancel, onDismiss, onOpen }: { t: Transfer } & Omit<TransfersPanelProps, 'transfers'>) {
  const active = isActive(t.status)
  const { fraction, detail } = active ? progressOf(t) : { fraction: null, detail: '' }
  const percent = fraction === null ? null : Math.round(Math.min(Math.max(fraction, 0), 1) * 100)

  return (
    <li className={styles.transfer}>
      <div className={styles.transferHead}>
        <KindIcon kind={t.kind} />
        <span className={styles.transferName} title={t.name}>{t.name}</span>
        {active && <span className={styles.transferState}>{stateLabel(t)}</span>}
        {active ? (
          <button
            className={`${styles.actionBtn} ${styles.actionBtnDanger}`}
            onClick={() => onCancel(t)}
            title="Cancel transfer"
            aria-label={`Cancel ${t.name}`}
          >
            <XCircle size={12} />
          </button>
        ) : (
          <button
            className={styles.actionBtn}
            onClick={() => onDismiss(t)}
            title="Dismiss"
            aria-label={`Dismiss ${t.name}`}
          >
            <X size={12} />
          </button>
        )}
      </div>

      {active && (
        <div className={styles.transferProgress}>
          <div
            className={styles.transferBar}
            role="progressbar"
            aria-label={`${t.name}: ${stateLabel(t)}`}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent ?? undefined}
          >
            <div
              className={`${styles.transferBarFill} ${percent === null ? styles.transferBarBusy : ''}`}
              style={{ width: `${percent ?? 100}%` }}
            />
          </div>
          {detail && <span className={styles.transferDetail}>{detail}</span>}
        </div>
      )}

      {t.status === 'done' && t.savedPath && (
        <button className={styles.transferLink} onClick={() => onOpen(t)} title={t.savedPath}>
          Saved as <code>{t.savedPath}</code>
        </button>
      )}
      {t.status === 'done' && stopReasonLabel(t.stoppedBecause) && (
        <div className={styles.transferNote}>{stopReasonLabel(t.stoppedBecause)}</div>
      )}
      {t.status === 'failed' && (
        <div className={styles.transferError} role="alert">
          {t.error}
          {needsGithubToken(t) && (
            <>
              {' '}
              {/* A new tab: leaving the graph page would stop following the other transfers. */}
              <a className={styles.transferKeysLink} href={SETTINGS_KEYS_HREF} target="_blank" rel="noopener noreferrer">
                Open API Keys
              </a>
            </>
          )}
        </div>
      )}
      {t.status === 'cancelled' && (
        <div className={styles.transferNote}>{t.cancelReason ? `Cancelled: ${t.cancelReason}` : 'Cancelled'}</div>
      )}
    </li>
  )
}

export function TransfersPanel({ transfers, onCancel, onDismiss, onOpen }: TransfersPanelProps) {
  if (transfers.length === 0) return null
  return (
    <ul className={styles.transferList} aria-label="Transfers">
      {transfers.map((t) => (
        <TransferRow key={t.id} t={t} onCancel={onCancel} onDismiss={onDismiss} onOpen={onOpen} />
      ))}
    </ul>
  )
}
