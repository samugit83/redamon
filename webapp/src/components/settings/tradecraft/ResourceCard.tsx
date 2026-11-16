'use client'

import { Loader2, Pencil, RotateCw, Square, Trash2 } from 'lucide-react'
import { Toggle } from '@/components/ui'
import { isRunning, jobLabel, relTime, type ResourceView } from '@/lib/tradecraft/client'
import css from './tradecraft.module.css'

export const STALE_TEXT = 'Ingested with older settings'
export const LEGACY_TEXT = 'Ingested before 2.0: refresh for headings, descriptions and search inside pages'

export interface ResourceCardProps {
  resource: ResourceView
  /** A Refresh or a Cancel this card sent and the server has not answered yet. */
  busy?: boolean
  onRefresh: (r: ResourceView) => void
  onCancel: (r: ResourceView) => void
  onEdit: (r: ResourceView) => void
  onDelete: (r: ResourceView) => void
  onToggleEnabled: (r: ResourceView, next: boolean) => void
}

/** One 2.0 resource: its state, its job's stage, and Refresh, which becomes Cancel while a job runs (§4.7). */
export function ResourceCard({ resource: r, busy = false, onRefresh, onCancel, onEdit, onDelete, onToggleEnabled }: ResourceCardProps) {
  const running = isRunning(r.job)
  const report = r.report
  return (
    <div className={`${css.card} ${r.enabled ? '' : css.cardDisabled}`} data-testid={`tc-card-${r.id}`}>
      <div className={css.cardHead}>
        <span className={css.cardName}>{r.name}</span>
        <span className={css.badge}>{r.storageMode === 'stored' ? 'Stored' : 'Live'}</span>
        <span className={css.badge}>{r.forcedType || r.resourceType}</span>
        {r.stale && (
          <span className={`${css.badge} ${css.badgeWarn}`}>
            {STALE_TEXT}
            {!running && (
              <button type="button" className={css.linkButton} onClick={() => onRefresh(r)} disabled={busy}>Refresh</button>
            )}
          </span>
        )}
        {r.mapVersion === 2 && <span className={`${css.badge} ${css.badgeInfo}`}>{LEGACY_TEXT}</span>}
        <div className={css.cardActions}>
          <Toggle checked={r.enabled} onChange={next => onToggleEnabled(r, next)} size="small" aria-label={`Enabled: ${r.name}`} />
          {running ? (
            <button type="button" className="secondaryButton" onClick={() => onCancel(r)} disabled={busy || r.job?.cancelRequested}>
              <Square size={12} /> Cancel
            </button>
          ) : (
            <button type="button" className="secondaryButton" onClick={() => onRefresh(r)} disabled={busy}>
              {busy ? <Loader2 size={12} className={css.spin} /> : <RotateCw size={12} />} Refresh
            </button>
          )}
          <button type="button" className="iconButton" onClick={() => onEdit(r)} aria-label={`Edit ${r.name}`} disabled={running}>
            <Pencil size={14} />
          </button>
          <button type="button" className="iconButton" onClick={() => onDelete(r)} aria-label={`Delete ${r.name}`}>
            <Trash2 size={14} />
          </button>
        </div>
      </div>
      <span className={css.cardUrl}>{r.url}</span>
      {r.job && running && (
        <div className={css.stage} role="status">
          <Loader2 size={12} className={css.spin} /> {jobLabel(r.job)}
        </div>
      )}
      {r.job && (r.job.status === 'failed' || r.job.status === 'cancelled') && (
        <div className={css.failure} role="status">{jobLabel(r.job)}</div>
      )}
      <div className={css.meta}>
        <span>Last refreshed {relTime(r.lastRefreshedAt ?? r.lastVerifiedAt)}</span>
        <span>{r.entryCount} {r.entryCount === 1 ? 'entry' : 'entries'}</span>
        {report && (
          <span data-testid="tc-report">
            {report.visited} visited, {report.kept} kept{report.stopReason ? `, stopped: ${report.stopReason}` : ''}
          </span>
        )}
      </div>
    </div>
  )
}
