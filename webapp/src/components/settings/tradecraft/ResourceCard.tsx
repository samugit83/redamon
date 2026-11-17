'use client'

import { useState } from 'react'
import { List, Loader2, Pencil, RotateCw, Square, Trash2 } from 'lucide-react'
import { Toggle } from '@/components/ui'
import { isRunning, jobLabel, lastRefreshedOf, relTime, type ResourceView } from '@/lib/tradecraft/client'
import { useEnabledImpactConfirm } from './EnabledImpactAlert'
import { IngestionReport } from './IngestionReport'
import { MapView } from './MapView'
import css from './tradecraft.module.css'

export const STALE_TEXT = 'Ingested with older settings'
export const LEGACY_TEXT = 'Ingested before 2.0: refresh for headings, descriptions and search inside pages'

export interface ResourceCardProps {
  /** The account: the Enabled alert reads its projects. */
  userId: string
  resource: ResourceView
  /** A Refresh or a Cancel this card sent and the server has not answered yet. */
  busy?: boolean
  onRefresh: (r: ResourceView) => void
  onCancel: (r: ResourceView) => void
  onEdit: (r: ResourceView) => void
  onDelete: (r: ResourceView) => void
  onToggleEnabled: (r: ResourceView, next: boolean) => void
}

/**
 * One 2.0 resource: its state, its job's stage, Refresh, which becomes Cancel while a job runs
 * (§4.7), the Map view (§6.10) and the full ingestion report (§3.3).
 */
export function ResourceCard({ userId, resource: r, busy = false, onRefresh, onCancel, onEdit, onDelete, onToggleEnabled }: ResourceCardProps) {
  const [mapOpen, setMapOpen] = useState(false)
  const running = isRunning(r.job)
  const confirmEnabled = useEnabledImpactConfirm(userId)
  const refreshedAt = lastRefreshedOf(r)
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
          <Toggle
            checked={r.enabled} size="small" aria-label={`Enabled: ${r.name}`}
            onChange={async next => { if (await confirmEnabled(r, next)) onToggleEnabled(r, next) }}
          />
          {running ? (
            <button type="button" className="secondaryButton" onClick={() => onCancel(r)} disabled={busy || r.job?.cancelRequested}>
              <Square size={12} /> Cancel
            </button>
          ) : (
            <button type="button" className="secondaryButton" onClick={() => onRefresh(r)} disabled={busy}>
              {busy ? <Loader2 size={12} className={css.spin} /> : <RotateCw size={12} />} Refresh
            </button>
          )}
          <button type="button" className="secondaryButton" onClick={() => setMapOpen(true)} aria-label={`Map of ${r.name}`}>
            <List size={12} /> Map
          </button>
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
        <span>Last refreshed {relTime(refreshedAt)}</span>
        <span>{r.entryCount} {r.entryCount === 1 ? 'entry' : 'entries'}</span>
      </div>
      {report && <IngestionReport report={report} testId="tc-report" />}
      {mapOpen && <MapView userId={userId} resource={r} onClose={() => setMapOpen(false)} />}
    </div>
  )
}
