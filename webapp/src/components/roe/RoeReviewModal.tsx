'use client'

/**
 * The review of what a Rules of Engagement document would change.
 *
 * The document is a third party's text and the model reading it is not a
 * sanitiser, so its output is a diff a person confirms, all or nothing. Every
 * value is shown whole (a payload hidden past a preview cut is how a "minor"
 * change slips through), refused values are shown with the reason, and what
 * confirming would do beyond the project (schedules paused, scans that refuse
 * it, an authorization needed) is shown BEFORE the confirm rather than after.
 *
 * On a project being created, confirming fills the form. On an existing one it
 * saves at once through the RoE route; a review gone stale is rebuilt against
 * the project as it is now, and confirmed again by itself when nothing it
 * would write has changed.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, CheckCircle, Clock, Info } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { confirmRoe, confirmedChanges, providerOfModel, rediffRoe, type RoeApiError } from './roeClient'
import styles from './RoeReviewModal.module.css'

interface Row {
  key: string
  kind?: 'set' | 'reset' | 'restore'
  before?: unknown
  after: unknown
  meaning: string
  section: string | null
  widening?: string
}

interface KeptRow {
  key: string
  current: unknown
  previousDocument: unknown
  meaning: string
  section: string | null
}

interface Rejection {
  key: string
  value: unknown
  why: string
}

export interface RoeReviewModalProps {
  review: Record<string, unknown>
  /** create: fills the form. existing: saves through the RoE route. */
  target: 'create' | 'existing'
  projectId?: string | null
  file?: File | null
  /** Unsaved form edits, so a replace that would overwrite one says so first. */
  unsavedKeys?: string[]
  onClose: () => void
  /** create only. */
  onApplyToForm?: (review: Record<string, unknown>) => void
  /** existing only: the route's answer after a successful save. */
  onApplied?: (result: Record<string, unknown>) => void
  /** existing only: a rebuilt review replaces the one shown. */
  onReviewChanged?: (review: Record<string, unknown>) => void
}

const PREVIEW_CHARS = 160

function render(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (Array.isArray(value)) return value.length === 0 ? '(empty)' : value.map(v => String(v)).join(', ')
  if (typeof value === 'object') return JSON.stringify(value, null, 1)
  const text = String(value)
  return text === '' ? '(empty)' : text
}

/** A value shown whole, folded behind a toggle only when it is long. Never cut silently. */
function Value({ value, className, label }: { value: unknown; className?: string; label: string }) {
  const [open, setOpen] = useState(false)
  const text = render(value)
  const long = text.length > PREVIEW_CHARS
  return (
    <div className={`${styles.value} ${className ?? ''}`}>
      <span className={styles.valueLabel}>{label}:</span>
      {long && !open ? `${text.slice(0, PREVIEW_CHARS)}…` : text}
      {long && (
        <button type="button" className={styles.expand} onClick={() => setOpen(o => !o)}>
          {open ? 'Show less' : `Show all (${text.length} characters)`}
        </button>
      )}
    </div>
  )
}

function Rows({ rows }: { rows: Row[] }) {
  return (
    <div className={styles.rows}>
      {rows.map(r => (
        <div key={r.key} className={styles.row} data-testid={`roe-row-${r.key}`}>
          <div className={styles.rowKey} title={r.meaning}>
            <span className={styles.keyName}>{r.key}</span>
            {r.section && <span className={styles.section}>{r.section}</span>}
            {r.widening && <span className={styles.badge} title={r.widening}>Widens: {r.widening}</span>}
          </div>
          <Value value={r.before} className={styles.before} label="Now" />
          <Value value={r.after} className={styles.after} label="Becomes" />
        </div>
      ))}
    </div>
  )
}

function Group({ title, rows }: { title: string; rows: Row[] }) {
  if (rows.length === 0) return null
  return (
    <div className={styles.group}>
      <h4 className={styles.groupTitle}>{title} ({rows.length})</h4>
      <Rows rows={rows} />
    </div>
  )
}

export function RoeReviewModal({
  review, target, projectId, file, unsavedKeys = [], onClose, onApplyToForm, onApplied, onReviewChanged,
}: RoeReviewModalProps) {
  const [busySaving, setBusySaving] = useState(false)
  const [error, setError] = useState<RoeApiError | null>(null)
  const [staleNotice, setStaleNotice] = useState(false)
  const [deleted, setDeleted] = useState(false)
  const autoRetried = useRef(false)

  const mode = typeof review.mode === 'string' ? review.mode : 'create'
  const changes = (Array.isArray(review.changes) ? review.changes : []) as Row[]
  const kept = (Array.isArray(review.kept) ? review.kept : []) as KeptRow[]
  const rejected = (Array.isArray(review.rejected) ? review.rejected : []) as Rejection[]
  const ignored = (Array.isArray(review.ignored) ? review.ignored : []) as string[]
  const unknownKeys = (Array.isArray(review.unknownKeys) ? review.unknownKeys : []) as string[]
  const warnings = (Array.isArray(review.warnings) ? review.warnings : []) as string[]
  const previews = (review.previews && typeof review.previews === 'object' ? review.previews : null) as {
    busy?: { busy: boolean; verified?: boolean; what?: string }
    schedulesToPause?: Array<{ id: string; label: string; why: string }> | null
    queuedJobsToReconfirm?: number
    thirdParty?: { ceilingMissing: boolean; needsAuthorization: boolean }
  } | null
  const model = typeof review.modelUsed === 'string' ? review.modelUsed : null
  const currentDocument = review.currentDocument && typeof review.currentDocument === 'object'
    ? review.currentDocument as { name: string; appliedAt?: string | null }
    : null

  const setRows = changes.filter(c => (c.kind ?? 'set') === 'set')
  const resetRows = changes.filter(c => c.kind === 'reset')
  const restoreRows = changes.filter(c => c.kind === 'restore')
  const keptRows: Row[] = kept.map(k => ({ key: k.key, before: k.previousDocument, after: k.current, meaning: k.meaning, section: k.section }))
  const conflicts = unsavedKeys.filter(k => changes.some(c => c.key === k))
  const widening = changes.some(c => c.widening)

  const busy = previews?.busy?.busy ? previews.busy : null
  const thirdParty = previews?.thirdParty
  const blocked = Boolean(busy) || Boolean(thirdParty?.needsAuthorization) || Boolean(thirdParty?.ceilingMissing) || deleted
    || previews?.schedulesToPause === null

  // While running work blocks the confirm, re-check every 10 s and re-enable once it stops.
  useEffect(() => {
    if (target !== 'existing' || !projectId || !(busy || error?.code === 'roe_busy')) return
    const timer = setInterval(async () => {
      const fresh = await rediffRoe(projectId, review)
      if (!fresh.ok) return
      const stillBusy = (fresh.value.previews as { busy?: { busy?: boolean } } | undefined)?.busy?.busy
      if (!stillBusy) {
        setError(null)
        onReviewChanged?.(fresh.value)
      }
    }, 10_000)
    return () => clearInterval(timer)
  }, [target, projectId, busy, error?.code, review, onReviewChanged])

  const confirm = useCallback(async (current: Record<string, unknown>): Promise<void> => {
    if (target === 'create') {
      onApplyToForm?.(current)
      return
    }
    if (!projectId) return
    // Saves `reviewed`; a stale answer may save the rebuilt review once more, from here.
    const save = async (reviewed: Record<string, unknown>): Promise<void> => {
      setBusySaving(true)
      setError(null)
      const result = await confirmRoe({ projectId, review: reviewed, file: file ?? null })
      if (result.ok) {
        setBusySaving(false)
        onApplied?.(result.value)
        return
      }
      const err = result.error
      if (err.code === 'roe_stale') {
        // The project moved while the person was reviewing. Rebuild against it;
        // when what would be written is unchanged, confirm again once by itself.
        const fresh = await rediffRoe(projectId, reviewed)
        if (fresh.ok) {
          const same = JSON.stringify(confirmedChanges(fresh.value)) === JSON.stringify(confirmedChanges(reviewed))
          onReviewChanged?.(fresh.value)
          if (same && !autoRetried.current) {
            autoRetried.current = true
            setBusySaving(false)
            await save(fresh.value)
            return
          }
          setStaleNotice(true)
          setBusySaving(false)
          return
        }
        if (fresh.error.status === 404) setDeleted(true)
        setError(fresh.error)
        setBusySaving(false)
        return
      }
      if (err.status === 404) setDeleted(true)
      setError(err)
      setBusySaving(false)
    }
    await save(current)
  }, [target, projectId, file, onApplyToForm, onApplied, onReviewChanged])

  const title = mode === 'remove' ? 'Review removing the Rules of Engagement' : 'Review what this document would change'
  const confirmLabel = target === 'create'
    ? `Apply ${changes.length} change${changes.length === 1 ? '' : 's'}`
    : mode === 'remove' ? 'Remove RoE and save' : 'Replace RoE and save'

  return (
    <Modal
      isOpen
      onClose={busySaving ? () => {} : onClose}
      title={title}
      size="large"
      closeOnOverlayClick={!busySaving}
      footer={
        <div className={styles.footer}>
          <span className={styles.footerNote}>
            {target === 'create'
              ? 'Applying fills the form; the project is saved when you create it.'
              : 'Confirming saves now. Running scans keep their settings; the next scan uses these.'}
          </span>
          <button type="button" className="secondaryButton" onClick={onClose} disabled={busySaving}>
            {target === 'create' ? 'Discard' : 'Cancel'}
          </button>
          {error && error.status !== 400 && !deleted && error.code !== 'roe_busy' && (
            <button type="button" className="secondaryButton" onClick={() => confirm(review)} disabled={busySaving}>
              Retry
            </button>
          )}
          <button
            type="button"
            className={mode === 'remove' ? styles.danger : styles.primary}
            onClick={() => confirm(review)}
            disabled={busySaving || blocked}
          >
            {busySaving ? 'Saving…' : confirmLabel}
          </button>
        </div>
      }
    >
      <div className={styles.body}>
        <p className={styles.meta}>
          {mode === 'remove'
            ? 'Removing the document undoes what it changed: the engagement record returns to its defaults and every setting the document set goes back to its value from before it, unless someone changed it since.'
            : target === 'create'
              ? 'Nothing has been applied yet. Each value was checked against the same bounds the API enforces.'
              : 'Nothing has been applied yet. The new document replaces the current one: what the old document changed is undone, then the new values apply.'}
        </p>
        {mode !== 'remove' && (
          <p className={styles.meta}>
            {typeof review.documentName === 'string' && <><strong>{review.documentName}</strong>{' · '}</>}
            {typeof review.pages === 'number' && review.pages > 0 && <>{review.pages} page{review.pages === 1 ? '' : 's'}{' · '}</>}
            Read by <code>{model ?? 'the RoE parsing model'}</code>; the document text was sent to <strong>{providerOfModel(model)}</strong>.
          </p>
        )}
        {currentDocument && (
          <p className={styles.meta}>
            Current document: <strong>{currentDocument.name}</strong>
            {currentDocument.appliedAt && `, applied ${new Date(currentDocument.appliedAt).toLocaleString()}`}
            . It is kept in the project&apos;s RoE history.
          </p>
        )}

        {deleted && (
          <div className={styles.noticeDanger} role="alert">
            <div className={styles.noticeTitle}><AlertTriangle size={16} />This project was deleted</div>
            Nothing was applied.
          </div>
        )}
        {staleNotice && !deleted && (
          <div className={styles.noticeInfo} role="status">
            <div className={styles.noticeTitle}><Info size={16} />The project changed while you were reviewing</div>
            The review below was rebuilt against the project as it is now. Check it, then confirm again.
          </div>
        )}
        {error && !deleted && (
          <div className={styles.noticeDanger} role="alert">
            <div className={styles.noticeTitle}><AlertTriangle size={16} />Not applied</div>
            {error.error}
            {error.keys && error.keys.length > 0 && <> (<code>{error.keys.join(', ')}</code>)</>}
            {error.code === 'roe_busy' && <> The review re-checks every few seconds and enables the confirm once the work stops.</>}
          </div>
        )}

        {busy && (
          <div className={styles.noticeDanger} role="status">
            <div className={styles.noticeTitle}><Clock size={16} />Running work keeps the current RoE</div>
            {busy.verified === false
              ? `Running scans could not be checked (${busy.what}). Confirming is disabled until they can.`
              : `Confirming is disabled while ${busy.what}. Stop it from the graph page toolbar or wait for it to finish; this re-checks every few seconds.`}
          </div>
        )}
        {thirdParty?.needsAuthorization && (
          <div className={styles.noticeDanger} role="status">
            <div className={styles.noticeTitle}><AlertTriangle size={16} />This widens a third-party engagement</div>
            Record an authorization for the new document first, with the MCP tool
            {' '}<code>attach_engagement_authorization</code> (documentKind <code>roe_document</code>), then upload it again.
            A document that only tightens the engagement needs none.
          </div>
        )}
        {thirdParty?.ceilingMissing && (
          <div className={styles.noticeDanger} role="status">
            <div className={styles.noticeTitle}><AlertTriangle size={16} />A third-party engagement must keep a rate ceiling</div>
            This would leave it with none, so it cannot be applied.
          </div>
        )}
        {previews?.schedulesToPause === null && (
          <div className={styles.noticeDanger} role="status">
            The scan schedules could not be checked against this RoE, so confirming is disabled. Try again shortly.
          </div>
        )}
        {previews?.schedulesToPause && previews.schedulesToPause.length > 0 && (
          <div className={styles.notice}>
            <div className={styles.noticeTitle}><AlertTriangle size={16} />{previews.schedulesToPause.length} scheduled scan{previews.schedulesToPause.length === 1 ? '' : 's'} will be paused</div>
            <ul className={styles.noticeList}>
              {previews.schedulesToPause.map(s => <li key={s.id}><strong>{s.label}</strong>: {s.why}</li>)}
            </ul>
            Re-enable them in the project&apos;s scan schedules once you have checked them.
          </div>
        )}
        {(previews?.queuedJobsToReconfirm ?? 0) > 0 && (
          <div className={styles.notice}>
            {previews!.queuedJobsToReconfirm} queued scan{previews!.queuedJobsToReconfirm === 1 ? '' : 's'} will wait for you to
            re-confirm it in the scan queue, because the settings it was queued with change.
          </div>
        )}
        {conflicts.length > 0 && (
          <div className={styles.notice} role="status">
            <div className={styles.noticeTitle}><AlertTriangle size={16} />You have unsaved edits this would replace</div>
            <code>{conflicts.join(', ')}</code>. Confirming saves the document&apos;s values instead; your other unsaved edits stay.
          </div>
        )}
        {warnings.map(w => (
          <div key={w} className={styles.notice}>
            <div className={styles.noticeTitle}><AlertTriangle size={16} />Warning</div>
            {w}
          </div>
        ))}
        {widening && (
          <p className={styles.meta}>Rows marked <span className={styles.badge}>Widens</span> loosen the engagement.</p>
        )}

        {changes.length === 0 && kept.length === 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <CheckCircle size={18} />
            <span>
              {target === 'create'
                ? 'The document proposes nothing this project does not already have set.'
                : 'No setting changes. Confirming still records this document as the project’s RoE.'}
            </span>
          </div>
        )}

        <Group title={mode === 'remove' ? 'Set' : 'Set by the new document'} rows={setRows} />
        <Group
          title={mode === 'remove' ? 'Reset to default' : 'Reset to default (the new document is silent on them)'}
          rows={resetRows}
        />
        <Group title="Restored (only the previous document set them)" rows={restoreRows} />
        {keptRows.length > 0 && (
          <div className={styles.group}>
            <h4 className={styles.groupTitle}>Kept: changed after the previous document ({keptRows.length})</h4>
            <p className={styles.meta}>Someone changed these after the previous document applied, so they stay as they are.</p>
            <Rows rows={keptRows} />
          </div>
        )}

        {rejected.length > 0 && (
          <div className={styles.notice}>
            <div className={styles.noticeTitle}><AlertTriangle size={16} />{rejected.length} value{rejected.length === 1 ? '' : 's'} refused</div>
            <ul className={styles.noticeList}>
              {rejected.map(r => (
                <li key={r.key}><code>{r.key}</code>{r.value !== null && r.value !== undefined && <> = <Value value={r.value} label="Value" /></>} — {r.why}</li>
              ))}
            </ul>
          </div>
        )}
        {(ignored.length > 0 || unknownKeys.length > 0) && (
          <p className={styles.meta} style={{ opacity: 0.8 }}>
            Ignored, because no setting a document may write matches them:{' '}
            <code>{[...ignored, ...unknownKeys].join(', ')}</code>. The engagement&apos;s target is among these by
            design: a scope document configures this project, it does not re-point it.
          </p>
        )}
      </div>
    </Modal>
  )
}
