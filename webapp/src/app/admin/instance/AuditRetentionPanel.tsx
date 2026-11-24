'use client'

import { useMemo, useState, type FormEvent } from 'react'
import { useToast } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import type { InstanceSettingsView } from './instanceView'
import { putInstanceSettings } from './instanceSettingsClient'
import { FieldRow, Panel, RootOnlyNote, Rows, ValueRow } from './Panel'
import styles from './instance.module.css'

/** lib/authz/auditRetention.ts AUDIT_RETENTION_MAX_DAYS; that module reads the database (instanceView.test.ts pins the copy). */
export const RETENTION_MAX_DAYS = 36_500

export interface RetentionView {
  /** The retention in force; null keeps every row. */
  days: number | null
  pending: { days: number | null; requestedAt: string; effectiveAt: string } | null
  minDays: number
  delayDays: number
}

/** The retention the settings carry, or null (switch off, or not an administrator). */
export function retentionOf(settings: InstanceSettingsView | null): RetentionView | null {
  const raw = settings?.auditRetention as Partial<RetentionView> | undefined
  if (!raw || typeof raw !== 'object' || typeof raw.minDays !== 'number' || typeof raw.delayDays !== 'number') return null
  return {
    days: typeof raw.days === 'number' ? raw.days : null,
    pending: raw.pending && typeof raw.pending === 'object' ? raw.pending : null,
    minDays: raw.minDays,
    delayDays: raw.delayDays,
  }
}

export const keptText = (days: number | null) => (days === null ? 'Kept forever' : `Deleted after ${days} days`)
const day = (iso: string) => new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' })

/** The draft's problem, or null: whole days from the floor to the bound. */
export function retentionProblem(text: string, minDays: number): string | null {
  const v = text.trim()
  const n = Number(v)
  return /^\d+$/.test(v) && n >= minDays && n <= RETENTION_MAX_DAYS
    ? null
    : `A whole number of days from ${minDays} (the shortest retention allowed) to ${RETENTION_MAX_DAYS}.`
}

const SAVE_FAILED = 'The audit retention was not changed'

/**
 * How long the audit log keeps its rows (step 6.6, AU-04, OQ-40): every administrator reads it, the
 * confirmed Root changes it with its password. A change never applies at once: it waits its delay (7
 * days), shown with its date, and Root may cancel it meanwhile (by asking for the value in force). The
 * marker rows the code reads back and the act-as and Fireteam tables are always kept.
 */
export function AuditRetentionPanel({ settings, unconfirmedRoot, onSaved }: {
  settings: InstanceSettingsView
  unconfirmedRoot: boolean
  onSaved: (settings: InstanceSettingsView) => void
}) {
  const toast = useToast()
  const retention = useMemo(() => retentionOf(settings), [settings])
  const canEdit = settings.canManageAuditRetention === true
  const [forever, setForever] = useState(retention?.days === null)
  const [daysText, setDaysText] = useState(retention?.days === null ? '' : String(retention?.days ?? ''))
  const [asking, setAsking] = useState<null | { days: number | null; cancel: boolean }>(null)
  // New settings (a save, a reload) start the draft again from what is in force.
  const [draftBase, setDraftBase] = useState(retention)
  if (draftBase !== retention) {
    setDraftBase(retention)
    setForever(retention?.days === null)
    setDaysText(retention?.days == null ? '' : String(retention.days))
  }
  if (!retention) return null

  const lead = `How long the audit log keeps its rows. A change applies ${retention.delayDays} days after Root asks for it; the rows the code reads back (upgrade markers, legacy-grant decisions) and the act-as and Fireteam records are always kept.`
  const pending = retention.pending && (
    <div className={styles.callout}>
      <span role="status">
        Change waiting: {keptText(retention.pending.days).toLowerCase()} from {day(retention.pending.effectiveAt)} (asked {day(retention.pending.requestedAt)}).
      </span>
      {canEdit && (
        <button type="button" className="secondaryButton" onClick={() => setAsking({ days: retention.days, cancel: true })}>
          Cancel the waiting change
        </button>
      )}
    </div>
  )

  if (!canEdit) {
    return (
      <Panel id="retention" title="Audit retention" lead={lead}>
        <dl className={styles.readList}>
          <dt>Audit rows</dt><dd>{keptText(retention.days)}</dd>
        </dl>
        {pending}
        <RootOnlyNote unconfirmedRoot={unconfirmedRoot} />
      </Panel>
    )
  }

  const problem = forever ? null : retentionProblem(daysText, retention.minDays)
  const asked = forever ? null : Number(daysText.trim())
  const target = retention.pending ? retention.pending.days : retention.days
  const dirty = !problem && asked !== target
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (dirty) setAsking({ days: asked, cancel: false })
  }

  return (
    <Panel id="retention" title="Audit retention" lead={lead}>
      {pending}
      <form onSubmit={submit} noValidate className={styles.page}>
        <Rows>
          <ValueRow label="In force now">{keptText(retention.days)}</ValueRow>
          <ValueRow label="Keep audit rows" labelId="retention-mode-label" hint="What the next change asks for.">
            <fieldset className={styles.choice} aria-labelledby="retention-mode-label">
              <label className={styles.choiceOption}>
                <input type="radio" className="radio" name="retention-mode" checked={forever} onChange={() => setForever(true)} /> Forever
              </label>
              <label className={styles.choiceOption}>
                <input type="radio" className="radio" name="retention-mode" checked={!forever} onChange={() => setForever(false)} /> For a number of days
              </label>
            </fieldset>
          </ValueRow>
          {!forever && (
            <FieldRow
              id="retention-days"
              label="Days to keep audit rows"
              hint={`At least ${retention.minDays} days. Once the change applies, older rows are deleted by the background maintenance.`}
              error={problem}
            >
              <input
                id="retention-days"
                className="textInput"
                inputMode="numeric"
                value={daysText}
                aria-invalid={problem ? true : undefined}
                aria-describedby="retention-days-hint"
                onChange={(e) => setDaysText(e.target.value)}
              />
            </FieldRow>
          )}
        </Rows>
        <div className={styles.actions}>
          <button type="submit" className="primaryButton" disabled={!dirty}>Ask for this retention</button>
          <span className={styles.hint}>Asking needs your password; the change applies {retention.delayDays} days later.</span>
        </div>
      </form>
      <StepUpModal
        isOpen={asking !== null}
        title={asking?.cancel ? 'Cancel the waiting change' : 'Change the audit retention'}
        message={asking?.cancel
          ? `The audit retention stays ${keptText(retention.days).toLowerCase()}. Enter your password to confirm.`
          : `Audit rows will be ${keptText(asking?.days ?? null).toLowerCase()} from ${retention.delayDays} days after now; until then nothing changes and you can cancel. Enter your password to confirm.`}
        confirmLabel={asking?.cancel ? 'Cancel the change' : 'Ask for this retention'}
        onConfirm={async (password) => {
          const answer = await putInstanceSettings({ auditRetentionDays: asking!.days, stepUpPassword: password }, SAVE_FAILED)
          onSaved(answer)
          toast.success(asking!.cancel ? 'The waiting change was cancelled' : `The new retention applies in ${retention.delayDays} days`)
        }}
        onClose={() => setAsking(null)}
      />
    </Panel>
  )
}
