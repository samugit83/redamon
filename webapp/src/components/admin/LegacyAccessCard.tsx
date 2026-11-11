'use client'

import { useCallback, useEffect, useState } from 'react'
import { useOptionalAlertModal } from '@/components/ui'
import { ApiError, fetchJson, toApiError } from '@/lib/apiError'
import {
  LEGACY_GRANT_LABELS, LEGACY_GRANTS_CHANGED_EVENT, LEGACY_REVIEW_ANCHOR, plural,
  type LegacyDecisionAnswer, type LegacyGrant, type LegacyGrantsAnswer, type LegacyHolderView,
} from './updateNotes'
import styles from './AdminNotices.module.css'

type View =
  | { kind: 'loading' }
  | { kind: 'hidden' }
  | { kind: 'error'; message: string }
  | { kind: 'loaded'; holders: LegacyHolderView[]; pending: number }

type Decision =
  | { action: 'keep' | 'remove'; userId: string; grant: LegacyGrant }
  | { action: 'keep_all' | 'remove_all' }

const ENDPOINT = '/api/admin/legacy-grants'
const NOT_GIVEN_BACK = 'A removed grant cannot be given back in this version.'

/**
 * The review of the shared tools members kept at the upgrade (HD-29, the feature document's
 * §14.7 card), on the Users page. It never blocks: nothing renders while it loads, for a
 * refusal or when nobody holds a grant, and "Decide later" folds it to one line. A removal
 * is confirmed first, since nothing can add a grant again.
 */
export function LegacyAccessCard() {
  const alerts = useOptionalAlertModal()
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [busy, setBusy] = useState(false)
  const [later, setLater] = useState(false)

  const load = useCallback(async () => {
    try {
      const answer = await fetchJson<LegacyGrantsAnswer>(ENDPOINT, { cache: 'no-store' }, 'Could not load the legacy access review')
      const holders = Array.isArray(answer.holders) ? answer.holders.filter(h => h.grants.length > 0) : []
      setView(holders.length === 0 ? { kind: 'hidden' } : { kind: 'loaded', holders, pending: answer.pending ?? 0 })
    } catch (err) {
      const e = toApiError(err, 'Could not load the legacy access review')
      setView(e instanceof ApiError && e.status === 403 ? { kind: 'hidden' } : { kind: 'error', message: e.message })
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function decide(decision: Decision, confirm?: { title: string; message: string; label: string }) {
    // Outside the app shell there is no dialog to ask with: a removal is then not made.
    if (confirm && !(await alerts?.dangerConfirm(confirm.message, confirm.title, { confirmLabel: confirm.label }))) return
    setBusy(true)
    try {
      const answer = await fetchJson<LegacyDecisionAnswer>(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(decision),
      }, 'Could not save the decision')
      const unclosed = answer.terminal?.error ?? (answer.terminals?.failed ? `${answer.terminals.failed} not confirmed` : null)
      if (unclosed) {
        void alerts?.alertWarning(
          `The grant was removed, but the agent did not confirm that the open Kali terminal was closed (${unclosed}). `
          + 'No new terminal can be opened with it.',
          'Terminal close not confirmed',
        )
      }
    } catch (err) {
      void alerts?.alertError(toApiError(err, 'Could not save the decision').message, 'Legacy access')
    } finally {
      window.dispatchEvent(new Event(LEGACY_GRANTS_CHANGED_EVENT))
      await load()
      setBusy(false)
    }
  }

  if (view.kind === 'loading' || view.kind === 'hidden') return null
  if (view.kind === 'error') {
    return (
      <p role="status" className={styles.error}>
        Could not load the legacy access review: {view.message}{' '}
        <button type="button" className="textButton" onClick={() => { setView({ kind: 'loading' }); void load() }}>Retry</button>
      </p>
    )
  }

  const { holders, pending } = view
  const grantCount = holders.reduce((n, h) => n + h.grants.length, 0)

  const removeOne = (h: LegacyHolderView, grant: LegacyGrant) => decide({ action: 'remove', userId: h.id, grant }, {
    title: 'Remove legacy access',
    label: 'Remove',
    message: `Remove ${LEGACY_GRANT_LABELS[grant]} from ${h.name}? ${h.name} loses it at once`
      + `${grant === 'kali_terminal' ? ', and an open Kali terminal is closed' : ''}. ${NOT_GIVEN_BACK}`,
  })

  const table = (
    <table className={styles.holders}>
      <thead>
        <tr><th scope="col">Account</th><th scope="col">Kept from the previous version</th></tr>
      </thead>
      <tbody>
        {holders.map(h => (
          <tr key={h.id}>
            <td>{h.name}<span className={styles.email}>{h.email}</span></td>
            <td>
              {h.grants.map(({ grant, state }) => (
                <div key={grant} className={styles.grant}>
                  <span className={styles.grantLabel}>{LEGACY_GRANT_LABELS[grant]}</span>
                  {state === 'kept' ? (
                    <span className={styles.kept}>Kept</span>
                  ) : (
                    <button
                      type="button" className={styles.small} disabled={busy}
                      aria-label={`Keep ${LEGACY_GRANT_LABELS[grant]} for ${h.name}`}
                      onClick={() => decide({ action: 'keep', userId: h.id, grant })}
                    >Keep</button>
                  )}
                  <button
                    type="button" className={`${styles.small} ${styles.danger}`} disabled={busy}
                    aria-label={`Remove ${LEGACY_GRANT_LABELS[grant]} from ${h.name}`}
                    onClick={() => removeOne(h, grant)}
                  >Remove</button>
                </div>
              ))}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  if (pending === 0) {
    return (
      <details id={LEGACY_REVIEW_ANCHOR} className={styles.card} aria-busy={busy}>
        <summary className={styles.summary}>
          {plural(holders.length, 'person keeps', 'people keep')} access to shared tools from the previous version.
        </summary>
        <p className={styles.cardText} style={{ marginTop: 'var(--space-3)' }}>
          You chose to keep these grants. You can still remove one. {NOT_GIVEN_BACK}
        </p>
        {table}
      </details>
    )
  }

  if (later) {
    return (
      <div id={LEGACY_REVIEW_ANCHOR} className={`${styles.card} ${styles.cardWarning}`}>
        {plural(pending, 'legacy grant waits', 'legacy grants wait')} for your review.{' '}
        <button type="button" className="textButton" onClick={() => setLater(false)}>Review now</button>
      </div>
    )
  }

  const title = `${plural(holders.length, 'person', 'people')} kept access to shared tools from the previous version.`
  return (
    <section
      id={LEGACY_REVIEW_ANCHOR} aria-labelledby="legacy-access-title" aria-busy={busy}
      className={`${styles.card} ${styles.cardWarning}`}
    >
      <h2 id="legacy-access-title" className={styles.cardTitle}>{title}</h2>
      <p className={styles.cardText}>
        These tools let them reach other users&apos; files and shells. Remove them on a server shared by people who
        should not see each other&apos;s work. Accounts created from now on get none.
      </p>
      {table}
      <div className={styles.actions}>
        <button
          type="button" className="secondaryButton" disabled={busy}
          onClick={() => decide({ action: 'remove_all' }, {
            title: 'Remove all legacy access',
            label: 'Remove all',
            message: `Remove all ${grantCount} legacy grants of ${plural(holders.length, 'person', 'people')}? `
              + `They lose these tools at once, and open Kali terminals are closed. ${NOT_GIVEN_BACK}`,
          })}
        >Remove all (recommended for shared servers)</button>
        <button type="button" className="secondaryButton" disabled={busy} onClick={() => decide({ action: 'keep_all' })}>
          Keep all
        </button>
        <button type="button" className="textButton" disabled={busy} onClick={() => setLater(true)}>Decide later</button>
      </div>
    </section>
  )
}
