'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { useOptionalAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { fetchJson, toApiError } from '@/lib/apiError'
import type { OldOwnerRole, TransferView } from '@/lib/authz/ownershipTransfer'
import type { ShareView } from '@/lib/authz/projectShares'
import { FINDING_IDS_NOTE, OWN_ROLE_TEXT, PROJECT_TRANSFER_CHANGED_EVENT, personName, untilDate } from './transferText'
import styles from '@/components/sharing/ShareDialog.module.css'

interface TransferSectionProps {
  project: { id: string; name: string }
  /** The project's shares as the dialog listed them; null while loading or unavailable. */
  shares: ShareView[] | null
  /** Acting as someone: shown, never changed (the routes refuse it). */
  readOnly: boolean
}

type State =
  | { kind: 'loading' }
  | { kind: 'hidden' }
  | { kind: 'ready'; offer: TransferView | null }
  | { kind: 'error'; message: string }

const JSON_HEADERS = { 'Content-Type': 'application/json' }

/** A share the project can be given to: an active account whose share has not ended. */
const eligible = (s: ShareView) => !s.expired && (s.user.status === null || s.user.status === 'active')

/**
 * The share dialog's "Transfer ownership" section (step 5.12; SH-15), for the owner while write sharing
 * is in force (the dialog renders it then; GET .../transfer answers `role: 'owner'` to the owner only,
 * and the section hides itself for anyone else). The owner picks one of the collaborators, says whether
 * they stay as a co-owner or leave, and confirms with their password; the collaborator then accepts or
 * declines from their banner. An open offer is shown with its end date and can be cancelled.
 */
export function TransferSection({ project, shares, readOnly }: TransferSectionProps) {
  const alerts = useOptionalAlertModal()
  const ids = { title: useId(), to: useId(), role: useId() }
  const base = `/api/projects/${encodeURIComponent(project.id)}/transfer`
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [toUserId, setToUserId] = useState('')
  const [role, setRole] = useState<OldOwnerRole>('co-owner')
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const body = await fetchJson<{ role: string; offer: TransferView | null }>(base, undefined, 'Could not read the ownership transfer')
      setState(body.role === 'owner' ? { kind: 'ready', offer: body.offer } : { kind: 'hidden' })
    } catch (err) {
      const apiError = toApiError(err, 'Could not read the ownership transfer')
      setState(apiError.status === 404 ? { kind: 'hidden' } : { kind: 'error', message: apiError.message })
    }
  }, [base])

  useEffect(() => {
    void load()
    const reload = () => void load()
    window.addEventListener(PROJECT_TRANSFER_CHANGED_EVENT, reload)
    return () => window.removeEventListener(PROJECT_TRANSFER_CHANGED_EVENT, reload)
  }, [load])

  if (state.kind === 'hidden') return null
  const candidates = (shares ?? []).filter(eligible)
  const chosen = candidates.find((s) => s.user.id === toUserId) ?? null
  const chosenName = chosen ? personName({ id: chosen.user.id, name: chosen.user.name, email: chosen.user.email }) : ''

  async function cancel(offer: TransferView) {
    const title = 'Cancel the transfer'
    if (!(await alerts?.confirm(`Cancel the offer of "${project.name}" to ${personName(offer.to)}? You stay its owner.`, title, { confirmLabel: 'Cancel the offer' }))) return
    setBusy(true)
    try {
      await fetchJson(`${base}/cancel`, { method: 'POST', headers: JSON_HEADERS, body: '{}' }, 'Could not cancel the transfer')
    } catch (err) {
      void alerts?.alertError(toApiError(err, 'Could not cancel the transfer').message, title)
    } finally {
      setBusy(false)
      window.dispatchEvent(new Event(PROJECT_TRANSFER_CHANGED_EVENT))
    }
  }

  return (
    <section className={styles.section} aria-labelledby={ids.title}>
      <h3 id={ids.title} className={styles.sectionTitle}>Transfer ownership</h3>
      {state.kind === 'loading' ? (
        <p className={styles.hint} role="status">Loading the transfer state...</p>
      ) : state.kind === 'error' ? (
        <div className={styles.error} role="alert">
          <span>{state.message}</span>
          <button type="button" className={styles.linkButton} onClick={() => { setState({ kind: 'loading' }); void load() }}>Retry</button>
        </div>
      ) : state.offer ? (
        <div className={styles.callout} role="status" aria-label="Ownership transfer offered">
          <p>
            {`Offered to ${personName(state.offer.to)} until ${untilDate(state.offer.expiresAt)}: the project moves when they accept; you then ${state.offer.oldOwnerRole === 'co-owner' ? 'stay on as a co-owner' : 'leave the project'}.`}
            {state.offer.status === 'failed' && ` The last attempt did not complete (${state.offer.error ?? 'failed'}); they can accept again.`}
            {state.offer.status === 'in_progress' && ' The transfer is in progress.'}
          </p>
          {!readOnly && state.offer.status !== 'in_progress' && (
            <button type="button" className={styles.linkButton} disabled={busy} onClick={() => void cancel(state.offer!)}>Cancel the offer</button>
          )}
        </div>
      ) : candidates.length === 0 ? (
        <p className={styles.hint}>Share the project with a person first: it can only go to one of its active collaborators.</p>
      ) : (
        <div className={styles.form}>
          <p className={styles.hint}>
            Give the project to one of its collaborators. They accept or decline from their banner within 7 days; until then
            nothing changes. On acceptance the project, its graph, findings and captured traffic become theirs and spend their
            keys; settings that use your own LLM providers, Nuclei templates or GitHub token are cleared for them, and your
            schedules on it pause until confirmed.
          </p>
          <div className={styles.row}>
            <div className={styles.field}>
              <label className={styles.label} htmlFor={ids.to}>New owner</label>
              <select id={ids.to} className={styles.input} value={toUserId} onChange={(e) => setToUserId(e.target.value)} disabled={readOnly || busy}>
                <option value="">Pick a collaborator</option>
                {candidates.map((s) => (
                  <option key={s.user.id} value={s.user.id}>{personName({ id: s.user.id, name: s.user.name, email: s.user.email })}</option>
                ))}
              </select>
            </div>
            <fieldset className={styles.field} aria-labelledby={ids.role}>
              <span id={ids.role} className={styles.label}>Then you</span>
              {(['co-owner', 'leave'] as const).map((r) => (
                <label key={r} className={styles.choice}>
                  <input type="radio" name={ids.role} value={r} checked={role === r} onChange={() => setRole(r)} disabled={readOnly || busy} />
                  <span>{r === 'co-owner' ? 'Stay as a co-owner' : 'Leave the project'}</span>
                </label>
              ))}
            </fieldset>
          </div>
          <p className={styles.notice}>{FINDING_IDS_NOTE}</p>
          <div className={styles.actions}>
            <button type="button" className="primaryButton" disabled={readOnly || busy || !chosen} onClick={() => setConfirming(true)}>
              Offer ownership...
            </button>
          </div>
        </div>
      )}
      <StepUpModal
        isOpen={confirming}
        title="Offer ownership"
        message={`Offer "${project.name}" to ${chosenName}? When they accept they become its owner, and you ${OWN_ROLE_TEXT[role]}. Confirm with your password.`}
        confirmLabel="Offer"
        onConfirm={async (pw) => {
          await fetchJson(base, {
            method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ toUserId, oldOwnerRole: role, stepUpPassword: pw }),
          }, 'Could not offer the project')
          setToUserId('')
          window.dispatchEvent(new Event(PROJECT_TRANSFER_CHANGED_EVENT))
        }}
        onClose={() => setConfirming(false)}
      />
    </section>
  )
}

export default TransferSection
