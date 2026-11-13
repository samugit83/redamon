'use client'

import { useCallback, useEffect, useId, useState, type FormEvent } from 'react'
import { Modal, useAlertModal } from '@/components/ui'
import { IdentityLabel } from '@/components/auth/IdentityLabel'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { useOptionalAuth } from '@/providers/AuthProvider'
import { ApiError, errorMessage, fetchJson, toApiError } from '@/lib/apiError'
import type { ShareGrantable, ShareView } from '@/lib/authz/projectShares'
import { AccessPicker, choiceOf, termsOf, type AccessChoice } from './AccessPicker'
import { CollaboratorList, displayName, type SharePatch } from './CollaboratorList'
import { TransferSection } from '@/components/projects/OwnershipTransfer/TransferSection'
import {
  CONSENT_PROMPT,
  COPY_WARNING,
  EXPLOIT_STEP_UP,
  NOTE_MAX_CHARS,
  RAW_DATA_WARNING,
  READ_SHOWS_FINDINGS_WARNING,
  consentNeeded,
  copyWarningApplies,
  endOfDayIso,
  shareTermsLabel,
  termsToBody,
  todayInputValue,
  writePresetsRefusal,
} from './sharePresets'
import styles from './ShareDialog.module.css'

export interface ShareDialogProject {
  id: string
  name: string
}

interface ShareDialogProps {
  project: ShareDialogProject
  onClose: () => void
}

type ListState =
  | { kind: 'loading' }
  /** `grantable`: what the person may grant, with write sharing in force (null otherwise). */
  | { kind: 'ready'; shares: ShareView[]; grantable: ShareGrantable | null }
  | { kind: 'error'; message: string }
  | { kind: 'denied'; permission: string }
  /** The share routes answered 404: sharing is not in force any more, or the project is not the person's to share. */
  | { kind: 'unavailable' }

const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/
const JSON_HEADERS = { 'Content-Type': 'application/json' }
const STEP_UP_CODES = new Set(['step_up_required', 'step_up_failed', 'step_up_locked'])

/** A refusal of the password itself: shown in the password prompt, which stays open for another try. */
const isStepUpRefusal = (err: unknown) => err instanceof ApiError && STEP_UP_CODES.has(err.code ?? '')

/** A password prompt the dialog is showing: what it confirms, and the requests the password goes with. */
interface PasswordAsk {
  title: string
  message: string
  confirmLabel: string
  run: (password: string) => Promise<void>
  settle: (confirmed: boolean) => void
}

/** The prompt's words: the consent (step 5.6) and the Exploitation step-up (ID-25), one password for both. */
function passwordAskText(consent: boolean, exploit: boolean, verb: 'share' | 'save'): Pick<PasswordAsk, 'title' | 'message' | 'confirmLabel'> {
  const message = [consent ? CONSENT_PROMPT : null, exploit ? EXPLOIT_STEP_UP : null, 'Confirm with your password.'].filter(Boolean).join(' ')
  const action = verb === 'share' ? 'share' : 'save'
  return consent
    ? { title: 'Allow spending your credentials', message, confirmLabel: `Allow and ${action}` }
    : { title: 'Grant Exploitation & shells', message, confirmLabel: verb === 'share' ? 'Share' : 'Save' }
}

/**
 * The share dialog (steps 4.12, 5.14; UI-07, SH-05, SH-20, SH-29, HD-22, ID-25, ID-31; feature document
 * §6.1, §6.4, §6.5): share the project with a person by exact email at a preset (Viewer, Analyst and,
 * with write sharing in force, Editor, Operator, Red-teamer, Co-owner) or Custom (the level and every
 * toggle), an optional end date and a note; then the person the server bound is shown as an
 * IdentityLabel (D-24 confirm mode: 4.4's route answers whether an account has the email, and the
 * dialog shows exactly that answer, nothing more). Below, who holds a share, with change and revoke
 * (CollaboratorList), and for the owner the ownership transfer (step 5.12).
 *
 * Granting a toggle that spends the owner's credentials before the owner allowed it asks the owner's
 * consent (with their password, step 5.6); granting Exploitation & shells asks the password (the
 * route's step-up): one prompt when both apply. A co-owner is offered only what they hold, and what
 * Root's policy keeps from members is shown disabled with why. Under act-as nothing can be changed
 * (the routes refuse it). Rendered only while open, by the owner's and co-owner's controls (projects
 * page, header) while sharing is in force.
 */
export function ShareDialog({ project, onClose }: ShareDialogProps) {
  const auth = useOptionalAuth()
  const { alertError, dangerConfirm } = useAlertModal()
  const user = auth?.user ?? null
  const actingAs = user?.actingAs ?? null
  const viewerId = actingAs?.id ?? user?.id ?? null
  const readOnly = Boolean(actingAs)
  const writeRefusal = writePresetsRefusal(user?.flags, user?.sharing)
  const ids = { email: useId(), emailHint: useId(), ends: useId(), endsHint: useId(), note: useId(), people: useId() }
  const base = `/api/projects/${encodeURIComponent(project.id)}`

  const [list, setList] = useState<ListState>({ kind: 'loading' })
  const [notice, setNotice] = useState<string | null>(null)
  const [email, setEmail] = useState('')
  const [choice, setChoice] = useState<AccessChoice>(() => choiceOf())
  const [endsOn, setEndsOn] = useState('')
  const [note, setNote] = useState('')
  const [pending, setPending] = useState(false)
  const [grantError, setGrantError] = useState<ApiError | string | null>(null)
  const [confirmed, setConfirmed] = useState<ShareView | null>(null)
  const [ask, setAsk] = useState<PasswordAsk | null>(null)
  const [withdrawing, setWithdrawing] = useState(false)

  const load = useCallback(async () => {
    try {
      const answer = await fetchJson<{ collaborators: ShareView[]; grantable?: ShareGrantable | null }>(
        `${base}/collaborators`, undefined, "Could not list the project's shares",
      )
      setList({ kind: 'ready', shares: answer.collaborators, grantable: answer.grantable ?? null })
    } catch (err) {
      const apiError = toApiError(err, "Could not list the project's shares")
      const permission = forbiddenPermission(apiError)
      if (permission) setList({ kind: 'denied', permission })
      else if (apiError.status === 404) setList({ kind: 'unavailable' })
      else setList({ kind: 'error', message: apiError.message })
    }
  }, [base])

  useEffect(() => { void load() }, [load])

  const terms = termsOf(choice)
  const grantable = list.kind === 'ready' ? list.grantable : null

  /** Opens the password prompt; true once `run` succeeded with the password, false when cancelled. */
  const askPassword = (text: Pick<PasswordAsk, 'title' | 'message' | 'confirmLabel'>, run: PasswordAsk['run']) =>
    new Promise<boolean>((settle) => setAsk({ ...text, run, settle }))

  /** The owner's consent (step 5.6), recorded before the share that needs it. */
  const giveConsent = async (password: string) => {
    await fetchJson(`${base}/access-policy`, {
      method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ ownerCredentialConsent: true, stepUpPassword: password }),
    }, 'Could not record your consent')
    setList(prev => (prev.kind === 'ready' && prev.grantable ? { ...prev, grantable: { ...prev.grantable, ownerConsent: true } } : prev))
  }

  /**
   * Sends a share change that may need the consent and the password. A refusal of the password stays in
   * the prompt; any other refusal of the change is answered for the caller to show where it belongs:
   * null when it went through, 'cancelled' when the person closed the prompt, else the error.
   */
  const withPassword = async (turnedOn: SharePatch, verb: 'share' | 'save', send: (password?: string) => Promise<void>): Promise<unknown> => {
    const consent = consentNeeded(turnedOn, grantable)
    const exploit = turnedOn.exploit === true
    if (!consent && !exploit) {
      try {
        await send()
        return null
      } catch (err) {
        return err
      }
    }
    let failure: unknown = null
    const ok = await askPassword(passwordAskText(consent, exploit, verb), async (password) => {
      if (consent) await giveConsent(password)
      try {
        await send(exploit ? password : undefined)
      } catch (err) {
        if (isStepUpRefusal(err)) throw err
        failure = err
      }
    })
    return ok ? failure : 'cancelled'
  }

  async function grant(e: FormEvent) {
    e.preventDefault()
    if (pending || readOnly) return
    setConfirmed(null)
    const address = email.trim()
    if (!EMAIL_SHAPE.test(address)) {
      setGrantError("Enter the person's exact sign-in email.")
      return
    }
    setGrantError(null)
    setPending(true)
    try {
      const body = {
        email: address,
        ...termsToBody(terms),
        ...(endsOn ? { expiresAt: endOfDayIso(endsOn) } : {}),
        ...(note.trim() ? { note: note.trim() } : {}),
      }
      const outcome = await withPassword(terms, 'share', async (password) => {
        const { collaborator } = await fetchJson<{ collaborator: ShareView }>(`${base}/collaborators`, {
          method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(password ? { ...body, stepUpPassword: password } : body),
        }, 'Could not share the project')
        setConfirmed(collaborator)
        setEmail('')
        setNote('')
        setEndsOn('')
        void load()
      })
      if (outcome === 'cancelled') setGrantError('Not shared: the password was not confirmed.')
      else if (outcome) setGrantError(toApiError(outcome, 'Could not share the project'))
    } finally {
      setPending(false)
    }
  }

  const change = async (share: ShareView, patch: SharePatch) => {
    const outcome = await withPassword(patch, 'save', async (password) => {
      await fetchJson(`${base}/collaborators/${encodeURIComponent(share.user.id)}`, {
        method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify(password ? { ...patch, stepUpPassword: password } : patch),
      }, 'Could not change the share')
    })
    if (outcome === 'cancelled') throw new Error('Not changed: the password was not confirmed.')
    if (outcome) throw outcome
    setNotice(null)
    await load()
  }

  const withdrawConsent = async () => {
    const ok = await dangerConfirm(
      "Collaborators stop spending this project's credentials now: their agent runs and connections on it end, their queued scans are cancelled, and Run scans, Use AI agent and Exploitation & shells give nothing until you allow it again.",
      'Withdraw your consent',
      { confirmLabel: 'Withdraw' },
    )
    if (!ok) return
    setWithdrawing(true)
    try {
      await fetchJson(`${base}/access-policy`, {
        method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ ownerCredentialConsent: false }),
      }, 'Could not withdraw your consent')
    } catch (err) {
      await alertError(errorMessage(err, 'Could not withdraw your consent'))
    } finally {
      setWithdrawing(false)
    }
    await load()
  }

  const revoke = async (share: ShareView) => {
    try {
      const { socketsClosed } = await fetchJson<{ socketsClosed?: boolean }>(
        `${base}/collaborators/${encodeURIComponent(share.user.id)}`,
        { method: 'DELETE' },
        'Could not revoke the share',
      )
      setNotice(socketsClosed === false
        ? `${displayName(share)}'s share is revoked. The agent could not confirm that their open connections closed; they cannot open new ones.`
        : null)
    } catch (err) {
      await alertError(errorMessage(err, 'Could not revoke the share'))
    }
    await load()
  }

  const grantPermission = grantError instanceof ApiError ? forbiddenPermission(grantError) : null
  const grantMessage = grantError instanceof ApiError ? grantError.message : grantError

  return (
    <Modal isOpen onClose={onClose} title={`Share "${project.name}"`} size="large">
      <div className={styles.dialog}>
        {readOnly && (
          <p className={styles.callout} role="note">
            {`You are acting as ${actingAs?.name || actingAs?.email || 'another account'}: the project's shares are listed but cannot be changed while you act as another account.`}
          </p>
        )}
        {list.kind === 'denied' ? (
          <ForbiddenNotice permission={list.permission} />
        ) : list.kind === 'unavailable' ? (
          <p className={styles.error} role="alert">
            Sharing is not available for this project now: it was turned off, or the project is not yours to share.
          </p>
        ) : (
          <>
            <form className={styles.form} aria-label="Share with a person" onSubmit={grant} noValidate>
              <div className={styles.field}>
                <label className={styles.label} htmlFor={ids.email}>Email</label>
                <input
                  id={ids.email}
                  type="email"
                  className={styles.input}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="person@example.com"
                  autoComplete="off"
                  maxLength={320}
                  aria-describedby={ids.emailHint}
                  disabled={readOnly || pending}
                  autoFocus
                />
                <span id={ids.emailHint} className={styles.hint}>
                  Their exact sign-in email. The share goes to the account it names now.
                </span>
              </div>
              <AccessPicker value={choice} onChange={setChoice} writeRefusal={writeRefusal} grantable={grantable} disabled={readOnly || pending} />
              <p className={styles.notice}>{READ_SHOWS_FINDINGS_WARNING}</p>
              {terms.rawData && <p className={styles.warning}>{RAW_DATA_WARNING}</p>}
              {copyWarningApplies(terms) && <p className={styles.warning}>{COPY_WARNING}</p>}
              <div className={styles.row}>
                <div className={styles.field}>
                  <label className={styles.label} htmlFor={ids.ends}>Ends on (optional)</label>
                  <input
                    id={ids.ends}
                    type="date"
                    className={styles.input}
                    value={endsOn}
                    min={todayInputValue()}
                    onChange={(e) => setEndsOn(e.target.value)}
                    aria-describedby={ids.endsHint}
                    disabled={readOnly || pending}
                  />
                  <span id={ids.endsHint} className={styles.hint}>
                    Empty: the instance&apos;s default end applies if one is set; otherwise until you revoke it.
                  </span>
                </div>
                <div className={styles.field}>
                  <label className={styles.label} htmlFor={ids.note}>Note (optional)</label>
                  <input
                    id={ids.note}
                    type="text"
                    className={styles.input}
                    value={note}
                    maxLength={NOTE_MAX_CHARS}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="e.g. until the engagement ends"
                    disabled={readOnly || pending}
                  />
                </div>
              </div>
              {grantPermission ? (
                <ForbiddenNotice permission={grantPermission} />
              ) : grantMessage ? (
                <div className={styles.error} role="alert">{grantMessage}</div>
              ) : null}
              {confirmed && (
                <div className={styles.confirmed} role="status" aria-label="Shared">
                  <span>Shared with</span>
                  <IdentityLabel
                    name={confirmed.user.name ?? ''}
                    email={confirmed.user.email ?? ''}
                    accountType={confirmed.user.accountType ?? undefined}
                  />
                  <span>{`as ${shareTermsLabel(confirmed)}${confirmed.expiresAt ? `, until ${new Date(confirmed.expiresAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}` : ''}.`}</span>
                </div>
              )}
              <div className={styles.actions}>
                <button type="submit" className="primaryButton" disabled={readOnly || pending}>
                  {pending ? 'Sharing...' : 'Share'}
                </button>
              </div>
            </form>

            {grantable?.grantor === 'owner' && (
              <div className={styles.callout} role="status" aria-label="Spending your credentials">
                {grantable.ownerConsent ? (
                  <>
                    <span>Collaborators with Run scans, Use AI agent or Exploitation &amp; shells may spend this project&apos;s credentials (your keys and providers).</span>
                    {!readOnly && (
                      <button type="button" className={styles.linkButton} onClick={() => void withdrawConsent()} disabled={withdrawing}>
                        {withdrawing ? 'Withdrawing...' : 'Withdraw'}
                      </button>
                    )}
                  </>
                ) : (
                  <span>Collaborators cannot spend this project&apos;s credentials yet: you are asked when you grant Run scans, Use AI agent or Exploitation &amp; shells.</span>
                )}
              </div>
            )}

            <section className={styles.section} aria-labelledby={ids.people}>
              <h3 id={ids.people} className={styles.sectionTitle}>People with access</h3>
              {notice && <p className={styles.warning} role="status">{notice}</p>}
              {list.kind === 'loading' ? (
                <p className={styles.hint} role="status">Loading who has access...</p>
              ) : list.kind === 'error' ? (
                <div className={styles.error} role="alert">
                  <span>{list.message}</span>
                  <button type="button" className={styles.linkButton} onClick={() => { setList({ kind: 'loading' }); void load() }}>
                    Retry
                  </button>
                </div>
              ) : list.shares.length === 0 ? (
                <p className={styles.hint}>Not shared with anyone yet.</p>
              ) : (
                <CollaboratorList
                  projectName={project.name}
                  shares={list.shares}
                  viewerId={viewerId}
                  writeRefusal={writeRefusal}
                  grantable={grantable}
                  readOnly={readOnly}
                  onChange={change}
                  onRevoke={revoke}
                />
              )}
            </section>
            {/* Ownership transfer (step 5.12): with write sharing in force; the section shows itself to the owner only. */}
            {user?.sharing?.enabled === true && user.sharing.maxLevel === 'write' && (
              <TransferSection project={project} shares={list.kind === 'ready' ? list.shares : null} readOnly={readOnly} />
            )}
          </>
        )}
      </div>
      <StepUpModal
        isOpen={ask !== null}
        title={ask?.title ?? ''}
        message={ask?.message ?? ''}
        confirmLabel={ask?.confirmLabel ?? 'Confirm'}
        onConfirm={async (password) => {
          if (!ask) return
          await ask.run(password)
          ask.settle(true)
        }}
        onClose={() => {
          ask?.settle(false)
          setAsk(null)
        }}
      />
    </Modal>
  )
}

export default ShareDialog
