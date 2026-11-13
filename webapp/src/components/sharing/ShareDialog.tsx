'use client'

import { useCallback, useEffect, useId, useState, type FormEvent } from 'react'
import { Modal, useAlertModal } from '@/components/ui'
import { IdentityLabel } from '@/components/auth/IdentityLabel'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { useOptionalAuth } from '@/providers/AuthProvider'
import { ApiError, errorMessage, fetchJson, toApiError } from '@/lib/apiError'
import type { ShareView } from '@/lib/authz/projectShares'
import { AccessPicker, termsOf, type AccessChoice } from './AccessPicker'
import { CollaboratorList, displayName, type SharePatch } from './CollaboratorList'
import {
  NOTE_MAX_CHARS,
  RAW_DATA_WARNING,
  READ_SHOWS_FINDINGS_WARNING,
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
  | { kind: 'ready'; shares: ShareView[] }
  | { kind: 'error'; message: string }
  | { kind: 'denied'; permission: string }
  /** The share routes answered 404: sharing is not in force any more, or the project is not the person's to share. */
  | { kind: 'unavailable' }

const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/
const JSON_HEADERS = { 'Content-Type': 'application/json' }

/**
 * The share dialog (step 4.12; UI-07, SH-05, SH-20, ID-31; feature document §6.1, §6.4): share the
 * project with a person by exact email at a preset (Viewer, Analyst, Custom with the Raw data
 * toggle), an optional end date and a note; then the person the server bound is shown as an
 * IdentityLabel (D-24 confirm mode: 4.4's route answers whether an account has the email, and the
 * dialog shows exactly that answer, nothing more). Below, who holds a share, with change and revoke
 * (CollaboratorList). Under act-as nothing can be changed (the routes refuse it). Rendered only while
 * open, by the owner's controls (projects page, header) while sharing is in force.
 */
export function ShareDialog({ project, onClose }: ShareDialogProps) {
  const auth = useOptionalAuth()
  const { alertError } = useAlertModal()
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
  const [choice, setChoice] = useState<AccessChoice>({ presetId: 'viewer', customRaw: false })
  const [endsOn, setEndsOn] = useState('')
  const [note, setNote] = useState('')
  const [pending, setPending] = useState(false)
  const [grantError, setGrantError] = useState<ApiError | string | null>(null)
  const [confirmed, setConfirmed] = useState<ShareView | null>(null)

  const load = useCallback(async () => {
    try {
      const { collaborators } = await fetchJson<{ collaborators: ShareView[] }>(`${base}/collaborators`, undefined, "Could not list the project's shares")
      setList({ kind: 'ready', shares: collaborators })
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
      const { collaborator } = await fetchJson<{ collaborator: ShareView }>(`${base}/collaborators`, {
        method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body),
      }, 'Could not share the project')
      setConfirmed(collaborator)
      setEmail('')
      setNote('')
      setEndsOn('')
      void load()
    } catch (err) {
      setGrantError(toApiError(err, 'Could not share the project'))
    } finally {
      setPending(false)
    }
  }

  const change = async (share: ShareView, patch: SharePatch) => {
    await fetchJson(`${base}/collaborators/${encodeURIComponent(share.user.id)}`, {
      method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify(patch),
    }, 'Could not change the share')
    setNotice(null)
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
              <AccessPicker value={choice} onChange={setChoice} writeRefusal={writeRefusal} disabled={readOnly || pending} />
              <p className={styles.notice}>{READ_SHOWS_FINDINGS_WARNING}</p>
              {terms.rawData && <p className={styles.warning}>{RAW_DATA_WARNING}</p>}
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
                  readOnly={readOnly}
                  onChange={change}
                  onRevoke={revoke}
                />
              )}
            </section>
          </>
        )}
      </div>
    </Modal>
  )
}

export default ShareDialog
