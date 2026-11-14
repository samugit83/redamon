'use client'

import { useState, type FormEvent } from 'react'
import { MailX, Send } from 'lucide-react'
import { CopyButton, Modal, useOptionalAlertModal } from '@/components/ui'
import { fetchJson, toApiError } from '@/lib/apiError'
import { ActionLabel } from './ActionLabel'
import { InitialSetPicker, NO_INITIAL_SET, initialSetFields, type InitialSetChoice } from './InitialSetPicker'
import styles from '@/app/settings/users/page.module.css'

/** A link as the invite routes answer it: shown once, never stored by the page. */
export interface InviteLink {
  link: string
  expiresAt: string
  localhostWarning: boolean
}

/**
 * The link, once (step 2.9, ID-14): a read-only field with Copy, its expiry, and, while the
 * instance has no public address, the warning that only this computer can open it. A reset link
 * (step 2.10) is shown the same way.
 */
export function InviteLinkPanel({ result, id, kind = 'invite' }: { result: InviteLink; id: string; kind?: 'invite' | 'reset' }) {
  const what = kind === 'invite' ? 'invite' : 'reset'
  return (
    <div className={styles.form}>
      <div className={styles.field}>
        <label className={styles.label} htmlFor={id}>{kind === 'invite' ? 'Invite link' : 'Reset link'}</label>
        <div className={styles.actions}>
          <input
            id={id}
            className={styles.input}
            value={result.link}
            readOnly
            onFocus={(e) => e.currentTarget.select()}
            aria-describedby={`${id}-hint`}
          />
          <CopyButton text={result.link} title={`Copy the ${what} link`} />
        </div>
        <span id={`${id}-hint`} className={styles.hint}>
          Expires {new Date(result.expiresAt).toLocaleString()}. This link is shown only once: send it to the person
          now. {kind === 'invite'
            ? 'It works once; Resend makes a new one and cancels this one.'
            : 'It works once; a new reset cancels it.'}
        </span>
      </div>
      {result.localhostWarning && (
        <div className={styles.error} role="note">
          This link points to localhost: only this computer can open it. Root can set the instance&apos;s public
          address (publicBaseUrl) in the instance settings.
        </div>
      )}
    </div>
  )
}

interface ModalProps {
  isOpen: boolean
  onClose: () => void
  /** An account was created: the list must be read again. */
  onInvited: () => void
  /** The signed-in person, whose permissions decide the sets they may choose (step 3.13). */
  selfId?: string
}

/**
 * "Invite user", the default way to add a person with the identity switch on (ID-36): the
 * admin gives a name and an address and gets a link; the person chooses their own password, so
 * the admin never knows a working one. The account is always a member. With the permissions
 * switch on, a person who assigns sets also chooses the one it starts with (ID-28).
 */
export function InviteUserModal({ isOpen, onClose, onInvited, selfId }: ModalProps) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [setChoice, setSetChoice] = useState<InitialSetChoice>(NO_INITIAL_SET)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<InviteLink | null>(null)

  function close() {
    setName('')
    setEmail('')
    setSetChoice(NO_INITIAL_SET)
    setError('')
    setResult(null)
    onClose()
  }

  async function submit(e?: FormEvent) {
    e?.preventDefault()
    if (busy) return
    setError('')
    if (!name.trim() || !email.trim()) {
      setError('Name and email are required')
      return
    }
    const fields = initialSetFields(setChoice)
    if ('error' in fields) {
      setError(fields.error)
      return
    }
    setBusy(true)
    try {
      const answer = await fetchJson<InviteLink>('/api/users/invite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), email: email.trim(), ...fields }),
      }, 'Could not invite the user')
      setResult({ link: answer.link, expiresAt: answer.expiresAt, localhostWarning: answer.localhostWarning })
      onInvited()
    } catch (err) {
      setError(toApiError(err, 'Could not invite the user').message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={close} title="Invite user">
      {result ? (
        <div className={styles.form}>
          <InviteLinkPanel result={result} id="invite-user-link" />
          <div className={styles.modalActions}>
            <button type="button" className="primaryButton" onClick={close}>Done</button>
          </div>
        </div>
      ) : (
        <form className={styles.form} onSubmit={submit} noValidate>
          {error && <div className={styles.error} role="alert">{error}</div>}
          <div className={styles.field}>
            <label className={styles.label} htmlFor="invite-user-name">Name</label>
            <input id="invite-user-name" className={styles.input} value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </div>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="invite-user-email">Email</label>
            <input
              id="invite-user-email"
              type="email"
              className={styles.input}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              aria-describedby="invite-user-email-hint"
            />
            <span id="invite-user-email-hint" className={styles.hint}>
              The person gets a member account and chooses their own password through the link.
            </span>
          </div>
          <InitialSetPicker idPrefix="invite-user" selfId={selfId} value={setChoice} onChange={setSetChoice} />
          <div className={styles.modalActions}>
            <button type="button" className={styles.actionButton} onClick={close}>Cancel</button>
            <button type="submit" className="primaryButton" disabled={busy}>
              {busy ? 'Creating…' : 'Create the invite link'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  )
}

interface RowProps {
  user: { id: string; name: string }
  buttonClassName: string
  dangerClassName: string
  /** The list must be read again. */
  onChanged: () => void
}

/**
 * Resend and Cancel invite on an invited row (step 2.9). Each is confirmed through the app's
 * dialog first (outside it nothing is sent); a refusal shows the server's message.
 */
export function InviteRowActions({ user, buttonClassName, dangerClassName, onChanged }: RowProps) {
  const alerts = useOptionalAlertModal()
  const [busy, setBusy] = useState(false)
  const [resent, setResent] = useState<InviteLink | null>(null)
  const base = `/api/users/${encodeURIComponent(user.id)}/invite`

  async function post<T>(path: string, failed: string): Promise<T> {
    return fetchJson<T>(`${base}/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    }, failed)
  }

  async function resend() {
    const ok = await alerts?.confirm(
      `Make a new invite link for ${user.name}? The link sent before stops working.`,
      'Resend the invite',
      { confirmLabel: 'Resend' },
    )
    if (!ok) return
    setBusy(true)
    try {
      setResent(await post<InviteLink>('resend', 'Could not resend the invite'))
    } catch (err) {
      void alerts?.alertError(toApiError(err, 'Could not resend the invite').message, user.name)
    } finally {
      setBusy(false)
    }
  }

  async function cancel() {
    const ok = await alerts?.dangerConfirm(
      `Cancel the invite of ${user.name}? The account is removed and its link stops working.`,
      'Cancel the invite',
      { confirmLabel: 'Cancel invite', cancelLabel: 'Keep the invite' },
    )
    if (!ok) return
    setBusy(true)
    try {
      await post('cancel', 'Could not cancel the invite')
    } catch (err) {
      void alerts?.alertError(toApiError(err, 'Could not cancel the invite').message, user.name)
    } finally {
      setBusy(false)
      onChanged()
    }
  }

  return (
    <>
      <button type="button" className={buttonClassName} disabled={busy} aria-label={`Resend the invite to ${user.name}`} onClick={() => void resend()}>
        <ActionLabel icon={Send}>Resend</ActionLabel>
      </button>
      <button
        type="button"
        className={`${buttonClassName} ${dangerClassName}`}
        disabled={busy}
        aria-label={`Cancel the invite of ${user.name}`}
        onClick={() => void cancel()}
      >
        <ActionLabel icon={MailX}>Cancel invite</ActionLabel>
      </button>
      <Modal isOpen={resent !== null} onClose={() => setResent(null)} title={`Invite link for ${user.name}`}>
        {resent && (
          <div className={styles.form}>
            <InviteLinkPanel result={resent} id={`invite-link-${user.id}`} />
            <div className={styles.modalActions}>
              <button type="button" className="primaryButton" onClick={() => setResent(null)}>Done</button>
            </div>
          </div>
        )}
      </Modal>
    </>
  )
}
