'use client'

import { useState, type FormEvent } from 'react'
import { Modal } from '@/components/ui'
import { fetchJson, toApiError } from '@/lib/apiError'
import { validateNewPassword, type PasswordPolicy } from '@/lib/authz/passwordPolicy'
import { InviteLinkPanel, type InviteLink } from './InviteUserModal'
import styles from '@/app/settings/users/page.module.css'

type Mode = 'link' | 'temporary'

interface ResetAnswer {
  mode: Mode
  link?: string
  expiresAt?: string
  localhostWarning?: boolean
}

interface Props {
  isOpen: boolean
  user: { id: string; name: string; email: string }
  /** Another admin: the confirmed Root's reset, with its own password (step 2.6). */
  targetIsAdmin: boolean
  /** The policy in force, for the temporary password (null: Phase 1's floor, no text). */
  policy: (PasswordPolicy & { description?: string }) | null
  onClose: () => void
  /** The account changed: the list must be read again. */
  onDone: () => void
}

/**
 * "Reset credentials" (step 2.10, ID-18, ID-19): a reset link by default, so the admin never
 * knows a working password, or a temporary password the person changes at the next sign-in.
 * Either ends every session and MCP token of the account. The reason is shown to the person at
 * their next sign-in; the server requires it once the person has signed in before.
 */
export function ResetCredentialsModal({ isOpen, user, targetIsAdmin, policy, onClose, onDone }: Props) {
  const [mode, setMode] = useState<Mode>('link')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [reason, setReason] = useState('')
  const [stepUp, setStepUp] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [link, setLink] = useState<InviteLink | null>(null)
  const [temporaryDone, setTemporaryDone] = useState(false)
  const id = `reset-${user.id}`

  function close() {
    setMode('link')
    setPassword('')
    setConfirm('')
    setReason('')
    setStepUp('')
    setError('')
    setLink(null)
    setTemporaryDone(false)
    onClose()
  }

  async function submit(e?: FormEvent) {
    e?.preventDefault()
    if (busy) return
    setError('')
    if (mode === 'temporary') {
      const check = validateNewPassword(password, policy ?? undefined, { email: user.email })
      if (!check.ok) {
        setError(check.message)
        return
      }
      if (password !== confirm) {
        setError('The two passwords do not match')
        return
      }
    }
    if (targetIsAdmin && !stepUp) {
      setError("Enter your password to reset another admin's credentials")
      return
    }
    const body: Record<string, string> = { mode }
    if (mode === 'temporary') body.temporaryPassword = password
    if (reason.trim()) body.reason = reason.trim()
    if (targetIsAdmin) body.stepUpPassword = stepUp
    setBusy(true)
    try {
      const answer = await fetchJson<ResetAnswer>(`/api/users/${encodeURIComponent(user.id)}/reset-credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }, 'Could not reset the credentials')
      setPassword('')
      setConfirm('')
      setStepUp('')
      if (answer.mode === 'link' && answer.link && answer.expiresAt) {
        setLink({ link: answer.link, expiresAt: answer.expiresAt, localhostWarning: answer.localhostWarning === true })
      } else {
        setTemporaryDone(true)
      }
      onDone()
    } catch (err) {
      setError(toApiError(err, 'Could not reset the credentials').message)
    } finally {
      setBusy(false)
    }
  }

  const done = link !== null || temporaryDone

  return (
    <Modal isOpen={isOpen} onClose={close} title={`Reset credentials - ${user.name}`}>
      {done ? (
        <div className={styles.form}>
          {link ? (
            <InviteLinkPanel result={link} id={`${id}-link`} kind="reset" />
          ) : (
            <div className={styles.success} role="status">
              The temporary password is set. {user.name} must choose a new one at the next sign-in; every
              session and MCP token of the account has ended.
            </div>
          )}
          <div className={styles.modalActions}>
            <button type="button" className="primaryButton" onClick={close}>Done</button>
          </div>
        </div>
      ) : (
        <form className={styles.form} onSubmit={submit} noValidate>
          {error && <div className={styles.error} role="alert">{error}</div>}
          <p className={styles.hint} id={`${id}-effect`}>
            {user.name} ({user.email}) is signed out everywhere and every MCP token of the account is revoked.
            Whoever holds the link or the temporary password can sign in as this person, so they are told.
          </p>
          <fieldset className={styles.field} aria-describedby={`${id}-effect`}>
            <legend className={styles.label}>How</legend>
            <label className={styles.checkboxLabel}>
              <input type="radio" name={`${id}-mode`} checked={mode === 'link'} onChange={() => setMode('link')} />
              {' '}Send a reset link
            </label>
            <label className={styles.checkboxLabel}>
              <input type="radio" name={`${id}-mode`} checked={mode === 'temporary'} onChange={() => setMode('temporary')} />
              {' '}Set a temporary password
            </label>
          </fieldset>
          {mode === 'temporary' && (
            <>
              <div className={styles.field}>
                <label className={styles.label} htmlFor={`${id}-password`}>Temporary password</label>
                <input
                  id={`${id}-password`}
                  type="password"
                  className={styles.input}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  aria-describedby={policy?.description ? `${id}-policy` : undefined}
                />
                {policy?.description && <span id={`${id}-policy`} className={styles.hint}>{policy.description}</span>}
              </div>
              <div className={styles.field}>
                <label className={styles.label} htmlFor={`${id}-confirm`}>Confirm the temporary password</label>
                <input
                  id={`${id}-confirm`}
                  type="password"
                  className={styles.input}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
            </>
          )}
          <div className={styles.field}>
            <label className={styles.label} htmlFor={`${id}-reason`}>Reason</label>
            <textarea
              id={`${id}-reason`}
              className={styles.input}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={500}
              rows={2}
              aria-describedby={`${id}-reason-hint`}
            />
            <span id={`${id}-reason-hint`} className={styles.hint}>
              Required once the person has signed in before. They will read it at their next sign-in.
            </span>
          </div>
          {targetIsAdmin && (
            <div className={styles.field}>
              <label className={styles.label} htmlFor={`${id}-step-up`}>Your password</label>
              <input
                id={`${id}-step-up`}
                type="password"
                className={styles.input}
                value={stepUp}
                onChange={(e) => setStepUp(e.target.value)}
                autoComplete="current-password"
              />
              <span className={styles.hint}>This account is an admin: confirm the reset with your own password.</span>
            </div>
          )}
          <div className={styles.modalActions}>
            <button type="button" className={styles.actionButton} onClick={close}>Cancel</button>
            <button type="submit" className="primaryButton" disabled={busy}>
              {busy ? 'Resetting…' : 'Reset credentials'}
            </button>
          </div>
        </form>
      )}
    </Modal>
  )
}
