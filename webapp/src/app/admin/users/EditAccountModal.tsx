'use client'

import { useEffect, useId, useState, type FormEvent } from 'react'
import { Modal } from '@/components/ui'
import { IdentityLabel } from '@/components/auth/IdentityLabel'
import { fetchJson, toApiError } from '@/lib/apiError'
import type { DirectoryRow } from '@/lib/authz/userDirectory'
import pageStyles from '@/app/settings/users/page.module.css'

interface Props {
  isOpen: boolean
  row: Pick<DirectoryRow, 'id' | 'name' | 'email' | 'accountType'>
  onClose: () => void
  /** Saved: the account must be read again. */
  onSaved: () => void
}

/**
 * "Edit" in the admin console (step 6.2, users:edit): an account's name and sign-in email, through
 * PUT /api/users/[id]. A new email, and any change to another admin, takes the editor's own password
 * (the server's step-up, step 2.11); the field shows only then. The server decides: a refusal is shown
 * as it came, in the dialog.
 */
export function EditAccountModal({ isOpen, row, onClose, onSaved }: Props) {
  const uid = useId()
  const [name, setName] = useState(row.name)
  const [email, setEmail] = useState(row.email)
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (isOpen) {
      setName(row.name)
      setEmail(row.email)
      setPassword('')
      setError('')
    }
  }, [isOpen, row.name, row.email])

  const nameChanged = name.trim() !== row.name
  const emailChanged = email.trim().toLowerCase() !== row.email.toLowerCase()
  const needsPassword = emailChanged || (row.accountType === 'admin' && nameChanged)

  async function save(e: FormEvent) {
    e.preventDefault()
    if (saving) return
    if (!name.trim() || !email.trim()) {
      setError('Name and email are required')
      return
    }
    if (!nameChanged && !emailChanged) {
      onClose()
      return
    }
    if (needsPassword && !password) {
      setError('Enter your password to confirm this change')
      return
    }
    setError('')
    setSaving(true)
    try {
      await fetchJson(`/api/users/${encodeURIComponent(row.id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...(nameChanged ? { name: name.trim() } : {}),
          ...(emailChanged ? { email: email.trim() } : {}),
          ...(needsPassword ? { stepUpPassword: password } : {}),
        }),
      }, 'Could not save the account')
      onSaved()
      onClose()
    } catch (err) {
      setError(toApiError(err, 'Could not save the account').message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={saving ? () => {} : onClose} title="Edit account" size="small">
      <form className={pageStyles.form} onSubmit={save} noValidate>
        <p className={pageStyles.hint}>
          <IdentityLabel name={row.name} email={row.email} accountType={row.accountType} />
        </p>
        {error && <div className={pageStyles.error} role="alert">{error}</div>}
        <div className={pageStyles.field}>
          <label className={pageStyles.label} htmlFor={`${uid}-name`}>Name</label>
          <input id={`${uid}-name`} className={pageStyles.input} value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div className={pageStyles.field}>
          <label className={pageStyles.label} htmlFor={`${uid}-email`}>Sign-in email</label>
          <input
            id={`${uid}-email`}
            type="email"
            className={pageStyles.input}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            aria-describedby={`${uid}-email-hint`}
          />
          <span id={`${uid}-email-hint`} className={pageStyles.hint}>
            The person signs in with the new address and is told about the change at their next sign-in.
          </span>
        </div>
        {needsPassword && (
          <div className={pageStyles.field}>
            <label className={pageStyles.label} htmlFor={`${uid}-password`}>Your password</label>
            <input
              id={`${uid}-password`}
              type="password"
              className={pageStyles.input}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              aria-describedby={`${uid}-password-hint`}
            />
            <span id={`${uid}-password-hint`} className={pageStyles.hint}>
              {emailChanged ? 'Changing a sign-in email' : "Changing another admin's account"} takes your own password.
            </span>
          </div>
        )}
        <div className={pageStyles.modalActions}>
          <button type="button" className={pageStyles.actionButton} onClick={onClose} disabled={saving}>Cancel</button>
          <button type="submit" className="primaryButton" disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
        </div>
      </form>
    </Modal>
  )
}
