'use client'

import { useEffect, useId, useState, type FormEvent, type ReactNode } from 'react'
import { Modal } from '@/components/ui'
import styles from './StepUpModal.module.css'

interface StepUpModalProps {
  isOpen: boolean
  title: string
  /** What the password confirms, shown above the field. */
  message: ReactNode
  confirmLabel: string
  /**
   * Runs the action with the typed password. Resolving closes the dialog; throwing
   * keeps it open and shows the error's message (an ApiError carries code and status).
   */
  onConfirm: (password: string) => Promise<void>
  onClose: () => void
}

/**
 * Asks the signed-in admin for their OWN password before an admin-on-admin action
 * (the server's step-up, ID-25). The password goes with that one request and is
 * never kept.
 */
export function StepUpModal({ isOpen, title, message, confirmLabel, onConfirm, onClose }: StepUpModalProps) {
  const fieldId = useId()
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (!isOpen) {
      setPassword('')
      setError('')
      setPending(false)
    }
  }, [isOpen])

  async function submit(e?: FormEvent) {
    e?.preventDefault()
    if (pending) return
    if (!password) {
      setError('Enter your password')
      return
    }
    setError('')
    setPending(true)
    try {
      await onConfirm(password)
      setPending(false)
      onClose()
    } catch (err) {
      setPending(false)
      setError(err instanceof Error ? err.message : 'The action was refused')
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={pending ? () => {} : onClose} title={title} size="small">
      <form className={styles.form} onSubmit={submit} noValidate>
        <p className={styles.message}>{message}</p>
        {error && <div className={styles.error} role="alert">{error}</div>}
        <div className={styles.field}>
          <label className={styles.label} htmlFor={fieldId}>Your password</label>
          <input
            id={fieldId}
            type="password"
            className={styles.input}
            value={password}
            onChange={e => setPassword(e.target.value)}
            autoComplete="current-password"
            autoFocus
            disabled={pending}
          />
        </div>
        <div className={styles.actions}>
          <button type="button" className={styles.cancel} onClick={onClose} disabled={pending}>Cancel</button>
          <button type="submit" className="primaryButton" disabled={pending}>
            {pending ? 'Checking...' : confirmLabel}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export default StepUpModal
