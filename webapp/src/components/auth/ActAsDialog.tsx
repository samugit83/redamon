'use client'

import { useEffect, useId, useState, type FormEvent } from 'react'
import { Modal } from '@/components/ui'
import { IdentityLabel, type AccountType } from './IdentityLabel'
import styles from './ActAsDialog.module.css'

/** The dialog's default (OQ-32), held to the instance limit. */
export const DEFAULT_ACT_AS_MINUTES = 60
const REASON_MAX = 500
const DURATIONS = [15, 30, 60, 120, 240, 480, 720]

/** The durations offered: the usual steps up to the instance limit, and the limit itself. */
export function durationChoices(maxMinutes: number): number[] {
  const max = Math.max(1, Math.floor(maxMinutes))
  const steps = DURATIONS.filter((m) => m < max)
  return [...steps, max]
}

export function durationLabel(minutes: number): string {
  if (minutes < 60 || minutes % 60 !== 0) return `${minutes} min`
  const hours = minutes / 60
  return hours === 1 ? '1 hour' : `${hours} hours`
}

export interface ActAsDialogTarget {
  id: string
  name: string
  email: string
  accountType?: AccountType
}

export interface ActAsRequestInput {
  reason: string
  durationMinutes: number
  password: string
}

interface ActAsDialogProps {
  isOpen: boolean
  target: ActAsDialogTarget | null
  /** The instance limit (`impersonationMaxMinutes`, at most 720). */
  maxMinutes: number
  /** Root made a reason mandatory. */
  reasonRequired: boolean
  /**
   * Starts the impersonation. Resolving closes the dialog; throwing keeps it open and shows the
   * error's message (an ApiError carries code and status).
   */
  onConfirm: (input: ActAsRequestInput) => Promise<void>
  onClose: () => void
}

/**
 * Starting to act as someone (step 3.14, IM-04; feature document §4.7): why, for how long, and the
 * admin's own password (ID-25). Every impersonation starts here: the browser no longer resumes one
 * by itself, and the server ends it when the time is up.
 */
export function ActAsDialog({ isOpen, target, maxMinutes, reasonRequired, onConfirm, onClose }: ActAsDialogProps) {
  const ids = { reason: useId(), duration: useId(), password: useId() }
  const choices = durationChoices(maxMinutes)
  const initial = Math.min(DEFAULT_ACT_AS_MINUTES, choices[choices.length - 1])
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState(initial)
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (!isOpen) {
      setReason('')
      setPassword('')
      setError('')
      setPending(false)
    }
    setDuration(initial)
  }, [isOpen, initial])

  async function submit(e?: FormEvent) {
    e?.preventDefault()
    if (pending) return
    if (reasonRequired && !reason.trim()) {
      setError('Say why you are acting as this account')
      return
    }
    if (!password) {
      setError('Enter your password')
      return
    }
    setError('')
    setPending(true)
    try {
      await onConfirm({ reason: reason.trim(), durationMinutes: duration, password })
      setPending(false)
      onClose()
    } catch (err) {
      setPending(false)
      setError(err instanceof Error ? err.message : 'The switch was refused')
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={pending ? () => {} : onClose} title="Act as another account" size="small">
      <form className={styles.form} onSubmit={submit} noValidate>
        {target && (
          <p className={styles.message}>
            You will see and do what{' '}
            <IdentityLabel name={target.name} email={target.email} accountType={target.accountType} />{' '}
            sees and does, with their API keys, until you stop or the time runs out. They will be told.
          </p>
        )}
        {error && <div className={styles.error} role="alert">{error}</div>}
        <div className={styles.field}>
          <label className={styles.label} htmlFor={ids.reason}>
            Reason{reasonRequired ? ' (required)' : ' (optional)'}
          </label>
          <input
            id={ids.reason}
            type="text"
            className={styles.input}
            value={reason}
            maxLength={REASON_MAX}
            placeholder="e.g. support ticket #42: recon settings not saving"
            onChange={(e) => setReason(e.target.value)}
            required={reasonRequired}
            disabled={pending}
            autoFocus
          />
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor={ids.duration}>For how long</label>
          <select
            id={ids.duration}
            className={styles.input}
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
            disabled={pending}
          >
            {choices.map((m) => <option key={m} value={m}>{durationLabel(m)}</option>)}
          </select>
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor={ids.password}>Your password</label>
          <input
            id={ids.password}
            type="password"
            className={styles.input}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            disabled={pending}
          />
        </div>
        <div className={styles.actions}>
          <button type="button" className={styles.cancel} onClick={onClose} disabled={pending}>Cancel</button>
          <button type="submit" className="primaryButton" disabled={pending}>
            {pending ? 'Checking...' : `Act as ${target?.name || 'this account'}`}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export default ActAsDialog
