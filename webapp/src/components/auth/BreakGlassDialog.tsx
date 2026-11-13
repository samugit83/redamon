'use client'

import { useEffect, useId, useState, type FormEvent } from 'react'
import { Modal } from '@/components/ui'
import { durationLabel } from './ActAsDialog'
import styles from './ActAsDialog.module.css'

/** The longest break-glass the server grants (lib/authz/breakGlass.ts BREAKGLASS_MAX_MINUTES). */
export const BREAK_GLASS_MAX_MINUTES = 240
export const BREAK_GLASS_DURATIONS = [15, 30, 60, 120, 240] as const
const DEFAULT_MINUTES = 60
const REASON_MAX = 500

export interface BreakGlassTarget {
  id: string
  name: string
  /** "Name (email)" of the owner. */
  owner: string
}

export interface BreakGlassInput {
  reason: string
  durationMinutes: number
  password: string
}

interface BreakGlassDialogProps {
  isOpen: boolean
  target: BreakGlassTarget | null
  /** Opens it. Resolving closes the dialog; throwing keeps it open and shows the error's message. */
  onConfirm: (input: BreakGlassInput) => Promise<void>
  onClose: () => void
}

/**
 * Root's break-glass on someone's project (step 4.14, SH-18; feature document §4.5): why, for how
 * long (at most 4 hours), and Root's own password. The owner is told, and the project's activity
 * feed lists it.
 */
export function BreakGlassDialog({ isOpen, target, onConfirm, onClose }: BreakGlassDialogProps) {
  const ids = { reason: useId(), duration: useId(), password: useId() }
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState(DEFAULT_MINUTES)
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (!isOpen) {
      setReason('')
      setPassword('')
      setError('')
      setPending(false)
      setDuration(DEFAULT_MINUTES)
    }
  }, [isOpen])

  async function submit(e?: FormEvent) {
    e?.preventDefault()
    if (pending) return
    if (!reason.trim()) {
      setError('Say why you need break-glass access')
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
      setError(err instanceof Error ? err.message : 'Break-glass was refused')
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={pending ? () => {} : onClose} title="Break-glass access" size="small">
      <form className={styles.form} onSubmit={submit} noValidate>
        {target && (
          <p className={styles.message}>
            You will read everything in &quot;{target.name}&quot;, raw data and files included, until the time runs out or you
            close it. {target.owner} will be told, with your reason, and the project&apos;s activity lists it.
          </p>
        )}
        {error && <div className={styles.error} role="alert">{error}</div>}
        <div className={styles.field}>
          <label className={styles.label} htmlFor={ids.reason}>Reason (required)</label>
          <input
            id={ids.reason}
            type="text"
            className={styles.input}
            value={reason}
            maxLength={REASON_MAX}
            placeholder="e.g. incident 7: a leaked key must be traced"
            onChange={(e) => setReason(e.target.value)}
            required
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
            {BREAK_GLASS_DURATIONS.map((m) => <option key={m} value={m}>{durationLabel(m)}</option>)}
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
            {pending ? 'Checking...' : 'Open break-glass'}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export default BreakGlassDialog
