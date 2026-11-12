'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import Image from 'next/image'
import { useOptionalAlertModal } from '@/components/ui'
import { showPendingNotices } from '@/components/auth/PendingNotices'
import { readApiError, toApiError } from '@/lib/apiError'
import { validateNewPassword, type PasswordPolicy } from '@/lib/authz/passwordPolicy'
import styles from '../login/page.module.css'

interface LinkState {
  kind: 'invite' | 'reset'
  name: string
  email: string
  expiresAt: string
  policy: PasswordPolicy & { maxBytes: number; description: string }
}

type View =
  | { type: 'loading' }
  | { type: 'error'; message: string }
  | { type: 'invalid' }
  | { type: 'ready'; link: LinkState }

const INVALID_TEXT = 'This link is not valid or has expired'

/**
 * The public page an invite or reset link lands on (step 2.9, ID-15). The token already left
 * the address: GET /invite/<token> traded it for a short cookie, which /api/invite/state reads.
 * The person chooses a password that meets the policy in force (checked here first, with the
 * server's own rules and messages), and is signed in. Every link that does not work shows the
 * same page, whatever the reason.
 */
export function InviteAcceptForm() {
  const alerts = useOptionalAlertModal()
  const [view, setView] = useState<View>({ type: 'loading' })
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [formError, setFormError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setView({ type: 'loading' })
    try {
      const res = await fetch('/api/invite/state', { cache: 'no-store' })
      if (!res.ok) {
        setView({ type: 'error', message: (await readApiError(res, 'Could not read the link')).message })
        return
      }
      const body = await res.json()
      setView(body?.valid ? { type: 'ready', link: body as LinkState } : { type: 'invalid' })
    } catch (err) {
      setView({ type: 'error', message: toApiError(err, 'Could not read the link').message })
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (view.type !== 'ready' || busy) return
    setFormError('')
    const check = validateNewPassword(password, view.link.policy, { email: view.link.email })
    if (!check.ok) {
      setFormError(check.message)
      return
    }
    if (password !== confirm) {
      setFormError('The two passwords do not match')
      return
    }
    setBusy(true)
    try {
      const res = await fetch('/api/invite/accept', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      })
      if (res.status === 410) {
        setView({ type: 'invalid' })
        return
      }
      if (!res.ok) {
        const err = await readApiError(res, 'Could not set the password')
        setFormError(err.message)
        return
      }
      const body = await res.json().catch(() => null)
      setPassword('')
      setConfirm('')
      await alerts?.alert(
        view.link.kind === 'invite' ? 'Your password is set and you are signed in. Welcome to RedAmon.' : 'Your password is set and you are signed in.',
        'Password set',
      )
      // A reset link's sign-in carries the reset's notice, shown once (step 2.10).
      await showPendingNotices(alerts, body?.notices)
      window.location.assign('/graph')
    } catch (err) {
      setFormError(toApiError(err, 'Could not set the password').message)
    } finally {
      setBusy(false)
    }
  }

  const heading = view.type === 'ready' && view.link.kind === 'reset' ? 'Choose a new password' : 'Accept your invitation'

  return (
    <div className={styles.page}>
      <div className={styles.card}>
        <div className={styles.header}>
          <div className={styles.logoRow}>
            <Image src="/logo.png" alt="RedAmon" width={63} height={40} priority />
            <span className={styles.logoText}>
              <span className={styles.logoAccent}>Red</span>Amon
            </span>
          </div>
          <h1 className={styles.subtitle}>{heading}</h1>
        </div>

        <div className={styles.body}>
          {view.type === 'loading' && <p className={styles.subtitle} role="status">Checking the link…</p>}

          {view.type === 'error' && (
            <div className={styles.form}>
              <div className={styles.error} role="alert">{view.message}</div>
              <button type="button" className={styles.submitButton} onClick={() => void load()}>Try again</button>
            </div>
          )}

          {view.type === 'invalid' && (
            <div className={styles.form}>
              <div className={styles.error} role="alert">{INVALID_TEXT}</div>
              <p className={styles.subtitle}>
                Open the link you were sent again, or ask an administrator for a new one.
              </p>
              <a className={styles.submitButton} href="/login">Go to sign in</a>
            </div>
          )}

          {view.type === 'ready' && (
            <form className={styles.form} onSubmit={submit} noValidate>
              <p className={styles.subtitle}>
                {view.link.name} ({view.link.email}): choose the password you will sign in with.
              </p>
              {formError && <div className={styles.error} role="alert">{formError}</div>}
              <div className={styles.field}>
                <label htmlFor="invite-password" className={styles.label}>Password</label>
                <input
                  id="invite-password"
                  type="password"
                  className={styles.input}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  aria-describedby="invite-policy"
                  autoFocus
                  required
                />
                <span id="invite-policy" className={styles.subtitle}>{view.link.policy.description}</span>
              </div>
              <div className={styles.field}>
                <label htmlFor="invite-confirm" className={styles.label}>Confirm password</label>
                <input
                  id="invite-confirm"
                  type="password"
                  className={styles.input}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="new-password"
                  required
                />
              </div>
              <button type="submit" className={styles.submitButton} disabled={busy || !password || !confirm}>
                {busy ? 'Setting the password…' : 'Set password and sign in'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}
