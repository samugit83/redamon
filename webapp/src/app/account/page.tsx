'use client'

import { useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'
import { useAlertModal } from '@/components/ui'
import { usePasswordPolicy } from '@/hooks/usePasswordPolicy'
import { BASE_PASSWORD_POLICY, validateNewPassword } from '@/lib/authz/passwordPolicy'
import { readApiError, toApiError } from '@/lib/apiError'
import { ActivitySection, MyPermissionsSection, ProfileSection, SessionsSection } from './AccountSections'
import { QuotaUsage } from '@/components/quotas/QuotaUsage'
import styles from './page.module.css'

/**
 * My account (step 2.8: the password form; step 2.11, UI-09: the rest). While an account's
 * password must change (identity switch on), the middleware holds the browser here with
 * `?changePassword=1` and every other API answers 403, so only the password form shows; the
 * password route then re-issues the login cookie without the must-change claim, so a full
 * navigation goes on into the app. With the identity switch on (the session then carries an
 * account type) the page also holds the profile, the sessions and My activity, and with the
 * permissions switch on My permissions (step 3.13); off, the password form alone, as step 2.8
 * built it.
 */
export default function AccountPage() {
  const { user, isLoading, sessionError } = useAuth()
  const forced = useSearchParams().get('changePassword') === '1'
  const policy = usePasswordPolicy(user?.flags?.identity === true)
  const { alert } = useAlertModal()

  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [changed, setChanged] = useState(false)
  const [saving, setSaving] = useState(false)

  if (isLoading) {
    return <main className={styles.page}><p className={styles.state} role="status">Loading your account…</p></main>
  }
  if (!user) {
    return (
      <main className={styles.page}>
        <h1 className={styles.title}>My account</h1>
        {sessionError ? (
          <>
            <div className={styles.error} role="alert">{sessionError.message}</div>
            <div className={styles.actions}>
              <button type="button" className="primaryButton" onClick={() => window.location.reload()}>Retry</button>
            </div>
          </>
        ) : (
          <p className={styles.state}>You are signed out. <Link href="/login">Sign in</Link> to change your password.</p>
        )}
      </main>
    )
  }
  const account = user

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setChanged(false)
    if (!current) {
      setError('Enter your current password')
      return
    }
    const check = validateNewPassword(next, policy ?? BASE_PASSWORD_POLICY, { email: account.email })
    if (!check.ok) {
      setError(check.message)
      return
    }
    if (next !== confirm) {
      setError('The new passwords do not match')
      return
    }
    setSaving(true)
    try {
      const res = await fetch(`/api/users/${account.id}/password`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: current, newPassword: next }),
      })
      if (!res.ok) {
        setError((await readApiError(res, 'Could not change your password')).message)
        return
      }
      setCurrent('')
      setNext('')
      setConfirm('')
      if (forced) {
        await alert('Your password was changed. You can now use RedAmon.', 'Password changed')
        // A full navigation, so the middleware reads the cookie this answer re-issued.
        window.location.assign('/graph')
        return
      }
      setChanged(true)
    } catch (err) {
      setError(toApiError(err, 'Could not change your password').message)
    } finally {
      setSaving(false)
    }
  }

  const full = account.accountType !== undefined && !forced

  return (
    <main className={styles.page}>
      <h1 className={styles.title}>My account</h1>
      {full && <ProfileSection account={account} />}
      <section className={styles.section} aria-labelledby="account-password-title">
        <h2 id="account-password-title" className={styles.sectionTitle}>Password</h2>
        {forced && (
          <p className={styles.notice}>
            You must change your password before you continue: the one you signed in with was set by an
            administrator or is shorter than this instance now asks for.
          </p>
        )}
        <form className={styles.form} onSubmit={onSubmit} noValidate>
          {error && <div className={styles.error} role="alert">{error}</div>}
          {changed && <div className={styles.success} role="status">Your password was changed.</div>}
          <div className={styles.field}>
            <label className={styles.label} htmlFor="account-current-password">Current password</label>
            <input
              id="account-current-password"
              type="password"
              className={styles.input}
              value={current}
              onChange={e => setCurrent(e.target.value)}
              autoComplete="current-password"
              autoFocus={!full}
            />
          </div>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="account-new-password">New password</label>
            <input
              id="account-new-password"
              type="password"
              className={styles.input}
              value={next}
              onChange={e => setNext(e.target.value)}
              autoComplete="new-password"
              aria-describedby={policy ? 'account-password-policy' : undefined}
            />
            {policy && <span id="account-password-policy" className={styles.hint}>{policy.description}</span>}
          </div>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="account-confirm-password">Confirm new password</label>
            <input
              id="account-confirm-password"
              type="password"
              className={styles.input}
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              autoComplete="new-password"
            />
          </div>
          <div className={styles.actions}>
            <button type="submit" className="primaryButton" disabled={saving}>
              {saving ? 'Saving…' : 'Change password'}
            </button>
          </div>
        </form>
      </section>
      {full && <SessionsSection account={account} />}
      {full && account.flags?.permissions === true && <MyPermissionsSection account={account} />}
      {full && account.flags?.governance === true && (
        <QuotaUsage userId={account.id} own classes={{ section: styles.section, title: styles.sectionTitle }} />
      )}
      {full && <ActivitySection />}
    </main>
  )
}
