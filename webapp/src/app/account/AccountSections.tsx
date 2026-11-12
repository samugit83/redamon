'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useAlertModal } from '@/components/ui'
import { IdentityLabel, type AccountType } from '@/components/auth/IdentityLabel'
import { RootTransferAction } from '@/components/admin/RootTransferAction'
import { useUsers } from '@/hooks/useUsers'
import { readApiError, toApiError } from '@/lib/apiError'
import type { AuthUser } from '@/providers/AuthProvider'
import styles from './page.module.css'

/**
 * The My account sections that exist with the identity switch on (step 2.11, UI-09): who the
 * account is, its name and sign-in email (the email with its current password, ID-30), "Sign out
 * everywhere", its MCP tokens, Root's transfer, and "My activity".
 */

const JSON_HEADERS = { 'Content-Type': 'application/json' }

export function ProfileSection({ account }: { account: AuthUser }) {
  const { alert } = useAlertModal()
  const [name, setName] = useState(account.name)
  const [nameState, setNameState] = useState<{ saving: boolean; error: string; saved: boolean }>({ saving: false, error: '', saved: false })
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [emailState, setEmailState] = useState<{ saving: boolean; error: string }>({ saving: false, error: '' })

  async function saveName(e: FormEvent) {
    e.preventDefault()
    if (!name.trim()) {
      setNameState({ saving: false, error: 'Enter a name.', saved: false })
      return
    }
    setNameState({ saving: true, error: '', saved: false })
    try {
      const res = await fetch(`/api/users/${account.id}`, { method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify({ name: name.trim() }) })
      if (!res.ok) {
        setNameState({ saving: false, error: (await readApiError(res, 'Could not save your name')).message, saved: false })
        return
      }
      setNameState({ saving: false, error: '', saved: true })
    } catch (err) {
      setNameState({ saving: false, error: toApiError(err, 'Could not save your name').message, saved: false })
    }
  }

  async function changeEmail(e: FormEvent) {
    e.preventDefault()
    if (!email.trim()) {
      setEmailState({ saving: false, error: 'Enter the new email address.' })
      return
    }
    if (!password) {
      setEmailState({ saving: false, error: 'Enter your current password to change your email.' })
      return
    }
    setEmailState({ saving: true, error: '' })
    try {
      const res = await fetch(`/api/users/${account.id}`, {
        method: 'PUT',
        headers: JSON_HEADERS,
        body: JSON.stringify({ email: email.trim(), currentPassword: password }),
      })
      if (!res.ok) {
        setEmailState({ saving: false, error: (await readApiError(res, 'Could not change your email')).message })
        return
      }
      const saved = await res.json().catch(() => ({})) as { email?: string }
      setPassword('')
      setEmailState({ saving: false, error: '' })
      await alert(`You now sign in with ${saved.email ?? email.trim().toLowerCase()}.`, 'Sign-in email changed')
      // The header and every screen read the address from the session: read it again.
      window.location.reload()
    } catch (err) {
      setEmailState({ saving: false, error: toApiError(err, 'Could not change your email').message })
    }
  }

  return (
    <section className={styles.section} aria-labelledby="account-profile-title">
      <h2 id="account-profile-title" className={styles.sectionTitle}>Profile</h2>
      <p className={styles.hint}>
        <IdentityLabel name={account.name} email={account.email} accountType={account.accountType as AccountType} />
      </p>
      <form className={styles.form} onSubmit={saveName} noValidate>
        {nameState.error && <div className={styles.error} role="alert">{nameState.error}</div>}
        {nameState.saved && <div className={styles.success} role="status">Your name was saved.</div>}
        <div className={styles.field}>
          <label className={styles.label} htmlFor="account-name">Name</label>
          <input id="account-name" className={styles.input} value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
        </div>
        <div className={styles.actions}>
          <button type="submit" className="primaryButton" disabled={nameState.saving}>
            {nameState.saving ? 'Saving…' : 'Save name'}
          </button>
        </div>
      </form>
      <form className={styles.form} onSubmit={changeEmail} noValidate>
        {emailState.error && <div className={styles.error} role="alert">{emailState.error}</div>}
        <div className={styles.field}>
          <label className={styles.label} htmlFor="account-new-email">New sign-in email</label>
          <input
            id="account-new-email"
            type="email"
            className={styles.input}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            aria-describedby="account-email-hint"
          />
          <span id="account-email-hint" className={styles.hint}>
            You sign in with this address. Changing it needs your current password and is shown to you at your next sign-in.
          </span>
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor="account-email-password">Current password for the email change</label>
          <input
            id="account-email-password"
            type="password"
            className={styles.input}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>
        <div className={styles.actions}>
          <button type="submit" className="primaryButton" disabled={emailState.saving}>
            {emailState.saving ? 'Saving…' : 'Change email'}
          </button>
        </div>
      </form>
    </section>
  )
}

export function SessionsSection({ account }: { account: AuthUser }) {
  const { dangerConfirm } = useAlertModal()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const confirmedRoot = account.accountType === 'root' && account.rbac?.root?.confirmed === true

  async function signOutEverywhere() {
    setError('')
    const ok = await dangerConfirm(
      'This signs you out of every browser, this one included, closes your open agent and terminal sessions, and revokes your MCP tokens.',
      'Sign out everywhere',
      { confirmLabel: 'Sign out everywhere' },
    )
    if (!ok) return
    setBusy(true)
    try {
      const res = await fetch('/api/auth/sessions/revoke-all', { method: 'POST', headers: JSON_HEADERS, body: '{}' })
      if (!res.ok) {
        setError((await readApiError(res, 'Could not sign out everywhere')).message)
        return
      }
      window.location.assign('/login')
    } catch (err) {
      setError(toApiError(err, 'Could not sign out everywhere').message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className={styles.section} aria-labelledby="account-sessions-title">
      <h2 id="account-sessions-title" className={styles.sectionTitle}>Sessions and tokens</h2>
      {error && <div className={styles.error} role="alert">{error}</div>}
      <p className={styles.hint}>
        Signed in somewhere you no longer use, or think someone else is? End every session of this account at once.
      </p>
      <div className={styles.actions}>
        <button type="button" className={styles.dangerButton} onClick={signOutEverywhere} disabled={busy}>
          Sign out everywhere
        </button>
      </div>
      <p className={styles.hint}>
        <Link href="/settings?tab=mcp-tokens">Manage your MCP tokens</Link>
      </p>
      {confirmedRoot && <RootTransferRow selfId={account.id} />}
    </section>
  )
}

/** Root's transfer, as on its own Users page row (step 2.6); the candidates are the admins. */
function RootTransferRow({ selfId }: { selfId: string }) {
  const { data: users } = useUsers()
  return (
    <div className={styles.actions}>
      <RootTransferAction selfId={selfId} users={users ?? []} className="secondaryButton" />
    </div>
  )
}

interface NoticeItem {
  id: string
  type: 'credentials_reset' | 'email_changed'
  at: string
  by: { name: string; email: string }
  reason?: string | null
  mode?: 'link' | 'temporary'
  from?: string
  to?: string
  self?: boolean
  shownAt: string | null
}

interface EventItem {
  id: string
  at: string
  action: string
  by: { name: string; email: string } | null
  details: Record<string, unknown>
}

const text = (v: unknown) => (typeof v === 'string' && v ? v : null)

function noticeText(n: NoticeItem): string {
  if (n.type === 'email_changed') return `Your sign-in email was changed from ${n.from} to ${n.to}`
  return `Your password was reset with ${n.mode === 'link' ? 'a reset link' : 'a temporary password'}${n.reason ? ` (reason: ${n.reason})` : ''}`
}

/** What an activity row says. The server sends only the safe fields of each action. */
export function eventText(e: EventItem): string {
  const d = e.details
  switch (e.action) {
    case 'user.credentials_reset':
      return `Password reset with ${d.mode === 'link' ? 'a reset link' : 'a temporary password'}${text(d.reason) ? ` (reason: ${d.reason})` : ''}`
    case 'auth.login.after_reset':
      return `First sign-in after a reset${text(d.ip) ? `, from ${d.ip}` : ''}${text(d.userAgent) ? ` (${d.userAgent})` : ''}`
    case 'user.email_changed':
      return `Sign-in email changed from ${d.from} to ${d.to}`
    case 'act_as.start':
      return 'An admin started acting as you'
    case 'act_as.end':
      return 'An admin stopped acting as you'
    case 'root.transfer_offered':
      return 'Root was offered to you'
    case 'root.transfer':
      return 'You became Root'
    case 'root.transfer_cancelled':
      return 'A Root transfer offer to you was withdrawn'
    case 'root.transfer_declined':
      return 'You declined a Root transfer'
    case 'root.set_by_host':
      return 'The host made you Root'
    case 'root.confirmed_by_host':
      return 'The host confirmed you as Root'
    case 'system.rbac_root_assigned':
      return 'You were chosen as Root automatically'
    default:
      return e.action
  }
}

const when = (iso: string) => new Date(iso).toLocaleString()
const byText = (by: { name: string; email: string } | null) => (by ? ` by ${by.name ? `${by.name} (${by.email})` : by.email}` : '')

export function ActivitySection() {
  const [state, setState] = useState<
    { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready'; notices: NoticeItem[]; events: EventItem[] }
  >({ kind: 'loading' })

  const load = useCallback(async () => {
    setState({ kind: 'loading' })
    try {
      const res = await fetch('/api/account/activity')
      if (!res.ok) {
        setState({ kind: 'error', message: (await readApiError(res, 'Could not read your activity')).message })
        return
      }
      const body = await res.json() as { notices?: NoticeItem[]; events?: EventItem[] }
      setState({ kind: 'ready', notices: body.notices ?? [], events: body.events ?? [] })
    } catch (err) {
      setState({ kind: 'error', message: toApiError(err, 'Could not read your activity').message })
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <section className={styles.section} aria-labelledby="account-activity-title">
      <h2 id="account-activity-title" className={styles.sectionTitle}>My activity</h2>
      {state.kind === 'loading' && <p className={styles.state} role="status">Loading your activity…</p>}
      {state.kind === 'error' && (
        <>
          <div className={styles.error} role="alert">{state.message}</div>
          <div className={styles.actions}>
            <button type="button" className="secondaryButton" onClick={() => void load()}>Retry</button>
          </div>
        </>
      )}
      {state.kind === 'ready' && state.notices.length === 0 && state.events.length === 0 && (
        <p className={styles.state}>Nothing to show yet.</p>
      )}
      {state.kind === 'ready' && (state.notices.length > 0 || state.events.length > 0) && (
        <ul className={styles.activity}>
          {state.notices.map((n) => (
            <li key={`n-${n.id}`} className={styles.activityItem}>
              <span className={styles.activityWhen}>{when(n.at)}</span>
              <span>
                {noticeText(n)}{n.self ? '' : byText(n.by)}.{' '}
                <span className={styles.activityTag}>{n.shownAt ? 'Notice, shown' : 'Notice, new'}</span>
              </span>
            </li>
          ))}
          {state.events.map((e) => (
            <li key={`e-${e.id}`} className={styles.activityItem}>
              <span className={styles.activityWhen}>{when(e.at)}</span>
              <span>{eventText(e)}{byText(e.by)}.</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
