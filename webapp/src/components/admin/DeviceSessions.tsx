'use client'

import { useCallback, useEffect, useState } from 'react'
import { useAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { ApiError, fetchJson, readApiError, toApiError } from '@/lib/apiError'
import styles from './DeviceSessions.module.css'

/**
 * One account's device sessions (step 6.10, GV-17, UI-09): each browser it signed in from, with its
 * address, its browser and when it was last active, and Revoke on the live ones, which signs that
 * browser out at its next request and leaves the others signed in. My account lists the person's own
 * (`/api/account/sessions`, the browser asking marked "This device", which signs out through Sign
 * out); the admin console's user detail lists another account's (`/api/users/[id]/sessions`), where
 * revoking an admin's asks for the admin's own password. Every revoke is confirmed first.
 */

export interface DeviceSessionItem {
  id: string
  createdAt: string
  lastSeenAt: string
  expiresAt: string
  ip: string | null
  ipTrusted: boolean
  userAgent: string | null
  state: 'active' | 'revoked' | 'signed_out' | 'ended' | 'expired'
  revokedAt: string | null
  current: boolean
}

interface RevokeAnswer {
  changed?: boolean
  agent?: { sockets?: { closed?: number; error?: string } }
}

interface Props {
  listUrl: string
  revokeUrl: (id: string) => string
  /** Whose sessions: the person's own, or another account's (its name). */
  subject: 'self' | { name: string }
  /** Another admin's: a revoke takes the admin's own password. */
  stepUp?: boolean
}

const STATE_LABEL: Record<DeviceSessionItem['state'], string> = {
  active: 'Active',
  revoked: 'Revoked',
  signed_out: 'Signed out',
  ended: 'Ended (signed out everywhere)',
  expired: 'Expired',
}

/** "Firefox on Linux" from a User-Agent header, or what can be told of it. */
export function describeUserAgent(ua: string | null): string {
  if (!ua) return 'Unknown browser'
  const browser = /Edg\//.test(ua) ? 'Edge'
    : /OPR\//.test(ua) ? 'Opera'
      : /Firefox\//.test(ua) ? 'Firefox'
        : /Chrome\//.test(ua) ? 'Chrome'
          : /Version\/[\d.]+.*Safari\//.test(ua) ? 'Safari'
            : /^curl\//.test(ua) ? 'curl'
              : null
  const os = /iPhone|iPad|iPod/.test(ua) ? 'iOS'
    : /Android/.test(ua) ? 'Android'
      : /Windows NT/.test(ua) ? 'Windows'
        : /Mac OS X|Macintosh/.test(ua) ? 'macOS'
          : /CrOS/.test(ua) ? 'ChromeOS'
            : /Linux/.test(ua) ? 'Linux'
              : null
  if (browser && os) return `${browser} on ${os}`
  return browser ?? os ?? 'Unknown browser'
}

const when = (iso: string) => new Date(iso).toLocaleString()

export function DeviceSessions({ listUrl, revokeUrl, subject, stepUp = false }: Props) {
  const { dangerConfirm, alertError, alertWarning } = useAlertModal()
  const [items, setItems] = useState<DeviceSessionItem[] | null>(null)
  const [loadError, setLoadError] = useState<ApiError | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [askPassword, setAskPassword] = useState<DeviceSessionItem | null>(null)
  const self = subject === 'self'

  const load = useCallback(async () => {
    setLoadError(null)
    try {
      const data = await fetchJson<{ sessions: DeviceSessionItem[] }>(listUrl, { cache: 'no-store' }, 'Could not read the sessions')
      setItems(Array.isArray(data.sessions) ? data.sessions : [])
    } catch (err) {
      setItems(null)
      setLoadError(toApiError(err, 'Could not read the sessions'))
    }
  }, [listUrl])

  useEffect(() => { void load() }, [load])

  /** Sends the revoke; a refusal throws its ApiError. */
  async function send(item: DeviceSessionItem, body?: Record<string, unknown>): Promise<void> {
    const res = await fetch(revokeUrl(item.id), {
      method: 'DELETE',
      ...(body ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}),
    })
    if (!res.ok) throw await readApiError(res, 'Could not revoke the session')
    const answer = await res.json().catch(() => ({})) as RevokeAnswer
    await load()
    const unclosed = answer.agent?.sockets?.error
    if (unclosed) {
      await alertWarning(
        `The session was revoked, but the agent did not confirm that its open agent and terminal connections closed (${unclosed}). `
        + 'They end when the agent is reachable again and closes them, or when the browser leaves the page.',
        'Session revoked',
      )
    }
  }

  async function revoke(item: DeviceSessionItem) {
    if (stepUp) {
      setAskPassword(item)
      return
    }
    const ok = await dangerConfirm(
      `${self ? 'Sign this browser out' : `Sign ${(subject as { name: string }).name} out of this browser`} (${describeUserAgent(item.userAgent)}${item.ip ? `, ${item.ip}` : ''})? `
      + 'It is refused from its next request on; the other browsers stay signed in. Open agent and terminal connections of the account close too, and reconnect on the browsers still signed in.',
      'Revoke a session',
      { confirmLabel: 'Revoke' },
    )
    if (!ok) return
    setBusy(item.id)
    try {
      await send(item)
    } catch (err) {
      await alertError(toApiError(err, 'Could not revoke the session').message, 'Session not revoked')
    } finally {
      setBusy(null)
    }
  }

  if (loadError) {
    const permission = forbiddenPermission(loadError)
    if (permission) return <ForbiddenNotice permission={permission} />
    return (
      <div className={styles.wrap}>
        <div className={styles.error} role="alert">{loadError.message}</div>
        <button type="button" className={`secondaryButton ${styles.retry}`} onClick={() => void load()}>Retry</button>
      </div>
    )
  }
  if (!items) return <p className={styles.state} role="status">Loading sessions…</p>

  return (
    <div className={styles.wrap}>
      <p className={styles.hint}>
        {self
          ? 'Each browser you signed in from. Revoking one signs that browser out at its next request; your other browsers stay signed in. A browser signed in before device sessions were turned on is not listed: Sign out everywhere ends it.'
          : 'Each browser this account signed in from. Revoking one signs that browser out at its next request; its other browsers stay signed in. A browser signed in before device sessions were turned on is not listed: signing the account out everywhere ends it.'}
      </p>
      {items.length === 0 ? (
        <p className={styles.state}>No device session is recorded{self ? ' for your account' : ' for this account'} yet.</p>
      ) : (
        <ul className={styles.list} aria-label={self ? 'Your device sessions' : `Device sessions of ${(subject as { name: string }).name}`}>
          {items.map((item) => {
            const label = describeUserAgent(item.userAgent)
            const live = item.state === 'active'
            return (
              <li key={item.id} className={live ? styles.item : `${styles.item} ${styles.ended}`}>
                <div className={styles.what}>
                  <span className={styles.device}>
                    <span title={item.userAgent ?? undefined}>{label}</span>
                    {item.current && live
                      ? <span className={`${styles.badge} ${styles.current}`}>This device</span>
                      : <span className={styles.badge}>{STATE_LABEL[item.state]}</span>}
                  </span>
                  <span className={styles.meta}>
                    {item.ip ? `${item.ip}${item.ipTrusted ? '' : ' (address not verified)'}` : 'Address unknown'}
                    {' · '}Signed in {when(item.createdAt)}
                    {' · '}Last active {when(item.lastSeenAt)}
                    {item.revokedAt ? ` · Ended ${when(item.revokedAt)}` : ''}
                  </span>
                </div>
                {live && !item.current && (
                  <button
                    type="button"
                    className={styles.revoke}
                    disabled={busy !== null}
                    aria-label={`Revoke the session of ${label}, last active ${when(item.lastSeenAt)}`}
                    onClick={() => void revoke(item)}
                  >
                    {busy === item.id ? 'Revoking…' : 'Revoke'}
                  </button>
                )}
              </li>
            )
          })}
        </ul>
      )}
      {stepUp && (
        <StepUpModal
          isOpen={askPassword !== null}
          title="Revoke an admin's session"
          message={`Sign ${self ? 'this' : (subject as { name: string }).name} out of ${askPassword ? describeUserAgent(askPassword.userAgent) : 'this browser'}? Confirm with your own password.`}
          confirmLabel="Revoke"
          onConfirm={async (password) => {
            if (askPassword) await send(askPassword, { stepUpPassword: password })
          }}
          onClose={() => setAskPassword(null)}
        />
      )}
    </div>
  )
}
