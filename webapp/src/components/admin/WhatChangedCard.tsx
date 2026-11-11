'use client'

import { useCallback, useEffect, useState } from 'react'
import { ApiError, fetchJson, toApiError } from '@/lib/apiError'
import {
  ADMIN_CHANGE_LINES, MEMBER_CHANGE_LINES, plural, type WhatsNewAnswer,
} from './updateNotes'
import styles from './AdminNotices.module.css'

type View =
  | { kind: 'loading' }
  | { kind: 'hidden' }
  | { kind: 'error'; message: string }
  | { kind: 'shown'; stdioMembers: WhatsNewAnswer['stdioMembers'] }

const ENDPOINT = '/api/admin/whats-new'

/**
 * The one-time "What changed in this update" card of the Users page (HD-32): shown to each
 * admin until that admin dismisses it, and never on an install where nothing changed (the
 * route's `applies`). It renders nothing while it loads or for a refusal.
 */
export function WhatChangedCard() {
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [dismissing, setDismissing] = useState(false)
  const [dismissError, setDismissError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const answer = await fetchJson<WhatsNewAnswer>(ENDPOINT, { cache: 'no-store' }, 'Could not load the update notes')
      setView(answer.dismissed || !answer.applies
        ? { kind: 'hidden' }
        : { kind: 'shown', stdioMembers: Array.isArray(answer.stdioMembers) ? answer.stdioMembers : [] })
    } catch (err) {
      const e = toApiError(err, 'Could not load the update notes')
      setView(e instanceof ApiError && e.status === 403 ? { kind: 'hidden' } : { kind: 'error', message: e.message })
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function dismiss() {
    setDismissing(true)
    setDismissError(null)
    try {
      await fetchJson(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'dismiss' }),
      }, 'Could not dismiss the update notes')
      setView({ kind: 'hidden' })
    } catch (err) {
      setDismissError(toApiError(err, 'Could not dismiss the update notes').message)
    } finally {
      setDismissing(false)
    }
  }

  if (view.kind === 'loading' || view.kind === 'hidden') return null
  if (view.kind === 'error') {
    return (
      <p role="status" className={styles.error}>
        Could not load the update notes: {view.message}{' '}
        <button type="button" className="textButton" onClick={() => { setView({ kind: 'loading' }); void load() }}>Retry</button>
      </p>
    )
  }

  return (
    <section aria-labelledby="whats-new-title" className={styles.card}>
      <h2 id="whats-new-title" className={styles.cardTitle}>What changed in this update</h2>
      <h3 className={styles.cardSubtitle}>For admins</h3>
      <ul className={styles.list}>
        {ADMIN_CHANGE_LINES.map(line => <li key={line}>{line}</li>)}
      </ul>
      <h3 className={styles.cardSubtitle}>For members</h3>
      <ul className={styles.list}>
        {MEMBER_CHANGE_LINES.map(line => <li key={line}>{line}</li>)}
      </ul>
      {view.stdioMembers.length > 0 && (
        <>
          <h3 className={styles.cardSubtitle}>stdio MCP servers that no longer load</h3>
          <p className={styles.cardText}>
            A stdio server runs inside the agent, so only an admin&apos;s is started now. These accounts&apos; servers stay
            saved but are not loaded:
          </p>
          <ul className={styles.list}>
            {view.stdioMembers.map(m => (
              <li key={m.id}>{m.name} ({m.email}): {plural(m.servers, 'server', 'servers')}</li>
            ))}
          </ul>
        </>
      )}
      {dismissError && <p role="alert" className={styles.inlineError}>{dismissError}</p>}
      <div className={styles.actions} style={{ marginTop: 'var(--space-3)' }}>
        <button type="button" className="secondaryButton" onClick={dismiss} disabled={dismissing}>
          {dismissing ? 'Saving...' : 'Got it'}
        </button>
      </div>
    </section>
  )
}
