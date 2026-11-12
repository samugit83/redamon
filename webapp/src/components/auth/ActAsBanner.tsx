'use client'

import { useEffect, useRef, useState } from 'react'
import { UserRoundCog } from 'lucide-react'
import { useAuth, type ActingAsView } from '@/providers/AuthProvider'
import { useProject } from '@/providers/ProjectProvider'
import { IdentityLabel } from './IdentityLabel'
import styles from './ActAsBanner.module.css'

// The countdown moves by the minute; a shorter tick only keeps it from lagging a whole minute.
const TICK_MS = 15_000

/** Whole minutes left until `endsAt` (at least 0), or null when unknown. */
export function minutesLeft(endsAt: string | null, nowMs: number): number | null {
  if (!endsAt) return null
  const end = Date.parse(endsAt)
  if (Number.isNaN(end)) return null
  return Math.max(0, Math.ceil((end - nowMs) / 60_000))
}

interface ActAsBannerProps {
  actingAs: ActingAsView
  onStop: () => Promise<unknown> | void
  /** Called once when the time is up: the server has ended the impersonation by then. */
  onExpired?: () => void
  /** Tests only: the clock. */
  now?: () => number
}

/**
 * Shown on every page while an admin acts as someone (step 3.14, IM-05, ID-31; feature document
 * §4.7): whom (name, email and type), why, how long is left, whose API keys are used, and Stop.
 */
export function ActAsBanner({ actingAs, onStop, onExpired, now = Date.now }: ActAsBannerProps) {
  const [nowMs, setNowMs] = useState(now)
  const [stopping, setStopping] = useState(false)
  const expiredSent = useRef(false)

  useEffect(() => {
    const timer = setInterval(() => setNowMs(now()), TICK_MS)
    return () => clearInterval(timer)
  }, [now])

  const left = minutesLeft(actingAs.endsAt, nowMs)
  useEffect(() => {
    if (left === 0 && !expiredSent.current) {
      expiredSent.current = true
      onExpired?.()
    }
  }, [left, onExpired])

  const stop = async () => {
    setStopping(true)
    try {
      await onStop()
    } finally {
      setStopping(false)
    }
  }

  const who = actingAs.name || actingAs.email
  return (
    <div role="status" aria-label={`You are acting as ${who}`} className={styles.banner} data-testid="act-as-banner">
      <UserRoundCog size={14} className={styles.icon} aria-hidden />
      <span className={styles.text}>
        <span>You are acting as</span>
        <IdentityLabel name={actingAs.name} email={actingAs.email} accountType={actingAs.accountType} />
        <span className={styles.sep} aria-hidden>·</span>
        <span>{actingAs.reason ? `reason: ${actingAs.reason}` : 'no reason given'}</span>
        {left !== null && (
          <>
            <span className={styles.sep} aria-hidden>·</span>
            <span>{left > 0 ? `ends in ${left} min` : 'ended'}</span>
          </>
        )}
        <span className={styles.sep} aria-hidden>·</span>
        <span>uses {who}&apos;s API keys</span>
      </span>
      <button type="button" className={styles.stop} onClick={stop} disabled={stopping}>
        {stopping ? 'Stopping...' : 'Stop'}
      </button>
    </div>
  )
}

/**
 * The banner where the header mounts it: from the session's `actingAs` (permissions switch on). Stop
 * and the end of the time go back to the admin's own account through the project provider, which
 * clears the cookie and reads the session again.
 */
export function ActAsBannerSlot() {
  const { user } = useAuth()
  const { setUserId } = useProject()
  const actingAs = user?.actingAs
  if (!actingAs || !user) return null
  const backToSelf = async () => {
    await setUserId(user.id)
  }
  return <ActAsBanner key={`${actingAs.id}:${actingAs.endsAt}`} actingAs={actingAs} onStop={backToSelf} onExpired={() => { void backToSelf() }} />
}

export default ActAsBanner
