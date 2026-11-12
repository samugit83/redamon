'use client'

import { useCallback, useEffect, useState } from 'react'
import { Crown } from 'lucide-react'
import { useOptionalAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { fetchJson, toApiError } from '@/lib/apiError'
import styles from './AdminNotices.module.css'

/** Fired after an offer is made, accepted, declined or cancelled: the banner reads it again. */
export const ROOT_TRANSFER_CHANGED_EVENT = 'redamon:root-transfer-changed'

export interface RootTransferOffer {
  toUserId: string
  toEmail: string
  fromEmail: string
  /** ISO time the offer ends. */
  expiresAt: string
  /** The signed-in admin is the recipient (else it is Root, who made it). */
  forYou: boolean
}

const WITHDRAW_FAILED = 'Could not withdraw the Root transfer'

/**
 * The header's Root transfer banner (step 2.6, ID-07): admins only, identity switch on. It reads
 * the pending offer from GET /api/root/transfer, which answers only Root and the recipient. The
 * recipient accepts with its own password (both accounts sign in again, so the browser goes to
 * /login) or declines; Root may cancel. Declining and cancelling are confirmed through the app's
 * dialog; refusals show the server's message and code. No offer, or a failed read: nothing (a
 * banner never blocks the page).
 */
export function RootTransferBanner() {
  const alerts = useOptionalAlertModal()
  const [offer, setOffer] = useState<RootTransferOffer | null>(null)
  const [accepting, setAccepting] = useState(false)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/root/transfer', { cache: 'no-store' })
      const body = res.ok ? await res.json() as { offer?: RootTransferOffer | null } : null
      setOffer(body?.offer ?? null)
    } catch {
      setOffer(null)
    }
  }, [])

  useEffect(() => {
    void load()
    const reload = () => void load()
    window.addEventListener(ROOT_TRANSFER_CHANGED_EVENT, reload)
    return () => window.removeEventListener(ROOT_TRANSFER_CHANGED_EVENT, reload)
  }, [load])

  if (!offer) return null
  const until = offer.expiresAt.slice(0, 10)

  async function withdraw(message: string, title: string, label: string) {
    if (!(await alerts?.confirm(message, title, { confirmLabel: label }))) return
    setBusy(true)
    try {
      await fetchJson('/api/root/transfer/cancel', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      }, WITHDRAW_FAILED)
    } catch (err) {
      void alerts?.alertError(toApiError(err, WITHDRAW_FAILED).message, title)
    } finally {
      setBusy(false)
      window.dispatchEvent(new Event(ROOT_TRANSFER_CHANGED_EVENT))
    }
  }

  if (!offer.forYou) {
    return (
      <div role="status" aria-label="Root transfer pending" className={`${styles.banner} ${styles.rootNotice}`}>
        <Crown size={14} className={styles.icon} aria-hidden />
        <span>
          You offered Root to <strong>{offer.toEmail}</strong> until {until} (UTC); it moves when they accept.{' '}
        </span>
        <button
          type="button"
          className={styles.bannerAction}
          disabled={busy}
          onClick={() => void withdraw(`Cancel the offer of Root to ${offer.toEmail}? You stay Root.`, 'Cancel the Root transfer', 'Cancel the offer')}
        >
          Cancel the offer
        </button>
      </div>
    )
  }

  return (
    <div role="status" aria-label="Root transfer offered to you" className={`${styles.banner} ${styles.rootNotice}`}>
      <Crown size={14} className={styles.icon} aria-hidden />
      <span>
        <strong>{offer.fromEmail}</strong> offers you Root until {until} (UTC).{' '}
      </span>
      <button type="button" className={styles.bannerAction} disabled={busy} onClick={() => setAccepting(true)}>
        Accept Root
      </button>
      <button
        type="button"
        className={styles.bannerAction}
        disabled={busy}
        onClick={() => void withdraw(`Decline Root from ${offer.fromEmail}? They stay Root.`, 'Decline Root', 'Decline')}
      >
        Decline
      </button>
      <StepUpModal
        isOpen={accepting}
        title="Accept Root"
        message="You become this instance's Root: you manage the admins and the security policy. You and the current Root both sign in again. Confirm with your own password."
        confirmLabel="Accept Root"
        onConfirm={async (pw) => {
          await fetchJson('/api/root/transfer/accept', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ stepUpPassword: pw }),
          }, 'Could not accept Root')
          // Both sessions ended; this browser's cookie was cleared on the answer.
          window.location.replace('/login')
        }}
        onClose={() => setAccepting(false)}
      />
    </div>
  )
}
