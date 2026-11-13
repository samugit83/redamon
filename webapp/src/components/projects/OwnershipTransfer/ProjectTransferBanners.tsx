'use client'

import { useCallback, useEffect, useState } from 'react'
import { ArrowRightLeft, ListChecks } from 'lucide-react'
import { useOptionalAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { useAuth } from '@/providers/AuthProvider'
import { fetchJson, toApiError } from '@/lib/apiError'
import type { ClearedView, TransferView } from '@/lib/authz/ownershipTransfer'
import { FINDING_IDS_NOTE, PROJECT_TRANSFER_CHANGED_EVENT, ROLE_TEXT, clearedLine, personName, untilDate } from './transferText'
import styles from './OwnershipTransfer.module.css'

interface Feed {
  incoming: TransferView[]
  outgoing: TransferView[]
  cleared: ClearedView[]
}

const EMPTY: Feed = { incoming: [], outgoing: [], cleared: [] }
const JSON_HEADERS = { 'Content-Type': 'application/json' }

const base = (projectId: string) => `/api/projects/${encodeURIComponent(projectId)}/transfer`

/**
 * The header's ownership transfer banners (step 5.12; SH-15): only while write sharing is in force
 * (/api/auth/me's `sharing`), from GET /api/projects/transfers. The recipient of an offer accepts it with
 * their own password or declines it; the owner who made one may cancel it; the new owner sees the settings
 * the transfer cleared, to re-pick, and the note about findings their scans will record anew (OQ-R8), until
 * they dismiss it. While an admin acts as someone the banners show and offer nothing to do (the routes
 * refuse it). A failed read shows nothing: a banner never blocks the page.
 */
export function ProjectTransferBanners() {
  // The header renders it, inside the auth provider (which the header itself needs).
  const { user } = useAuth()
  const alerts = useOptionalAlertModal()
  const inForce = user?.sharing?.enabled === true && user.sharing.maxLevel === 'write'
  const readOnly = Boolean(user?.actingAs)
  const [feed, setFeed] = useState<Feed>(EMPTY)
  const [accepting, setAccepting] = useState<TransferView | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    if (!inForce) {
      setFeed(EMPTY)
      return
    }
    try {
      const res = await fetch('/api/projects/transfers', { cache: 'no-store' })
      setFeed(res.ok ? { ...EMPTY, ...(await res.json() as Partial<Feed>) } : EMPTY)
    } catch {
      setFeed(EMPTY)
    }
  }, [inForce])

  useEffect(() => {
    void load()
    const reload = () => void load()
    window.addEventListener(PROJECT_TRANSFER_CHANGED_EVENT, reload)
    return () => window.removeEventListener(PROJECT_TRANSFER_CHANGED_EVENT, reload)
  }, [load])

  async function act(path: string, failure: string, confirm?: { message: string; title: string; label: string }) {
    if (confirm && !(await alerts?.confirm(confirm.message, confirm.title, { confirmLabel: confirm.label }))) return
    setBusy(true)
    try {
      await fetchJson(path, { method: 'POST', headers: JSON_HEADERS, body: '{}' }, failure)
    } catch (err) {
      void alerts?.alertError(toApiError(err, failure).message, confirm?.title)
    } finally {
      setBusy(false)
      window.dispatchEvent(new Event(PROJECT_TRANSFER_CHANGED_EVENT))
    }
  }

  if (!inForce || (feed.incoming.length + feed.outgoing.length + feed.cleared.length === 0)) return null

  return (
    <div className={styles.slot}>
      {feed.incoming.map((o) => (
        <div key={o.id} role="status" aria-label={`Ownership of ${o.project.name} offered to you`} className={styles.banner}>
          <ArrowRightLeft size={14} className={styles.icon} aria-hidden />
          <span className={styles.text}>
            <strong>{personName(o.from)}</strong> offers you ownership of <strong>{o.project.name}</strong> until {untilDate(o.expiresAt)};
            they {ROLE_TEXT[o.oldOwnerRole]}.
            {o.status === 'failed' && ` The last attempt did not complete (${o.error ?? 'failed'}): you can accept again.`}
            {o.status === 'in_progress' && ' The transfer is in progress.'}
          </span>
          {!readOnly && o.status !== 'in_progress' && (
            <>
              <button type="button" className={styles.action} disabled={busy} onClick={() => setAccepting(o)}>Accept</button>
              <button
                type="button"
                className={styles.action}
                disabled={busy}
                onClick={() => void act(`${base(o.project.id)}/decline`, 'Could not decline the project', {
                  message: `Decline ownership of "${o.project.name}"? ${personName(o.from)} stays its owner and you keep your share.`,
                  title: 'Decline the project', label: 'Decline',
                })}
              >
                Decline
              </button>
            </>
          )}
        </div>
      ))}
      {feed.outgoing.map((o) => (
        <div key={o.id} role="status" aria-label={`Ownership of ${o.project.name} offered`} className={styles.banner}>
          <ArrowRightLeft size={14} className={styles.icon} aria-hidden />
          <span className={styles.text}>
            You offered <strong>{o.project.name}</strong> to <strong>{personName(o.to)}</strong> until {untilDate(o.expiresAt)}; it
            moves when they accept, and you {o.oldOwnerRole === 'co-owner' ? 'then stay on as a co-owner' : 'then leave the project'}.
            {o.status === 'failed' && ` The last attempt did not complete (${o.error ?? 'failed'}).`}
          </span>
          {!readOnly && o.status !== 'in_progress' && (
            <button
              type="button"
              className={styles.action}
              disabled={busy}
              onClick={() => void act(`${base(o.project.id)}/cancel`, 'Could not cancel the transfer', {
                message: `Cancel the offer of "${o.project.name}" to ${personName(o.to)}? You stay its owner.`,
                title: 'Cancel the transfer', label: 'Cancel the offer',
              })}
            >
              Cancel the offer
            </button>
          )}
        </div>
      ))}
      {feed.cleared.map((c) => (
        <div key={c.transferId} role="status" aria-label={`Settings to re-pick on ${c.project.name}`} className={`${styles.banner} ${styles.repick}`}>
          <ListChecks size={14} className={styles.icon} aria-hidden />
          <span className={styles.text}>
            You own <strong>{c.project.name}</strong> now. These settings used {personName(c.from)}&apos;s own providers, templates or
            token and were cleared; pick yours in the project settings:
            <ul className={styles.list}>
              {c.cleared.map((s) => <li key={s.field}>{clearedLine(s)}</li>)}
            </ul>
            {FINDING_IDS_NOTE}
          </span>
          {!readOnly && (
            <button type="button" className={styles.action} disabled={busy} onClick={() => void act(`${base(c.project.id)}/acknowledge`, 'Could not dismiss the list')}>
              Dismiss
            </button>
          )}
        </div>
      ))}
      <StepUpModal
        isOpen={accepting !== null}
        title="Accept the project"
        message={accepting ? (
          <>
            You become the owner of &quot;{accepting.project.name}&quot;: its scans, agent runs and AI features spend your keys from now
            on, and settings that used {personName(accepting.from)}&apos;s own providers or templates are cleared for you to re-pick.
            The project must have nothing running (no scan, agent or triage run, no queued scan). Confirm with your own password.
          </>
        ) : ''}
        confirmLabel="Accept"
        onConfirm={async (pw) => {
          const offer = accepting!
          await fetchJson(`${base(offer.project.id)}/accept`, {
            method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ stepUpPassword: pw }),
          }, 'Could not accept the project')
          window.dispatchEvent(new Event(PROJECT_TRANSFER_CHANGED_EVENT))
        }}
        onClose={() => setAccepting(null)}
      />
    </div>
  )
}

export default ProjectTransferBanners
