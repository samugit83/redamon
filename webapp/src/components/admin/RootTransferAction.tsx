'use client'

import { useId, useState } from 'react'
import { Crown } from 'lucide-react'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { fetchJson } from '@/lib/apiError'
import pageStyles from '@/app/settings/users/page.module.css'
import { ActionLabel } from './ActionLabel'
import { ROOT_TRANSFER_CHANGED_EVENT } from './RootTransferBanner'

export interface TransferCandidate {
  id: string
  name: string
  email: string
  role: string
  /** active | invited | disabled; absent reads as active. */
  status?: string
  hasPassword: boolean
}

interface Props {
  selfId: string
  /** The Users page rows: the admins among them who can sign in may receive Root. */
  users: TransferCandidate[]
  className: string
}

/**
 * "Transfer Root" on the confirmed Root's own Users page row (step 2.6, ID-07, ID-25): pick an
 * admin who can sign in (active, with a password) and confirm with Root's own password. The admin
 * then accepts or declines from the header banner, which is told to read the offer again. The
 * server checks everything again; a refusal stays in the dialog with its code.
 */
export function RootTransferAction({ selfId, users, className }: Props) {
  const pickId = useId()
  const [open, setOpen] = useState(false)
  const [target, setTarget] = useState('')
  const candidates = users.filter((u) => u.id !== selfId && u.role === 'admin' && u.hasPassword && (u.status ?? 'active') === 'active')

  const message = candidates.length === 0
    ? 'No other admin can receive Root: make an active account with a password an admin first.'
    : (
      <>
        Root goes to the admin you pick once they accept (the offer lasts 24 hours); you stay an admin with every
        admin right, and you both sign in again.
        {/* Spans, not divs: StepUpModal renders the message inside a <p>. */}
        <span className={pageStyles.inlineField}>
          <label className={pageStyles.label} htmlFor={pickId}>Transfer Root to</label>
          <select id={pickId} className={pageStyles.select} value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">Pick an admin</option>
            {candidates.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.email})</option>)}
          </select>
        </span>
      </>
    )

  return (
    <>
      <button type="button" className={className} onClick={() => { setTarget(''); setOpen(true) }}>
        <ActionLabel icon={Crown}>Transfer Root</ActionLabel>
      </button>
      <StepUpModal
        isOpen={open}
        title="Transfer Root"
        message={message}
        confirmLabel="Offer Root"
        onConfirm={async (pw) => {
          if (candidates.length === 0) throw new Error('No other admin can receive Root.')
          if (!target) throw new Error('Pick the admin to transfer Root to.')
          await fetchJson('/api/root/transfer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetUserId: target, stepUpPassword: pw }),
          }, 'Could not offer Root')
          window.dispatchEvent(new Event(ROOT_TRANSFER_CHANGED_EVENT))
        }}
        onClose={() => setOpen(false)}
      />
    </>
  )
}
