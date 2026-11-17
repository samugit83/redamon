'use client'

import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import tc from '../tradecraft.module.css'
import css from './dialog.module.css'

export const BUDGET_NOTE = 'They are refreshed one at a time, in the background. The batch stops if the daily model budget is used up, so your chats keep their calls.'

/**
 * Save & refresh all's confirmation (§3.2): every enabled resource, each ticked; unticking one
 * leaves it out. Nothing is saved or started before Confirm.
 */
export function RefreshAllConfirm({ resources, busy = false, error = '', onConfirm, onCancel }: {
  resources: { id: string; name: string }[]
  busy?: boolean
  error?: string
  onConfirm: (ids: string[]) => void
  onCancel: () => void
}) {
  const [ticked, setTicked] = useState<Set<string>>(() => new Set(resources.map(r => r.id)))
  const toggle = (id: string, on: boolean) => setTicked(prev => {
    const next = new Set(prev)
    if (on) next.add(id)
    else next.delete(id)
    return next
  })
  const chosen = resources.filter(r => ticked.has(r.id)).map(r => r.id)
  return (
    <Modal
      isOpen
      onClose={busy ? () => {} : onCancel}
      title="Save & refresh all"
      closeOnOverlayClick={false}
      footer={(
        <div className={css.footer}>
          {error && <span className={tc.failure} role="alert">{error}</span>}
          <span className={css.footerSpacer} />
          <button type="button" className="secondaryButton" onClick={onCancel} disabled={busy}>Cancel</button>
          <button type="button" className="primaryButton" onClick={() => onConfirm(chosen)} disabled={busy || chosen.length === 0}>
            {busy && <Loader2 size={14} className={tc.spin} />} Save &amp; refresh {chosen.length}
          </button>
        </div>
      )}
    >
      {resources.length === 0 ? (
        <p className={tc.state}>No enabled resource to refresh: Save keeps the settings for the next add or refresh.</p>
      ) : (
        <>
          <p className={tc.hint}>Saves the settings, then refreshes {chosen.length} of {resources.length} enabled resources with them. {BUDGET_NOTE}</p>
          <ul aria-label="Resources to refresh" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
            {resources.map(r => (
              <li key={r.id}>
                <label className={css.inline}>
                  <input type="checkbox" checked={ticked.has(r.id)} onChange={e => toggle(r.id, e.target.checked)} disabled={busy} />
                  <span>{r.name}</span>
                </label>
              </li>
            ))}
          </ul>
        </>
      )}
    </Modal>
  )
}
