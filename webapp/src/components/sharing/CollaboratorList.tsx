'use client'

import { useId, useState, type FormEvent } from 'react'
import { useAlertModal } from '@/components/ui'
import { ACCOUNT_TYPE_LABEL, IdentityLabel } from '@/components/auth/IdentityLabel'
import type { ShareView } from '@/lib/authz/projectShares'
import { AccessPicker, termsOf, type AccessChoice } from './AccessPicker'
import {
  NOTE_MAX_CHARS,
  dateInputValue,
  endOfDayIso,
  presetOf,
  shareTermsLabel,
  todayInputValue,
  toggleLabels,
} from './sharePresets'
import styles from './ShareDialog.module.css'

/** The fields PATCH .../collaborators/[userId] takes; only what changed is sent. */
export interface SharePatch {
  access?: 'read' | 'write'
  rawData?: boolean
  expiresAt?: string | null
  note?: string | null
}

interface CollaboratorListProps {
  projectName: string
  shares: ShareView[]
  /** The person signed in (the account acted as, under act-as): "Granted by you". */
  viewerId: string | null
  writeRefusal: string | null
  /** Nothing can be changed (acting as the owner): neither change nor revoke is offered. */
  readOnly?: boolean
  /** Throws to keep the editor open with the error's message. */
  onChange: (share: ShareView, patch: SharePatch) => Promise<void>
  /** Called after the person confirmed the revoke. */
  onRevoke: (share: ShareView) => Promise<void>
}

const formatDay = (iso: string) =>
  new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })

export const displayName = (share: ShareView) => share.user.name || share.user.email || 'this account'

/** "Name (email)", for a sentence that names the person. */
const fullName = (share: ShareView) => {
  const { name, email } = share.user
  return name && email ? `${name} (${email})` : name || email || 'this account'
}

function expiryText(share: ShareView): string {
  if (!share.expiresAt) return 'No end date'
  if (share.expired) return `Expired ${formatDay(share.expiresAt)}: it gives no access`
  return `Ends ${formatDay(share.expiresAt)}`
}

function grantedByText(share: ShareView, viewerId: string | null): string {
  if (viewerId && share.grantedById === viewerId) return 'Granted by you'
  const by = share.grantedBy
  if (!by) return 'Granted by an account that no longer exists'
  const detail = [by.email, ACCOUNT_TYPE_LABEL[by.accountType]].filter(Boolean).join(', ')
  return `Granted by ${by.name || by.email || 'an account'}${detail ? ` (${detail})` : ''}`
}

/**
 * Who holds a share of the project, in the share dialog (step 4.12; UI-07, ID-31): each person as an
 * IdentityLabel (name, email, account type: a display name alone is not an identity) with the level,
 * toggles, end date, who granted it and the note, and Change and Revoke. Revoke asks first, through
 * useAlertModal; a change sends only the fields that changed.
 */
export function CollaboratorList({ projectName, shares, viewerId, writeRefusal, readOnly = false, onChange, onRevoke }: CollaboratorListProps) {
  const { dangerConfirm } = useAlertModal()
  const [editing, setEditing] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)

  const revoke = async (share: ShareView) => {
    const ok = await dangerConfirm(
      `${fullName(share)} loses access to "${projectName}" now: their open pages of it close within 30 seconds, and their open connections to it are closed.`,
      'Revoke access',
      { confirmLabel: 'Revoke' },
    )
    if (!ok) return
    setRevoking(share.user.id)
    try {
      await onRevoke(share)
    } finally {
      setRevoking(null)
    }
  }

  return (
    <ul className={styles.people} aria-label="People with access">
      {shares.map((share) => {
        const name = displayName(share)
        const toggles = toggleLabels(share)
        const inactive = share.user.status && share.user.status !== 'active' ? share.user.status : null
        return (
          <li key={share.user.id} className={styles.person} aria-label={name}>
            <div className={styles.personHead}>
              <IdentityLabel name={share.user.name ?? ''} email={share.user.email ?? ''} accountType={share.user.accountType ?? undefined} />
              {!readOnly && editing !== share.user.id && (
                <span className={styles.personActions}>
                  <button
                    type="button"
                    className={styles.linkButton}
                    aria-label={`Change access for ${name}`}
                    onClick={() => setEditing(share.user.id)}
                  >
                    Change
                  </button>
                  <button
                    type="button"
                    className={styles.dangerButton}
                    aria-label={`Revoke access for ${name}`}
                    onClick={() => void revoke(share)}
                    disabled={revoking === share.user.id}
                  >
                    {revoking === share.user.id ? 'Revoking...' : 'Revoke'}
                  </button>
                </span>
              )}
            </div>
            <div className={styles.personMeta}>
              <span className="tag">{shareTermsLabel(share)}</span>
              <span>{`Toggles: ${toggles.length ? toggles.join(', ') : 'none'}`}</span>
              <span className={share.expired ? styles.warnText : undefined}>{expiryText(share)}</span>
              <span>{grantedByText(share, viewerId)}</span>
            </div>
            {inactive && <p className={styles.warnText}>{`This account is ${inactive}: the share gives no access while it is.`}</p>}
            {share.note && <p className={styles.note}>{share.note}</p>}
            {editing === share.user.id && (
              <ShareEditor
                share={share}
                name={name}
                writeRefusal={writeRefusal}
                onCancel={() => setEditing(null)}
                onSave={async (patch) => {
                  if (Object.keys(patch).length > 0) await onChange(share, patch)
                  setEditing(null)
                }}
              />
            )}
          </li>
        )
      })}
    </ul>
  )
}

interface ShareEditorProps {
  share: ShareView
  name: string
  writeRefusal: string | null
  onCancel: () => void
  onSave: (patch: SharePatch) => Promise<void>
}

function ShareEditor({ share, name, writeRefusal, onCancel, onSave }: ShareEditorProps) {
  const ids = { ends: useId(), note: useId(), endsHint: useId() }
  const initialDay = dateInputValue(share.expiresAt)
  const [choice, setChoice] = useState<AccessChoice>({ presetId: presetOf(share), customRaw: share.rawData })
  const [endsOn, setEndsOn] = useState(initialDay)
  const [note, setNote] = useState(share.note ?? '')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  async function save(e: FormEvent) {
    e.preventDefault()
    if (pending) return
    const terms = termsOf(choice)
    const patch: SharePatch = {}
    if (terms.access !== share.access) patch.access = terms.access
    if (terms.rawData !== share.rawData) patch.rawData = terms.rawData
    if (endsOn !== initialDay) patch.expiresAt = endsOn ? endOfDayIso(endsOn) : null
    const trimmed = note.trim()
    if (trimmed !== (share.note ?? '')) patch.note = trimmed || null
    setError('')
    setPending(true)
    try {
      await onSave(patch)
    } catch (err) {
      setPending(false)
      setError(err instanceof Error && err.message ? err.message : 'Could not change the share')
    }
  }

  return (
    <form className={styles.editor} aria-label={`Change access for ${name}`} onSubmit={save} noValidate>
      <AccessPicker value={choice} onChange={setChoice} writeRefusal={writeRefusal} disabled={pending} />
      <div className={styles.row}>
        <div className={styles.field}>
          <label className={styles.label} htmlFor={ids.ends}>Ends on</label>
          <input
            id={ids.ends}
            type="date"
            className={styles.input}
            value={endsOn}
            min={todayInputValue()}
            onChange={(e) => setEndsOn(e.target.value)}
            aria-describedby={ids.endsHint}
            disabled={pending}
          />
          <span id={ids.endsHint} className={styles.hint}>Empty: no end date.</span>
        </div>
        <div className={styles.field}>
          <label className={styles.label} htmlFor={ids.note}>Note</label>
          <input
            id={ids.note}
            type="text"
            className={styles.input}
            value={note}
            maxLength={NOTE_MAX_CHARS}
            onChange={(e) => setNote(e.target.value)}
            disabled={pending}
          />
        </div>
      </div>
      {error && <div className={styles.error} role="alert">{error}</div>}
      <div className={styles.actions}>
        <button type="button" className={styles.cancel} onClick={onCancel} disabled={pending}>Cancel</button>
        <button type="submit" className="primaryButton" disabled={pending}>{pending ? 'Saving...' : 'Save'}</button>
      </div>
    </form>
  )
}
