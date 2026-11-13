'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useToast } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { readApiError } from '@/lib/apiError'
import { failureText } from '@/components/settings/failureText'
import { DEFAULT_MEMBER_SET_ID } from '@/lib/authz/builtinSets'
import { FieldRow, Panel, RootOnlyNote } from './Panel'
import styles from './instance.module.css'

interface SetRow { id: string; name: string; description: string | null; builtin: boolean; holders: number }

type View =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'denied'; permission: string }
  | { kind: 'ready'; sets: SetRow[]; current: string }

const SETS_URL = '/api/admin/permission-sets'
const LOAD_FAILED = "Couldn't load the permission sets"
const SAVE_FAILED = 'The default set was not changed'

/**
 * The defaults for new members: the member permission set a member gets while never assigned one
 * (step 3.11, PE-17). Read from the permission sets list (roles:manage or users:assign_permissions)
 * and changed through `PUT /api/admin/permission-sets/[id] {instanceDefault: true}`: the confirmed
 * Root's, with its password. No stored default reads as the built-in Default member set.
 */
export function DefaultSetPanel({ canEdit, unconfirmedRoot }: { canEdit: boolean; unconfirmedRoot: boolean }) {
  const toast = useToast()
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [pick, setPick] = useState('')
  const [confirming, setConfirming] = useState(false)

  const load = useCallback(async () => {
    setView({ kind: 'loading' })
    try {
      const res = await fetch(SETS_URL, { cache: 'no-store' })
      if (!res.ok) {
        const err = await readApiError(res, LOAD_FAILED)
        const permission = forbiddenPermission(err)
        setView(permission ? { kind: 'denied', permission } : { kind: 'error', message: err.message })
        return
      }
      const body = await res.json() as { sets?: SetRow[]; instanceDefaultSetId?: string | null }
      const current = body.instanceDefaultSetId ?? DEFAULT_MEMBER_SET_ID
      setView({ kind: 'ready', sets: body.sets ?? [], current })
      setPick(current)
    } catch (err) {
      setView({ kind: 'error', message: failureText(LOAD_FAILED, err) })
    }
  }, [])

  useEffect(() => { load() }, [load])

  const lead = 'The permission set a member gets until an administrator assigns one: new members, and members never assigned a set.'
  if (view.kind === 'loading') {
    return <Panel id="default-set" title="Defaults for new members" lead={lead}><p className={styles.state} role="status">Loading the permission sets…</p></Panel>
  }
  if (view.kind === 'denied') {
    return <Panel id="default-set" title="Defaults for new members" lead={lead}><ForbiddenNotice permission={view.permission} /></Panel>
  }
  if (view.kind === 'error') {
    return (
      <Panel id="default-set" title="Defaults for new members" lead={lead}>
        <div className={styles.error} role="alert">
          {view.message}.{' '}
          <button type="button" className="textButton" onClick={load}>Retry</button>
        </div>
      </Panel>
    )
  }

  const nameOf = (id: string) => view.sets.find((s) => s.id === id)?.name ?? id
  if (!canEdit) {
    return (
      <Panel id="default-set" title="Defaults for new members" lead={lead}>
        <dl className={styles.readList}>
          <dt>Default member set</dt>
          <dd>{nameOf(view.current)}</dd>
        </dl>
        <RootOnlyNote unconfirmedRoot={unconfirmedRoot} />
      </Panel>
    )
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (pick && pick !== view.current) setConfirming(true)
  }

  return (
    <Panel id="default-set" title="Defaults for new members" lead={lead}>
      <form onSubmit={submit} className={styles.page} style={{ gap: 'var(--space-2)' }}>
        <FieldRow
          id="default-member-set"
          label="Default member set"
          hint="A member never assigned a set who loses a permission with the change is signed out."
        >
          <select
            id="default-member-set"
            className="select"
            value={pick}
            aria-describedby="default-member-set-hint"
            onChange={(e) => setPick(e.target.value)}
          >
            {view.sets.map((s) => (
              <option key={s.id} value={s.id}>{s.name}{s.builtin ? ' (built-in)' : ''}</option>
            ))}
          </select>
        </FieldRow>
        <div className={styles.actions}>
          <button type="submit" className="primaryButton" disabled={!pick || pick === view.current}>Make it the default</button>
          <span className={styles.hint}>Saving asks for your password.</span>
        </div>
      </form>
      <StepUpModal
        isOpen={confirming}
        title="Change the default member set"
        message={`New members and members never assigned a set will hold "${nameOf(pick)}" instead of "${nameOf(view.current)}". Those who lose a permission are signed out. Enter your password to confirm.`}
        confirmLabel="Make it the default"
        onConfirm={async (password) => {
          const res = await fetch(`${SETS_URL}/${encodeURIComponent(pick)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ instanceDefault: true, stepUpPassword: password }),
          })
          if (!res.ok) throw await readApiError(res, SAVE_FAILED)
          const body = await res.json() as { signedOut?: number }
          toast.success(body.signedOut
            ? `Default member set changed; ${body.signedOut} member(s) signed out`
            : 'Default member set changed')
          setView((v) => (v.kind === 'ready' ? { ...v, current: pick } : v))
        }}
        onClose={() => setConfirming(false)}
      />
    </Panel>
  )
}
