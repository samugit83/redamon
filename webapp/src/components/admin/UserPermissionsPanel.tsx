'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { ApiError, fetchJson, toApiError } from '@/lib/apiError'
import type { PermissionId } from '@/lib/authz/permissions'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { EffectivePermissions } from './EffectivePermissions'
import { PermissionPicker } from './PermissionPicker'
import {
  DEFAULT_MEMBER_SET, FULL_ADMIN_PROFILE, changeBody, draftOf, givableFrom, givingOf, notGivable, permissionsUrl,
  profileAssignable, profileOf, setInForceText, stepUpNeeded,
  type AccountPermissionsView, type Draft, type OverrideEffect, type OverrideView, type SetList, type SetOption,
} from './permissionModel'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from './UserPermissions.module.css'

interface UserPermissionsPanelProps {
  user: { id: string; name: string; email: string }
  /** The signed-in person: what they hold decides what they may give. */
  selfId: string
  /** A change was saved: the list may show it. */
  onChanged?: () => void
}

interface Loaded {
  target: AccountPermissionsView
  me: AccountPermissionsView
  givable: ReadonlySet<PermissionId>
  /** Member sets; an error is shown in their section, the rest of the panel still works. */
  sets: SetList | ApiError
  /** Admin targets only. */
  profiles: SetList | ApiError | null
}

type State =
  | { kind: 'loading' }
  | { kind: 'denied'; error: ApiError }
  | { kind: 'error'; message: string }
  | ({ kind: 'ready' } & Loaded)

interface PutAnswer {
  changed: boolean
  added?: string[]
  removed?: string[]
  signedOut?: boolean
}

const JSON_HEADERS = { 'Content-Type': 'application/json' }
const MAX_REASON = 500

async function listOf(url: string, fallback: string): Promise<SetList | ApiError> {
  try {
    return await fetchJson<SetList>(url, undefined, fallback)
  } catch (err) {
    return toApiError(err, fallback)
  }
}

async function load(userId: string, selfId: string): Promise<Loaded> {
  const [target, me] = await Promise.all([
    fetchJson<AccountPermissionsView>(permissionsUrl(userId), undefined, "Could not read the account's permissions"),
    fetchJson<AccountPermissionsView>(permissionsUrl(selfId), undefined, 'Could not read your own permissions'),
  ])
  const [sets, profiles] = await Promise.all([
    listOf('/api/admin/permission-sets', 'Could not list the permission sets'),
    target.accountType === 'admin' ? listOf('/api/admin/admin-profiles', 'Could not list the admin profiles') : Promise.resolve(null),
  ])
  return { target, me, givable: givableFrom(me.explain), sets, profiles }
}

function ListError({ error }: { error: ApiError }) {
  const permission = forbiddenPermission(error)
  return permission ? <ForbiddenNotice permission={permission} /> : <div className={pageStyles.error} role="alert">{error.message}</div>
}

const localTime = (iso: string) => new Date(iso).toLocaleString()

/**
 * One account's permissions on the Users page (step 3.13; PE-15, PE-16, UI-12): its member sets
 * (multi-select of built-in and custom sets), its overrides (a permission picked by area, grant or
 * deny, an optional expiry and reason), an admin's profile, and what it holds now with the
 * "because" lines. It mirrors the server's rules (step 3.11): a set, a grant or a profile holding
 * what the person does not hold is disabled with the reason; a change to an admin, or one giving a
 * cross-tenant tool, an exploitation approval, sessions or Kali exec, asks for the person's own
 * password first (the server's step-up). The server decides; its refusal is shown as it came.
 */
export function UserPermissionsPanel({ user, selfId, onChanged }: UserPermissionsPanelProps) {
  const uid = useId()
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [draft, setDraft] = useState<Draft>({ sets: [], overrides: [], profile: null })
  const [saving, setSaving] = useState(false)
  const [notice, setNotice] = useState('')
  const [saveError, setSaveError] = useState('')
  const [stepUp, setStepUp] = useState<{ body: Record<string, unknown>; why: string } | null>(null)

  const [effect, setEffect] = useState<OverrideEffect>('grant')
  const [permission, setPermission] = useState<PermissionId | ''>('')
  const [expires, setExpires] = useState('')
  const [reason, setReason] = useState('')
  const [addError, setAddError] = useState('')

  const reload = useCallback(async () => {
    setState({ kind: 'loading' })
    try {
      const loaded = await load(user.id, selfId)
      setDraft(draftOf(loaded.target))
      setState({ kind: 'ready', ...loaded })
    } catch (err) {
      const error = toApiError(err, "Could not read the account's permissions")
      setState(error.status === 403 ? { kind: 'denied', error } : { kind: 'error', message: error.message })
    }
  }, [user.id, selfId])

  useEffect(() => {
    void reload()
  }, [reload])

  if (state.kind === 'loading') {
    return <p className={pageStyles.empty} role="status">Loading the permissions…</p>
  }
  if (state.kind === 'denied') {
    const permissionNeeded = forbiddenPermission(state.error)
    return permissionNeeded ? <ForbiddenNotice permission={permissionNeeded} /> : (
      <div className={pageStyles.error} role="alert">
        You cannot manage this account&apos;s permissions. {state.error.message}
      </div>
    )
  }
  if (state.kind === 'error') {
    return (
      <div className={pageStyles.errorState}>
        <div className={pageStyles.error} role="alert">{state.message}</div>
        <button type="button" className={pageStyles.actionButton} onClick={() => void reload()}>Retry</button>
      </div>
    )
  }

  const { target, me, givable, sets, profiles } = state
  const setRows: SetOption[] = sets instanceof ApiError ? [] : sets.sets
  const profileRows: SetOption[] = profiles && !(profiles instanceof ApiError) ? profiles.sets : []
  const defaultSet = sets instanceof ApiError ? null
    : setRows.find((s) => s.id === (sets.instanceDefaultSetId ?? DEFAULT_MEMBER_SET)) ?? null
  const gone = draft.sets.filter((id) => !setRows.some((s) => s.id === id))
  const expired = target.assignment.overrides.length - draftOf(target).overrides.length
  const liveDeny = (p: PermissionId) => draftOf(target).overrides.some((o) => o.permission === p && o.effect === 'deny')

  function toggleSet(id: string, on: boolean) {
    setNotice('')
    setDraft((d) => ({ ...d, sets: on ? [...d.sets, id] : d.sets.filter((s) => s !== id) }))
  }

  function removeOverride(p: PermissionId) {
    setNotice('')
    setDraft((d) => ({ ...d, overrides: d.overrides.filter((o) => o.permission !== p) }))
  }

  function chooseEffect(next: OverrideEffect) {
    setEffect(next)
    if (next === 'grant' && permission && !givable.has(permission)) setPermission('')
  }

  function addOverride() {
    setAddError('')
    if (!permission) {
      setAddError('Choose a permission.')
      return
    }
    if (effect === 'grant' && !givable.has(permission)) {
      setAddError(`You do not hold ${permission}: you can grant only what you hold.`)
      return
    }
    let expiresAt: string | null = null
    if (expires) {
      const at = new Date(expires)
      if (Number.isNaN(at.getTime()) || at.getTime() <= Date.now()) {
        setAddError('The expiry must be a date and time in the future.')
        return
      }
      expiresAt = at.toISOString()
    }
    if (reason.length > MAX_REASON) {
      setAddError(`The reason is at most ${MAX_REASON} characters.`)
      return
    }
    const added: OverrideView = { permission, effect, expiresAt, reason: reason.trim() || null }
    setNotice('')
    setDraft((d) => ({ ...d, overrides: [...d.overrides.filter((o) => o.permission !== permission), added] }))
    setPermission('')
    setExpires('')
    setReason('')
  }

  async function put(body: Record<string, unknown>, password?: string): Promise<void> {
    const answer = await fetchJson<PutAnswer>(permissionsUrl(user.id), {
      method: 'PUT',
      headers: JSON_HEADERS,
      body: JSON.stringify(password ? { ...body, stepUpPassword: password } : body),
    }, "Could not change the account's permissions")
    const added = answer.added?.length ?? 0
    const removed = answer.removed?.length ?? 0
    setNotice(!answer.changed ? 'Nothing changed.' : `Saved: ${added} permission${added === 1 ? '' : 's'} added, ${removed} removed.${
      answer.signedOut ? ' The account lost a permission, so it was signed out everywhere.' : ''}`)
    onChanged?.()
    try {
      const loaded = await load(user.id, selfId)
      setDraft(draftOf(loaded.target))
      setState({ kind: 'ready', ...loaded })
    } catch (err) {
      setSaveError(`Saved, but the permissions could not be read again: ${toApiError(err, 'read failed').message}`)
    }
  }

  async function save() {
    setSaveError('')
    setNotice('')
    const body = changeBody(target, draft)
    if (!body) {
      setNotice('Nothing to save.')
      return
    }
    const giving = givingOf(target, draft, setRows, profileRows)
    const missing = notGivable(giving, givable)
    if (missing.length) {
      setSaveError(`You can give only permissions you hold yourself; you do not hold: ${missing.join(', ')}.`)
      return
    }
    const step = stepUpNeeded(target, giving)
    if (step) {
      setStepUp({
        body,
        why: step === 'admin'
          ? 'This account is an admin: every change to its permissions takes your own password.'
          : `This change gives ${step.join(', ')}. Giving a cross-tenant tool, an exploitation approval, shell sessions or Kali commands takes your own password.`,
      })
      return
    }
    setSaving(true)
    try {
      await put(body)
    } catch (err) {
      const error = toApiError(err, "Could not change the account's permissions")
      if (error.code === 'step_up_required') setStepUp({ body, why: 'Confirm this change with your own password.' })
      else setSaveError(error.message)
    } finally {
      setSaving(false)
    }
  }

  const profileId = `${uid}-profile`
  const ids = { effect: `${uid}-effect`, permission: `${uid}-permission`, expires: `${uid}-expires`, reason: `${uid}-reason` }

  return (
    <div className={styles.panel}>
      <p className={pageStyles.hint}>{user.name} ({user.email}), {target.accountType === 'admin' ? 'an admin' : 'a member'}.</p>
      {notice && <div className={pageStyles.success} role="status">{notice}</div>}
      {saveError && (
        <div className={pageStyles.errorState}>
          <div className={pageStyles.error} role="alert">{saveError}</div>
          <button type="button" className={pageStyles.actionButton} onClick={() => void reload()}>Reload</button>
        </div>
      )}

      <fieldset className={styles.section}>
        <legend className={styles.sectionTitle}>Member permission sets</legend>
        {sets instanceof ApiError ? <ListError error={sets} /> : (
          <>
            <span className={pageStyles.hint}>
              {draft.sets.length === 0
                ? `None ticked: the account holds the instance default set${defaultSet ? `, ${defaultSet.name}` : ''}, and follows it when it changes.`
                : 'The account holds every set ticked, together.'}
            </span>
            {setRows.map((s, i) => {
              const assigned = target.assignment.sets.includes(s.id)
              const missing = assigned ? [] : notGivable(s.permissions, givable)
              const refused = missing.length > 0 && !draft.sets.includes(s.id)
              const hint = `${uid}-set-${i}`
              return (
                <div key={s.id} className={styles.item}>
                  <label className={styles.choice}>
                    <input
                      type="checkbox"
                      checked={draft.sets.includes(s.id)}
                      disabled={refused || saving}
                      onChange={(e) => toggleSet(s.id, e.target.checked)}
                      aria-describedby={hint}
                    />
                    <span>
                      {s.name}
                      {s.instanceDefault && <span className={styles.tag}>instance default</span>}
                      {!s.builtin && <span className={styles.tag}>custom</span>}
                    </span>
                  </label>
                  <span id={hint} className={styles.description}>
                    {s.description ?? `${s.permissions.length} permissions.`}
                    {refused && <span className={styles.refusal}> You do not hold {missing.join(', ')}: you can give only what you hold.</span>}
                  </span>
                </div>
              )
            })}
            {gone.map((id) => (
              <label key={id} className={styles.choice}>
                <input type="checkbox" checked onChange={() => toggleSet(id, false)} disabled={saving} />
                <span>{id} (this set no longer exists: it gives nothing)</span>
              </label>
            ))}
          </>
        )}
      </fieldset>

      <fieldset className={styles.section}>
        <legend className={styles.sectionTitle}>Overrides</legend>
        {draft.overrides.length === 0 ? <p className={styles.description}>No overrides.</p> : (
          <ul className={styles.list} aria-label="Overrides">
            {draft.overrides.map((o) => {
              const liftRefused = o.effect === 'deny' && liveDeny(o.permission) && !givable.has(o.permission)
              return (
                <li key={o.permission} className={styles.row}>
                  <span>
                    {o.effect === 'grant' ? 'Grant' : 'Deny'} <code className={styles.permission}>{o.permission}</code>
                    {o.expiresAt ? ` until ${localTime(o.expiresAt)}` : ', no expiry'}
                    {o.reason ? `: ${o.reason}` : ''}
                    {liftRefused && <span className={styles.refusal}> You do not hold {o.permission}, so you cannot lift this deny.</span>}
                  </span>
                  <button
                    type="button"
                    className={pageStyles.actionButton}
                    disabled={liftRefused || saving}
                    aria-label={`Remove the override of ${o.permission}`}
                    onClick={() => removeOverride(o.permission)}
                  >
                    Remove
                  </button>
                </li>
              )
            })}
          </ul>
        )}
        {expired > 0 && (
          <span className={pageStyles.hint}>
            {expired} expired override{expired === 1 ? '' : 's'} not listed: they no longer apply, and saving the overrides removes them.
          </span>
        )}
        <div className={styles.grid}>
          <div className={pageStyles.field}>
            <label className={pageStyles.label} htmlFor={ids.effect}>Effect</label>
            <select id={ids.effect} className={pageStyles.select} value={effect} onChange={(e) => chooseEffect(e.target.value === 'deny' ? 'deny' : 'grant')}>
              <option value="grant">Grant</option>
              <option value="deny">Deny</option>
            </select>
          </div>
          <div className={pageStyles.field}>
            <label className={pageStyles.label} htmlFor={ids.expires}>Expires (optional)</label>
            <input id={ids.expires} type="datetime-local" className={pageStyles.input} value={expires} onChange={(e) => setExpires(e.target.value)} />
          </div>
        </div>
        <PermissionPicker
          id={ids.permission}
          label="Permission"
          accountType={target.accountType}
          effect={effect}
          givable={givable}
          exclude={new Set(draft.overrides.map((o) => o.permission))}
          value={permission}
          onChange={setPermission}
        />
        <div className={pageStyles.field}>
          <label className={pageStyles.label} htmlFor={ids.reason}>Reason (optional)</label>
          <input id={ids.reason} className={pageStyles.input} value={reason} maxLength={MAX_REASON} onChange={(e) => setReason(e.target.value)} />
        </div>
        {addError && <div className={pageStyles.error} role="alert">{addError}</div>}
        <div className={pageStyles.actions}>
          <button type="button" className={pageStyles.actionButton} onClick={addOverride} disabled={saving}>Add the override</button>
        </div>
      </fieldset>

      {target.accountType === 'admin' && (
        <fieldset className={styles.section}>
          <legend className={styles.sectionTitle}>Admin profile</legend>
          {profiles instanceof ApiError ? <ListError error={profiles} /> : (
            <div className={pageStyles.field}>
              <label className={pageStyles.label} htmlFor={profileId}>Profile</label>
              <select
                id={profileId}
                className={pageStyles.select}
                value={draft.profile ?? FULL_ADMIN_PROFILE}
                disabled={saving}
                aria-describedby={`${profileId}-hint`}
                onChange={(e) => {
                  const next = e.target.value
                  setNotice('')
                  // No profile recorded already means Full admin: choosing it changes nothing.
                  setDraft((d) => ({ ...d, profile: next === FULL_ADMIN_PROFILE && profileOf(target) === null ? null : next }))
                }}
              >
                {profileRows.map((p) => {
                  const refused = p.id !== (profileOf(target) ?? FULL_ADMIN_PROFILE) && !profileAssignable(me, givable, p.permissions)
                  return (
                    <option key={p.id} value={p.id} disabled={refused}>
                      {p.name}{refused ? ' (not strictly inside your own admin permissions)' : ''}
                    </option>
                  )
                })}
              </select>
              <span id={`${profileId}-hint`} className={pageStyles.hint}>
                Root gives any profile; an admin holding admins:manage gives only a profile strictly inside their own.
              </span>
            </div>
          )}
        </fieldset>
      )}

      <div className={pageStyles.modalActions}>
        <button type="button" className="primaryButton" onClick={() => void save()} disabled={saving}>
          {saving ? 'Saving…' : 'Save the permissions'}
        </button>
      </div>

      <section className={styles.section} aria-labelledby={`${uid}-effective`}>
        <h3 id={`${uid}-effective`} className={styles.sectionTitle}>Effective permissions</h3>
        <span className={pageStyles.hint}>
          In force now: {target.sets.map(setInForceText).join('; ') || 'nothing'}. A saved change shows here once saved.
        </span>
        <EffectivePermissions explain={target.explain} />
      </section>

      <StepUpModal
        isOpen={stepUp !== null}
        title="Confirm with your password"
        message={stepUp?.why ?? ''}
        confirmLabel="Save the permissions"
        onConfirm={async (password) => {
          if (!stepUp) return
          await put(stepUp.body, password)
        }}
        onClose={() => setStepUp(null)}
      />
    </div>
  )
}

export default UserPermissionsPanel
