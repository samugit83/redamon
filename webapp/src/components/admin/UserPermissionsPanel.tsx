'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import { ListChecks, Undo2 } from 'lucide-react'
import { ApiError, fetchJson, toApiError } from '@/lib/apiError'
import type { PermissionId } from '@/lib/authz/permissions'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { EffectivePermissions } from './EffectivePermissions'
import { PermissionPicker } from './PermissionPicker'
import { SetPermissionsModal } from './SetPermissionsModal'
import {
  DEFAULT_MEMBER_SET, FULL_ADMIN_PROFILE, changeBody, draftChanges, draftOf, givableFrom, givingOf, heldDiff, notGivable,
  offeredMemberSets, permissionsUrl, previewOf, profileAssignable, profileOf, setInForceText, stepUpNeeded,
  type AccountPermissionsView, type Draft, type DraftChanges, type OverrideEffect, type OverrideView, type SetList, type SetOption,
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
const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`
const overrideText = (o: OverrideView) =>
  `${o.effect === 'grant' ? 'Grant' : 'Deny'} ${o.permission}${o.expiresAt ? ` until ${localTime(o.expiresAt)}` : ', no expiry'}${o.reason ? ` (${o.reason})` : ''}`

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
  const [viewing, setViewing] = useState<SetOption | null>(null)
  /** Effective permissions as saved, or as the form would leave them. */
  const [mode, setMode] = useState<'saved' | 'draft'>('saved')

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
  // Kept on screen while it is saved on the account, so it can be unticked (or ticked back before saving).
  const offered = offeredMemberSets(setRows, target.assignment.sets)
  const profileRows: SetOption[] = profiles && !(profiles instanceof ApiError) ? profiles.sets : []
  const defaultSet = sets instanceof ApiError ? null
    : setRows.find((s) => s.id === (sets.instanceDefaultSetId ?? DEFAULT_MEMBER_SET)) ?? null
  const gone = draft.sets.filter((id) => !setRows.some((s) => s.id === id))
  const expired = target.assignment.overrides.length - draftOf(target).overrides.length
  const liveDeny = (p: PermissionId) => draftOf(target).overrides.some((o) => o.permission === p && o.effect === 'deny')
  const preview = previewOf(target, draft, {
    sets: sets instanceof ApiError ? null : sets,
    profiles: profiles instanceof ApiError ? null : profiles,
  })
  const diff = preview ? heldDiff(target.explain, preview.explain) : null
  const edits = draftChanges(target, draft)
  const dirty = edits.count > 0
  /** A disabled or invited account holds nothing whatever its sets; they apply once it is active. */
  const inactive = (() => {
    for (const e of target.explain) for (const r of e.reasons) if (r.kind === 'inactive') return r.status
    return null
  })()
  const setName = (id: string) => setRows.find((s) => s.id === id)?.name ?? id
  const profileName = (id: string | null) => profileRows.find((p) => p.id === (id ?? FULL_ADMIN_PROFILE))?.name ?? id ?? 'Full admin'
  const shownProfile = profileRows.find((p) => p.id === (draft.profile ?? FULL_ADMIN_PROFILE)) ?? null

  function discard() {
    setDraft(draftOf(target))
    setNotice('')
    setSaveError('')
    setAddError('')
  }

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
    setMode('saved')
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
            {offered.map((s, i) => {
              const assigned = target.assignment.sets.includes(s.id)
              const missing = assigned ? [] : notGivable(s.permissions, givable)
              const refused = missing.length > 0 && !draft.sets.includes(s.id)
              const hint = `${uid}-set-${i}`
              return (
                <div key={s.id} className={styles.setRow}>
                <div className={styles.item}>
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
                      {s.id === DEFAULT_MEMBER_SET && <span className={styles.tag}>no longer offered</span>}
                    </span>
                  </label>
                  <span id={hint} className={styles.description}>
                    {s.id === DEFAULT_MEMBER_SET
                      ? 'The same permissions as Red-team operator. Untick it to follow the instance default, or tick Red-team operator to keep these rights.'
                      : s.description ?? `${s.permissions.length} permissions.`}
                    {refused && <span className={styles.refusal}> You do not hold {missing.join(', ')}: you can give only what you hold.</span>}
                  </span>
                </div>
                <ViewSetButton set={s} onView={setViewing} />
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
              <div className={styles.inlineRow}>
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
              {shownProfile && <ViewSetButton set={shownProfile} onView={setViewing} />}
              </div>
              <span id={`${profileId}-hint`} className={pageStyles.hint}>
                Root gives any profile; an admin holding admins:manage gives only a profile strictly inside their own.
              </span>
            </div>
          )}
        </fieldset>
      )}

      <section className={styles.section} aria-labelledby={`${uid}-effective`}>
        <h3 id={`${uid}-effective`} className={styles.sectionTitle}>Effective permissions</h3>
        <div className={styles.segmented} role="group" aria-label="Which permissions to show">
          <button type="button" className={styles.segment} aria-pressed={mode === 'saved'} onClick={() => setMode('saved')}>
            Saved
          </button>
          <button type="button" className={styles.segment} aria-pressed={mode === 'draft'} onClick={() => setMode('draft')}>
            With your changes
            {diff && diff.gained.length + diff.lost.length > 0 && (
              <span className={styles.segmentBadge}>+{diff.gained.length} / −{diff.lost.length}</span>
            )}
          </button>
        </div>
        {mode === 'saved' ? (
          <>
            <span className={pageStyles.hint}>
              In force now: {target.sets.map(setInForceText).join('; ') || 'nothing'}.
            </span>
            <EffectivePermissions explain={target.explain} />
          </>
        ) : preview && diff ? (
          <>
            <span className={pageStyles.hint}>
              {inactive
                ? `The account is ${inactive}: it holds nothing until it is active, whatever its sets. `
                : ''}
              {dirty
                ? `After saving: ${preview.sets.map(setInForceText).join('; ') || 'nothing'}. Added and removed permissions are tagged.`
                : 'No unsaved changes: this is what is saved.'}{' '}
              A preview of the form as it is now; the server decides when you save.
            </span>
            <EffectivePermissions explain={preview.explain} changes={{ gained: new Set(diff.gained), lost: new Set(diff.lost) }} />
          </>
        ) : (
          <p className={pageStyles.hint}>No preview: the list of permission sets could not be read. Saving still works.</p>
        )}
      </section>

      {dirty && <ReviewChanges uid={uid} edits={edits} diff={diff} inactive={inactive} setName={setName} profileName={profileName} />}

      <div className={styles.saveBar}>
        <span className={styles.saveSummary} aria-live="polite">
          {dirty ? (
            <>
              <strong>{plural(edits.count, 'unsaved change')}</strong>
              {diff && (
                <>
                  {' · '}
                  <span className={styles.gainText}>+{diff.gained.length}</span>
                  {' / '}
                  <span className={styles.lossText}>−{diff.lost.length}</span> permissions
                </>
              )}
            </>
          ) : 'No unsaved changes'}
        </span>
        <div className={styles.saveActions}>
          <button type="button" className={pageStyles.actionButton} onClick={discard} disabled={!dirty || saving}>
            <Undo2 size={14} /> Discard changes
          </button>
          <button type="button" className="primaryButton" onClick={() => void save()} disabled={saving}>
            {saving ? 'Saving…' : 'Save the permissions'}
          </button>
        </div>
      </div>

      <SetPermissionsModal set={viewing} all={viewing?.kind === 'admin' ? profileRows : offered} onClose={() => setViewing(null)} />

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

/** "N permissions" on a set's row: opens the set's contents. */
function ViewSetButton({ set, onView }: { set: SetOption; onView: (set: SetOption) => void }) {
  const count = plural(set.permissions.length, 'permission')
  return (
    <button
      type="button"
      className={`${pageStyles.actionButton} ${styles.viewButton}`}
      aria-label={`${count} in ${set.name}`}
      onClick={() => onView(set)}
    >
      <ListChecks size={14} /> {count}
    </button>
  )
}

/** What the form changed, and what saving it does to the permissions held: shown before saving. */
function ReviewChanges({ uid, edits, diff, inactive, setName, profileName }: {
  uid: string
  edits: DraftChanges
  diff: { gained: PermissionId[]; lost: PermissionId[] } | null
  /** The account's status when it is not active. */
  inactive: string | null
  setName: (id: string) => string
  profileName: (id: string | null) => string
}) {
  return (
    <section className={styles.review} aria-labelledby={`${uid}-review`}>
      <h3 id={`${uid}-review`} className={styles.reviewTitle}>Review before saving</h3>
      <div className={styles.reviewGrid}>
        <div className={styles.reviewPart}>
          <h4 className={styles.reviewHead}>What you changed</h4>
          <ul className={styles.changeList}>
            {edits.setsAdded.map((id) => <li key={`sa-${id}`} className={styles.changeAdd}>Set <strong>{setName(id)}</strong> ticked</li>)}
            {edits.setsRemoved.map((id) => <li key={`sr-${id}`} className={styles.changeRemove}>Set <strong>{setName(id)}</strong> unticked</li>)}
            {edits.overridesAdded.map((o) => <li key={`oa-${o.permission}`} className={styles.changeAdd}>Override added: {overrideText(o)}</li>)}
            {edits.overridesChanged.map((o) => <li key={`oc-${o.permission}`} className={styles.changeEdit}>Override changed: {overrideText(o)}</li>)}
            {edits.overridesRemoved.map((o) => <li key={`or-${o.permission}`} className={styles.changeRemove}>Override removed: {overrideText(o)}</li>)}
            {edits.profile && (
              <li className={styles.changeEdit}>Admin profile: {profileName(edits.profile.from)} → <strong>{profileName(edits.profile.to)}</strong></li>
            )}
          </ul>
        </div>
        <div className={styles.reviewPart}>
          <h4 className={styles.reviewHead}>What the account gains and loses</h4>
          {inactive ? (
            <p className={pageStyles.hint}>
              Nothing yet: the account is {inactive} and holds nothing until it is active. These changes apply from then.
            </p>
          ) : !diff ? (
            <p className={pageStyles.hint}>No preview: the list of permission sets could not be read.</p>
          ) : diff.gained.length + diff.lost.length === 0 ? (
            <p className={pageStyles.hint}>Nothing: the account can do exactly what it can do now.</p>
          ) : (
            <div className={styles.diffColumns}>
              <div>
                <span className={styles.gainText}>+ {plural(diff.gained.length, 'permission')} gained</span>
                {diff.gained.length > 0 && (
                  <ul className={styles.codeList} aria-label="Permissions gained">
                    {diff.gained.map((p) => <li key={p}><code className={styles.permission}>{p}</code></li>)}
                  </ul>
                )}
              </div>
              <div>
                <span className={styles.lossText}>− {plural(diff.lost.length, 'permission')} lost</span>
                {diff.lost.length > 0 && (
                  <ul className={styles.codeList} aria-label="Permissions lost">
                    {diff.lost.map((p) => <li key={p}><code className={styles.permission}>{p}</code></li>)}
                  </ul>
                )}
              </div>
            </div>
          )}
          {!inactive && diff && diff.lost.length > 0 && (
            <p className={pageStyles.hint}>Taking a permission away signs the account out when you save.</p>
          )}
        </div>
      </div>
    </section>
  )
}

export default UserPermissionsPanel
