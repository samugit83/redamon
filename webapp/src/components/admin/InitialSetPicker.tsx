'use client'

import { useCallback, useContext, useEffect, useState } from 'react'
import { fetchJson, toApiError } from '@/lib/apiError'
import { stepUpPermissionsIn } from '@/lib/authz/hierarchy'
import type { PermissionId } from '@/lib/authz/permissions'
import { useCan, useRbacFlags } from '@/hooks/useCan'
import { AuthContext } from '@/providers/authContext'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import {
  DEFAULT_MEMBER_SET, givableFrom, notGivable, offeredMemberSets, permissionsUrl,
  type AccountPermissionsView, type SetList, type SetOption,
} from './permissionModel'
import styles from '@/app/settings/users/page.module.css'

/** The set a new account starts with: '' = the instance default (nothing sent). */
export interface InitialSetChoice {
  setId: string
  /** The person's own password, when the chosen set needs it. */
  password: string
  needsPassword: boolean
}

export const NO_INITIAL_SET: InitialSetChoice = Object.freeze({ setId: '', password: '', needsPassword: false })

/**
 * The fields the invite or create request carries for the choice (POST /api/users/invite and POST
 * /api/users, step 3.13), or the message to show when the password is missing.
 */
export function initialSetFields(choice: InitialSetChoice): { sets?: string[]; stepUpPassword?: string } | { error: string } {
  if (!choice.setId) return {}
  if (choice.needsPassword && !choice.password) return { error: 'Enter your password to give this permission set.' }
  return { sets: [choice.setId], ...(choice.needsPassword ? { stepUpPassword: choice.password } : {}) }
}

interface InitialSetPickerProps {
  idPrefix: string
  /** The signed-in person, whose holdings decide which sets they may give; default: the session's. */
  selfId?: string
  value: InitialSetChoice
  onChange: (value: InitialSetChoice) => void
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string; permission: string | null }
  | { kind: 'ready'; sets: SetOption[]; defaultSet: SetOption | null; givable: ReadonlySet<PermissionId> }

/**
 * "Permission set" in the invite and create dialogs (step 3.13, ID-28: permissions are chosen at
 * creation). Shown with the permissions switch on to whoever holds `users:assign_permissions`;
 * otherwise nothing renders and the account gets the instance default set. The default choice is
 * the instance default (nothing sent, so the account follows it when it changes). A set holding
 * what the person does not hold is listed disabled with the reason; one that gives a cross-tenant
 * tool, an exploitation approval, sessions or Kali exec adds the person's password field (ID-25).
 */
export function InitialSetPicker({ idPrefix, selfId: given, value, onChange }: InitialSetPickerProps) {
  const sessionUserId = useContext(AuthContext)?.user?.id
  const selfId = given ?? sessionUserId
  const flags = useRbacFlags()
  const canAssign = useCan('users:assign_permissions')
  const shown = flags?.permissions === true && canAssign && Boolean(selfId)
  const [state, setState] = useState<State>({ kind: 'loading' })

  const load = useCallback(async () => {
    if (!selfId) return
    setState({ kind: 'loading' })
    try {
      const [list, me] = await Promise.all([
        fetchJson<SetList>('/api/admin/permission-sets', undefined, 'Could not list the permission sets'),
        fetchJson<AccountPermissionsView>(permissionsUrl(selfId), undefined, 'Could not read your own permissions'),
      ])
      const defaultId = list.instanceDefaultSetId ?? DEFAULT_MEMBER_SET
      setState({
        kind: 'ready',
        // The first option already is the instance default; Default member is not offered on its own.
        sets: offeredMemberSets(list.sets),
        defaultSet: list.sets.find((s) => s.id === defaultId) ?? null,
        givable: givableFrom(me.explain),
      })
    } catch (err) {
      const error = toApiError(err, 'Could not list the permission sets')
      setState({ kind: 'error', message: error.message, permission: forbiddenPermission(error) })
    }
  }, [selfId])

  useEffect(() => {
    if (shown) void load()
  }, [shown, load])

  if (!shown) return null
  const selectId = `${idPrefix}-set`
  const hintId = `${selectId}-hint`

  if (state.kind === 'loading') {
    return <div className={styles.field}><span className={styles.hint} role="status">Loading the permission sets…</span></div>
  }
  if (state.kind === 'error') {
    return (
      <div className={styles.field}>
        {state.permission ? <ForbiddenNotice permission={state.permission} /> : <div className={styles.error} role="alert">{state.message}</div>}
        <span className={styles.hint}>The account gets the instance default set; you can change it afterwards.</span>
        {!state.permission && <button type="button" className={styles.actionButton} onClick={() => void load()}>Retry</button>}
      </div>
    )
  }

  const chosen = state.sets.find((s) => s.id === value.setId) ?? null
  const stepUpFor = chosen ? stepUpPermissionsIn(chosen.permissions) : []

  function choose(setId: string) {
    const set = state.kind === 'ready' ? state.sets.find((s) => s.id === setId) : undefined
    const needsPassword = Boolean(set && stepUpPermissionsIn(set.permissions).length)
    onChange({ setId, password: needsPassword ? value.password : '', needsPassword })
  }

  return (
    <>
      <div className={styles.field}>
        <label className={styles.label} htmlFor={selectId}>Permission set</label>
        <select id={selectId} className={styles.select} value={value.setId} onChange={(e) => choose(e.target.value)} aria-describedby={hintId}>
          <option value="">Instance default{state.defaultSet ? `: ${state.defaultSet.name}` : ''}</option>
          {state.sets.map((s) => {
            const missing = notGivable(s.permissions, state.givable)
            return (
              <option key={s.id} value={s.id} disabled={missing.length > 0}>
                {s.name}{missing.length ? ` (you do not hold ${missing.length === 1 ? missing[0] : `${missing.length} of its permissions`})` : ''}
              </option>
            )
          })}
        </select>
        <span id={hintId} className={styles.hint}>
          {chosen
            ? chosen.description ?? `${chosen.permissions.length} permissions.`
            : 'The account follows the instance default set, also when it changes later. You can give only sets whose permissions you hold.'}
        </span>
      </div>
      {stepUpFor.length > 0 && (
        <div className={styles.field}>
          <label className={styles.label} htmlFor={`${selectId}-step-up`}>Your password</label>
          <input
            id={`${selectId}-step-up`}
            type="password"
            className={styles.input}
            value={value.password}
            onChange={(e) => onChange({ ...value, password: e.target.value })}
            autoComplete="current-password"
            aria-describedby={`${selectId}-step-up-hint`}
          />
          <span id={`${selectId}-step-up-hint`} className={styles.hint}>
            This set gives {stepUpFor.join(', ')}: confirm with your own password.
          </span>
        </div>
      )}
    </>
  )
}

export default InitialSetPicker
