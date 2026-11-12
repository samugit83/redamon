'use client'

import { PERMISSIONS, isPermissionId, type PermissionId } from '@/lib/authz/permissions'
import { PERMISSION_AREAS } from '@/lib/authz/permissionAreas'
import { overrideAllowed } from '@/lib/authz/hierarchy'
import type { AccountType, OverrideEffect } from './permissionModel'
import pageStyles from '@/app/settings/users/page.module.css'

interface PermissionPickerProps {
  id: string
  label: string
  /** The account the override is for: what an override may name depends on it (D-20, PE-30). */
  accountType: AccountType
  effect: OverrideEffect
  /** What the person may give (permissionModel.ts `givableFrom`). */
  givable: ReadonlySet<PermissionId>
  /** Permissions that already have an override on this account: one each. */
  exclude?: ReadonlySet<PermissionId>
  value: PermissionId | ''
  onChange: (value: PermissionId | '') => void
}

export const NOT_HELD_SUFFIX = ' (you do not hold it)'

/**
 * A permission for an override, grouped by area (step 3.13). Only what an override may name on
 * this account is listed (hierarchy.ts `overrideAllowed`: member permissions, a platform tool on a
 * member, never an administration right). For a grant, what the person does not hold is listed
 * disabled, with the reason in its text (PE-03: you give only what you hold); a deny gives nothing,
 * so every listed permission can be denied.
 */
export function PermissionPicker({ id, label, accountType, effect, givable, exclude, value, onChange }: PermissionPickerProps) {
  const groups = PERMISSION_AREAS
    .map((area) => ({ area, ids: area.permissions.filter((p) => overrideAllowed(p, accountType) && !exclude?.has(p)) }))
    .filter((g) => g.ids.length > 0)
  const hintId = `${id}-hint`

  return (
    <div className={pageStyles.field}>
      <label className={pageStyles.label} htmlFor={id}>{label}</label>
      <select
        id={id}
        className={pageStyles.select}
        value={value}
        onChange={(e) => onChange(isPermissionId(e.target.value) ? e.target.value : '')}
        aria-describedby={hintId}
      >
        <option value="">Choose a permission</option>
        {groups.map(({ area, ids }) => (
          <optgroup key={area.id} label={area.title}>
            {ids.map((p) => {
              const refused = effect === 'grant' && !givable.has(p)
              return (
                <option key={p} value={p} disabled={refused}>
                  {p}{refused ? NOT_HELD_SUFFIX : ''}
                </option>
              )
            })}
          </optgroup>
        ))}
      </select>
      <span id={hintId} className={pageStyles.hint}>
        {value ? PERMISSIONS[value].description : effect === 'grant'
          ? 'You can grant only permissions you hold yourself; the others are listed disabled.'
          : 'A deny wins over every set and grant while it lasts.'}
      </span>
    </div>
  )
}

export default PermissionPicker
