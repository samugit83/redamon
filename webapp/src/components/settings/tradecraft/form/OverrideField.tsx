'use client'

import { useId } from 'react'
import { cloneValue, type SettingDef, type SettingValue } from '@/lib/tradecraft/settingsSpec'
import { Control, VALUE_LABELS } from '../dialog/SettingField'
import { formatValue } from '../dialog/draft'
import { ListModeField } from './ListModeField'
import css from './form.module.css'

export interface OverrideFieldProps {
  def: SettingDef
  /** What the resource gets without an override: the account's value, or the default of a resource-only key. */
  inherited: SettingValue
  /** The override as the form holds it, or undefined while the field inherits. */
  value: unknown
  onChange: (value: unknown) => void
  userId: string
  error?: string
  /** Extra controls under the field, such as Check URL's suggestions. */
  hint?: React.ReactNode
}

/**
 * One per-resource setting (§6.1): Inherit by default, showing the inherited value; Override
 * unlocks it, starting from that value; turning Override off returns to it.
 */
export function OverrideField(props: OverrideFieldProps) {
  const { def, inherited, value, onChange, userId, error, hint } = props
  const id = useId()
  if (def.listMode) return <ListModeField {...props} />
  const overridden = value !== undefined
  const labels = VALUE_LABELS[def.key]
  const source = def.level === 'resource' ? 'Default' : 'Using your setting'
  return (
    <div className={css.override} data-setting={def.key}>
      <div className={css.overrideHead}>
        <label htmlFor={id}>{def.label}</label>
        <label className={css.overrideToggle}>
          <input
            type="checkbox" aria-label={`Override ${def.label}`} checked={overridden}
            onChange={e => onChange(e.target.checked ? cloneValue(inherited) : undefined)}
          />
          Override
        </label>
      </div>
      {overridden ? (
        def.type === 'bool' ? (
          <label className={css.overrideHead}>
            <input id={id} type="checkbox" checked={value === true} onChange={e => onChange(e.target.checked)} />
            <span>{value === true ? 'On' : 'Off'}</span>
          </label>
        ) : (
          <Control id={id} def={def} value={value} labels={labels} userId={userId} onChange={onChange} />
        )
      ) : (
        <span id={id} className={css.inherited}>{source}: {formatValue(def, inherited, labels)}</span>
      )}
      <span className={css.inherited}>{def.help}</span>
      {hint}
      {error && <div className={css.checkFailed} role="alert">{error}</div>}
    </div>
  )
}
