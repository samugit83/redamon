'use client'

import { useId } from 'react'
import type { ListMode, SettingValue } from '@/lib/tradecraft/settingsSpec'
import { ListField } from '../dialog/SettingField'
import { formatValue } from '../dialog/draft'
import type { OverrideFieldProps } from './OverrideField'
import css from './form.module.css'

type ListOverride = { mode: ListMode; items: string[] }
type TextOverride = { mode: ListMode; text: string }

/**
 * A list or text a resource can add to the account's, or replace (§6.1, R-132): include and
 * exclude paths, GitHub file types, the summary's extra instructions. Adding is the default.
 */
export function ListModeField({ def, inherited, value, onChange, error, hint }: OverrideFieldProps) {
  const id = useId()
  const isText = def.type === 'string'
  const overridden = value !== undefined && value !== null
  const current = (overridden ? value : null) as ListOverride | TextOverride | null
  const start = (): ListOverride | TextOverride => (isText ? { mode: 'add', text: '' } : { mode: 'add', items: [] })
  const setMode = (mode: ListMode) => onChange({ ...current!, mode })
  return (
    <div className={css.field} data-setting={def.key}>
      <div className={css.fieldHead}>
        <label className={css.fieldLabel} htmlFor={id}>{def.label}</label>
        <label className={css.overrideToggle}>
          <input type="checkbox" className="checkbox" aria-label={`Override ${def.label}`} checked={overridden} onChange={e => onChange(e.target.checked ? start() : undefined)} />
          Override
        </label>
      </div>
      <span className={css.inheritedValue}>Using your setting: {formatValue(def, inherited as SettingValue)}</span>
      {current && (
        <>
          <div className={css.radioRow} role="radiogroup" aria-label={`${def.label}: add or replace`}>
            <label className={css.checkLine}><input type="radio" className="radio" checked={current.mode === 'add'} onChange={() => setMode('add')} /> Add to mine</label>
            <label className={css.checkLine}><input type="radio" className="radio" checked={current.mode === 'replace'} onChange={() => setMode('replace')} /> Replace mine</label>
          </div>
          {isText ? (
            <textarea
              id={id} className="textarea" rows={3} maxLength={def.maxLength} value={(current as TextOverride).text}
              onChange={e => onChange({ ...current, text: e.target.value })}
            />
          ) : (
            <ListField id={id} def={def} value={(current as ListOverride).items} onChange={items => onChange({ ...current, items })} />
          )}
        </>
      )}
      <span className="formHint">{def.help}</span>
      {hint}
      {error && <div className="formError" role="alert">{error}</div>}
    </div>
  )
}
