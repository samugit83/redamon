'use client'

import { useId, useState } from 'react'
import { Plus, X } from 'lucide-react'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { excludeLoop } from '@/lib/agentInTheLoop'
import type { SettingDef } from '@/lib/tradecraft/settingsSpec'
import { allowedText, formatValue, parseDraft, sameValue } from './draft'
import css from './dialog.module.css'

/** The words of each enum value and list item, where the spec's own value is a code. */
export const VALUE_LABELS: Readonly<Record<string, Record<string, string>>> = {
  'fetching.browserWaitUntil': { load: 'Page load', domcontentloaded: 'DOM ready', networkidle: 'Network idle' },
  'detection.enabledDetectors': {
    mkdocs: 'MkDocs/mdBook', sphinx: 'Sphinx/Docusaurus', gitbook: 'GitBook', github: 'GitHub', cve: 'CVE archive',
  },
  'knownTypes.language': { auto: 'Auto (English)', all: 'Keep all languages', preferred: 'Preferred language' },
  'crawl.strategy': { llm: 'LLM-guided', auto: 'Auto', rules: 'Rule-based' },
  'crawl.onLlmStop': { obey: 'Obey', ignoreUntil: 'Ignore until N pages' },
  'crawl.hostScope': { exact: 'Exact host', www: 'Also www', subdomains: 'All subdomains' },
  'crawl.queryStrings': { keep: 'Keep', drop: 'Drop the query', keepN: 'Keep up to N per path' },
  'storage.defaultMode': { live: 'Live', stored: 'Stored', recommended: "The type's recommendation" },
  'refreshing.onFailure': { keep: 'Keep the previous version', replace: 'Replace it' },
  'focus.defaultMode': { everything: 'Everything', focused: 'Focused', tag_only: 'Tag only' },
  'focus.defaultStrictness': { loose: 'Loose', balanced: 'Balanced', strict: 'Strict' },
  'focus.tagEveryPage': { rules_model: 'Rules + model for the rest', rules: 'Rules only' },
}

/** Keys the dialog shows with a picker of the person's models instead of free text. */
const MODEL_KEYS = new Set(['summary.defaultModel'])

export interface SettingFieldProps {
  def: SettingDef
  value: unknown
  error?: string
  /** Shown dimmed, still editable: the setting is used only when another one has a given value. */
  inactiveHint?: string
  userId: string
  onChange: (value: unknown) => void
}

/** One setting of a settings dialog: label, control, help, default and allowed values, changed marker, error. */
export function SettingField({ def, value, error, inactiveHint, userId, onChange }: SettingFieldProps) {
  const id = useId()
  const labels = VALUE_LABELS[def.key]
  const changed = !sameValue(parseDraft(def, value), def.default)
  const allowed = allowedText(def)
  return (
    <div className={`${css.field}${inactiveHint ? ` ${css.fieldInactive}` : ''}`} data-setting={def.key}>
      <div className={css.fieldHead}>
        {def.type === 'bool' ? (
          <label className={css.inline}>
            <input id={id} type="checkbox" checked={value === true} onChange={e => onChange(e.target.checked)} />
            <span>{def.label}</span>
          </label>
        ) : (
          <label htmlFor={id}>{def.label}</label>
        )}
        {changed && <span className={css.changed} title="Changed from the default">● changed</span>}
      </div>
      {def.type !== 'bool' && <Control id={id} def={def} value={value} labels={labels} userId={userId} onChange={onChange} />}
      <div className={css.fieldMeta}>
        {def.help} Default: {formatValue(def, def.default, labels)}.{allowed ? ` Allowed: ${allowed}.` : ''}
        {inactiveHint ? ` ${inactiveHint}` : ''}
      </div>
      {error && <div className={css.fieldError} role="alert">{error}</div>}
    </div>
  )
}

/** The input of one setting by its spec type (the resource form reuses it for an override). */
export function Control({ id, def, value, labels, userId, onChange }: {
  id: string; def: SettingDef; value: unknown; labels?: Record<string, string>; userId: string; onChange: (v: unknown) => void
}) {
  if (MODEL_KEYS.has(def.key)) {
    return (
      <ModelPicker
        userId={userId} value={typeof value === 'string' ? value : ''} onChange={v => onChange(v)}
        placeholder="no default: pick a model on each resource" filter={excludeLoop}
      />
    )
  }
  switch (def.type) {
    case 'int':
    case 'number':
      return (
        <div className={css.inline}>
          <input
            id={id} className={`textInput ${css.numberInput}`} inputMode={def.type === 'int' ? 'numeric' : 'decimal'}
            value={typeof value === 'number' ? String(value) : String(value ?? '')} onChange={e => onChange(e.target.value)}
          />
          {def.unit && <span className={css.fieldMeta}>{def.unit}</span>}
        </div>
      )
    case 'enum':
      return (
        <select id={id} className="select" value={String(value)} onChange={e => onChange(e.target.value)}>
          {def.values!.map(v => <option key={v} value={v}>{labels?.[v] ?? v}</option>)}
        </select>
      )
    case 'string':
      return def.maxLength! > 200
        ? <textarea id={id} className="textarea" rows={3} maxLength={def.maxLength} value={String(value ?? '')} onChange={e => onChange(e.target.value)} />
        : <input id={id} className="textInput" maxLength={def.maxLength} value={String(value ?? '')} onChange={e => onChange(e.target.value)} />
    case 'list':
      return def.values
        ? <ChoiceList id={id} def={def} value={value as string[]} labels={labels} onChange={onChange} />
        : <ListField id={id} def={def} value={value as string[]} onChange={onChange} />
    default:
      return null
  }
}

function ChoiceList({ id, def, value, labels, onChange }: {
  id: string; def: SettingDef; value: string[]; labels?: Record<string, string>; onChange: (v: unknown) => void
}) {
  const on = new Set(Array.isArray(value) ? value : [])
  return (
    <div id={id} className={css.inline} role="group" aria-label={def.label}>
      {def.values!.map(v => (
        <label key={v} className={css.inline}>
          <input
            type="checkbox" checked={on.has(v)}
            onChange={e => onChange(def.values!.filter(x => (x === v ? e.target.checked : on.has(x))))}
          />
          <span>{labels?.[v] ?? v}</span>
        </label>
      ))}
    </div>
  )
}

/** An editable list: chips with a remove button, and a box to add one item. */
export function ListField({ id, def, value, onChange, addLabel }: {
  id: string; def: SettingDef; value: string[]; onChange: (v: string[]) => void; addLabel?: string
}) {
  const [text, setText] = useState('')
  const items = Array.isArray(value) ? value : []
  const add = () => {
    const item = text.trim()
    if (!item) return
    if (!items.includes(item)) onChange([...items, item])
    setText('')
  }
  return (
    <div className={css.field}>
      <div className={css.chips} aria-label={`${def.label} items`}>
        {items.map(item => (
          <span key={item} className={css.chip}>
            {item}
            <button type="button" className={css.chipRemove} aria-label={`Remove ${item}`} onClick={() => onChange(items.filter(x => x !== item))}>
              <X size={10} />
            </button>
          </span>
        ))}
      </div>
      <div className={css.inline}>
        <input
          id={id} className="textInput" value={text} maxLength={def.maxLength}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add() } }}
          placeholder="add an item"
        />
        <button type="button" className="secondaryButton" aria-label={addLabel ?? `Add to ${def.label}`} onClick={add}><Plus size={12} /></button>
      </div>
    </div>
  )
}

