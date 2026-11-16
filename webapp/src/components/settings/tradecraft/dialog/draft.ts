/**
 * A settings dialog's draft: what a person typed, read through the spec. A number field keeps
 * its raw text while it is edited (an empty or half-typed number is not a value yet), so the
 * draft holds strings where the saved value is a number.
 */
import { canonicalJson } from '@/lib/tradecraft/effectiveSettings'
import { describeRange, isValidValue, type SettingDef, type SettingValue } from '@/lib/tradecraft/settingsSpec'

export type Draft = Record<string, unknown>

export function parseDraft(def: SettingDef, raw: unknown): unknown {
  if ((def.type === 'int' || def.type === 'number') && typeof raw === 'string') {
    const t = raw.trim()
    return t === '' ? NaN : Number(t)
  }
  if (def.type === 'list' && Array.isArray(raw)) return raw.map(x => String(x).trim()).filter(Boolean)
  return raw
}

/** The inline message for a draft value a save would refuse, or '' when it is valid. */
export function draftError(def: SettingDef, raw: unknown): string {
  return isValidValue(def, parseDraft(def, raw)) ? '' : `Must be ${describeRange(def)}`
}

export function sameValue(a: unknown, b: unknown): boolean {
  return canonicalJson(a) === canonicalJson(b)
}

export function formatValue(def: SettingDef, v: SettingValue, labels?: Record<string, string>): string {
  if (def.type === 'bool') return v ? 'on' : 'off'
  if (def.type === 'enum') return labels?.[v as string] ?? String(v)
  if (def.type === 'list') {
    const items = v as string[]
    if (items.length === 0) return 'none'
    return items.map(i => labels?.[i] ?? i).join(', ')
  }
  if (def.type === 'string') return v === '' ? 'empty' : String(v)
  return `${(v as number).toLocaleString('en-US')}${def.unit ? ` ${def.unit}` : ''}`
}

/** The allowed values in a field's footnote, shorter than `describeRange`. */
export function allowedText(def: SettingDef): string {
  if (def.type === 'int' || def.type === 'number') {
    return `${def.min!.toLocaleString('en-US')}–${def.max!.toLocaleString('en-US')}${def.unit ? ` ${def.unit}` : ''}`
  }
  if (def.type === 'string') return `up to ${def.maxLength} characters`
  if (def.type === 'list') return `up to ${def.maxItems} items`
  return ''
}
