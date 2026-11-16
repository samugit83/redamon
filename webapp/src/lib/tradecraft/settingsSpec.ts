/**
 * Tradecraft 2.0 settings: the one spec every layer reads.
 *
 * settingsSpec.json lists every ingestion and search setting (default, range, ceiling,
 * level, list mode) and every fixed constant. scripts/gen-tradecraft-spec.mjs copies it
 * byte for byte to agentic/tradecraft/settings_spec.json, where the agent clamps every
 * value it receives a second time (agentic/tradecraft/settings.py).
 *
 * Levels: `user` is set only in the user's dialogs, `both` is a user default a resource
 * may override, `resource` exists only on a resource. The stored JSON holds only the
 * values a person changed, keyed by the spec key: TradecraftUserSettings.ingestion and
 * .search for the user, UserTradecraftResource.overrides for a resource.
 *
 * A resource override of a `listMode` setting says whether it adds to the inherited value
 * or replaces it: `{ mode, items }` for a list, `{ mode, text }` for a text.
 */
import spec from './settingsSpec.json'

export type SettingScope = 'ingestion' | 'search'
export type SettingLevel = 'user' | 'both' | 'resource'
export type SettingType = 'int' | 'number' | 'bool' | 'enum' | 'string' | 'list'
export type SettingValue = number | boolean | string | string[]
export type ListMode = 'add' | 'replace'

export interface SettingDef {
  key: string
  section: string
  scope: SettingScope
  level: SettingLevel
  type: SettingType
  default: SettingValue
  min?: number
  max?: number
  ceiling?: number
  values?: string[]
  maxLength?: number
  maxItems?: number
  listMode?: boolean
  appliesTo?: string[]
  unit?: string
  label: string
  help: string
}

export interface SectionDef {
  id: string
  scope: SettingScope
  label: string
  appliesTo?: string[]
}

export type ListOverride = { mode: ListMode; items: string[] }
export type TextOverride = { mode: ListMode; text: string }
export type OverrideValue = SettingValue | ListOverride | TextOverride

export type SettingsValues = Record<string, SettingValue>
export type ResourceOverrides = Record<string, OverrideValue>

export interface SettingError {
  key: string
  code: 'unknown_key' | 'wrong_scope' | 'user_only' | 'resource_only' | 'bad_value' | 'bad_mode' | 'not_an_object'
  message: string
}

export type ValidationResult<T> = { ok: true; value: T } | { ok: false; errors: SettingError[] }

export const SETTINGS_SPEC_VERSION: number = spec.version
export const SETTINGS: readonly SettingDef[] = spec.settings as SettingDef[]
export const SECTIONS: readonly SectionDef[] = spec.sections as SectionDef[]
export const SETTINGS_CONSTANTS = spec.constants
/** The 1.x/forced type name (`mkdocs-wiki`, ...) to the short name the spec keys use (`wiki`, ...). */
export const SITE_TYPE_KEYS: Readonly<Record<string, string>> = spec.siteTypes

const BY_KEY: ReadonlyMap<string, SettingDef> = new Map(SETTINGS.map(s => [s.key, s]))

export function settingDef(key: string): SettingDef | undefined {
  return BY_KEY.get(key)
}

export function settingsOf(scope: SettingScope): SettingDef[] {
  return SETTINGS.filter(s => s.scope === scope)
}

export function specDefaults(scope: SettingScope): SettingsValues {
  const out: SettingsValues = {}
  for (const s of settingsOf(scope)) out[s.key] = cloneValue(s.default)
  return out
}

export function cloneValue<T extends SettingValue>(v: T): T {
  return (Array.isArray(v) ? [...v] : v) as T
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** The range a person may save, in words, for 400 answers that name the key and its range. */
export function describeRange(def: SettingDef): string {
  switch (def.type) {
    case 'int':
      return `an integer from ${def.min} to ${def.max}`
    case 'number':
      return `a number from ${def.min} to ${def.max}`
    case 'bool':
      return 'true or false'
    case 'enum':
      return `one of ${def.values!.join(', ')}`
    case 'string':
      return `text of at most ${def.maxLength} characters`
    case 'list':
      return def.values
        ? `a list of at most ${def.maxItems} items from ${def.values.join(', ')}`
        : `a list of at most ${def.maxItems} items of at most ${def.maxLength} characters each`
  }
}

/** Whether `v` is a value a person may save for `def` (the UI range, which never exceeds the ceiling). */
export function isValidValue(def: SettingDef, v: unknown): v is SettingValue {
  switch (def.type) {
    case 'int':
      return typeof v === 'number' && Number.isInteger(v) && v >= def.min! && v <= def.max!
    case 'number':
      return typeof v === 'number' && Number.isFinite(v) && v >= def.min! && v <= def.max!
    case 'bool':
      return typeof v === 'boolean'
    case 'enum':
      return typeof v === 'string' && def.values!.includes(v)
    case 'string':
      return typeof v === 'string' && v.length <= def.maxLength!
    case 'list':
      return isValidList(def, v)
  }
}

function isValidList(def: SettingDef, v: unknown): v is string[] {
  if (!Array.isArray(v) || v.length > def.maxItems!) return false
  return v.every(item =>
    typeof item === 'string' && item.length > 0 && item.length <= def.maxLength! && (!def.values || def.values.includes(item)))
}

function badValue(def: SettingDef): SettingError {
  return { key: def.key, code: 'bad_value', message: `${def.key} must be ${describeRange(def)}` }
}

/**
 * Validates the values a person saves in Configure ingestion (`scope: 'ingestion'`) or
 * Configure search (`'search'`). Accepts only keys of that scope with level `user` or
 * `both`; every error names its key.
 */
export function validateUserSettings(scope: SettingScope, input: unknown): ValidationResult<SettingsValues> {
  if (!isPlainObject(input)) return { ok: false, errors: [{ key: '', code: 'not_an_object', message: 'settings must be an object' }] }
  const errors: SettingError[] = []
  const value: SettingsValues = {}
  for (const [key, raw] of Object.entries(input)) {
    const def = BY_KEY.get(key)
    if (!def) { errors.push({ key, code: 'unknown_key', message: `${key} is not a setting` }); continue }
    if (def.scope !== scope) { errors.push({ key, code: 'wrong_scope', message: `${key} is not a ${scope} setting` }); continue }
    if (def.level === 'resource') { errors.push({ key, code: 'resource_only', message: `${key} is set on a resource only` }); continue }
    if (!isValidValue(def, raw)) { errors.push(badValue(def)); continue }
    value[key] = cloneValue(raw)
  }
  return errors.length ? { ok: false, errors } : { ok: true, value }
}

function isListMode(v: unknown): v is ListMode {
  return v === 'add' || v === 'replace'
}

/**
 * Validates a resource's `overrides`. Only `both` and `resource` keys may appear (a
 * user-only setting never reaches the form, §6.1); a `listMode` key carries its mode.
 */
export function validateOverrides(input: unknown): ValidationResult<ResourceOverrides> {
  if (!isPlainObject(input)) return { ok: false, errors: [{ key: '', code: 'not_an_object', message: 'overrides must be an object' }] }
  const errors: SettingError[] = []
  const value: ResourceOverrides = {}
  for (const [key, raw] of Object.entries(input)) {
    const def = BY_KEY.get(key)
    if (!def) { errors.push({ key, code: 'unknown_key', message: `${key} is not a setting` }); continue }
    if (def.level === 'user') { errors.push({ key, code: 'user_only', message: `${key} is a user-only setting` }); continue }
    if (def.listMode) {
      if (!isPlainObject(raw) || !isListMode(raw.mode)) {
        errors.push({ key, code: 'bad_mode', message: `${key} must be { mode: "add" | "replace", ${def.type === 'list' ? 'items' : 'text'} }` })
        continue
      }
      const inner = def.type === 'list' ? raw.items : raw.text
      if (Object.keys(raw).length !== 2 || !isValidValue(def, inner)) { errors.push(badValue(def)); continue }
      value[key] = def.type === 'list'
        ? { mode: raw.mode, items: [...(inner as string[])] }
        : { mode: raw.mode, text: inner as string }
      continue
    }
    if (!isValidValue(def, raw)) { errors.push(badValue(def)); continue }
    value[key] = cloneValue(raw)
  }
  return errors.length ? { ok: false, errors } : { ok: true, value }
}
