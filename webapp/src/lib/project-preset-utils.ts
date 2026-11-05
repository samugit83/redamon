/**
 * What a project preset carries, and how it is captured and applied.
 *
 * A preset is a reusable CONFIGURATION: every registry column, minus the classes
 * that are not configuration. Letting any of those ride along is how a preset
 * saved from project A quietly re-scopes project B:
 *
 *   the scope         what the project scans and the proof that it may: the
 *                     domain, the address list, the batch, the ownership check,
 *                     the guardrail, the other scanners' targets. The registry
 *                     marks these `create_only` ("moves with the scope").
 *   the engagement    its LIMITS (the rate ceiling, the excluded hosts, the
 *                     scanning window, the agent's denylists), its RECORD (the
 *                     client, the contacts, the dates, the document text), and
 *                     its kind and identity header.
 *   files             every upload reference: a preset naming one would point a
 *                     second project at a file only the first one uploaded.
 *   credentials       tokens and auth values. A per-target credential applied to
 *                     another project sends it to a target it was never issued for.
 *   the row itself    id, owner, timestamps, activation state. A preset carrying
 *                     `id` makes the receiving project's next save try to
 *                     rewrite its primary key.
 *
 * Everything is asked of the registry rather than matched on a name prefix. These
 * columns are still called `roe*` and will stay called that, but a guard written
 * as `key.startsWith('roe')` survives a reclassification by accident, so the next
 * person to rename a column silently removes a live control.
 */
import {
  engagementLimitFields,
  engagementRecordFields,
  field,
  fieldKeys,
  fieldsWhere,
} from '@/lib/reconSettings/registry'
import { canonicalJson, cyrb53 } from '@/lib/fingerprint'
import { isLoopModel } from '@/lib/agentInTheLoop'

/** Columns with no registry classification that says "not configuration". */
const UNCLASSIFIED_EXCLUDED_FIELDS = [
  'name',
  'description',
  // Text content tied to the project, not reusable across targets.
  'vhostSniCustomWordlist',
  // Selects WHICH supply-chain input the scan reads (an upload, a repository, an
  // org). The inputs themselves move with the scope, so carrying the selector
  // alone points the Other Scans card at an input this project never set.
  'supplyChainInputMode',
]

/**
 * Every column a preset must never capture or apply.
 *
 * Built from registry queries, so reclassifying a field updates this set with it.
 * `project-preset-utils.test.ts` asserts the composition, which is what stops a
 * query being replaced by a snapshot of its answer.
 */
export const PRESET_EXCLUDED_FIELDS: ReadonlySet<string> = new Set([
  ...UNCLASSIFIED_EXCLUDED_FIELDS,
  ...fieldsWhere(f => f.mcp === 'create_only').map(f => f.key),
  ...engagementLimitFields().map(f => f.key),
  ...engagementRecordFields().map(f => f.key),
  ...fieldsWhere(f => f.tool === 'engagement').map(f => f.key),
  ...fieldsWhere(f => f.deny_reason === 'upload-managed').map(f => f.key),
  ...fieldsWhere(f => f.read_deny_reason === 'credential').map(f => f.key),
  ...fieldsWhere(f => f.validator === 'provider_reference').map(f => f.key),
  // A preset that does not name one of these resets it to its default, and the
  // default of `mcpKaliExecEnabled` is ON: carrying it let applying any preset
  // quietly re-enable the MCP sandbox a person had switched off.
  ...fieldsWhere(f => f.deny_reason === 'escalation' || f.deny_reason === 'not-tuning').map(f => f.key),
  // reconPresetId is internal too, but it is what the "Started from" badge is
  // restored from when a user preset is loaded, so it travels.
  ...fieldsWhere((f, key) =>
    (f.deny_reason === 'identity' || f.deny_reason === 'internal' || f.deny_reason === 'derived')
    && key !== 'reconPresetId'
  ).map(f => f.key),
  ...fieldsWhere(f => f.deny_reason === 'secret').map(f => f.key),
])

/** Every column a preset captures and applies: the whole registry minus the excluded set. */
export const PRESET_FIELD_KEYS: readonly string[] = fieldKeys().filter(k => !PRESET_EXCLUDED_FIELDS.has(k))

/**
 * Kept as they are when a preset does not name them, instead of being reset.
 *
 * The first two are models the user may have no provider for, which is why the
 * create form makes them pick explicitly. The per-hook Jev fields (the four
 * *AiUseJev engine switches and the Jev-only hooks) are tied to whether the
 * project selects a Jev provider, a fact no preset can know; resetting them to false on
 * every preset apply would silently turn Jev off for the project. Built-in
 * presets never name any of these; an AI-generated one can name a Jev field, and
 * switching one on is then refused without that selection (jevEngine.ts).
 */
export const KEPT_WHEN_ABSENT: ReadonlySet<string> = new Set([
  'agentOpenaiModel', 'aiPipelineModel',
  'ffufAiUseJev', 'nucleiTagsAiUseJev', 'wafAiUseJev', 'takeoverAiUseJev',
  'ffufJevBasePaths', 'httpxJevPageType', 'resourceEnumJevToolHealth', 'hakrawlerJevSeedOrder',
  'serializedScanJevRank', 'routeExposureJevRank', 'routeExposureJevWallCheck', 'routeExposureJevAssess',
])

export type Lookup = { found: true; value: unknown } | { found: false }

const hasOwn = (obj: Record<string, unknown>, key: string) =>
  Object.prototype.hasOwnProperty.call(obj, key)

/**
 * A column's Prisma default, from the registry's joined copy.
 *
 * Json columns carry their default as the literal Prisma string, so it is parsed
 * into the value the form holds. A nullable column with no default resets to null.
 */
function registryDefault(key: string): Lookup {
  const f = field(key)
  if (!f) return { found: false }
  if (f.has_default && f.default !== undefined && f.default !== null) {
    if (f.type === 'json' && typeof f.default === 'string') {
      try {
        return { found: true, value: JSON.parse(f.default) }
      } catch {
        return { found: false }
      }
    }
    return { found: true, value: f.default }
  }
  if (f.optional) return { found: true, value: null }
  return { found: false }
}

/**
 * The value a preset field resets to when the preset does not name it.
 *
 * `/api/projects/defaults` wins where it has the key, because the recon and agent
 * backends are the runtime source of truth (test_prisma_default_parity.py keeps
 * their defaults equal to Prisma's). It does not cover every column, so the
 * Prisma default fills the rest. Without that fallback those columns would keep
 * whatever the previous configuration had, and settings would stick across presets.
 */
export function defaultFor(key: string, backendDefaults: Record<string, unknown>): Lookup {
  if (hasOwn(backendDefaults, key)) return { found: true, value: backendDefaults[key] }
  return registryDefault(key)
}

/**
 * Capture a preset from form data: every preset field, and only those.
 *
 * A key the form does not hold yet is captured at its Prisma default. The create
 * form only holds what `/defaults` returned, so without this a preset saved
 * there would miss every column `/defaults` does not cover. Anything that is
 * not a preset field (the row id, relations like `user`, keys `/defaults` returns
 * that are not columns) is dropped.
 */
export function extractPresetSettings(
  formData: Record<string, unknown>
): Record<string, unknown> {
  const settings: Record<string, unknown> = {}
  for (const key of PRESET_FIELD_KEYS) {
    if (hasOwn(formData, key)) {
      settings[key] = formData[key]
      continue
    }
    const d = registryDefault(key)
    if (d.found) settings[key] = d.value
  }
  return settings
}

/**
 * Apply a preset over the current form: the preset REPLACES the configuration.
 *
 * Every preset field takes the preset's value, or its default when the preset
 * does not name it, so the result never depends on what was configured before.
 * Nothing outside the preset fields is touched, so the scope, the engagement,
 * the files and the credentials stay exactly as they were. That is also what
 * neutralises presets saved before the exclusions existed: whatever they carry
 * outside the preset fields is never read.
 *
 * `backendDefaults` is the `/api/projects/defaults` response; pass `{}` when it
 * is unavailable and the Prisma defaults are used for every field.
 */
export function applyPresetSettings(
  current: Record<string, unknown>,
  presetSettings: Record<string, unknown>,
  backendDefaults: Record<string, unknown>,
): Record<string, unknown> {
  const next: Record<string, unknown> = { ...current }
  for (const key of PRESET_FIELD_KEYS) {
    if (key === 'attackSkillConfig') {
      const fromPreset: Lookup = hasOwn(presetSettings, key) ? { found: true, value: presetSettings[key] } : defaultFor(key, backendDefaults)
      if (fromPreset.found) next[key] = withOwnSkillToggles(fromPreset.value, current[key], hasOwn(presetSettings, key))
      continue
    }
    // A preset never chooses Agent in the Loop, even one stored before that was
    // refused: the value is treated as absent, so the project keeps its model.
    if (hasOwn(presetSettings, key) && !(KEPT_WHEN_ABSENT.has(key) && isLoopModel(presetSettings[key]))) {
      next[key] = presetSettings[key]
      continue
    }
    if (KEPT_WHEN_ABSENT.has(key)) continue
    const d = defaultFor(key, backendDefaults)
    if (d.found) next[key] = d.value
  }
  return next
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

/**
 * `attackSkillConfig` is half preset, half the person's own. `builtIn` follows the preset
 * (or the default) like any field; `user`, the toggles of their own skills, is kept as the
 * project has it unless the preset itself carries a non-empty `user` map. A preset cannot
 * know the person's skills, and with a missing toggle meaning OFF, resetting `user` to the
 * default `{}` would silently turn every one of them off on each apply. An empty map says
 * nothing either: an imported preset trimmed of another account's ids, or one saved when a
 * missing toggle meant ON.
 */
function withOwnSkillToggles(presetValue: unknown, currentValue: unknown, named: boolean): unknown {
  if (!isPlainObject(presetValue)) return presetValue
  if (named && isPlainObject(presetValue.user) && Object.keys(presetValue.user).length > 0) return presetValue
  const currentUser = isPlainObject(currentValue) && isPlainObject(currentValue.user) ? currentValue.user : {}
  return { ...presetValue, user: { ...currentUser } }
}

/** The preset fields of `data`: the body a preset load saves. */
export function pickPresetFields(data: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of PRESET_FIELD_KEYS) {
    if (hasOwn(data, key)) out[key] = data[key]
  }
  return out
}

/**
 * What a project records about the preset last loaded into it (the
 * `loadedPreset` column). The badge shows `name` only while the saved settings
 * still hash to `fingerprint`, so ANY later change to a preset field hides it,
 * whichever door it came through: the form, a workflow toggle, or MCP.
 *
 * `presetId` and `source` say which preset it was, so renaming a user preset
 * renames its badges and deleting one clears them. A badge written before they
 * existed carries neither and keeps its name.
 */
export interface LoadedPreset {
  name: string
  fingerprint: string
  presetId?: string
  source?: 'builtin' | 'user'
}

export function readLoadedPreset(value: unknown): LoadedPreset | null {
  if (!value || typeof value !== 'object') return null
  const { name, fingerprint, presetId, source } = value as Record<string, unknown>
  if (typeof name !== 'string' || typeof fingerprint !== 'string') return null
  return {
    name,
    fingerprint,
    ...(typeof presetId === 'string' ? { presetId } : {}),
    ...(source === 'builtin' || source === 'user' ? { source } : {}),
  }
}

const FINGERPRINT_PREFIX = 'v2:'

function atRegistryDefault(key: string, value: unknown): boolean {
  const d = registryDefault(key)
  return d.found && canonicalJson(d.value) === canonicalJson(value)
}

/**
 * A digest of every preset field in `data` that is NOT at its Prisma default,
 * missing ones counting as their default.
 *
 * Leaving the defaults out is what lets a badge outlive a registry change: a
 * column added later reaches every existing row at its default, and a column
 * that stops being a preset field only matters where the project held something
 * else. A digest of every field changed with each of those and hid every badge
 * at once, as removing two fields from presets did.
 */
export function presetFingerprint(data: Record<string, unknown>): string {
  const settings = extractPresetSettings(data)
  const lines = [...PRESET_FIELD_KEYS].sort()
    .filter(k => !atRegistryDefault(k, settings[k]))
    .map(k => `${k}=${canonicalJson(settings[k])}`)
  return FINGERPRINT_PREFIX + cyrb53(lines.join('\n'))
}

/**
 * The two preset fields that became escalation settings and left presets.
 * The unversioned digest a badge saved before then covered them too.
 */
const LEFT_PRESETS = new Set(['mcpKaliExecEnabled', 'updateGraphDb'])

/**
 * The unversioned digests a badge written before `presetFingerprint` skipped
 * defaults may hold: every preset field in registry order, over the field set
 * of the time. Accepting them is the backfill: those badges still show, and the
 * next preset load writes the current form.
 */
function unversionedFingerprints(data: Record<string, unknown>): string[] {
  const valueOf = (k: string) => {
    if (hasOwn(data, k)) return data[k]
    const d = registryDefault(k)
    return d.found ? d.value : undefined
  }
  const digest = (keys: readonly string[]) =>
    cyrb53(keys.map(k => `${k}=${canonicalJson(valueOf(k))}`).join('\n'))
  const current = new Set(PRESET_FIELD_KEYS)
  return [
    digest(PRESET_FIELD_KEYS),
    digest(fieldKeys().filter(k => current.has(k) || LEFT_PRESETS.has(k))),
  ]
}

/** The name of the loaded preset, if `data` still holds exactly the settings it produced. */
export function appliedPresetName(data: Record<string, unknown>): string | null {
  const loaded = readLoadedPreset(data.loadedPreset)
  if (!loaded) return null
  const matches = loaded.fingerprint.startsWith(FINGERPRINT_PREFIX)
    ? presetFingerprint(data) === loaded.fingerprint
    : unversionedFingerprints(data).includes(loaded.fingerprint)
  return matches ? loaded.name : null
}
