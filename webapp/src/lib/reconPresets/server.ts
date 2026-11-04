/**
 * Recon presets on the server: what a stored preset may hold, which presets a
 * user may reach, and applying one to a project exactly as the project form does.
 *
 * Every rule about WHICH fields a preset carries lives in
 * `project-preset-utils.ts` and is imported, never re-derived: a second copy of
 * that set is how a preset once carried the MCP sandbox switch. This module adds
 * only what the browser never needed - validating stored values, bounding a
 * write, and reading defaults server-side with a timeout.
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { canonicalJson } from '@/lib/fingerprint'
import { getPresetById, type ReconPreset } from '@/lib/recon-presets'
import {
  KEPT_WHEN_ABSENT,
  PRESET_FIELD_KEYS,
  applyPresetSettings,
  pickPresetFields,
  presetFingerprint,
  type LoadedPreset,
} from '@/lib/project-preset-utils'
import { DENY_REASON_DOC } from '@/lib/reconSettings/filter'
import { field, type RegistryField } from '@/lib/reconSettings/registry'
import { validateValue } from '@/lib/reconSettings/validators'
import { isLoopModel } from '@/lib/agentInTheLoop'

/**
 * A preset is applied by people who often do not read it, so it must not
 * choose the brain: a loop model is refused on save over MCP, dropped from a UI
 * save or an import, and never written by an apply (applyPresetSettings).
 */
const LOOP_MODEL_KEYS: ReadonlySet<string> = new Set(['agentOpenaiModel', 'aiPipelineModel'])
const PRESET_LOOP_REFUSAL =
  'cannot be Agent in the Loop: a preset cannot choose it; a person selects it in the project form'
import { validateCrossFieldRules } from '@/lib/reconSettings/crossField'
import { JEV_VERIFY_FAILED, jevSwitchedOn, validateJevEngineChange } from '@/lib/reconSettings/jevEngine'

/** Constants rather than env vars: an env var would need the four-hop deploy chain. */
export const MAX_USER_PRESETS = 200
export const PRESET_MAX_BYTES = 256 * 1024
export const PRESET_NAME_MAX = 120
export const PRESET_DESCRIPTION_MAX = 2000

const PRESET_KEYS: ReadonlySet<string> = new Set(PRESET_FIELD_KEYS)

const hasOwn = (obj: object, key: string) => Object.prototype.hasOwnProperty.call(obj, key)

export type PresetValidation =
  | { ok: true; settings: Record<string, unknown> }
  | { ok: false; key: string; error: string }

/**
 * Strip control characters and cap the length, as token names are. A
 * description may keep its line breaks and tabs; a name is one line.
 */
export function sanitizePresetText(raw: unknown, max: number, opts: { multiline?: boolean } = {}): string {
  if (typeof raw !== 'string') return ''
  const control = opts.multiline
    // eslint-disable-next-line no-control-regex
    ? /[\x00-\x08\x0b-\x1f\x7f]/g
    // eslint-disable-next-line no-control-regex
    : /[\x00-\x1f\x7f]/g
  return raw.replace(control, '').trim().slice(0, max)
}

/** A preset name as it is compared for duplicates: trimmed, case-insensitive. */
export function presetNameKey(name: string): string {
  return name.trim().toLowerCase()
}

/**
 * Why a real column is not a preset field, naming the tool that does own it.
 * A caller told only "not allowed" goes looking for the wrong fix.
 */
function exclusionReason(key: string, spec: RegistryField): string {
  if (spec.validator === 'provider_reference') {
    return `'${key}' is an account-scoped provider selection. Select it explicitly on the receiving project.`
  }
  if (spec.mcp === 'create_only') {
    return `'${key}' is part of the engagement scope, which a preset never carries: a preset ` +
      'loaded into another project would re-point it. It is fixed at creation by create_project.'
  }
  if (spec.group === 'engagement_limits' || spec.tool === 'engagement') {
    return `'${key}' belongs to one engagement rather than to a reusable configuration, so a ` +
      'preset never carries it. Set it on the project with update_recon_settings.'
  }
  if (spec.read_deny_reason === 'credential') {
    return `'${key}' is a credential. A preset never carries one: applied to another project it ` +
      'would be sent to a target it was never issued for.'
  }
  if (spec.deny_reason === 'upload-managed') {
    return `'${key}' names an uploaded file, which only the project that uploaded it may use.`
  }
  const doc = spec.deny_reason ? DENY_REASON_DOC[spec.deny_reason] : undefined
  if (doc) return `'${key}' is not configuration: ${doc}.`
  return `'${key}' is tied to one project rather than to a reusable configuration, so a preset never carries it.`
}

/**
 * One value, judged the way a write to the project would judge it.
 *
 * `null` on a nullable column is a real value (the form holds it, and a reset
 * with no default produces it). `reconPresetId` is the "Started from" badge and
 * may only name a built-in preset.
 */
function checkPresetValue(key: string, spec: RegistryField, value: unknown, projectId?: string): string | null {
  if (LOOP_MODEL_KEYS.has(key) && isLoopModel(value)) return PRESET_LOOP_REFUSAL
  if (value === null && spec.optional) return null
  if (key === 'reconPresetId') {
    return typeof value === 'string' && getPresetById(value)
      ? null
      : 'must be null or the id of a built-in preset'
  }
  return validateValue(key, spec, value, projectId)
}

/**
 * Validate settings a caller wants STORED as a preset. Fail closed, naming the
 * first rejection, as `filterReconSettings` does for a project write.
 *
 * No projectId: a preset outlives the project it came from, so an upload path
 * is never valid in one.
 */
export function validatePresetSettings(input: unknown): PresetValidation {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, key: '', error: 'settings must be an object.' }
  }
  const entries = Object.entries(input as Record<string, unknown>)
  if (entries.length === 0) {
    return { ok: false, key: '', error: 'settings must contain at least one field.' }
  }
  if (entries.length > PRESET_FIELD_KEYS.length) {
    return { ok: false, key: '', error: `a preset holds at most ${PRESET_FIELD_KEYS.length} fields.` }
  }
  if (Buffer.byteLength(JSON.stringify(input), 'utf8') > PRESET_MAX_BYTES) {
    return { ok: false, key: '', error: `a preset is at most ${PRESET_MAX_BYTES / 1024} KiB.` }
  }

  const settings: Record<string, unknown> = {}
  for (const [key, value] of entries) {
    const spec = field(key)
    if (!spec) {
      return {
        ok: false, key,
        error: `'${key}' is not a recon setting. Call describe_recon_settings for the fields and their bounds.`,
      }
    }
    if (!PRESET_KEYS.has(key)) return { ok: false, key, error: exclusionReason(key, spec) }
    const problem = checkPresetValue(key, spec, value)
    if (problem) return { ok: false, key, error: `'${key}' ${problem}` }
    settings[key] = value
  }
  return { ok: true, settings }
}

/**
 * The preset fields of a STORED settings blob, never the blob itself.
 *
 * The UI's save and the project import both stored whatever object arrived, so
 * an old preset can carry a credential, a target or plain junk. Reading through
 * this is what keeps those in the database.
 */
export function projectPresetForRead(stored: unknown): { settings: Record<string, unknown>; ignoredKeys: string[] } {
  if (!stored || typeof stored !== 'object' || Array.isArray(stored)) return { settings: {}, ignoredKeys: [] }
  const settings: Record<string, unknown> = {}
  const ignoredKeys: string[] = []
  for (const [key, value] of Object.entries(stored as Record<string, unknown>)) {
    if (PRESET_KEYS.has(key)) settings[key] = value
    else ignoredKeys.push(key)
  }
  return { settings, ignoredKeys }
}

/**
 * The preset fields of a settings blob arriving from a UI save or an import:
 * kept when they are preset fields, dropped otherwise, with the size bound
 * enforced. Values are NOT judged here, matching what the form could always
 * store; applying over MCP judges them instead.
 */
export function presetSettingsForStorage(
  input: unknown
): { ok: true; settings: Record<string, unknown>; dropped: number } | { ok: false; error: string } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, error: 'Settings object is required' }
  }
  const { settings, ignoredKeys } = projectPresetForRead(input)
  if (Buffer.byteLength(JSON.stringify(settings), 'utf8') > PRESET_MAX_BYTES) {
    return { ok: false, error: `A preset is at most ${PRESET_MAX_BYTES / 1024} KiB` }
  }
  // Saved from a loop project's form: keep the preset, without the brain. An
  // apply then keeps each project's own model (KEPT_WHEN_ABSENT).
  let dropped = ignoredKeys.length
  for (const key of LOOP_MODEL_KEYS) {
    if (isLoopModel(settings[key])) {
      delete settings[key]
      dropped += 1
    }
  }
  return { ok: true, settings, dropped }
}

export type ResolvedPreset =
  | {
      source: 'builtin'
      id: string
      name: string
      description: string
      settings: Record<string, unknown>
      builtin: ReconPreset
    }
  | {
      source: 'user'
      id: string
      name: string
      description: string
      settings: Record<string, unknown>
      ignoredKeys: string[]
      updatedAt: Date
      createdVia: string
      updatedVia: string
      lastWriterTokenPrefix: string | null
    }

export const PRESET_ROW_SELECT = {
  id: true, name: true, description: true, settings: true, updatedAt: true,
  createdVia: true, updatedVia: true, lastWriterTokenPrefix: true,
} as const

/**
 * A preset this user may use, or null.
 *
 * A built-in by its exact id, otherwise one of the user's OWN presets. Another
 * user's preset id and one that does not exist give the same null, so a caller
 * cannot enumerate ids. A database error throws: "could not look" is never
 * reported as "not there".
 */
export async function resolvePreset(userId: string, presetId: string): Promise<ResolvedPreset | null> {
  const builtin = getPresetById(presetId)
  if (builtin) {
    return {
      source: 'builtin',
      id: builtin.id,
      name: builtin.name,
      description: builtin.shortDescription,
      // What the project form applies for a built-in: its parameters, and the
      // badge that says which one it started from.
      settings: { ...(builtin.parameters as Record<string, unknown>), reconPresetId: builtin.id },
      builtin,
    }
  }
  const row = await prisma.userProjectPreset.findFirst({ where: { id: presetId, userId }, select: PRESET_ROW_SELECT })
  if (!row) return null
  const { settings, ignoredKeys } = projectPresetForRead(row.settings)
  return {
    source: 'user',
    id: row.id,
    name: row.name,
    description: row.description,
    settings,
    ignoredKeys,
    updatedAt: row.updatedAt,
    createdVia: row.createdVia,
    updatedVia: row.updatedVia,
    lastWriterTokenPrefix: row.lastWriterTokenPrefix,
  }
}

// --- backend defaults ----------------------------------------------------------------

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'
const DEFAULTS_TIMEOUT_MS = 10_000

export class DefaultsUnavailable extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DefaultsUnavailable'
  }
}

async function readDefaults(res: Response, which: string): Promise<Record<string, unknown>> {
  if (!res.ok) throw new DefaultsUnavailable(`the ${which} defaults answered ${res.status}`)
  const body = await res.json()
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new DefaultsUnavailable(`the ${which} defaults are not an object`)
  }
  return body as Record<string, unknown>
}

/** The recon orchestrator's defaults. Throws DefaultsUnavailable. */
export async function fetchReconDefaults(): Promise<Record<string, unknown>> {
  let res: Response
  try {
    res = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/defaults`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(DEFAULTS_TIMEOUT_MS),
    })
  } catch (err) {
    throw new DefaultsUnavailable(`the recon defaults are unreachable: ${String(err)}`)
  }
  return readDefaults(res, 'recon')
}

/** The agent's defaults. Throws DefaultsUnavailable. */
export async function fetchAgentDefaults(): Promise<Record<string, unknown>> {
  let res: Response
  try {
    res = await fetch(`${AGENT_API_URL}/defaults`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(DEFAULTS_TIMEOUT_MS),
    })
  } catch (err) {
    throw new DefaultsUnavailable(`the agent defaults are unreachable: ${String(err)}`)
  }
  return readDefaults(res, 'agent')
}

/**
 * Both backends' defaults, the agent's winning on overlap, as
 * `/api/projects/defaults` merges them. Either failing throws: an apply that
 * fell back to the Prisma defaults would reset fields to values the running
 * backends do not use, so the server-side apply fails closed. (The form's route
 * degrades the agent half instead; that is its choice to make.)
 */
export async function fetchBackendDefaults(): Promise<Record<string, unknown>> {
  const [recon, agent] = await Promise.all([fetchReconDefaults(), fetchAgentDefaults()])
  return { ...recon, ...agent }
}

// --- applying a preset ------------------------------------------------------------------

/** canonicalJson renders every Date as `{}`, which would hide a changed timestamp. */
function comparable(value: unknown): string {
  return value instanceof Date ? value.toISOString() : canonicalJson(value)
}

export interface PresetApplication {
  /** Every preset field, as the project form's preset load saves it. */
  data: Record<string, unknown>
  /** Preset fields whose value moves. */
  changed: string[]
  /** Changed fields the preset did not name: they were reset to their default. */
  resetToDefault: string[]
  /** Fields a replace leaves alone when the preset does not name them. */
  keptAsIs: string[]
  unchangedCount: number
  loadedPreset: LoadedPreset
}

/**
 * What applying `presetSettings` to `currentRow` writes. The project form's
 * preset load, computed server-side: the same `applyPresetSettings`, the same
 * field set, the same badge fingerprint.
 */
export function computePresetApplication(
  currentRow: Record<string, unknown>,
  presetSettings: Record<string, unknown>,
  backendDefaults: Record<string, unknown>,
  preset: { name: string; id: string; source: 'builtin' | 'user' },
): PresetApplication {
  const next = applyPresetSettings(currentRow, presetSettings, backendDefaults)
  const data = pickPresetFields(next)
  const changed = Object.keys(data).filter(k => comparable(data[k]) !== comparable(currentRow[k]))
  const named = (k: string) => hasOwn(presetSettings, k)
  return {
    data,
    changed,
    resetToDefault: changed.filter(k => !named(k)),
    keptAsIs: [...KEPT_WHEN_ABSENT].filter(k => !named(k)).sort(),
    unchangedCount: PRESET_FIELD_KEYS.length - changed.length,
    loadedPreset: {
      name: preset.name,
      fingerprint: presetFingerprint(next),
      presetId: preset.id,
      source: preset.source,
    },
  }
}

/**
 * Judge an application before it is written: every CHANGED value against the
 * registry, then the cross-field rules on the row as it would be.
 *
 * Unchanged values are not a new write and are not re-judged, so a project
 * holding a value a later bound tightened is not locked out of every preset.
 * A backend default that breaks its bound refuses the whole apply rather than
 * writing it.
 */
export async function validateApplication(
  application: Pick<PresetApplication, 'data' | 'changed'>,
  currentRow: Record<string, unknown>,
  projectId: string,
  actorUserId: string,
): Promise<{ key: string; error: string } | null> {
  for (const key of application.changed) {
    const spec = field(key)
    if (!spec) return { key, error: `'${key}' is not a recon setting` }
    const problem = checkPresetValue(key, spec, application.data[key], projectId)
    if (problem) return { key, error: `'${key}' ${problem}` }
  }
  // The user-skill toggles are judged against the project OWNER's skills, never the actor's.
  let ownerUserId: string | null | undefined
  if (application.changed.includes('attackSkillConfig')) {
    try {
      ownerUserId = (await prisma.project.findUnique({ where: { id: projectId }, select: { userId: true } }))?.userId ?? null
    } catch {
      return { key: '', error: 'The project owner could not be read to check its skill toggles; nothing was written' }
    }
  }
  const nextRow: Record<string, unknown> = { ...currentRow, ...application.data }
  const crossField = await validateCrossFieldRules(nextRow, application.changed, actorUserId, { ownerUserId })
  if (crossField) return { key: '', error: crossField }
  if ('attackSkillConfig' in application.data) application.data.attackSkillConfig = nextRow.attackSkillConfig

  // Presets cannot choose an account-scoped provider. A switch-on uses the
  // receiving project's explicit selection, bound to its owner. The empty key
  // tells the caller to configure the project rather than rewrite the preset.
  if (jevSwitchedOn(currentRow, application.data).length > 0) {
    let owner: string | null = null
    try {
      const project = await prisma.project.findUnique({ where: { id: projectId }, select: { userId: true, jevProviderId: true } })
      owner = project?.userId ?? null
      currentRow = { ...currentRow, jevProviderId: project?.jevProviderId ?? null }
    } catch {
      return { key: '', error: JEV_VERIFY_FAILED.replace(/\.$/, '') }
    }
    const jevError = await validateJevEngineChange(currentRow, application.data, owner)
    if (jevError) return { key: '', error: jevError.replace(/\.$/, '') }
  }
  return null
}
