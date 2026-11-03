/**
 * Registry-driven filtering for the recon-settings surface.
 *
 * This replaces a positive allowlist of 126 columns with four dispositions over
 * all 712, and the replacement is the whole point of the work: blocking a field
 * by name was a crude proxy for "this value could be dangerous", and it was
 * wrong in both directions at once.
 *
 *   settable      write any time
 *   create_only   write once at creation; refused afterwards, naming the tool
 *                 that can set it
 *   never         not a pipeline parameter at all; refused with its class
 *
 * There is no one-direction disposition any more. The engagement's limits are
 * ordinary settable fields: what makes them safe is that every one of them is
 * ENFORCED at scan start whatever tuning says, so lowering a ceiling and raising
 * it are equally permitted and equally auditable, which is how the rest of this
 * surface already works. A write-time direction check bought the appearance of
 * that guarantee and not the guarantee: five of the fields it covered accepted a
 * widening while reporting 'tightened'.
 *
 * Fail-closed in every direction, as before: an unknown key rejects the WHOLE
 * call naming the key, and an out-of-range value rejects it naming the bound.
 * Nothing is silently stripped or clamped, because a caller who believes a
 * setting applied when it did not will act on a scan configured differently
 * from the one it asked for.
 */
import {
  createOnlyFields,
  field,
  fieldsWhere,
  loadRegistry,
  neverFields,
  mcpReadableFields,
  rescopableFields,
  settableFields,
  type RegistryField,
} from './registry'
import { validateValue } from './validators'
import { isLoopModel } from '@/lib/agentInTheLoop'

/**
 * A model value no MCP write may set, and why. A token must not choose the
 * brain it could then drive (the reason mirrors mcpKaliExecEnabled's
 * 'escalation'); the recon AI hooks run outside any chat, where no external
 * agent can answer.
 */
export function loopModelRefusal(key: string, value: unknown): string | null {
  if (!isLoopModel(value)) return null
  if (key === 'agentOpenaiModel') {
    return `'${key}' cannot be set to Agent in the Loop over MCP (escalation): only a person ` +
      'selects Agent in the Loop, in the project form.'
  }
  if (key === 'aiPipelineModel') {
    return `'${key}' cannot be Agent in the Loop (not_supported): the recon AI hooks run ` +
      'outside any chat, where no external agent can answer. Pick a provider model.'
  }
  return null
}

/**
 * update   an existing project's settings (update_recon_settings)
 * create   a new project, scope included (create_project)
 * rescope  an existing project's target lists and nothing else (update_project_scope)
 */
export type SettingsMode = 'update' | 'create' | 'rescope'

export interface SettingsRejection {
  ok: false
  key: string
  error: string
}

export interface SettingsAccepted {
  ok: true
  /** Only the permitted, validated keys. Safe to spread into prisma.update. */
  data: Record<string, unknown>
}

export type SettingsValidation = SettingsAccepted | SettingsRejection

/** Why each closed class is closed, for the error message and the docs. */
export const DENY_REASON_DOC: Readonly<Record<string, string>> = Object.freeze({
  identity: 'row identity and audit columns, which configure nothing',
  internal: 'internal state written by the application, not a setting',
  escalation: 'would let a token grant itself a capability it was not issued',
  secret: 'a stored credential; reading or rewriting it is credential theft, not tuning',
  'upload-managed':
    'written only by the endpoint that also places the file on disk, so a second ' +
    'writer could name a file this project never uploaded',
  'engagement-record':
    'part of the engagement RECORD rather than its limits: who the client is, who to ' +
    'call, what the document said. A person writes it and a model reads it; nothing ' +
    'enforces it, and it carries third-party personal data',
  'not-tuning':
    'a debug switch rather than a pipeline parameter; changing it would alter what a ' +
    'later read MEANS rather than how the scan runs',
  derived:
    'derived from the engagement limits that are actually set, and written by nothing. ' +
    'Set a ceiling, an exclusion or a time window instead',
})

/**
 * The refused half of the write surface, as one sentence for the tool
 * descriptions an agent reads.
 *
 * Built from the registry rather than written, because the hand-written
 * version described a 126-field allowlist long after the surface had grown to
 * the whole pipeline, and agents believed it.
 */
export function refusedFieldsSentence(): string {
  const createOnly = createOnlyFields().map(f => f.key)
  const rescope = rescopableFields().map(f => f.key)
  const classes = [...new Set(neverFields().map(f => f.deny_reason).filter((r): r is NonNullable<typeof r> => Boolean(r)))]
    .sort()
  return (
    'It can NEVER change the engagement scope, which is fixed at creation by create_project: ' +
    `${createOnly.join(', ')}. ` +
    `Of those, update_project_scope alone may change ${rescope.join(', ')}, under its own permission. ` +
    'Nor any column that is not a pipeline parameter at all, in these classes: ' +
    classes.map(c => `${c} (${DENY_REASON_DOC[c]})`).join('; ') + '. ' +
    'An attempt to set one is refused by name, never silently ignored.'
  )
}

/**
 * A rejected key as it may appear in an audit row: the key itself when it is a
 * registry column, and a placeholder otherwise, so caller text never reaches
 * the one-line console audit record.
 */
export function auditableKey(key: string): string | undefined {
  if (!key) return undefined
  return field(key) ? key : '<unknown>'
}

/** Every key a caller may write in this mode. */
export function permittedKeys(mode: SettingsMode): string[] {
  if (mode === 'create') {
    return fieldsWhere(f => f.mcp !== 'never').map(f => f.key)
  }
  if (mode === 'rescope') return rescopableFields().map(f => f.key)
  return settableFields().map(f => f.key)
}

export function settableFieldCount(): number {
  return settableFields().length
}

/**
 * Why this key cannot be written at all, ahead of any question about its value.
 *
 * Disposition before validation, deliberately: telling a caller that
 * `roeEnabled` "must be true or false" when it may not change it at all sends
 * it away to fix the wrong thing.
 */
function explainRefusal(
  key: string,
  spec: RegistryField,
  mode: SettingsMode
): string | null {
  if (spec.mcp === 'never') {
    const reason = spec.deny_reason ? DENY_REASON_DOC[spec.deny_reason] : undefined
    const written = spec.written_by ? ` It is written by ${spec.written_by}.` : ''
    return `'${key}' is not a pipeline parameter: ${reason ?? 'it configures nothing about a scan'}.${written}`
  }
  if (mode === 'create') return null
  if (mode === 'rescope') {
    if (spec.mcp === 'create_only' && spec.rescope) return null
    if (spec.mcp === 'create_only') {
      return (
        `'${key}' stays fixed on an existing project whatever the token holds: changing it ` +
        `would re-point or re-verify the engagement itself, not one scanner's target list. ` +
        `A different target means a different project; use create_project. This tool changes ` +
        `only ${rescopableFields().map(f => f.key).join(', ')}.`
      )
    }
    return `'${key}' is not a target list. Change it with update_recon_settings.`
  }
  if (spec.mcp === 'create_only') {
    if (spec.rescope) {
      return (
        `'${key}' is a target list of this engagement, fixed at creation for this tool. ` +
        `update_project_scope changes it on an existing project, under its own permission.`
      )
    }
    return (
      `'${key}' is part of this project's engagement scope and is fixed at creation. ` +
      `Changing it on an existing project would re-point the platform at a different ` +
      `target, so it is refused here; use create_project to open a new engagement.`
    )
  }
  return null
}

/**
 * Filter a caller-supplied settings object, validating every value.
 *
 * Returns the FIRST rejection rather than a list: the whole call is refused
 * either way, and naming one offending key is clearer than a wall of them.
 *
 * Engagement limits come through here like any other setting. They are not
 * special-cased and no direction is checked: the control is that every one of
 * them is enforced at scan start, and the audit row records the move.
 */
/** The most fields one write may carry. See the check in `filterReconSettings`. */
export const MAX_KEYS_PER_CALL = 200

export function filterReconSettings(
  input: unknown,
  options: {
    mode?: SettingsMode
    /**
     * Whose project this write is for. The `project_file` validator needs it
     * because the upload directory is shared between projects; without it no
     * upload path is accepted.
     */
    projectId?: string
  } = {}
): SettingsValidation {
  const mode = options.mode ?? 'update'

  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, key: '', error: 'settings must be an object.' }
  }
  const entries = Object.entries(input as Record<string, unknown>)
  if (entries.length === 0) {
    return { ok: false, key: '', error: 'settings must contain at least one field.' }
  }
  // Per-value bounds do not bound a CALL. There are over 700 columns and the
  // free-text ones accept 20,000 characters each, so an unbounded key count is
  // a multi-megabyte row written by one request. No real caller writes more
  // than a handful of settings at once.
  if (entries.length > MAX_KEYS_PER_CALL) {
    return {
      ok: false,
      key: '',
      error:
        `${entries.length} fields in one call; at most ${MAX_KEYS_PER_CALL} may be written ` +
        'at a time. Split the batch.',
    }
  }

  const data: Record<string, unknown> = {}
  for (const [key, value] of entries) {
    const spec = field(key)
    if (!spec) {
      return {
        ok: false,
        key,
        error:
          `'${key}' is not a recon setting. Call describe_recon_settings for the ` +
          `fields this surface accepts and their bounds.`,
      }
    }

    const refusal = explainRefusal(key, spec, mode) ?? loopModelRefusal(key, value)
    if (refusal) return { ok: false, key, error: refusal }

    const problem = validateValue(key, spec, value, options.projectId)
    if (problem) return { ok: false, key, error: `'${key}' ${problem}` }

    data[key] = value
  }
  return { ok: true, data }
}

/**
 * The settings subset of a loaded project row, for `get_recon_settings`.
 *
 * Built by projecting the registry over the row, so a credential-bearing column
 * can never appear in the result even if the caller loaded the whole project.
 *
 * NARROWER than `readableKeys()` on purpose. `id`, `name`, `createdAt` and
 * `updatedAt` are readable and are returned as METADATA by the tools that need
 * them; putting them inside `settings` would make them look settable, and
 * `updatedAt` in particular is the optimistic-concurrency token a caller passes
 * back rather than a value it may write.
 */
export function settingsKeys(): string[] {
  return mcpReadableFields().filter(f => f.mcp !== 'never').map(f => f.key).sort()
}

export function projectReconSettings(row: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of settingsKeys()) {
    if (Object.prototype.hasOwnProperty.call(row, key)) out[key] = row[key]
  }
  return out
}

/**
 * Columns a caller may READ.
 *
 * Wider than what it may write in one direction and narrower in another. Scope
 * and most of the Rules of Engagement are readable, because an agent that
 * cannot see its own rate ceiling cannot verify that it is inside it. But the
 * RoE block also carries third-party personal data and the signed document
 * itself, and those are withheld from every read whatever their write
 * disposition is.
 */
export function readableKeys(): string[] {
  return mcpReadableFields().map(f => f.key).sort()
}

/** Prisma `select` for loading exactly the columns `get_recon_settings` returns. */
export function reconSettingsSelect(): Record<string, true> {
  const select: Record<string, true> = {}
  for (const key of settingsKeys()) select[key] = true
  return select
}

/** The three disposition sets, for the docs and the tests. */
export function dispositionSummary() {
  return {
    settable: settableFields().length,
    create_only: createOnlyFields().length,
    never: neverFields().length,
    total: Object.keys(loadRegistry().fields).length,
  }
}
