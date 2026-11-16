/**
 * The fields a person may write on a 2.0 resource, and the rules each one follows. Keys the
 * browser sends that are not listed here are ignored: the server owns the rest of the row
 * (type found by detection, maps, claim, snapshot, summary), and a spread body could carry a
 * relation input Prisma would apply as a nested write.
 *
 * Every per-resource setting of the spec (§6), the `type.*` options included, is one key of
 * `overrides`; `typeOptions` mirrors its `type.*` keys for the readers of the row (T4.2). The
 * summary has its own route (summary/route.ts).
 */
import { NextResponse } from 'next/server'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { SITE_TYPES, SLUG_RE, STORAGE_MODES, type SiteType, type StorageMode } from '../agentContract'
import { isMaskedValue } from '../masking'
import { presetByKey } from '../presets'
import { validateOverrides, type ResourceOverrides } from '../settingsSpec'
import { validateUrl } from '../urls'
import { validateFocus } from './focusFields'

export interface ResourceFields {
  name?: string
  url?: string
  enabled?: boolean
  llmModel?: string
  /** Absent: keep the stored token. '' clears it. */
  githubTokenOverride?: string
  storageMode?: StorageMode
  forcedType?: '' | SiteType
  /** Only `null`, which removes the login: phase 6 (T6.5) lets a person set one. */
  credentials?: null
  focus?: Record<string, never>
  /** The Resource ID: chosen at creation, read-only afterwards (R-137). */
  slug?: string
  /** The whole override map: what the form sends replaces what is stored. */
  overrides?: ResourceOverrides
  /** The Quick Add preset the resource was added from (OQ-6); creation only. */
  presetKey?: string
}

export interface FieldError {
  field: string
  code: string
  error: string
}

export type FieldsResult = { ok: true; value: ResourceFields } | { ok: false; error: FieldError }

const NAME_MAX = 500
const URL_MAX = 2048
const TOKEN_MAX = 500

/**
 * The storage a type always gets (§4.5, R-082, R-142): a PDF is downloaded once, so it is
 * kept; a CVE database is a live index of many small repositories, so it is read live.
 */
export function forcedStorageMode(type: string): StorageMode | null {
  if (type === 'pdf') return 'stored'
  if (type === 'cve-poc-db') return 'live'
  return null
}

/**
 * The type's recommended mode (§4.5 "Recommended mode per type"). A wiki, GitBook or docs site is
 * Stored only when Check URL found it fits the size limits (T4.1); without that estimate, and
 * for a type not yet known (Auto, before detection), it is the spec's own default, Live.
 */
export function recommendedStorageMode(type: string, fitsSizeLimits: boolean | null = null): StorageMode {
  const forced = forcedStorageMode(type)
  if (forced) return forced
  if (type === 'agentic-crawl' || type === 'github-repo') return 'stored'
  if (type === 'mkdocs-wiki' || type === 'sphinx-docs' || type === 'gitbook') return fitsSizeLimits === true ? 'stored' : 'live'
  return 'live'
}

/** The account's `storage.defaultMode` as a mode a row can hold: `recommended` becomes the type's. */
export function defaultStorageMode(setting: unknown, type: string): StorageMode {
  if (setting === 'recommended') return recommendedStorageMode(type)
  return setting === 'stored' ? 'stored' : 'live'
}

function bad(field: string, error: string, code = 'bad_field'): FieldsResult {
  return { ok: false, error: { field, code, error } }
}

/** The `type.*` options of an override map, as the `typeOptions` column holds them. */
export function typeOptionsOf(overrides: ResourceOverrides): Record<string, unknown> {
  return Object.fromEntries(Object.entries(overrides).filter(([k]) => k.startsWith('type.')))
}

export function parseResourceFields(body: Record<string, unknown>, mode: 'create' | 'update'): FieldsResult {
  const value: ResourceFields = {}
  const has = (k: string) => Object.hasOwn(body, k) && body[k] !== undefined

  if (has('name') || mode === 'create') {
    const name = typeof body.name === 'string' ? body.name.trim() : ''
    if (!name) return bad('name', 'A name is required')
    if (name.length > NAME_MAX) return bad('name', `A name holds at most ${NAME_MAX} characters`)
    value.name = name
  }
  if (has('url') || mode === 'create') {
    const url = typeof body.url === 'string' ? body.url.trim() : ''
    if (!url) return bad('url', 'A URL is required')
    if (url.length > URL_MAX) return bad('url', `A URL holds at most ${URL_MAX} characters`)
    const check = validateUrl(url)
    if (!check.ok) return bad('url', check.error, check.code ?? 'bad_url')
    value.url = url
  }
  if (has('enabled')) {
    if (typeof body.enabled !== 'boolean') return bad('enabled', 'enabled must be true or false')
    value.enabled = body.enabled
  }
  if (has('llmModel') || mode === 'create') {
    const model = typeof body.llmModel === 'string' ? body.llmModel.trim() : ''
    if (!model) return bad('llmModel', 'Pick a model for this resource', 'model_required')
    if (isLoopModel(model)) {
      return bad('llmModel', 'Agent in the Loop answers only inside a chat run; pick a provider model for this resource', 'loop_model_not_allowed')
    }
    value.llmModel = model
  }
  if (has('githubTokenOverride')) {
    const token = body.githubTokenOverride
    if (typeof token !== 'string') return bad('githubTokenOverride', 'The GitHub token must be text')
    if (!isMaskedValue(token)) {
      if (token.length > TOKEN_MAX) return bad('githubTokenOverride', `A GitHub token holds at most ${TOKEN_MAX} characters`)
      value.githubTokenOverride = token.trim()
    }
  }
  if (has('storageMode')) {
    if (!(STORAGE_MODES as readonly unknown[]).includes(body.storageMode)) return bad('storageMode', 'Storage is "live" or "stored"')
    value.storageMode = body.storageMode as StorageMode
  }
  if (has('forcedType')) {
    if (body.forcedType !== '' && !(SITE_TYPES as readonly unknown[]).includes(body.forcedType)) {
      return bad('forcedType', `The type is "" (Auto) or one of ${SITE_TYPES.join(', ')}`)
    }
    value.forcedType = body.forcedType as '' | SiteType
  }
  if (Object.hasOwn(body, 'credentials') && mode === 'update') {
    if (body.credentials !== null) return bad('credentials', 'A site login cannot be set yet; send null to remove one')
    value.credentials = null
  }
  if (has('focus')) {
    const focus = validateFocus(body.focus)
    if (!focus.ok) return bad('focus', focus.error)
    value.focus = focus.value
  }
  if (has('slug')) {
    // The agent names the resource and prefixes its page IDs with it (§6.4): the contract's pattern.
    if (typeof body.slug !== 'string' || !SLUG_RE.test(body.slug)) {
      return bad('slug', 'A resource ID is lowercase letters, digits and dashes, starting with a letter or a digit', 'bad_slug')
    }
    value.slug = body.slug
  }
  if (has('overrides')) {
    const parsed = validateOverrides(body.overrides)
    if (!parsed.ok) {
      const first = parsed.errors[0]
      return bad(first.key ? `overrides.${first.key}` : 'overrides', first.message, first.code)
    }
    value.overrides = parsed.value
  }
  if (has('presetKey') && mode === 'create') {
    if (typeof body.presetKey !== 'string' || !presetByKey(body.presetKey)) return bad('presetKey', 'Not a Quick Add preset', 'bad_preset')
    value.presetKey = body.presetKey
  }
  return { ok: true, value }
}

export function fieldErrorResponse(error: FieldError): NextResponse {
  return NextResponse.json(error, { status: 400 })
}
