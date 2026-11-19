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
import { PRIORITIES, SITE_TYPES, SLUG_RE, STORAGE_MODES, type SiteType, type StorageMode } from '../agentContract'
import { isMaskedValue } from '../masking'
import { presetByKey } from '../presets'
import { validateOverrides, type ResourceOverrides } from '../settingsSpec'
import { validateUrl } from '../urls'
import type { Focus } from '../focus'
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
  /** `null` removes the login; a patch is merged with the stored one (`applyCredentials`). */
  credentials?: null | CredentialsPatch
  /** `{}` is no focus (Everything). The writer keeps only the owner's skill topics (`withOwnSkillTopics`). */
  focus?: Focus | Record<string, never>
  /** The Resource ID: chosen at creation, read-only afterwards (R-137). */
  slug?: string
  /** The whole override map: what the form sends replaces what is stored. */
  overrides?: ResourceOverrides
  /** The Quick Add preset the resource was added from (OQ-6); creation only. */
  presetKey?: string
  /** How search ranks the resource's pages (Q11 "Resource priority"); a search setting, never stale. */
  priority?: (typeof PRIORITIES)[number]
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

export { defaultStorageMode, forcedStorageMode, recommendedStorageMode } from '../storageModes'

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
  if (Object.hasOwn(body, 'credentials') && body.credentials !== undefined) {
    if (body.credentials === null) {
      // A new resource has no login to remove.
      if (mode === 'update') value.credentials = null
    } else {
      const patch = parseCredentials(body.credentials)
      if (!patch.ok) return { ok: false, error: patch.error }
      value.credentials = patch.value
    }
  }
  if (has('focus')) {
    const focus = validateFocus(body.focus)
    if (!focus.ok) return bad(focus.field, focus.error, 'bad_focus')
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
  if (has('priority')) {
    if (!(PRIORITIES as readonly unknown[]).includes(body.priority)) return bad('priority', `The priority is one of ${PRIORITIES.join(', ')}`)
    value.priority = body.priority as ResourceFields['priority']
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

// --- site logins (§6.6) ------------------------------------------------------------

/** A secret the browser sent: a new value, or the "set" placeholder that keeps the stored one. */
export type SecretInput = { keep: true } | { value: string }

/**
 * What a write asks of the login. An absent part stays as stored; `headers` replaces the list
 * (a header sent back with "set" keeps its stored value); `basicAuth: null` removes it.
 */
export interface CredentialsPatch {
  cookie?: SecretInput
  headers?: { name: string; value: SecretInput }[]
  basicAuth?: null | { username: string; password: SecretInput }
}

/** The stored login, in the contract's shape (`agentContract.Credentials`); `{}` when there is none. */
export interface StoredCredentials {
  cookie?: string
  headers?: { name: string; value: string }[]
  basic_auth?: { username: string; password: string } | null
}

const COOKIE_MAX = 8000
const HEADERS_MAX = 20
const HEADER_NAME_MAX = 200
const HEADER_VALUE_MAX = 4096
const USERNAME_MAX = 500
const PASSWORD_MAX = 2000
// RFC 9110 token characters: a name outside them would let a value start a header of its own.
const HTTP_TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/
// The request's framing, its host and the two headers the other fields own.
const FORBIDDEN_HEADERS: ReadonlySet<string> = new Set(['host', 'content-length', 'transfer-encoding', 'connection', 'cookie', 'authorization'])
// A stored value is sent as a header line: CR or LF would end it and start one the person did not
// write, NUL truncates it in some servers (D-55).
const LINE_BREAKING = /[\r\n\u0000]/
const CREDENTIAL_KEYS: ReadonlySet<string> = new Set(['cookie', 'headers', 'basic_auth'])

type Parsed<T> = { ok: true; value: T } | { ok: false; error: FieldError }
const badLogin = (field: string, error: string): { ok: false; error: FieldError } => ({ ok: false, error: { field, code: 'bad_credentials', error } })

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function secretInput(input: unknown, field: string, max: number): Parsed<SecretInput> {
  if (typeof input !== 'string') return badLogin(field, `${field} must be text`)
  if (isMaskedValue(input)) return { ok: true, value: { keep: true } }
  // Never trimmed: a password may end with a space, and a trimmed line break would hide a bad value.
  if (LINE_BREAKING.test(input)) return badLogin(field, `${field} cannot hold a line break or a NUL character`)
  if (input.length > max) return badLogin(field, `${field} holds at most ${max} characters`)
  return { ok: true, value: { value: input } }
}

export function parseCredentials(input: unknown): Parsed<CredentialsPatch> {
  if (!isRecord(input)) return badLogin('credentials', 'The login is {cookie, headers, basic_auth}, or null to remove it')
  const unknown = Object.keys(input).find(k => !CREDENTIAL_KEYS.has(k))
  if (unknown) return badLogin('credentials', `The login has no field ${unknown}`)
  const patch: CredentialsPatch = {}
  if (input.cookie !== undefined) {
    const cookie = secretInput(input.cookie, 'credentials.cookie', COOKIE_MAX)
    if (!cookie.ok) return cookie
    patch.cookie = cookie.value
  }
  if (input.headers !== undefined) {
    if (!Array.isArray(input.headers)) return badLogin('credentials.headers', 'The headers are a list of {name, value}')
    if (input.headers.length > HEADERS_MAX) return badLogin('credentials.headers', `At most ${HEADERS_MAX} headers`)
    const headers: { name: string; value: SecretInput }[] = []
    for (const [i, h] of input.headers.entries()) {
      const field = `credentials.headers[${i}]`
      if (!isRecord(h)) return badLogin(field, 'A header is {name, value}')
      const name = typeof h.name === 'string' ? h.name.trim() : ''
      if (!name || name.length > HEADER_NAME_MAX || !HTTP_TOKEN.test(name)) {
        return badLogin(`${field}.name`, 'A header name is letters, digits and - (an HTTP token)')
      }
      if (FORBIDDEN_HEADERS.has(name.toLowerCase())) {
        return badLogin(`${field}.name`, `${name} cannot be set here: use the cookie or basic authentication fields, or leave it to the request`)
      }
      if (headers.some(x => x.name.toLowerCase() === name.toLowerCase())) return badLogin(`${field}.name`, `The header ${name} is named twice`)
      const value = secretInput(h.value, `${field}.value`, HEADER_VALUE_MAX)
      if (!value.ok) return value
      headers.push({ name, value: value.value })
    }
    patch.headers = headers
  }
  if (input.basic_auth !== undefined) {
    if (input.basic_auth === null) {
      patch.basicAuth = null
    } else {
      const basic = input.basic_auth
      if (!isRecord(basic)) return badLogin('credentials.basic_auth', 'Basic authentication is {username, password}, or null')
      const rawName = typeof basic.username === 'string' ? basic.username : ''
      const username = rawName.trim()
      // Basic authentication joins the two with a colon: one in the name would move the split.
      if (!username || username.length > USERNAME_MAX || username.includes(':') || LINE_BREAKING.test(rawName)) {
        return badLogin('credentials.basic_auth.username', `A user name of 1-${USERNAME_MAX} characters, without ":" or a line break`)
      }
      const password = secretInput(basic.password, 'credentials.basic_auth.password', PASSWORD_MAX)
      if (!password.ok) return password
      patch.basicAuth = { username, password: password.value }
    }
  }
  return { ok: true, value: patch }
}

function storedOf(raw: unknown): Required<StoredCredentials> {
  const c = isRecord(raw) ? raw : {}
  const headers = Array.isArray(c.headers)
    ? c.headers.filter((h): h is { name: string; value: string } => isRecord(h) && typeof h.name === 'string' && typeof h.value === 'string')
    : []
  const basic = isRecord(c.basic_auth) && typeof c.basic_auth.username === 'string'
    ? { username: c.basic_auth.username, password: typeof c.basic_auth.password === 'string' ? c.basic_auth.password : '' }
    : null
  return { cookie: typeof c.cookie === 'string' ? c.cookie : '', headers, basic_auth: basic }
}

/** Whether a stored login holds anything: what `hasLogin` is rewritten to on every write of it. */
export function hasCredentials(raw: unknown): boolean {
  const c = storedOf(raw)
  return c.cookie !== '' || c.headers.length > 0 || c.basic_auth !== null
}

/** The stored login after a patch; `{}` when nothing is left. A "set" with no stored value to keep is refused. */
export function applyCredentials(stored: unknown, patch: CredentialsPatch): Parsed<StoredCredentials> {
  const before = storedOf(stored)
  const cookie = patch.cookie === undefined ? before.cookie : 'keep' in patch.cookie ? before.cookie : patch.cookie.value
  let headers = before.headers
  if (patch.headers !== undefined) {
    headers = []
    for (const [i, h] of patch.headers.entries()) {
      if ('keep' in h.value) {
        const kept = before.headers.find(x => x.name.toLowerCase() === h.name.toLowerCase())
        if (!kept) return badLogin(`credentials.headers[${i}].value`, `No stored value of ${h.name} to keep: type it`)
        headers.push({ name: h.name, value: kept.value })
      } else {
        headers.push({ name: h.name, value: h.value.value })
      }
    }
  }
  let basic = before.basic_auth
  if (patch.basicAuth === null) {
    basic = null
  } else if (patch.basicAuth !== undefined) {
    const p = patch.basicAuth.password
    if ('keep' in p && !before.basic_auth) return badLogin('credentials.basic_auth.password', 'No stored password to keep: type it')
    basic = { username: patch.basicAuth.username, password: 'keep' in p ? before.basic_auth!.password : p.value }
  }
  const after = { cookie, headers, basic_auth: basic }
  return { ok: true, value: hasCredentials(after) ? after : {} }
}

/**
 * The secret parts of the stored login a write keeps without the person typing them (a part the
 * patch leaves out, or sends back as "set"), as `credentials.*` names: what a new host would get.
 * Read from the patch, not from the values, so a value typed again counts as typed. A removed
 * login (`null`) keeps nothing.
 */
export function keptLoginParts(storedRaw: unknown, patch: CredentialsPatch | null | undefined): string[] {
  if (patch === null) return []
  const before = storedOf(storedRaw)
  const p = patch ?? {}
  const out: string[] = []
  if (before.cookie !== '' && (p.cookie === undefined || 'keep' in p.cookie)) out.push('credentials.cookie')
  if (p.headers === undefined) {
    out.push(...before.headers.map(h => `credentials.headers.${h.name}`))
  } else {
    for (const h of p.headers) if ('keep' in h.value) out.push(`credentials.headers.${h.name}`)
  }
  if (before.basic_auth !== null && (p.basicAuth === undefined || (p.basicAuth !== null && 'keep' in p.basicAuth.password))) {
    out.push('credentials.basic_auth.password')
  }
  return out
}

/** The names of what a write changed in the login, for its audit row: field and header names only. */
export function changedLoginFields(beforeRaw: unknown, afterRaw: unknown): string[] {
  const before = storedOf(beforeRaw)
  const after = storedOf(afterRaw)
  const out: string[] = []
  if (before.cookie !== after.cookie) out.push('cookie')
  const key = (n: string) => n.toLowerCase()
  for (const h of after.headers) {
    const old = before.headers.find(x => key(x.name) === key(h.name))
    if (!old || old.value !== h.value) out.push(`header:${h.name}`)
  }
  for (const h of before.headers) {
    if (!after.headers.some(x => key(x.name) === key(h.name))) out.push(`header:${h.name}`)
  }
  if ((before.basic_auth?.username ?? null) !== (after.basic_auth?.username ?? null)) out.push('basic_auth.username')
  if ((before.basic_auth?.password ?? null) !== (after.basic_auth?.password ?? null)) out.push('basic_auth.password')
  return out
}
