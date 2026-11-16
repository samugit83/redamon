/**
 * The fields a person may write on a 2.0 resource, and the rules each one follows. Keys the
 * browser sends that are not listed here are ignored: the server owns the rest of the row
 * (slug, type found by detection, maps, claim, snapshot), and a spread body could carry a
 * relation input Prisma would apply as a nested write. T4.5 adds the full form's fields.
 */
import { NextResponse } from 'next/server'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { SITE_TYPES, STORAGE_MODES, type SiteType, type StorageMode } from '../agentContract'
import { isMaskedValue } from '../masking'
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

function bad(field: string, error: string, code = 'bad_field'): FieldsResult {
  return { ok: false, error: { field, code, error } }
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
  return { ok: true, value }
}

export function fieldErrorResponse(error: FieldError): NextResponse {
  return NextResponse.json(error, { status: 400 })
}
