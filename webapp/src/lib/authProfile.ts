/**
 * ProjectAuthProfile read boundary + input validation.
 *
 * The stored session (authValue / extraHeaders values) is write-only from the
 * UI: it is handed to recon and the agent (X-Internal-Key callers) and never
 * returned to a browser. Every browser-facing read goes through
 * toAuthProfileMetadata.
 *
 * Kept free of Node-only imports so client components can import the types.
 */

export const AUTH_TYPES = ['none', 'bearer', 'cookie', 'header', 'basic', 'apikey'] as const
export type AuthType = (typeof AUTH_TYPES)[number]

export const MAX_HEADER_NAME_LEN = 256
export const MAX_HEADER_VALUE_LEN = 8192
export const MAX_SCOPE_HOSTS = 200
export const MAX_EXTRA_HEADERS = 32

export interface AuthProfileRow {
  authType: string
  authHeaderName: string
  authValue: string
  extraHeaders: unknown
  scopeHosts: string[]
  reconEnabled?: boolean
  agentEnabled?: boolean
  source: string
  status: string
  lastValidatedAt: Date | string | null
  updatedAt?: Date | string | null
}

export interface AuthProfileMetadata {
  authType: string
  authHeaderName: string
  /** Header names only; their values are as secret as authValue. */
  extraHeaderNames: string[]
  scopeHosts: string[]
  reconEnabled: boolean
  agentEnabled: boolean
  source: string
  status: string
  lastValidatedAt: Date | string | null
  updatedAt: Date | string | null
  hasValue: boolean
}

function extraHeaderNames(extra: unknown): string[] {
  if (!extra || typeof extra !== 'object' || Array.isArray(extra)) return []
  return Object.keys(extra as Record<string, unknown>)
}

// Built field-by-field (an allowlist, not a spread-and-delete) so a column added
// to the model later stays off browser responses until someone opts it in here.
export function toAuthProfileMetadata(profile: AuthProfileRow | null | undefined): AuthProfileMetadata | null {
  if (!profile) return null
  const names = extraHeaderNames(profile.extraHeaders)
  return {
    authType: profile.authType,
    authHeaderName: profile.authHeaderName,
    extraHeaderNames: names,
    scopeHosts: profile.scopeHosts,
    // Default on when the column is absent (older row / never set).
    reconEnabled: profile.reconEnabled !== false,
    agentEnabled: profile.agentEnabled !== false,
    source: profile.source,
    status: profile.status,
    lastValidatedAt: profile.lastValidatedAt,
    updatedAt: profile.updatedAt ?? null,
    hasValue: profile.authValue.length > 0 || names.length > 0,
  }
}

// ---------------------------------------------------------------------------
// Validation. Mirrors recon/helpers/auth_profile.py, which re-checks at use
// time: the value reaches each recon tool's -H, and hakrawler (';;') / arjun
// ('\n') join every header - including the internal X-Redamon-Ctx tag - into
// one argument.

const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/
// Every C0 control except TAB, plus DEL.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS_RE = /[\x00-\x08\x0a-\x1f\x7f]/
const RESERVED_HEADER_NAMES = new Set(['x-redamon-ctx'])
// Hostname, *.suffix wildcard, IPv4/IPv6 address or CIDR. No scheme, path or spaces.
const SCOPE_ENTRY_RE = /^(\*\.)?[a-z0-9_.:-]+(\/\d{1,3})?$/

export function validateHeaderName(name: unknown): string | null {
  if (typeof name !== 'string') return 'Header name must be a string'
  const n = name.trim()
  if (!n) return 'Header name is empty'
  if (n.length > MAX_HEADER_NAME_LEN) return 'Header name is too long'
  if (!HEADER_NAME_RE.test(n)) return `Invalid header name "${n.slice(0, 40)}"`
  if (RESERVED_HEADER_NAMES.has(n.toLowerCase())) return `"${n}" is reserved`
  return null
}

export function validateHeaderValue(value: unknown, label = 'Value'): string | null {
  if (typeof value !== 'string') return `${label} must be a string`
  if (CONTROL_CHARS_RE.test(value)) return `${label} contains line breaks or control characters`
  if (value.includes(';;')) return `${label} contains ";;"`
  if (value.length > MAX_HEADER_VALUE_LEN) return `${label} is longer than ${MAX_HEADER_VALUE_LEN} characters`
  return null
}

export function normalizeScopeHosts(raw: unknown): { hosts: string[]; error: string | null } {
  if (raw === undefined || raw === null) return { hosts: [], error: null }
  const list = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(/[\s,]+/) : null
  if (!list) return { hosts: [], error: 'scopeHosts must be a list' }
  const hosts: string[] = []
  for (const entry of list) {
    if (typeof entry !== 'string') return { hosts: [], error: 'scopeHosts entries must be strings' }
    const h = entry.trim().toLowerCase().replace(/\.$/, '')
    if (!h) continue
    if (!SCOPE_ENTRY_RE.test(h)) return { hosts: [], error: `Invalid scope host "${h.slice(0, 60)}"` }
    if (!hosts.includes(h)) hosts.push(h)
  }
  if (hosts.length > MAX_SCOPE_HOSTS) return { hosts: [], error: `At most ${MAX_SCOPE_HOSTS} scope hosts` }
  return { hosts, error: null }
}

export interface AuthProfileInput {
  authType?: unknown
  authHeaderName?: unknown
  authValue?: unknown
  extraHeaders?: unknown
  scopeHosts?: unknown
  reconEnabled?: unknown
  agentEnabled?: unknown
  clearValue?: unknown
}

export interface AuthProfilePatch {
  authType?: AuthType
  authHeaderName?: string
  authValue?: string
  extraHeaders?: Record<string, string>
  scopeHosts?: string[]
  reconEnabled?: boolean
  agentEnabled?: boolean
}

/**
 * Validate a UI write. Absent fields are left untouched, which is what makes the
 * form write-only: it never has the stored value, so it simply omits authValue
 * to keep it. `clearValue: true` is the only way to blank it.
 */
export function parseAuthProfileInput(body: AuthProfileInput): { patch: AuthProfilePatch; error: string | null } {
  const patch: AuthProfilePatch = {}

  if (body.authType !== undefined) {
    if (typeof body.authType !== 'string' || !(AUTH_TYPES as readonly string[]).includes(body.authType)) {
      return { patch, error: `authType must be one of ${AUTH_TYPES.join(', ')}` }
    }
    patch.authType = body.authType as AuthType
  }

  if (body.authHeaderName !== undefined) {
    if (typeof body.authHeaderName !== 'string') return { patch, error: 'authHeaderName must be a string' }
    const name = body.authHeaderName.trim()
    if (name) {
      const err = validateHeaderName(name)
      if (err) return { patch, error: err }
    }
    patch.authHeaderName = name
  }

  if (body.clearValue === true) {
    patch.authValue = ''
  } else if (body.authValue !== undefined && body.authValue !== '') {
    const err = validateHeaderValue(body.authValue, 'Auth value')
    if (err) return { patch, error: err }
    patch.authValue = (body.authValue as string).trim()
  }

  if (body.extraHeaders !== undefined) {
    const extra = body.extraHeaders
    if (!extra || typeof extra !== 'object' || Array.isArray(extra)) {
      return { patch, error: 'extraHeaders must be an object of name: value' }
    }
    const entries = Object.entries(extra as Record<string, unknown>)
    if (entries.length > MAX_EXTRA_HEADERS) return { patch, error: `At most ${MAX_EXTRA_HEADERS} extra headers` }
    const out: Record<string, string> = {}
    for (const [name, value] of entries) {
      const nameErr = validateHeaderName(name)
      if (nameErr) return { patch, error: nameErr }
      const valueErr = validateHeaderValue(value, `Header "${name.trim()}"`)
      if (valueErr) return { patch, error: valueErr }
      out[name.trim()] = (value as string).trim()
    }
    patch.extraHeaders = out
  }

  if (body.scopeHosts !== undefined) {
    const { hosts, error } = normalizeScopeHosts(body.scopeHosts)
    if (error) return { patch, error }
    patch.scopeHosts = hosts
  }

  if (body.reconEnabled !== undefined) {
    if (typeof body.reconEnabled !== 'boolean') return { patch, error: 'reconEnabled must be a boolean' }
    patch.reconEnabled = body.reconEnabled
  }
  if (body.agentEnabled !== undefined) {
    if (typeof body.agentEnabled !== 'boolean') return { patch, error: 'agentEnabled must be a boolean' }
    patch.agentEnabled = body.agentEnabled
  }

  return { patch, error: null }
}

/** Mask a secret for display ("abcd...wxyz"); mirrors recon mask_auth_value. */
export function maskAuthValue(value: string): string {
  if (!value) return ''
  if (value.length > 10) return `${value.slice(0, 4)}...${value.slice(-4)}`
  if (value.length > 4) return `${value.slice(0, 2)}***`
  return '***'
}
