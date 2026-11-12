/**
 * The instance security policy (step 2.6; feature document §4.4 "instance security policy"):
 * the password policy, the session and link lifetimes, the impersonation settings and the
 * public base URL of the instance settings row. Only the confirmed Root changes them, with its
 * password (the instance settings route checks that); this module says which fields they are
 * and whether a value is acceptable. Later steps read them (2.8 the password minimum, 2.9 the
 * invite links and base URL, 2.11 the lifetimes, Phase 3 impersonation).
 *
 * Bounds: the password minimum never goes below 12 (HD-12) nor above 72 (bcrypt reads at most
 * 72 bytes); the lifetimes are whole numbers kept inside bounds no deployment needs to pass
 * (their defaults are PLACEHOLDER(OQ-38), PLACEHOLDER(OQ-32) in the schema).
 */

type Values = Record<string, unknown>

const INTEGER_BOUNDS = {
  passwordMinLength: [12, 72],
  memberSessionTtlHours: [1, 8760],
  adminSessionTtlHours: [1, 168],
  adminIdleMinutes: [5, 1440],
  inviteTtlHours: [1, 720],
  resetTtlHours: [1, 168],
  impersonationMaxMinutes: [5, 1440],
} as const

const BOOLEAN_FIELDS = ['passwordAskChangeIfShort', 'impersonationReasonRequired', 'impersonationNotifyTarget'] as const

export const SECURITY_POLICY_FIELDS = [
  ...(Object.keys(INTEGER_BOUNDS) as (keyof typeof INTEGER_BOUNDS)[]),
  ...BOOLEAN_FIELDS,
  'publicBaseUrl',
] as const

export type SecurityPolicyField = (typeof SECURITY_POLICY_FIELDS)[number]
export type SecurityPolicyPatch = Partial<Record<SecurityPolicyField, number | boolean | string | null>>

const MAX_URL_LENGTH = 2048

/** An http(s) address with no credentials, query or fragment, without its trailing slash; null to clear. */
function parseBaseUrl(raw: unknown): { value: string | null } | { message: string } {
  if (raw === null || raw === '') return { value: null }
  if (typeof raw !== 'string') return { message: 'publicBaseUrl must be text (an http or https address) or empty' }
  const text = raw.trim()
  if (text === '') return { value: null }
  if (text.length > MAX_URL_LENGTH) return { message: `publicBaseUrl is longer than ${MAX_URL_LENGTH} characters` }
  let url: URL
  try {
    url = new URL(text)
  } catch {
    return { message: 'publicBaseUrl is not an address (e.g. https://redamon.example.com)' }
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return { message: 'publicBaseUrl must start with http:// or https://' }
  if (url.username || url.password) return { message: 'publicBaseUrl must not carry a user name or password' }
  if (url.search || url.hash || text.includes('?') || text.includes('#')) {
    return { message: 'publicBaseUrl must not carry a query or a fragment' }
  }
  return { value: url.origin + url.pathname.replace(/\/+$/, '') }
}

/**
 * The security policy fields the body names, checked; `error` names the first refused field.
 * A body that names none gives an empty patch.
 */
export function parseSecurityPolicyPatch(body: Values):
  | { patch: SecurityPolicyPatch }
  | { error: { field: SecurityPolicyField; message: string } } {
  const patch: SecurityPolicyPatch = {}
  for (const [field, [min, max]] of Object.entries(INTEGER_BOUNDS) as [keyof typeof INTEGER_BOUNDS, readonly [number, number]][]) {
    if (!(field in body)) continue
    const v = body[field]
    if (typeof v !== 'number' || !Number.isInteger(v) || v < min || v > max) {
      return { error: { field, message: `${field} must be a whole number from ${min} to ${max}` } }
    }
    patch[field] = v
  }
  for (const field of BOOLEAN_FIELDS) {
    if (!(field in body)) continue
    if (typeof body[field] !== 'boolean') return { error: { field, message: `${field} must be true or false` } }
    patch[field] = body[field] as boolean
  }
  if ('publicBaseUrl' in body) {
    const url = parseBaseUrl(body.publicBaseUrl)
    if ('message' in url) return { error: { field: 'publicBaseUrl', message: url.message } }
    patch.publicBaseUrl = url.value
  }
  return { patch }
}

/** The patch's fields whose value differs from the stored one. */
export function changedSecurityPolicyFields(stored: Values, patch: SecurityPolicyPatch): SecurityPolicyField[] {
  return (Object.keys(patch) as SecurityPolicyField[]).filter((f) => (stored[f] ?? null) !== (patch[f] ?? null))
}

/** The policy as stored, for an admin's view of the instance settings. */
export function securityPolicyView(row: Values): Record<SecurityPolicyField, unknown> {
  return Object.fromEntries(SECURITY_POLICY_FIELDS.map((f) => [f, row[f] ?? null])) as Record<SecurityPolicyField, unknown>
}
