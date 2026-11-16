/**
 * What a browser may see of a resource's secrets (§6.6, U1): never a value.
 *
 * The 1.x answers keep their format (the GitHub token as `••••••••` and its last four characters),
 * which the 1.x form sends back unchanged to mean "keep it". The 2.0 answers say only whether a
 * secret is set, with the contract's placeholder, which no write and no agent request accepts as a
 * value (`agentContract.ts` SECRET_PLACEHOLDER).
 */
import { SECRET_PLACEHOLDER } from './agentContract'

export function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

/** The 2.0 view of one secret: the placeholder when set, else empty. */
export function secretState(value: unknown): '' | typeof SECRET_PLACEHOLDER {
  return typeof value === 'string' && value.length > 0 ? SECRET_PLACEHOLDER : ''
}

export interface MaskedCredentials {
  cookie: '' | typeof SECRET_PLACEHOLDER
  headers: { name: string; value: '' | typeof SECRET_PLACEHOLDER }[]
  basic_auth: { username: string; password: '' | typeof SECRET_PLACEHOLDER } | null
}

/** The stored login with every secret value replaced; header names and the user name stay. */
export function maskCredentials(stored: unknown): MaskedCredentials {
  const c = stored && typeof stored === 'object' && !Array.isArray(stored) ? (stored as Record<string, unknown>) : {}
  const headers = Array.isArray(c.headers) ? c.headers : []
  const basic = c.basic_auth && typeof c.basic_auth === 'object' ? (c.basic_auth as Record<string, unknown>) : null
  return {
    cookie: secretState(c.cookie),
    headers: headers
      .filter((h): h is Record<string, unknown> => !!h && typeof h === 'object')
      .map(h => ({ name: typeof h.name === 'string' ? h.name : '', value: secretState(h.value) })),
    basic_auth: basic ? { username: typeof basic.username === 'string' ? basic.username : '', password: secretState(basic.password) } : null,
  }
}

/**
 * A row for a browser answer: the GitHub token in the 1.x format, and the login masked when the
 * row carries one. A 1.x read selects the 1.x columns by name (resourceAccess.ts LEGACY_SELECT),
 * so a 1.x row carries no login; the mask is the second line of defence.
 */
export function maskResource(r: Record<string, unknown>): Record<string, unknown> {
  return {
    ...r,
    githubTokenOverride: maskSecret(r.githubTokenOverride as string),
    ...('credentials' in r ? { credentials: maskCredentials(r.credentials) } : {}),
  }
}

/** Whether a value the browser sent back is a mask of the stored secret, meaning "keep it". */
export function isMaskedValue(value: unknown): boolean {
  return typeof value === 'string' && (value.startsWith('••••') || value.trim() === SECRET_PLACEHOLDER)
}
