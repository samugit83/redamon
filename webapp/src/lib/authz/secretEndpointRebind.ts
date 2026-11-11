/**
 * Re-entry of a stored secret when the endpoint it is sent to changes (HD-24, F-19).
 *
 * Every route that stores a secret returns it masked and, on a save, keeps the stored
 * value when the body sends the mask back (or omits the field). That is what lets a
 * stolen session, or anyone else who can write the row, harvest a key it never saw:
 * point the endpoint elsewhere, keep the mask, and the next run delivers the key to the
 * new address. So a write that changes an endpoint must carry each secret bound to it
 * typed again, or cleared. It holds for everyone, the account itself included.
 *
 * The endpoint -> secret pairs: an LLM provider's base URL or type -> its key fields;
 * the GitHub Enterprise host -> githubEnterpriseToken (only that token is ever sent to
 * it, scanners/supply_chain_scan/project_settings.py); the chisel server URL ->
 * chiselAuth; an outbound MCP server's URL -> its bearer token and header values.
 */
import { NextResponse } from 'next/server'

export const SECRET_REENTRY_CODE = 'secret_reentry_required'

const MASK_PREFIX = '••••'

/** The placeholder the GETs return for a stored secret: never a value. */
export function isMaskedSecret(value: unknown): boolean {
  return typeof value === 'string' && value.startsWith(MASK_PREFIX)
}

export interface SecretReentry {
  /** The first secret to type again: the one the form focuses. */
  field: string
  /** Every secret the write would have kept for the new endpoint. */
  fields: string[]
  /** The endpoint field whose change asks for them. */
  endpoint: string
  message: string
}

const SECRET_LABELS: Record<string, string> = {
  apiKey: 'API key',
  awsAccessKeyId: 'AWS access key ID',
  awsSecretKey: 'AWS secret access key',
  awsBearerToken: 'Bedrock API key',
  githubEnterpriseToken: 'GitHub Enterprise token',
  chiselAuth: 'chisel auth',
  'auth.token': 'bearer token',
}

const ENDPOINT_LABELS: Record<string, string> = {
  baseUrl: 'base URL',
  providerType: 'provider type',
  githubEnterpriseHost: 'GitHub Enterprise host',
  chiselServerUrl: 'chisel server URL',
  url: 'server URL',
}

function secretLabel(field: string): string {
  if (field.startsWith('headers.')) return `value of the header "${field.slice('headers.'.length)}"`
  return SECRET_LABELS[field] ?? field
}

function refusal(endpoint: string, fields: string[]): SecretReentry | null {
  if (fields.length === 0) return null
  const names = fields.map(secretLabel).join(', ')
  return {
    field: fields[0],
    fields,
    endpoint,
    message: `The ${ENDPOINT_LABELS[endpoint] ?? endpoint} changed: type the ${names} again, or clear it. `
      + 'A stored secret is never sent to a new address unless it is entered again.',
  }
}

const text = (v: unknown): string => (v === null || v === undefined ? '' : String(v))
const hasStored = (v: unknown): boolean => typeof v === 'string' && v.length > 0

/** A save keeps the stored value for a field it omits or sends back masked. */
const keepsStored = (body: Record<string, unknown>, field: string): boolean =>
  !(field in body) || isMaskedSecret(body[field])

function changed(body: Record<string, unknown>, field: string, stored: unknown,
  normalize: (v: unknown) => string = text): boolean {
  return field in body && normalize(body[field]) !== normalize(stored)
}

const PROVIDER_SECRETS = ['apiKey', 'awsAccessKeyId', 'awsSecretKey', 'awsBearerToken'] as const

/**
 * A provider save (PUT) or a saved provider's test with an edited form: either starts
 * from the stored row and keeps a secret the body omits or masks. Jev rows never get
 * here: their type is locked and their transport pinned.
 */
export function llmProviderSecretReentry(
  stored: { providerType: string; baseUrl: string | null } & Partial<Record<(typeof PROVIDER_SECRETS)[number], string | null>>,
  body: Record<string, unknown>,
): SecretReentry | null {
  const endpoint = changed(body, 'providerType', stored.providerType) ? 'providerType'
    : changed(body, 'baseUrl', stored.baseUrl) ? 'baseUrl' : null
  if (!endpoint) return null
  return refusal(endpoint, PROVIDER_SECRETS.filter(f => hasStored(stored[f]) && keepsStored(body, f)))
}

/** The host the settings PUT stores: no scheme, no path, lowercase. */
export function normalizeGithubHost(raw: unknown): string {
  return text(raw).trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/.*$/, '').toLowerCase()
}

const SETTINGS_BINDINGS: { endpoint: string; secret: string; normalize?: (v: unknown) => string }[] = [
  { endpoint: 'githubEnterpriseHost', secret: 'githubEnterpriseToken', normalize: normalizeGithubHost },
  { endpoint: 'chiselServerUrl', secret: 'chiselAuth' },
]

/** The settings PUT: it writes only the fields the body names, so an omitted secret stays. */
export function settingsSecretReentry(
  stored: Record<string, unknown> | null,
  body: Record<string, unknown>,
): SecretReentry | null {
  if (!stored) return null
  const due = SETTINGS_BINDINGS.filter(b =>
    changed(body, b.endpoint, stored[b.endpoint], b.normalize)
    && hasStored(stored[b.secret]) && keepsStored(body, b.secret))
  return due.length ? refusal(due[0].endpoint, due.map(b => b.secret)) : null
}

interface StoredMcpServer {
  url?: string | null
  auth?: { token?: string } | null
  headers?: Record<string, string> | null
}

/**
 * An MCP server save replaces the whole server and restores only the values sent back
 * masked (lib/mcp/mask.ts restoreMaskedToken): the bearer token and each header value.
 * `/api/mcp/test` restores the token alone, so it passes `headers: false`.
 */
export function mcpServerSecretReentry(
  stored: StoredMcpServer,
  incoming: Record<string, unknown>,
  { headers = true }: { headers?: boolean } = {},
): SecretReentry | null {
  if (text(incoming.url) === text(stored.url)) return null
  const fields: string[] = []
  const auth = incoming.auth as { token?: unknown } | undefined
  if (hasStored(stored.auth?.token) && isMaskedSecret(auth?.token)) fields.push('auth.token')
  const incomingHeaders = incoming.headers
  if (headers && incomingHeaders && typeof incomingHeaders === 'object') {
    for (const [name, value] of Object.entries(incomingHeaders as Record<string, unknown>)) {
      if (isMaskedSecret(value) && hasStored(stored.headers?.[name])) fields.push(`headers.${name}`)
    }
  }
  return refusal('url', fields)
}

/** The 400 every route answers; `extra` keeps a route's own answer shape (`success`, `ok`). */
export function secretReentryResponse(r: SecretReentry, extra: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json(
    { ...extra, error: r.message, code: SECRET_REENTRY_CODE, field: r.field, fields: r.fields, endpoint: r.endpoint },
    { status: 400 },
  )
}
