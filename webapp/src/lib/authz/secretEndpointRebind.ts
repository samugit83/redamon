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
 * The endpoint -> secret pairs: an LLM provider's base URL or type -> its key fields and
 * its Extra Headers values;
 * the GitHub Enterprise host -> githubEnterpriseToken (only that token is ever sent to
 * it, scanners/supply_chain_scan/project_settings.py); the chisel server URL ->
 * chiselAuth; an outbound MCP server's URL -> its bearer token and header values; a stdio
 * MCP server's command, arguments and working directory (the process its env values are
 * handed to) -> its env values; a change of transport re-points the server too.
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
  transport: 'transport',
  command: 'command',
  args: 'arguments',
  cwd: 'working directory',
}

function secretLabel(field: string): string {
  if (field.startsWith('headers.')) return `value of the header "${field.slice('headers.'.length)}"`
  if (field.startsWith('defaultHeaders.')) return `value of the header "${field.slice('defaultHeaders.'.length)}"`
  if (field.startsWith('env.')) return `value of the environment variable "${field.slice('env.'.length)}"`
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

type StoredProvider = { providerType: string; baseUrl: string | null; defaultHeaders?: unknown }
  & Partial<Record<(typeof PROVIDER_SECRETS)[number], string | null>>

const recordOf = (v: unknown): Record<string, unknown> =>
  v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {}

/** The field whose change sends a provider's key, headers and prompts elsewhere, or null. */
export function llmProviderEndpointChange(stored: StoredProvider, body: Record<string, unknown>): string | null {
  return changed(body, 'providerType', stored.providerType) ? 'providerType'
    : changed(body, 'baseUrl', stored.baseUrl) ? 'baseUrl' : null
}

/**
 * A provider save (PUT) or a saved provider's test with an edited form: either starts
 * from the stored row and keeps a secret the body omits or masks. The Extra Headers are
 * one field: omitted, every stored header is kept; sent, each masked value is kept and
 * a header left out is dropped. Jev rows never get here: their type is locked and their
 * transport pinned.
 */
export function llmProviderSecretReentry(stored: StoredProvider, body: Record<string, unknown>): SecretReentry | null {
  const endpoint = llmProviderEndpointChange(stored, body)
  if (!endpoint) return null
  const sentHeaders = recordOf(body.defaultHeaders)
  const keptHeaders = Object.entries(recordOf(stored.defaultHeaders))
    .filter(([name, value]) => hasStored(value)
      && (!('defaultHeaders' in body) || isMaskedSecret(sentHeaders[name])))
    .map(([name]) => `defaultHeaders.${name}`)
  return refusal(endpoint, [
    ...PROVIDER_SECRETS.filter(f => hasStored(stored[f]) && keepsStored(body, f)),
    ...keptHeaders,
  ])
}

/** The host the settings PUT stores: no scheme, no path, lowercase. */
export function normalizeGithubHost(raw: unknown): string {
  return text(raw).trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/.*$/, '').toLowerCase()
}

const SETTINGS_BINDINGS: { endpoint: string; secret: string; normalize?: (v: unknown) => string }[] = [
  { endpoint: 'githubEnterpriseHost', secret: 'githubEnterpriseToken', normalize: normalizeGithubHost },
  { endpoint: 'chiselServerUrl', secret: 'chiselAuth' },
]

/**
 * The settings endpoint a PUT re-points, or null (ID-25 asks the step-up for it): a host or
 * URL changed to a new value while something is configured for it, the old endpoint or its
 * secret. Setting one on an empty row, or clearing it, moves nothing stored.
 */
export function settingsEndpointChange(
  stored: Record<string, unknown> | null,
  body: Record<string, unknown>,
): string | null {
  if (!stored) return null
  const due = SETTINGS_BINDINGS.find(b =>
    changed(body, b.endpoint, stored[b.endpoint], b.normalize)
    && (b.normalize ?? text)(body[b.endpoint]) !== ''
    && (hasStored(stored[b.endpoint]) || hasStored(stored[b.secret])))
  return due ? due.endpoint : null
}

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
  transport?: string | null
  url?: string | null
  auth?: { token?: string } | null
  headers?: Record<string, string> | null
  command?: string | null
  args?: string[] | null
  cwd?: string | null
  env?: Record<string, string> | null
}

const argList = (v: unknown): string => JSON.stringify(Array.isArray(v) ? v.map(String) : [])

/**
 * The field whose change sends a server's secrets somewhere else, or null. An HTTP server
 * sends its token and headers to its URL (sse and streamable_http to the same URL are the
 * same address); a stdio server hands its env values to the process its command, arguments
 * and working directory start (a relative command resolves in that directory). Turning one
 * kind into the other re-points it.
 */
export function mcpServerEndpointChange(stored: StoredMcpServer, incoming: Record<string, unknown>): string | null {
  const wasStdio = text(stored.transport) === 'stdio'
  const isStdio = text(incoming.transport) === 'stdio'
  if (wasStdio !== isStdio && text(stored.transport) !== '') return 'transport'
  if (!isStdio) return text(incoming.url) === text(stored.url) ? null : 'url'
  if (text(incoming.command) !== text(stored.command)) return 'command'
  if (argList(incoming.args) !== argList(stored.args)) return 'args'
  if (text(incoming.cwd) !== text(stored.cwd)) return 'cwd'
  return null
}

function maskedStoredValues(prefix: string, incoming: unknown, stored: Record<string, string> | null | undefined): string[] {
  if (!incoming || typeof incoming !== 'object') return []
  return Object.entries(incoming as Record<string, unknown>)
    .filter(([name, value]) => isMaskedSecret(value) && hasStored(stored?.[name]))
    .map(([name]) => `${prefix}${name}`)
}

/**
 * An MCP server save replaces the whole server and restores only the values sent back
 * masked (lib/mcp/mask.ts restoreMaskedToken): the bearer token, each header value and
 * each env value. Only the secrets the new endpoint would receive are asked for: an HTTP
 * server's token and headers, a stdio server's env. `/api/mcp/test` restores the token
 * alone, so it passes `headers: false`, which skips the env values too.
 */
export function mcpServerSecretReentry(
  stored: StoredMcpServer,
  incoming: Record<string, unknown>,
  { headers = true }: { headers?: boolean } = {},
): SecretReentry | null {
  const endpoint = mcpServerEndpointChange(stored, incoming)
  if (!endpoint) return null
  if (text(incoming.transport) === 'stdio') {
    return headers ? refusal(endpoint, maskedStoredValues('env.', incoming.env, stored.env)) : null
  }
  const fields: string[] = []
  const auth = incoming.auth as { token?: unknown } | undefined
  if (hasStored(stored.auth?.token) && isMaskedSecret(auth?.token)) fields.push('auth.token')
  if (headers) fields.push(...maskedStoredValues('headers.', incoming.headers, stored.headers))
  return refusal(endpoint, fields)
}

/** The 400 every route answers; `extra` keeps a route's own answer shape (`success`, `ok`). */
export function secretReentryResponse(r: SecretReentry, extra: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json(
    { ...extra, error: r.message, code: SECRET_REENTRY_CODE, field: r.field, fields: r.fields, endpoint: r.endpoint },
    { status: 400 },
  )
}
