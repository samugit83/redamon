/**
 * An LLM provider's secrets in an API answer: the key fields and every Extra Headers
 * value (an `Authorization` or `X-Api-Key` header is a key too) go out masked to any
 * browser caller, an admin's read of another account included (HD-23). A save that sends
 * a masked header value back keeps the stored one; the re-entry rule (HD-24,
 * lib/authz/secretEndpointRebind.ts) decides first whether it may.
 */
import { isMaskedSecret } from '@/lib/authz/secretEndpointRebind'

const KEY_FIELDS = ['apiKey', 'awsAccessKeyId', 'awsSecretKey', 'awsBearerToken'] as const

function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

export function maskProvider(provider: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...provider }
  for (const f of KEY_FIELDS) out[f] = maskSecret(provider[f] as string)
  // Headers that are not a map of values cannot be masked one by one: not returned.
  const headers = isRecord(provider.defaultHeaders) ? provider.defaultHeaders : {}
  out.defaultHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, maskSecret(String(v ?? ''))]))
  return out
}

/** A masked value keeps the stored one; a mask with nothing stored is dropped, never saved. */
export function restoreMaskedHeaders(incoming: unknown, stored: unknown): unknown {
  if (!isRecord(incoming)) return incoming
  const saved = isRecord(stored) ? stored : {}
  const out: Record<string, unknown> = {}
  for (const [name, value] of Object.entries(incoming)) {
    if (!isMaskedSecret(value)) out[name] = value
    else if (typeof saved[name] === 'string') out[name] = saved[name]
  }
  return out
}
