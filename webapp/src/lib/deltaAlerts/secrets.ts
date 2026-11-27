import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import { isMaskedSecret, type SecretReentry } from '@/lib/authz/secretEndpointRebind'
import { DeltaAlertEgressError, validateAlertWebhookUrl } from './egress'
import type { MaskedDeltaAlertChannel, StoredDeltaAlertChannel } from './types'

export const MAX_ALERT_CHANNELS = 10
const MASK_PLACEHOLDER = '••••'

const ChannelInputSchema = z.object({
  id: z.string().trim().max(80).optional(),
  type: z.enum(['webhook', 'slack']),
  name: z.string().trim().min(1, 'Channel name is required').max(80),
  url: z.string().trim().min(1, 'Webhook URL is required').max(2048),
  enabled: z.boolean().optional().default(true),
  secret: z.string().max(512).nullable().optional(),
})

export const ChannelsArraySchema = z
  .array(ChannelInputSchema)
  .max(MAX_ALERT_CHANNELS, `At most ${MAX_ALERT_CHANNELS} alert channels are allowed`)

function maskSecretValue(secret: string | undefined): string | null {
  if (!secret) return null
  if (secret.length <= 4) return MASK_PLACEHOLDER
  return `••••••••${secret.slice(-4)}`
}

/**
 * Masks Slack webhook token paths so GET responses never reveal the secret
 * incoming-webhook token while still showing the host and last 4 characters.
 */
export function maskSlackWebhookUrl(rawUrl: string): string {
  try {
    const u = new URL(rawUrl)
    const path = u.pathname || ''
    const tail = path.length > 4 ? path.slice(-4) : ''
    if (path.startsWith('/services/')) {
      return `${u.origin}/services/${MASK_PLACEHOLDER}${tail}`
    }
    return `${u.origin}/${MASK_PLACEHOLDER}${tail}`
  } catch {
    return `${MASK_PLACEHOLDER}`
  }
}

export function isMaskedSlackUrl(value: string): boolean {
  return value.includes(MASK_PLACEHOLDER)
}

export function maskChannelForApi(channel: StoredDeltaAlertChannel): MaskedDeltaAlertChannel {
  const hasSecret = Boolean(channel.secret && channel.secret.length > 0)
  return {
    id: channel.id,
    type: channel.type,
    name: channel.name,
    url: channel.type === 'slack' ? maskSlackWebhookUrl(channel.url) : channel.url,
    enabled: channel.enabled,
    hasSecret,
    maskedSecret: maskSecretValue(channel.secret),
  }
}

export function parseStoredChannels(raw: unknown): StoredDeltaAlertChannel[] {
  if (!Array.isArray(raw)) return []
  const out: StoredDeltaAlertChannel[] = []
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue
    const rec = item as Record<string, unknown>
    if (
      typeof rec.id === 'string' &&
      (rec.type === 'webhook' || rec.type === 'slack') &&
      typeof rec.name === 'string' &&
      typeof rec.url === 'string'
    ) {
      out.push({
        id: rec.id,
        type: rec.type,
        name: rec.name,
        url: rec.url,
        enabled: rec.enabled !== false,
        ...(typeof rec.secret === 'string' && rec.secret.length > 0 ? { secret: rec.secret } : {}),
      })
    }
  }
  return out
}

function normalizeWebhookEndpoint(rawUrl: string): string {
  try {
    const u = new URL(rawUrl.trim())
    const port = u.port || (u.protocol === 'https:' ? '443' : '80')
    return `${u.protocol}//${u.hostname.toLowerCase()}:${port}${u.pathname}${u.search}`
  } catch {
    return rawUrl.trim()
  }
}

export type MergeChannelsResult =
  | { ok: true; channels: StoredDeltaAlertChannel[] }
  | { ok: false; secretReentry: SecretReentry }
  | { ok: false; error: string }

/**
 * Validates incoming channel edits and enforces secret re-entry when a webhook
 * endpoint changes without typing a new secret or explicitly clearing it (`""`).
 */
export function mergeChannelsForSave(
  existing: StoredDeltaAlertChannel[],
  incoming: unknown,
): MergeChannelsResult {
  const parsed = ChannelsArraySchema.safeParse(incoming)
  if (!parsed.success) {
    return {
      ok: false,
      error: parsed.error.issues[0]?.message || 'Invalid channels payload',
    }
  }

  const byId = new Map(existing.map((c) => [c.id, c]))
  const usedIds = new Set<string>()
  const next: StoredDeltaAlertChannel[] = []

  for (const item of parsed.data) {
    let id = item.id && item.id.length > 0 ? item.id : randomUUID()
    if (usedIds.has(id)) id = randomUUID()
    usedIds.add(id)

    const prev = byId.get(id)

    if (item.type === 'slack') {
      let resolvedUrl = item.url
      if (isMaskedSlackUrl(item.url)) {
        if (!prev || prev.type !== 'slack' || !prev.url) {
          return {
            ok: false,
            error: `Channel "${item.name}": enter a complete Slack webhook URL.`,
          }
        }
        resolvedUrl = prev.url
      } else {
        try {
          validateAlertWebhookUrl(item.url, 'slack')
        } catch (err) {
          return {
            ok: false,
            error: err instanceof DeltaAlertEgressError ? err.message : 'Invalid Slack webhook URL',
          }
        }
      }

      next.push({
        id,
        type: 'slack',
        name: item.name,
        url: resolvedUrl,
        enabled: item.enabled,
      })
      continue
    }

    // Generic webhook: validate URL and check secret rebinding.
    try {
      validateAlertWebhookUrl(item.url, 'webhook')
    } catch (err) {
      return {
        ok: false,
        error: err instanceof DeltaAlertEgressError ? err.message : 'Invalid webhook URL',
      }
    }

    const hadSecret = Boolean(prev?.type === 'webhook' && prev.secret && prev.secret.length > 0)
    const endpointChanged =
      !prev ||
      prev.type !== 'webhook' ||
      normalizeWebhookEndpoint(prev.url) !== normalizeWebhookEndpoint(item.url)

    let resolvedSecret: string | undefined
    if (item.secret === '') {
      // Explicit empty string clears the stored secret intentionally.
      resolvedSecret = undefined
    } else if (item.secret === undefined || item.secret === null || isMaskedSecret(item.secret)) {
      if (hadSecret) {
        if (endpointChanged) {
          return {
            ok: false,
            secretReentry: {
              field: 'secret',
              fields: ['secret'],
              endpoint: 'url',
              message: `Re-enter the signing secret for "${item.name}" because the webhook URL changed (or clear it explicitly).`,
            },
          }
        }
        resolvedSecret = prev!.secret
      }
    } else {
      resolvedSecret = item.secret
    }

    next.push({
      id,
      type: 'webhook',
      name: item.name,
      url: item.url,
      enabled: item.enabled,
      ...(resolvedSecret ? { secret: resolvedSecret } : {}),
    })
  }

  return { ok: true, channels: next }
}
