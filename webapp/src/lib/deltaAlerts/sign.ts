import { createHmac, timingSafeEqual } from 'node:crypto'

/**
 * Computes an HMAC-SHA256 signature (`sha256=<hex>`) over `${timestampSec}.${rawBody}`.
 */
export function signWebhookPayload(
  secret: string,
  timestampSec: number | string,
  rawBody: string,
): string {
  const mac = createHmac('sha256', secret)
    .update(`${String(timestampSec)}.${rawBody}`)
    .digest('hex')
  return `sha256=${mac}`
}

/**
 * Constant-time verification of an incoming `X-RedAmon-Signature-256` header.
 */
export function verifyWebhookSignature(
  secret: string,
  timestampSec: number | string,
  rawBody: string,
  headerValue: string,
): boolean {
  if (!secret || typeof headerValue !== 'string' || !headerValue.startsWith('sha256=')) {
    return false
  }
  const expected = signWebhookPayload(secret, timestampSec, rawBody)
  const a = Buffer.from(expected, 'utf8')
  const b = Buffer.from(headerValue, 'utf8')
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}
