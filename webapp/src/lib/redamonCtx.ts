import { createHmac } from 'crypto'

/**
 * TypeScript minter for the X-Redamon-Ctx capture tag.
 *
 * Byte-for-byte compatible with `redamon_ctx.py` (verified by the ingest worker):
 * canonical JSON = only the allowlisted fields, nulls dropped, keys sorted,
 * compact separators; token = base64url(json).base64url(hmac_sha256), no '='.
 *
 * Used to mint the `operator` recording tag with INTERNAL_API_KEY. The webapp is
 * the ONLY TS minter; recon/agent mint in Python with their own keys.
 */

// Must match _ALLOWED_FIELDS in redamon_ctx.py exactly (order irrelevant; sorted below).
const ALLOWED_FIELDS = [
  'source', 'project_id', 'user_id', 'run_id', 'session_id',
  'tool', 'phase', 'step', 'member_id', 'is_replay', 'origin_id',
] as const

export type CtxPayload = Partial<Record<(typeof ALLOWED_FIELDS)[number], string | boolean>>

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function canonical(payload: CtxPayload): string {
  const filtered: Record<string, string | boolean> = {}
  for (const k of [...ALLOWED_FIELDS].sort()) {
    const v = payload[k]
    if (v !== undefined && v !== null) filtered[k] = v
  }
  // JSON.stringify with no spaces matches Python separators (',',':'); our values
  // are ASCII ids so ensure_ascii vs not is moot.
  return JSON.stringify(filtered)
}

export function signTag(payload: CtxPayload, key: string): string {
  if (!key) throw new Error('empty signing key')
  const raw = Buffer.from(canonical(payload), 'utf-8')
  const sig = createHmac('sha256', key).update(raw).digest()
  return `${b64url(raw)}.${b64url(sig)}`
}
