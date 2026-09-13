import { validateHeaderName, validateHeaderValue } from '@/lib/authProfile'
import type { RecordingMaterial } from '@/lib/recordingSession'

/**
 * Validate + sanitize login material POSTed by the ingest worker. The values are
 * target-controlled (the target set the Set-Cookie), so this re-applies the same
 * CR/LF / ";;" / reserved-name rejection the recon builder uses (defense in depth,
 * per plan 1.3). Returns null when nothing usable survives.
 */
export function parseObservedMaterial(raw: unknown, hostHint: unknown): RecordingMaterial | null {
  if (!raw || typeof raw !== 'object') return null
  const m = raw as Record<string, unknown>
  const out: RecordingMaterial = {}

  if (typeof m.cookie === 'string' && m.cookie && !validateHeaderValue(m.cookie)) {
    out.cookie = m.cookie
  }
  if (typeof m.authorization === 'string' && m.authorization && !validateHeaderValue(m.authorization)) {
    out.authorization = m.authorization
  }
  if (m.extra && typeof m.extra === 'object' && !Array.isArray(m.extra)) {
    const extra: Record<string, string> = {}
    for (const [name, value] of Object.entries(m.extra as Record<string, unknown>)) {
      if (validateHeaderName(name)) continue
      if (typeof value !== 'string' || validateHeaderValue(value)) continue
      extra[name.trim()] = value
    }
    if (Object.keys(extra).length) out.extra = extra
  }

  const host = typeof m.host === 'string' && m.host ? m.host
    : typeof hostHint === 'string' && hostHint ? hostHint : undefined
  if (host) out.host = host.trim().toLowerCase()

  const hasMaterial = out.cookie || out.authorization || (out.extra && Object.keys(out.extra).length)
  return hasMaterial ? out : null
}
