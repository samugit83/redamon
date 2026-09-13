import { createHash } from 'crypto'
import prisma from '@/lib/prisma'

// Scan kinds whose traffic carries the auth profile (the recon fan-out).
const AUTH_AWARE_KINDS = new Set(['full_recon', 'partial_recon'])

export interface FingerprintableAuthProfile {
  authType: string
  authHeaderName: string
  authValue: string
  extraHeaders: unknown
  scopeHosts: string[]
  reconEnabled?: boolean
}

const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')

function canonicalExtras(extra: unknown): string {
  if (!extra || typeof extra !== 'object' || Array.isArray(extra)) return '{}'
  const rec = extra as Record<string, unknown>
  return JSON.stringify(Object.keys(rec).sort().map(k => [k, rec[k]]))
}

/**
 * Change-detection fingerprint of the auth profile for JobQueue.settingsHash.
 *
 * The profile is a relation, so the Project-row settingsFingerprint cannot see
 * it; without this an edit between enqueue and dispatch would silently run the
 * queued scan with a different identity. Secrets enter only as their own hash,
 * so the fingerprint is safe to store next to the job.
 */
export function authProfileFingerprint(profile: FingerprintableAuthProfile | null | undefined): string {
  if (!profile) return 'none'
  return sha256([
    profile.authType,
    profile.authHeaderName,
    [...profile.scopeHosts].sort().join(','),
    // The recon gate changes whether a scan runs authenticated at all, so a
    // toggle between enqueue and dispatch must register as a settings change.
    profile.reconEnabled === false ? 'recon:off' : 'recon:on',
    sha256(profile.authValue),
    sha256(canonicalExtras(profile.extraHeaders)),
  ].join('|'))
}

/**
 * Fingerprint-extra contribution for the JobQueue settings hash (G7). The auth
 * profile is a relation, so settingsFingerprint (Project-row only) cannot see it;
 * without this an edit between enqueue and dispatch would run the queued scan
 * with a different identity undetected. Only for auth-aware scan kinds; the value
 * enters as a hash, never in the clear.
 */
export async function authProfileFingerprintExtra(
  kind: string, projectId: string,
): Promise<Record<string, string>> {
  if (!AUTH_AWARE_KINDS.has(kind)) return {}
  try {
    const profile = await prisma.projectAuthProfile.findUnique({ where: { projectId } })
    return { authProfileFp: authProfileFingerprint(profile) }
  } catch {
    // Resilient: the fingerprint is only change-detection (the profile is read
    // live at scan start). A lookup hiccup omits the contribution rather than
    // failing enqueue/dispatch; a one-sided omission just triggers needs_review.
    return {}
  }
}
