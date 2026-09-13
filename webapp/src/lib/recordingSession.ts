import { normalizeScopeHosts } from '@/lib/authProfile'

// Server-side max recording window. The operator re-starts to extend.
export const RECORDING_TTL_MS = 30 * 60 * 1000

// How long after Stop a late spool record may still be folded in. The ingest
// worker polls the spool on a ~1s loop, so the final response of a login (the
// one carrying Set-Cookie) routinely lands AFTER the operator clicks Stop.
export const OBSERVE_GRACE_MS = 2 * 60 * 1000

export interface RecordingSessionRow {
  id: string
  state: string
  scopeHosts: string[]
  expiresAt: Date
  observedCount: number
  lastError: string | null
}

/** Browser-safe view of a recording session (no secrets are stored on it). */
export function publicRecordingSession(s: RecordingSessionRow) {
  return {
    id: s.id,
    state: s.state,
    scopeHosts: s.scopeHosts,
    expiresAt: s.expiresAt.toISOString(),
    observedCount: s.observedCount,
    lastError: s.lastError,
  }
}

export interface RecordingMaterial {
  cookie?: string
  authorization?: string
  extra?: Record<string, string>
  host?: string
  hosts?: string[]
}

export interface DerivedProfile {
  authType: string
  authValue: string
  authHeaderName: string
  extraHeaders: Record<string, string>
}

/**
 * Turn accumulated recording material into a ProjectAuthProfile shape.
 * Cookie → cookie mode; a lone Bearer → bearer; anything else → extra headers.
 * A cookie + bearer keeps both (bearer rides along as an extra Authorization).
 */
export function deriveProfileFromMaterial(m: RecordingMaterial): DerivedProfile {
  const extra: Record<string, string> = { ...(m.extra || {}) }
  const cookie = m.cookie?.trim()
  const authz = m.authorization?.trim()

  if (cookie) {
    if (authz) extra['Authorization'] = authz
    return { authType: 'cookie', authValue: cookie, authHeaderName: '', extraHeaders: extra }
  }
  if (authz && /^bearer\s+/i.test(authz)) {
    return { authType: 'bearer', authValue: authz.replace(/^bearer\s+/i, ''), authHeaderName: '', extraHeaders: extra }
  }
  if (authz) extra['Authorization'] = authz
  return { authType: 'none', authValue: '', authHeaderName: '', extraHeaders: extra }
}

export function materialIsEmpty(m: RecordingMaterial | null | undefined): boolean {
  if (!m) return true
  const d = deriveProfileFromMaterial(m)
  return !d.authValue && Object.keys(d.extraHeaders).length === 0
}

/** Masked, secret-free summary of what a recording captured, for operator confirm. */
export function summarizeMaterial(m: RecordingMaterial | null | undefined) {
  if (!m) return { hasCookie: false, hasBearer: false, extraHeaderNames: [] as string[], hosts: [] as string[] }
  const d = deriveProfileFromMaterial(m)
  return {
    hasCookie: d.authType === 'cookie',
    hasBearer: d.authType === 'bearer',
    authType: d.authType,
    extraHeaderNames: Object.keys(d.extraHeaders),
    hosts: m.hosts || (m.host ? [m.host] : []),
  }
}

function parseCookiePairs(cookie: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of String(cookie || '').split(';')) {
    const p = part.trim()
    const i = p.indexOf('=')
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim()
  }
  return out
}

/** Merge a freshly observed record into the running material. */
export function mergeMaterial(prev: RecordingMaterial | null | undefined, next: RecordingMaterial): RecordingMaterial {
  const out: RecordingMaterial = { ...(prev || {}) }
  if (next.cookie) {
    // Merge by cookie NAME, never whole-string replacement. Spool records arrive
    // in no guaranteed order and span several hosts, so a later request carrying
    // only `theme=dark` would otherwise wipe the session cookie captured moments
    // earlier and the recording would silently store the wrong identity.
    const pairs = { ...parseCookiePairs(out.cookie), ...parseCookiePairs(next.cookie) }
    out.cookie = Object.entries(pairs).map(([n, v]) => `${n}=${v}`).join('; ')
  }
  if (next.authorization) out.authorization = next.authorization
  if (next.extra) out.extra = { ...(out.extra || {}), ...next.extra }
  const hosts = new Set([...(out.hosts || []), ...(next.hosts || [])])
  if (next.host) hosts.add(next.host)
  out.hosts = [...hosts].filter(Boolean)
  return out
}

interface ProjectScopeFields {
  ipMode?: boolean
  targetDomain?: string | null
  subdomainList?: string[]
  targetIps?: string[]
  roeEnabled?: boolean
  roeExcludedHosts?: string[]
}

function isRoeExcluded(host: string, excluded: string[]): boolean {
  for (const raw of excluded) {
    const e = raw.trim().toLowerCase()
    if (!e) continue
    if (host === e || host.endsWith('.' + e)) return true
  }
  return false
}

/**
 * Default recording scope: the project's own target host(s) (plus listed
 * subdomains, or target IPs in IP mode), minus RoE-excluded hosts. Fail-safe:
 * never broader than what the project targets; the proxy only tags in-scope
 * requests, so operator browsing elsewhere never lands in the corpus.
 */
export function defaultRecordingScope(project: ProjectScopeFields): string[] {
  const raw: string[] = []
  if (project.ipMode) {
    raw.push(...(project.targetIps || []))
  } else {
    const root = (project.targetDomain || '').trim()
    if (root) {
      raw.push(root)
      // Subdomains too, mirroring default_scope_hosts in recon. Operators log in
      // at app./www./portal. far more often than at the apex, and an apex-only
      // recording scope meant the proxy tagged nothing at all: the operator
      // recorded a login and the modal reported "no login detected".
      // Residual, deliberate: the proxy cannot evaluate RoE, so a recording may
      // capture an RoE-excluded subdomain. The scan-time fan-out still refuses
      // RoE-excluded hosts (merge_auth_headers checks each one).
      raw.push(`*.${root}`)
      for (const pre of project.subdomainList || []) {
        const clean = String(pre).trim().replace(/\.$/, '')
        if (clean && clean !== '.') raw.push(`${clean}.${root}`)
      }
    }
  }
  let { hosts } = normalizeScopeHosts(raw)
  if (project.roeEnabled && project.roeExcludedHosts?.length) {
    hosts = hosts.filter(h => !isRoeExcluded(h, project.roeExcludedHosts!))
  }
  return hosts
}
