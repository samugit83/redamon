/**
 * Per-source status of the OpenAPI documents a project configures.
 *
 * Recon writes one string per configured document on the org Domain of the
 * scan root it ran for: "<scan root>|<source id>|<sha256(public url)[:12]>|<code>|<ISO time>"
 * (older runs wrote the same without the scan root). It holds no URL,
 * since a document URL can carry a token. The form shows a status only while
 * the row's current URL hashes to the stored one; an edited URL reads
 * "Not fetched yet" until the next run.
 */
import type { ProjectTargetFields } from './partialReconScope'
import { authScopePatterns, resolveScopeGroups } from './scopeGroups'
import { isRoeExcluded } from './roeScope'
import { matches, parseEntries } from './ipHostnameFilter'

export interface OpenApiSourceStatus {
  hash: string
  code: string
  at: string
}

export interface OpenApiSourceRow {
  id?: string
  url?: string
  enabled?: boolean
}

export const NOT_FETCHED = 'Not fetched yet'

export function parseOpenApiSourceStatus(entries: unknown): Map<string, OpenApiSourceStatus> {
  const out = new Map<string, OpenApiSourceStatus>()
  if (!Array.isArray(entries)) return out
  for (const entry of entries) {
    if (typeof entry !== 'string') continue
    const parts = entry.split('|')
    // Five segments lead with the scan root; a document fetched for several
    // roots shows its newest status.
    const [id, hash, code, at = ''] = parts.length >= 5 ? parts.slice(1) : parts
    if (!id || !hash || !code) continue
    const seen = out.get(id)
    if (!seen || at > seen.at) out.set(id, { hash, code, at })
  }
  return out
}

/** What recon hashes: scheme, host, non-default port and path; never the query. */
export function publicDocumentUrl(url: string): string | null {
  try {
    const parsed = new URL(url.trim())
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
    const host = parsed.host.replace(/\.(?=$|:)/, '')
    return `${parsed.protocol}//${host}${parsed.pathname || '/'}`
  } catch {
    return null
  }
}

/** The 12-hex-digit hash recon stores, or null where the browser cannot hash (plain HTTP). */
export async function documentUrlHash(url: string): Promise<string | null> {
  const location = publicDocumentUrl(url)
  if (!location || typeof crypto === 'undefined' || !crypto.subtle) return null
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(location))
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 12)
}

export function openApiStatusLabel(code: string): string {
  if (code === 'ok') return 'Imported'
  if (code === 'out_of_scope') return 'Outside scope'
  if (code === 'blocked_address') return 'Internal address blocked'
  if (/^http_\d+$/.test(code)) return `HTTP ${code.slice(5)}`
  if (code === 'invalid_document') return 'Invalid document'
  if (code === 'unsupported_version') return 'Unsupported version'
  if (code === 'host_down') return 'Host down'
  if (code === 'transport_error') return 'Unreachable'
  if (code === 'limit_reached') return 'Limit reached'
  return 'Unknown'
}

/**
 * The label for one row: its status while its URL is the one fetched,
 * NOT_FETCHED otherwise, or null when it cannot be told (status unread, or no
 * hashing in this browser).
 */
export function rowStatusLabel(
  row: OpenApiSourceRow,
  statuses: Map<string, OpenApiSourceStatus> | null,
  rowHash: string | null | undefined,
): string | null {
  if (!statuses || rowHash === null) return null
  const status = row.id ? statuses.get(row.id) : undefined
  if (!status || rowHash === undefined || status.hash !== rowHash) return NOT_FETCHED
  return openApiStatusLabel(status.code)
}

function ipv4ToInt(value: string): number | null {
  const parts = value.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part) || Number(part) > 255) return null
    n = n * 256 + Number(part)
  }
  return n
}

function inIpv4Target(host: string, target: string): boolean | null {
  const [base, bits] = target.trim().split('/')
  const ip = ipv4ToInt(host)
  const net = ipv4ToInt(base)
  if (ip === null || net === null) return null
  const prefix = bits === undefined ? 32 : Number(bits)
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null
  const size = 2 ** (32 - prefix)
  return Math.floor(ip / size) === Math.floor(net / size)
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

/** recon's _normalize_host: lower case, without scheme, port, IPv6 brackets or trailing dot. */
function normalizeHost(value: string): string {
  let host = value.trim()
  if (host.includes('://')) {
    try {
      host = new URL(host).hostname
    } catch {
      return ''
    }
  }
  if (host.startsWith('[')) host = host.slice(1).split(']')[0]
  else if (host.split(':').length === 2) host = host.split(':')[0]
  return host.trim().replace(/\.+$/, '').toLowerCase()
}

/**
 * The hosts one legacy group record admits, as recon's OpenAPI scope builds them
 * (scope_payload in recon/helpers/openapi/discovery.py): each listed prefix as
 * an exact host, the apex only through the "." prefix, and every subdomain
 * (`*.root`) through "*". Only for a batch whose host list the caller lacks.
 */
function rootScopeEntries(rootValue: unknown, prefixValues: unknown): string[] {
  const root = typeof rootValue === 'string' ? normalizeHost(rootValue) : ''
  if (!root) return []
  const prefixes = strings(prefixValues).map(p => p.trim())
  const listed = prefixes
    .filter(p => p !== '*' && p.replace(/\.+$/, ''))
    .map(p => `${p.replace(/\.+$/, '').toLowerCase()}.${root}`)
  const entries = [...listed]
  if (prefixes.some(p => !p.replace(/\.+$/, ''))) entries.push(root)
  if (prefixes.includes('*')) entries.push(`*.${root}`)
  return entries
}

/** recon's host_in_scope: an exact host, `*.suffix` (subdomains, not the apex), or a CIDR. */
function hostInScope(host: string, entries: readonly string[]): boolean {
  return entries.some(entry => {
    if (entry.startsWith('*.')) return host.endsWith(entry.slice(1))
    if (entry.includes('/')) return inIpv4Target(host, entry) === true
    return host === entry
  })
}

/**
 * The hosts the next scan's OpenAPI scope admits. Derived from the target fields
 * being edited, as the project routes derive them on save: the scope groups'
 * hosts (`*.root` for an enumerated group, the listed hosts of an exact one,
 * the root only with Root on) are exactly what recon's scope_payload admits.
 * The stored legacy record only when a batch arrives without its host list.
 */
function scopeEntries(project: DocumentScopeFields): string[] {
  const hosts = strings(project.domainBatchHosts).filter(h => h.trim())
  if (project.domainBatchMode && !hosts.length) {
    const groups = Array.isArray(project.domainBatchGroups) ? project.domainBatchGroups : []
    return groups.flatMap(group => (group && typeof group === 'object'
      ? rootScopeEntries((group as Record<string, unknown>).rootDomain, (group as Record<string, unknown>).prefixes)
      : []))
  }
  return authScopePatterns(resolveScopeGroups({
    domainBatchMode: project.domainBatchMode,
    domainBatchHosts: hosts,
    targetDomain: project.targetDomain,
    subdomainList: strings(project.subdomainList).filter(s => s.trim()),
  }).groups)
}

export type DocumentScopeFields = ProjectTargetFields & {
  targetIps?: unknown
  subdomainList?: unknown
  domainBatchHosts?: unknown
  roeExcludedHosts?: unknown
  ipHostnameMode?: unknown
  ipHostnameInclude?: unknown
  ipHostnameExclude?: unknown
}

/** IP mode: whether the hostname policy could make `host` a scan target. Only
 *  the pattern part: the run also needs every address it resolves to to be a
 *  target, which the form cannot know. An unreadable filter admits nothing. */
function hostnamePolicyMayScan(host: string, project: DocumentScopeFields): boolean {
  if (project.ipHostnameMode === 'scan_all') return true
  if (project.ipHostnameMode !== 'record_filter') return false
  const include = parseEntries(Array.isArray(project.ipHostnameInclude) ? project.ipHostnameInclude : [])
  const exclude = parseEntries(Array.isArray(project.ipHostnameExclude) ? project.ipHostnameExclude : [])
  if (include.invalid.length || exclude.invalid.length) return false
  return matches(host, include.patterns, exclude.patterns).included
}

/**
 * Whether recon will fetch a document URL, as far as the form can tell. It
 * mirrors recon's OpenAPI scope: the target IPs and CIDRs in IP mode (a
 * hostname its policy may scan is null: the run decides, by its DNS); the
 * target's subdomains, or only the listed ones, in domain mode; the hosts a
 * group lists, or its whole domain with "*", in a Domain batch; minus the Rules
 * of Engagement exclusions. null when it cannot tell: an unparseable URL, no
 * target yet, an IPv6 address. Advisory only: recon decides, and the save is
 * never blocked on it.
 */
export function documentInProjectScope(url: string, project: DocumentScopeFields): boolean | null {
  let host: string
  try {
    host = normalizeHost(new URL(url.trim()).hostname)
  } catch {
    return null
  }
  if (!host || host.includes(':')) return null
  if (project.ipMode) {
    if (ipv4ToInt(host) === null) {
      // A hostname is a target only if this run's selection picks it.
      if (isRoeExcluded(host, strings(project.roeExcludedHosts))) return false
      return hostnamePolicyMayScan(host, project) ? null : false
    }
    const verdicts = strings(project.targetIps).map(target => inIpv4Target(host, target))
    if (!verdicts.includes(true)) return verdicts.includes(null) ? null : false
  } else {
    const entries = scopeEntries(project)
    if (!entries.length) return null
    if (!hostInScope(host, entries)) return false
  }
  return !isRoeExcluded(host, strings(project.roeExcludedHosts))
}
