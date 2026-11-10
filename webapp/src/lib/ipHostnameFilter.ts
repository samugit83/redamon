/**
 * Hostnames on target IPs: the TypeScript mirror of the selection rule.
 *
 * The rule is `recon_settings/ip_hostnames.py`, the only code that decides what
 * a run scans. The form preview, the preview route and the graph drawer need
 * the same answer without asking Python, so this file mirrors the part that
 * needs no DNS: parsing the include/exclude filters, matching a name, and
 * checks 1-9 of the rule. A name that passes them shows the reason its last run
 * recorded when that reason came from DNS (where it pointed then), else "would
 * scan", with the cap applied in the rule's sorted order. Both sides answer
 * `tests/fixtures/ip_hostname_vectors.json`.
 *
 * Filter entries parse with the Domain-batch rules (`domainBatch.parseEntry`),
 * public-suffix refusals included: the Python rule leaves those to callers that
 * have a PSL, and this is one.
 */
import { normalizeHost, parseEntry, type InvalidEntry } from '@/lib/domainBatch'

export const IP_HOSTNAME_MODES = ['ip_only', 'record_only', 'record_filter', 'scan_all'] as const
export type IpHostnameMode = (typeof IP_HOSTNAME_MODES)[number]

/** ip_only discovers no name: nothing to evaluate, as in the Python rule. */
const EVALUATING_MODES: ReadonlySet<string> = new Set(['record_only', 'record_filter', 'scan_all'])

/** Every reason code, in the rule's check order, in words for the UI. */
export const REASON_TEXT = {
  invalid_name: 'not a valid hostname',
  hard_blocked: 'a protected government or public-institution domain',
  roe_excluded: 'excluded by the rules of engagement',
  record_only: 'recorded only: this mode scans the IPs, not the names',
  invalid_filter: 'a filter entry could not be read, so no name is scanned',
  filter_excluded: 'matches an exclude entry',
  filter_no_match: 'matches no include entry',
  no_registrable_domain: 'no registrable domain (a public suffix or unknown)',
  attribution_unavailable: 'IP attribution did not run or failed for the IP it was seen on',
  shared_edge_ip: 'seen on a shared CDN or hosting edge address',
  dns_disabled: 'DNS lookups are disabled for this project',
  resolver_unavailable: 'the DNS resolver was unavailable',
  no_current_resolution: 'resolves to no address',
  never_scannable_address: 'resolves to a loopback, link-local, multicast or unspecified address',
  resolves_outside_targets: 'points outside your IPs',
  wildcard_zone: 'under a wildcard DNS zone',
  cap_reached: 'over the limit of hostnames scanned per run',
  scanned: 'scanned',
  moved_during_scan: 'moved to an address outside your IPs during the scan',
  out_of_policy: 'no longer in the hostname policy',
} as const satisfies Record<string, string>

export type ReasonCode = keyof typeof REASON_TEXT

/** Reasons that depend on where the name pointed when it was resolved. The
 *  preview cannot know where it points now, so it shows the last run's. */
const LAST_RUN_REASONS: ReadonlySet<string> = new Set<ReasonCode>([
  'dns_disabled', 'resolver_unavailable', 'no_current_resolution', 'never_scannable_address',
  'resolves_outside_targets', 'wildcard_zone', 'moved_during_scan',
])

export interface Pattern {
  host: string
  wildcard: boolean
  /** `*.host` or `host`: the canonical spelling, as stored and reported. */
  token: string
}

export interface ParsedFilter {
  patterns: Pattern[]
  invalid: InvalidEntry[]
}

/** How a refused non-string filter entry is reported (both languages). */
export const NOT_A_STRING = '<not a string>'

/** Parse include/exclude entries: blank lines skipped, a non-string refused
 *  (unlike the Domain batch, which skips it: an unreadable exclude entry must
 *  not widen what is scanned), patterns deduplicated in operator order, each
 *  refused entry reported once. */
export function parseEntries(entries: readonly unknown[]): ParsedFilter {
  const patterns: Pattern[] = []
  const invalid: InvalidEntry[] = []
  const seen = new Set<string>()
  const refuse = (entry: string, reason: InvalidEntry['reason']) => {
    if (!invalid.some(i => i.entry === entry)) invalid.push({ entry, reason })
  }
  for (const raw of entries) {
    if (typeof raw !== 'string') {
      refuse(NOT_A_STRING, 'not_hostname')
      continue
    }
    if (!raw.trim()) continue
    const p = parseEntry(raw)
    if (!p.ok) {
      refuse(raw.trim(), p.reason)
      continue
    }
    const token = p.wildcard ? `*.${p.host}` : p.host
    if (seen.has(token)) continue
    seen.add(token)
    patterns.push({ host: p.host, wildcard: p.wildcard, token })
  }
  return { patterns, invalid }
}

/**
 * The canonical spelling of a hostname, or null when it is not one (check 1).
 * A public suffix is still a hostname here: the rule refuses it later, at
 * check 7, with its own reason.
 */
export function normalizeName(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const host = normalizeHost(raw)
  if (host.includes('*')) return null
  const p = parseEntry(host)
  return p.ok || p.reason === 'public_suffix' ? host : null
}

export interface MatchResult {
  included: boolean
  excluded: boolean
  /** The first deciding entry, in operator order; null when none applies. */
  matchedBy: string | null
}

function hits(p: Pattern, host: string): boolean {
  return p.wildcard ? host.endsWith(`.${p.host}`) : host === p.host
}

/** Exclude wins over include. */
export function matches(name: string, include: readonly Pattern[], exclude: readonly Pattern[]): MatchResult {
  const host = normalizeHost(name)
  const ex = exclude.find(p => hits(p, host))
  if (ex) return { included: false, excluded: true, matchedBy: ex.token }
  const inc = include.find(p => hits(p, host))
  return inc
    ? { included: true, excluded: false, matchedBy: inc.token }
    : { included: false, excluded: false, matchedBy: null }
}

// Addresses, compared as recon_settings/ip_hostnames.py canonical_ip compares
// them: Python's ipaddress parsing rules (strict dotted quads, RFC 4291 IPv6
// text, an optional %scope), RFC 5952 output, and IPv4-mapped written
// `::ffff:a.b.c.d`. Both sides answer the `canonical` vectors.

function ipv4Octets(text: string): number[] | null {
  const octets = text.split('.')
  if (octets.length !== 4) return null
  const out: number[] = []
  for (const o of octets) {
    if (!/^[0-9]{1,3}$/.test(o) || (o.length > 1 && o[0] === '0') || Number(o) > 255) return null
    out.push(Number(o))
  }
  return out
}

function ipv6Hextets(text: string): number[] | null {
  const parts = text.split(':')
  if (parts.length < 3) return null
  if (parts[parts.length - 1].includes('.')) {
    const v4 = ipv4Octets(parts.pop()!)
    if (!v4) return null
    parts.push(((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16))
  }
  if (parts.length > 9) return null
  let skip = -1
  for (let i = 1; i < parts.length - 1; i += 1) {
    if (parts[i]) continue
    if (skip !== -1) return null
    skip = i
  }
  let hi = parts.length
  let lo = 0
  if (skip !== -1) {
    hi = skip
    lo = parts.length - skip - 1
    if (!parts[0] && --hi) return null
    if (!parts[parts.length - 1] && --lo) return null
    if (hi + lo > 7) return null
  } else if (parts.length !== 8) {
    return null
  }
  const given = [...parts.slice(0, hi), ...parts.slice(parts.length - lo)]
  if (!given.every(h => /^[0-9a-fA-F]{1,4}$/.test(h))) return null
  const words = given.map(h => parseInt(h, 16))
  return [...words.slice(0, hi), ...new Array<number>(8 - hi - lo).fill(0), ...words.slice(hi)]
}

/** RFC 5952: the longest run of two or more zero groups (the first on a tie)
 *  becomes `::`. */
function compressHextets(words: number[]): string {
  let best = -1
  let bestLen = 0
  let run = 0
  words.forEach((w, i) => {
    run = w === 0 ? run + 1 : 0
    if (run > bestLen) {
      bestLen = run
      best = i - run + 1
    }
  })
  const hex = words.map(w => w.toString(16))
  if (bestLen < 2) return hex.join(':')
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`
}

/** The one spelling of an address; anything else comes back trimmed, as is. */
export function canonicalIp(value: string): string {
  const text = value.trim()
  if (text.includes('/')) return text
  if (ipv4Octets(text)) return text
  const pct = text.indexOf('%')
  const scope = pct === -1 ? '' : text.slice(pct + 1)
  if (pct !== -1 && (!scope || scope.includes('%'))) return text
  const words = ipv6Hextets(pct === -1 ? text : text.slice(0, pct))
  if (!words) return text
  const suffix = scope ? `%${scope}` : ''
  if (words.slice(0, 5).every(w => w === 0) && words[5] === 0xffff) {
    return `::ffff:${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}${suffix}`
  }
  return compressHextets(words) + suffix
}

export interface PreviewCandidate {
  name: string
  /** Target IPs the name was seen on; none yet for a passive-expansion name. */
  ipsSeen?: readonly string[]
  /** Registrable domain from the PSL; null when the name is a public suffix. */
  orgDomain?: string | null
  /** The reason the last run recorded for this name, if any. */
  lastReason?: string | null
}

/**
 * Every input that is missing or unreadable refuses names, never admits them
 * (I-6), exactly as in the Python rule.
 */
export interface PreviewOptions {
  mode: string
  /** null (unknown) is invalid_filter in record_filter. */
  include: readonly unknown[] | null
  exclude: readonly unknown[] | null
  cap: number
  /** null when IP attribution did not run: scan_all then refuses every name. */
  sharedEdge: ReadonlySet<string> | null
  /** Target IPs whose attribution failed; null when unknown, which scan_all
   *  also refuses (never read as "none failed"). */
  attributionFailed: ReadonlySet<string> | null
  /** Names the last run's wildcard DNS control dropped; an empty set when
   *  expansion did not run, null when unknown (record_filter then refuses). */
  wildcardZone: ReadonlySet<string> | null
  /** Strict predicates: only `false` lets a name through; any other value or
   *  a throw refuses it. */
  hardBlocked: (name: string) => boolean
  roeExcluded: (name: string) => boolean
}

export interface PreviewResult {
  /** Names that would be scanned (DNS permitting), sorted. */
  selected: string[]
  reasons: Record<string, ReasonCode>
}

/** Canonical addresses, or null (unknown) when any entry is not a string; a
 *  single string is one address, never its characters. As in the rule. */
function addressSet(values: unknown): Set<string> | null {
  if (values === null || values === undefined) return null
  const list = typeof values === 'string' ? [values] : [...(values as Iterable<unknown>)]
  if (!list.every(v => typeof v === 'string')) return null
  return new Set((list as string[]).map(canonicalIp))
}

function passes(check: (name: string) => unknown, name: string): boolean {
  try {
    return check(name) === false
  } catch {
    return false
  }
}

/** Checks 1-9 of the rule, in its order. */
function beforeDns(
  c: PreviewCandidate, opts: PreviewOptions, include: ParsedFilter | null, exclude: ParsedFilter | null,
): ReasonCode | null {
  if (normalizeName(c.name) !== c.name) return 'invalid_name'
  if (!passes(opts.hardBlocked, c.name)) return 'hard_blocked'
  if (!passes(opts.roeExcluded, c.name)) return 'roe_excluded'
  if (opts.mode === 'record_only') return 'record_only'
  if (opts.mode === 'record_filter') {
    if (!include || !exclude || include.invalid.length || exclude.invalid.length) return 'invalid_filter'
    const m = matches(c.name, include.patterns, exclude.patterns)
    if (m.excluded) return 'filter_excluded'
    if (!m.included) return 'filter_no_match'
  }
  if (typeof c.orgDomain !== 'string' || !c.orgDomain) return 'no_registrable_domain'
  if (opts.mode === 'scan_all') {
    // A name seen on no target IP cannot be attributed to one.
    const seen = [...(addressSet(c.ipsSeen) ?? [])]
    const failed = addressSet(opts.attributionFailed)
    const edge = addressSet(opts.sharedEdge)
    if (!edge || !failed || !seen.length || seen.some(a => failed.has(a))) return 'attribution_unavailable'
    if (seen.some(a => edge.has(a))) return 'shared_edge_ip'
  }
  return null
}

function lastRunReason(c: PreviewCandidate, mode: string): ReasonCode | null {
  const last = c.lastReason
  if (!last || !LAST_RUN_REASONS.has(last)) return null
  // Wildcard DNS control runs only in record_filter (check 15).
  if (last === 'wildcard_zone' && mode !== 'record_filter') return null
  return last as ReasonCode
}

/**
 * What a run would do with the names found last time, under this policy.
 * Throws for a mode that evaluates nothing (ip_only, or not a mode at all).
 */
export function evaluatePreview(candidates: readonly PreviewCandidate[], opts: PreviewOptions): PreviewResult {
  if (!EVALUATING_MODES.has(opts.mode)) {
    throw new Error(`evaluatePreview needs a recording mode, got ${JSON.stringify(opts.mode)}`)
  }
  const include = opts.include === null ? null : parseEntries(opts.include)
  const exclude = opts.exclude === null ? null : parseEntries(opts.exclude)
  const zone: unknown = opts.wildcardZone
  const wildcard = opts.mode !== 'record_filter' ? new Set<string>()
    : typeof zone === 'string' ? new Set([zone]) : opts.wildcardZone
  const byName = new Map(candidates.map(c => [c.name, c]))
  const reasons: Record<string, ReasonCode> = {}
  const passing: string[] = []
  // Same order as the rule (Python sorts by code point; names are ASCII).
  for (const name of [...byName.keys()].sort()) {
    const c = byName.get(name)!
    // Check 15 after the last run's DNS reasons, as in the rule.
    const reason = beforeDns(c, opts, include, exclude) ?? lastRunReason(c, opts.mode)
      ?? (wildcard === null || wildcard.has(name) ? 'wildcard_zone' : null)
    if (reason) reasons[name] = reason
    else passing.push(name)
  }
  // A finite number, truncated; anything else scans nothing, as in the rule.
  const cap = typeof opts.cap === 'number' && Number.isFinite(opts.cap) ? Math.max(Math.trunc(opts.cap), 0) : 0
  const selected = passing.slice(0, cap)
  for (const name of selected) reasons[name] = 'scanned'
  for (const name of passing.slice(cap)) reasons[name] = 'cap_reached'
  return { selected, reasons }
}
