/**
 * Domain batch: turn a flat hostname list into ordered domain groups.
 *
 * This is the ONLY implementation of the grouping rule. The form renders its
 * preview from it and the project routes re-derive `domainBatchGroups` from it
 * server-side, so what the operator approved is literally what the pipeline runs
 * and a crafted `domainBatchGroups` in a request body is never trusted.
 *
 * The rule is deliberately "the last two labels are the domain", NOT a public
 * suffix list: it is the same thing an operator does by hand when filling the
 * single-domain form (target = the domain, everything else = subdomain prefixes),
 * so a batch and a hand-built project scan identically. `foo.example.co.uk`
 * therefore groups under `co.uk`. That is a known, tested consequence, not an
 * oversight - see the tests.
 *
 * Group order is first-appearance order, and it is the RUN order: the operator
 * approves a list in the preview and the pipeline walks it top to bottom.
 */

/** Prefixes are stored with a trailing dot, and "." means the root domain itself,
 *  matching toStoredPrefixes() in ProjectForm/sections/TargetSection.tsx. */
export const ROOT_DOMAIN_PREFIX = '.'

export interface DomainGroup {
  /** The registrable domain, e.g. "domain3.com". */
  rootDomain: string
  /** Stored-form prefixes, e.g. ["sub3.", "suba.sub3."] or ["."] for the bare root. */
  prefixes: string[]
  /** The normalized hostnames that produced this group, in input order. */
  hosts: string[]
}

export interface GroupingResult {
  groups: DomainGroup[]
  /** Entries rejected verbatim as the operator typed them, for the UI to show. */
  invalid: string[]
}

/**
 * Caps on one batch. MAX_BATCH_GROUPS mirrors supplyChainOrgMaxRepos (the org
 * batch's own fan-out cap): without one, a pasted list becomes a single run that
 * holds the project's one scan slot for weeks with no visible end.
 */
export const MAX_BATCH_HOSTS = 500
export const MAX_BATCH_GROUPS = 50

/**
 * Everything a hostname may contain once normalized. This is the choke point for
 * untrusted input: a host reaches a Cypher MERGE, a scan target and (via its
 * group slug) a filename, so anything outside this set is REJECTED rather than
 * sanitized - silently stripping characters would scan a different host than the
 * operator read in the preview.
 */
const HOSTNAME_CHARSET = /^[a-z0-9.-]+$/

/** Strip the things people paste around a hostname: scheme, credentials, path,
 *  query, port, surrounding whitespace and a trailing root dot. */
function normalizeHost(raw: string): string {
  let h = raw.trim().toLowerCase()
  if (!h) return ''
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')  // scheme
  h = h.split('/')[0].split('?')[0].split('#')[0]  // path / query / fragment
  const at = h.lastIndexOf('@')
  if (at !== -1) h = h.slice(at + 1)  // credentials
  h = h.split(':')[0]  // port
  h = h.replace(/\.+$/, '')  // trailing root dot
  return h
}

/** The last two labels. "suba.sub3.domain3.com" -> "domain3.com". */
function rootOf(host: string): string {
  const labels = host.split('.')
  return labels.slice(-2).join('.')
}

function isUsableHost(host: string): boolean {
  if (!host || !HOSTNAME_CHARSET.test(host)) return false
  const labels = host.split('.')
  // A single label is not a scannable target and has no derivable domain.
  if (labels.length < 2) return false
  // No empty labels ("a..b"), no label starting or ending with a hyphen, and a
  // TLD of at least two letters - the same shape REGEX_DOMAIN enforces.
  if (labels.some(l => l.length === 0 || l.length > 63)) return false
  if (labels.some(l => l.startsWith('-') || l.endsWith('-'))) return false
  if (!/^[a-z]{2,}$/.test(labels[labels.length - 1])) return false
  return true
}

/**
 * Group hostnames by their registrable domain, preserving first-appearance order.
 * Duplicates are dropped. Entries that cannot be grouped are returned in
 * `invalid` as the operator typed them, so the UI can point at the offending line.
 */
export function groupHostsByRootDomain(hosts: readonly string[]): GroupingResult {
  const groups: DomainGroup[] = []
  const byRoot = new Map<string, DomainGroup>()
  const invalid: string[] = []
  const seen = new Set<string>()

  for (const raw of hosts) {
    if (typeof raw !== 'string' || !raw.trim()) continue
    const host = normalizeHost(raw)
    if (!isUsableHost(host)) {
      if (!invalid.includes(raw.trim())) invalid.push(raw.trim())
      continue
    }
    if (seen.has(host)) continue
    seen.add(host)

    const rootDomain = rootOf(host)
    let group = byRoot.get(rootDomain)
    if (!group) {
      group = { rootDomain, prefixes: [], hosts: [] }
      byRoot.set(rootDomain, group)
      groups.push(group)
    }
    group.hosts.push(host)

    // The bare root contributes "."; anything deeper contributes its prefix with
    // a trailing dot, which is what parse_target() in recon/main.py expects.
    const prefix = host === rootDomain
      ? ROOT_DOMAIN_PREFIX
      : `${host.slice(0, host.length - rootDomain.length - 1)}.`
    if (!group.prefixes.includes(prefix)) group.prefixes.push(prefix)
  }

  return { groups, invalid }
}

/**
 * Filesystem-safe identifier for a group's per-run output file. The root domain
 * is already charset-filtered by isUsableHost, so this cannot emit a separator or
 * a traversal sequence; the extra guard keeps that true if the caller ever passes
 * an unvalidated string.
 */
export function groupSlug(rootDomain: string): string {
  const slug = rootDomain.toLowerCase()
    .replace(/[^a-z0-9.-]/g, '_')
    .replace(/\.\.+/g, '_')
    .replace(/^[.\-_]+/, '')
    .replace(/[.\-_]+$/, '')
  // A slug of only separators names nothing and would collide across groups.
  return /[a-z0-9]/.test(slug) ? slug : 'group'
}

export interface BatchValidation {
  ok: boolean
  errors: string[]
  groups: DomainGroup[]
  invalid: string[]
}

/**
 * The shared gate for a batch host list: grouping plus the caps. Used by the form
 * before submit and by the project routes before persisting, so the UI and the
 * server can never disagree about what is acceptable.
 */
export function validateDomainBatch(hosts: readonly string[]): BatchValidation {
  const { groups, invalid } = groupHostsByRootDomain(hosts)
  const errors: string[] = []

  const supplied = hosts.filter(h => typeof h === 'string' && h.trim()).length
  if (supplied > MAX_BATCH_HOSTS) {
    errors.push(`Too many hostnames: ${supplied}. The limit is ${MAX_BATCH_HOSTS}.`)
  }
  if (groups.length > MAX_BATCH_GROUPS) {
    errors.push(`Too many domains: ${groups.length}. The limit is ${MAX_BATCH_GROUPS}.`)
  }
  if (invalid.length > 0) {
    errors.push(`Not valid hostnames: ${invalid.slice(0, 5).join(', ')}`
      + (invalid.length > 5 ? ` (+${invalid.length - 5} more)` : ''))
  }
  if (groups.length === 0 && errors.length === 0) {
    errors.push('Domain batch mode needs at least one hostname.')
  }

  return { ok: errors.length === 0, errors, groups, invalid }
}
