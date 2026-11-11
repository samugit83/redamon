/**
 * A project's scope as scope groups, derived on every read and never stored.
 *
 * The one source of truth is the stored target fields: domainBatchHosts for a
 * Domain batch, targetDomain + subdomainList for a single domain (a batch with
 * one group). The stored domainBatchGroups is a legacy record for not-yet-
 * migrated readers and is never read here. GET /api/projects/[id] returns the
 * result as `scopeGroups`, so every service reads one derivation.
 */
import {
  type InvalidEntry, type ScopeGroup, describeInvalid, groupHostsByScanRoot, isAtOrUnder, normalizeHost,
  splitWildcard,
} from '@/lib/domainBatch'
import { icannRegistrable, isIpLiteral, orgDomain } from '@/lib/publicSuffix'
import { firstHardBlocked } from '@/lib/hard-guardrail'
import { IP_HOSTNAME_MODES, type IpHostnameMode, type Pattern, parseEntries } from '@/lib/ipHostnameFilter'

export type { ScopeGroup } from '@/lib/domainBatch'

/**
 * Which name the graph's Domain node carries: the org (registrable domain).
 * A deeper scan root is a Subdomain of it (`is_scan_root`) when it is a target.
 */
export const GRAPH_DOMAIN_IS_ORG = true

/** The scope fields of a project row or a create/update body. */
export interface ScopeFields extends IpHostnamePolicyFields {
  ipMode?: boolean | null
  domainBatchMode?: boolean | null
  domainBatchHosts?: readonly string[] | null
  targetDomain?: string | null
  subdomainList?: readonly string[] | null
}

/**
 * "Hostnames on target IPs": what an IP-mode project does with the names it sees
 * on its addresses. Part of the scope (a policy edit is a scope change), ignored
 * outside IP mode. The rule that applies it is recon_settings/ip_hostnames.py.
 */
export interface IpHostnamePolicyFields {
  ipHostnameMode?: string | null
  ipHostnameInclude?: readonly string[] | null
  ipHostnameExclude?: readonly string[] | null
  ipHostnamePassiveExpand?: boolean | null
  ipHostnameScanAllConfirmed?: boolean | null
  ipHostnameMaxScanned?: number | null
  ipHostnamePassiveMaxNames?: number | null
  engagementKind?: string | null
}

export const IP_HOSTNAME_FIELDS = [
  'ipHostnameMode', 'ipHostnameInclude', 'ipHostnameExclude', 'ipHostnamePassiveExpand',
  'ipHostnameScanAllConfirmed', 'ipHostnameMaxScanned', 'ipHostnamePassiveMaxNames',
] as const
export type IpHostnameField = (typeof IP_HOSTNAME_FIELDS)[number]

/** The Prisma defaults (pinned to the registry by scopeGroups.ipHostnames.test.ts). */
export const IP_HOSTNAME_DEFAULTS = {
  ipHostnameMode: 'ip_only',
  ipHostnameInclude: [] as string[],
  ipHostnameExclude: [] as string[],
  ipHostnamePassiveExpand: true,
  ipHostnameScanAllConfirmed: false,
  ipHostnameMaxScanned: 100,
  ipHostnamePassiveMaxNames: 500,
} as const satisfies Record<IpHostnameField, unknown>

/** Prisma `select` for the policy columns. A start path or a view that judges or
 *  reports the policy loads all of them: a column left out reads as its default,
 *  which would let an unconfirmed scan_all start. */
export const IP_HOSTNAME_SELECT = {
  ipHostnameMode: true, ipHostnameInclude: true, ipHostnameExclude: true, ipHostnamePassiveExpand: true,
  ipHostnameScanAllConfirmed: true, ipHostnameMaxScanned: true, ipHostnamePassiveMaxNames: true,
} as const satisfies Record<IpHostnameField, true>

/** Decision D-05: a filter list is stored on the Project row, so it is bounded. */
export const IP_HOSTNAME_MAX_ENTRIES = 200

/** The registry bounds of the two caps (registry.yaml), repeated for a rule that
 *  must judge rows no registry validator saw (an import, a stored row). */
const IP_HOSTNAME_CAP_BOUNDS = {
  ipHostnameMaxScanned: [1, 2000],
  ipHostnamePassiveMaxNames: [1, 10000],
} as const

export interface ResolvedScope {
  groups: ScopeGroup[]
  invalid: InvalidEntry[]
}

/** A single-domain project as one group (§4.4). The target may be at any depth,
 *  never a public suffix or an IP; prefixes may have several labels. */
function singleDomainScope(targetDomain: string, subdomainList: readonly string[]): ResolvedScope {
  const typed = String(targetDomain ?? '').trim()
  if (!typed) return { groups: [], invalid: [] }
  const target = splitWildcard(normalizeHost(typed)).rest
  if (isIpLiteral(target)) return { groups: [], invalid: [{ entry: typed, reason: 'ip_literal' }] }
  const org = orgDomain(target)
  if (!org) return { groups: [], invalid: [{ entry: typed, reason: 'public_suffix' }] }

  const invalid: InvalidEntry[] = []
  const prefixes: string[] = []
  let includeRoot = false
  for (const raw of subdomainList ?? []) {
    const p = String(raw ?? '').trim().toLowerCase()
    if (!p) continue
    if (p === '.') { includeRoot = true; continue }
    const clean = p.replace(/\.+$/, '')
    const host = `${clean}.${target}`
    const bad = !clean || clean.includes('*') || clean.split('.').some(l => !l)
      || clean === target || clean.endsWith(`.${target}`)
      || !/^[a-z0-9.-]+$/.test(clean) || clean.split('.').some(l => l.length > 63 || l.startsWith('-') || l.endsWith('-'))
      || host.length > 253
    if (bad) { invalid.push({ entry: String(raw), reason: 'invalid_prefix' }); continue }
    if (!prefixes.includes(clean)) prefixes.push(clean)
  }

  const exactHosts = prefixes.map(p => `${p}.${target}`)
  return {
    groups: [{
      scanRoot: target, orgDomain: org,
      mode: exactHosts.length > 0 ? 'exact' : 'enumerate',
      includeRoot, exactHosts,
      entries: [
        ...(exactHosts.length > 0 ? [] : [`*.${target}`]),
        ...(includeRoot ? [target] : []),
        ...exactHosts,
      ],
      notes: [],
    }],
    invalid,
  }
}

/** The project's scope groups and the entries the current rules refuse. */
export function resolveScopeGroups(project: ScopeFields): ResolvedScope {
  if (project.ipMode) return { groups: [], invalid: [] }
  if (project.domainBatchMode) {
    const { groups, invalid } = groupHostsByScanRoot(project.domainBatchHosts ?? [])
    return { groups, invalid }
  }
  return singleDomainScope(project.targetDomain ?? '', project.subdomainList ?? [])
}

function dedupe(names: Iterable<string>): string[] {
  const out: string[] = []
  for (const n of names) if (n && !out.includes(n)) out.push(n)
  return out
}

/**
 * Every name the hard guardrail checks (§4.7): each entry (wildcard marker
 * stripped, collapsed ones included), each exact host, each scan root and each
 * org. Entries first, so a refusal names the line the operator typed.
 */
export function guardrailNames(groups: readonly ScopeGroup[]): string[] {
  return dedupe([
    ...groups.flatMap(g => g.entries.map(e => splitWildcard(e).rest)),
    ...groups.flatMap(g => g.exactHosts),
    ...groups.map(g => g.scanRoot),
    ...groups.map(g => g.orgDomain),
  ])
}

/** The hard-guardrail names of a project row or body, whatever its mode. An
 *  entry the rules refuse is named too: refused for a reason does not mean
 *  it may skip the one check that cannot be switched off. */
export function scopeGuardrailNames(scope: ScopeFields): string[] {
  if (scope.ipMode) return ipHostnameIncludeBases(scope.ipHostnameInclude)
  if (!scope.domainBatchMode) {
    // From the fields, not the groups: a target refused as a public suffix
    // (org.jm) still names its prefix hosts (isa.org.jm).
    const target = splitWildcard(normalizeHost(scope.targetDomain ?? '')).rest
    if (!target) return []
    return dedupe([target, ...(scope.subdomainList ?? []).map(raw => {
      const prefix = String(raw ?? '').trim().toLowerCase().replace(/\.+$/, '')
      return prefix && !prefix.includes('*') ? `${prefix}.${target}` : ''
    })])
  }
  const { groups, invalid } = resolveScopeGroups(scope)
  return dedupe([
    ...guardrailNames(groups),
    ...invalid.map(i => splitWildcard(normalizeHost(i.entry)).rest),
  ])
}

/**
 * The names the soft (LLM) guardrail judges: orgs and scan roots, plus the ICANN
 * registrable domain of a private-section org (`alice.github.io` -> also
 * `github.io`), so the model sees the platform owner. The agent has no PSL.
 */
export function softGuardrailNames(groups: readonly ScopeGroup[]): string[] {
  const names: string[] = []
  for (const g of groups) {
    names.push(g.orgDomain, g.scanRoot)
    const icann = icannRegistrable(g.orgDomain)
    if (icann && icann !== g.orgDomain) names.push(icann)
  }
  return dedupe(names)
}

/**
 * Where an authenticated session may send its headers (§4.6): `*.<root>` (strict
 * subdomains) for an ENUMERATE group, the exact hosts for an EXACT one, and the
 * scan root itself only when it is a target.
 */
export function authScopePatterns(groups: readonly ScopeGroup[]): string[] {
  const out: string[] = []
  for (const g of groups) {
    if (g.mode === 'enumerate') out.push(`*.${g.scanRoot}`)
    else out.push(...g.exactHosts)
    if (g.includeRoot) out.push(g.scanRoot)
  }
  return dedupe(out)
}

/** The default scope of a traffic recording: the same hosts as the auth scope. */
export function recordingScope(groups: readonly ScopeGroup[]): string[] {
  return authScopePatterns(groups)
}

/**
 * The canonical scope, for EQUALITY only ("did the scope change"): a regroup of
 * the same hosts, a reordering, or a legacy stored row re-derived, gives the
 * same set. A seed under an ENUMERATE root is not part of it: the root already
 * admits it.
 */
export function scopeSignature(groups: readonly ScopeGroup[]): Set<string> {
  const sig = new Set<string>()
  for (const g of groups) {
    if (g.mode === 'enumerate') sig.add(`enum|${g.scanRoot}`)
    else for (const h of g.exactHosts) sig.add(`exact|${h}`)
    if (g.includeRoot) sig.add(`root|${g.scanRoot}`)
  }
  return sig
}

export function sameScope(a: readonly ScopeGroup[], b: readonly ScopeGroup[]): boolean {
  const x = scopeSignature(a)
  const y = scopeSignature(b)
  return x.size === y.size && [...x].every(s => y.has(s))
}

/** Whether this scope admits `host` (§4.6 scan targets: strict subdomains of an
 *  ENUMERATE root, an EXACT group's hosts, a scan root only with Root on). */
export function admitsHost(groups: readonly ScopeGroup[], host: string): boolean {
  return groups.some(g =>
    (g.includeRoot && host === g.scanRoot)
    || g.exactHosts.includes(host)
    || (g.mode === 'enumerate' && host.endsWith(`.${g.scanRoot}`)))
}

/**
 * True when `next` admits a host `old` did not (D-21, containment): an exact host
 * not covered, an ENUMERATE root neither equal to nor strictly under an old one,
 * or a newly included scan root. A narrowing (`*.example.com` ->
 * `*.api.example.com`) or a regroup is not a widening.
 */
export function isScopeWidening(old: readonly ScopeGroup[], next: readonly ScopeGroup[]): boolean {
  const oldEnumRoots = old.filter(g => g.mode === 'enumerate').map(g => g.scanRoot)
  for (const g of next) {
    if (g.mode === 'enumerate'
        && !oldEnumRoots.some(r => isAtOrUnder(g.scanRoot, r))) return true
    if (g.includeRoot && !admitsHost(old, g.scanRoot)) return true
    if (g.mode === 'exact' && g.exactHosts.some(h => !admitsHost(old, h))) return true
  }
  return false
}

/** The names the graph's Domain nodes should carry for this scope (D-18). */
export function expectedDomainNames(groups: readonly ScopeGroup[]): string[] {
  return dedupe(groups.map(g => (GRAPH_DOMAIN_IS_ORG ? g.orgDomain : g.scanRoot).toLowerCase()))
}

/** One group as one short line: `*.api.example.com (enumerated, +root)` or
 *  `example.com: www, shop (listed)`. */
export function groupLabel(g: ScopeGroup): string {
  if (g.mode === 'enumerate') {
    return `*.${g.scanRoot} (enumerated${g.includeRoot ? ', +root' : ''}${g.exactHosts.length ? `, ${g.exactHosts.length} seeded` : ''})`
  }
  const shown = g.exactHosts.slice(0, 3).map(h => h.slice(0, h.length - g.scanRoot.length - 1))
  const more = g.exactHosts.length > 3 ? ` +${g.exactHosts.length - 3}` : ''
  const listed = [...(g.includeRoot ? [g.scanRoot] : []), ...shown].join(', ')
  return `${g.scanRoot}: ${listed}${more} (listed)`
}

/** The whole scope as one line, for cards, headers and the report cover. */
export function scopeSummary(groups: readonly ScopeGroup[]): string {
  if (groups.length === 0) return ''
  if (groups.length === 1) return groupLabel(groups[0])
  const orgs = new Set(groups.map(g => g.orgDomain)).size
  const enumerated = groups.filter(g => g.mode === 'enumerate').length
  return `${groups.length} scope groups across ${orgs} domain${orgs === 1 ? '' : 's'}`
    + (enumerated ? ` (${enumerated} enumerated)` : '')
}

/**
 * Why a scan of this saved scope cannot start, or null. A row saved under older
 * rules can hold entries the current ones refuse. A headless start (a schedule,
 * the queue), re-enabling a schedule and the schedule badge all ask this one
 * question, so they agree on when a schedule is paused for its scope.
 */
export function scopeStartProblem(project: ScopeFields): { invalid: InvalidEntry[]; message: string } | null {
  if (project.ipMode) {
    const message = ipHostnameStartProblem(project)
    return message ? { invalid: [], message } : null
  }
  const { groups, invalid } = resolveScopeGroups(project)
  if (invalid.length > 0) {
    return { invalid, message: `The saved scope is no longer valid. ${describeInvalid(invalid)}.` }
  }
  if (project.domainBatchMode && groups.length === 0) {
    return { invalid, message: 'Project has no valid domain groups. Re-save its hostname list before scanning.' }
  }
  return null
}

// ---------------------------------------------------------------------------
// Hostnames on target IPs (design §9): validation, start checks, widening and
// narrowing. Pure, so the form, the routes and the MCP tools ask one question.
// ---------------------------------------------------------------------------

/** The mode a run reads: anything but a known mode is ip_only, as in recon. */
export function ipHostnameModeOf(raw: unknown): IpHostnameMode {
  return (IP_HOSTNAME_MODES as readonly unknown[]).includes(raw) ? raw as IpHostnameMode : 'ip_only'
}

/** The base name of each include entry (`*.x` and `x` both give x), for the hard
 *  guardrail. A refused entry is named too, as for a batch. */
export function ipHostnameIncludeBases(include: readonly unknown[] | null | undefined): string[] {
  if (!Array.isArray(include)) return []
  return dedupe(include.map(e => (typeof e === 'string' ? splitWildcard(normalizeHost(e)).rest : '')))
}

/**
 * The first problem with a project's hostname policy, or null. Judged on the
 * EFFECTIVE row (the stored row with the change applied) by every write path,
 * through reconSettings/crossField.ts; recon re-validates at load.
 *
 * Outside IP mode the policy must stay at its defaults: it scans nothing there,
 * and a value accepted now would start applying silently after a mode flip.
 */
export function ipHostnamePolicyProblem(row: ScopeFields): string | null {
  const mode = row.ipHostnameMode ?? IP_HOSTNAME_DEFAULTS.ipHostnameMode
  if (typeof mode !== 'string' || !(IP_HOSTNAME_MODES as readonly string[]).includes(mode)) {
    return `ipHostnameMode must be one of ${IP_HOSTNAME_MODES.join(', ')}`
  }
  const include: readonly unknown[] = row.ipHostnameInclude ?? []
  const exclude: readonly unknown[] = row.ipHostnameExclude ?? []
  for (const [key, list] of [['ipHostnameInclude', include], ['ipHostnameExclude', exclude]] as const) {
    if (!Array.isArray(list)) return `${key} must be a list of hostnames`
    if (list.length > IP_HOSTNAME_MAX_ENTRIES) return `${key} has more than ${IP_HOSTNAME_MAX_ENTRIES} entries`
  }
  for (const [key, [low, high]] of Object.entries(IP_HOSTNAME_CAP_BOUNDS)) {
    const value: unknown = row[key as keyof typeof IP_HOSTNAME_CAP_BOUNDS]
    if (value != null && (typeof value !== 'number' || !Number.isInteger(value) || value < low || value > high)) {
      return `${key} must be a whole number between ${low} and ${high}`
    }
  }
  if (!row.ipMode) {
    const set = mode !== 'ip_only' || include.length > 0 || exclude.length > 0
      || row.ipHostnameScanAllConfirmed === true
    return set
      ? 'The hostname policy (ipHostnameMode, its filters and its confirmation) applies only to ' +
        'IP-mode projects: leave it at ip_only with empty lists.'
      : null
  }
  const inc = parseEntries(include)
  if (inc.invalid.length > 0) return `ipHostnameInclude: ${describeInvalid(inc.invalid)}`
  const exc = parseEntries(exclude)
  if (exc.invalid.length > 0) return `ipHostnameExclude: ${describeInvalid(exc.invalid)}`
  const blocked = firstHardBlocked(inc.patterns.map(p => p.host))
  if (blocked) return `Target permanently blocked: ${blocked.name}: ${blocked.reason}`
  if (mode === 'record_filter' && inc.patterns.length === 0) {
    return 'ipHostnameMode record_filter needs at least one ipHostnameInclude entry (for example *.example.com).'
  }
  if (mode === 'scan_all' && row.engagementKind === 'third_party') {
    return 'ipHostnameMode scan_all is refused on a third_party engagement: an authorization for ' +
      'addresses does not cover every name hosted on them. Use record_filter with the names the client owns.'
  }
  if (mode === 'scan_all' && row.ipHostnameScanAllConfirmed !== true) {
    return 'ipHostnameMode scan_all needs ipHostnameScanAllConfirmed: true, the confirmation that every ' +
      'hostname found on these IPs may be scanned.'
  }
  return null
}

/**
 * The policy as it is stored, applied in place to a row ipHostnamePolicyProblem
 * accepted: include/exclude as canonical tokens (`*.x` or `x`, lower case,
 * deduplicated), and the scan_all confirmation reset whenever the mode is not
 * scan_all, so a return to scan_all always asks for it again. Returns the
 * fields it changed, which the caller must write too.
 */
export function normalizeIpHostnamePolicy(row: Record<string, unknown>): IpHostnameField[] {
  const changed: IpHostnameField[] = []
  for (const key of ['ipHostnameInclude', 'ipHostnameExclude'] as const) {
    const list = row[key]
    if (!Array.isArray(list)) continue
    const tokens = parseEntries(list).patterns.map(p => p.token)
    if (JSON.stringify(tokens) !== JSON.stringify(list)) {
      row[key] = tokens
      changed.push(key)
    }
  }
  if (row.ipHostnameScanAllConfirmed === true && ipHostnameModeOf(row.ipHostnameMode) !== 'scan_all') {
    row.ipHostnameScanAllConfirmed = false
    changed.push('ipHostnameScanAllConfirmed')
  }
  return changed
}

/** Why an IP-mode project's hostname policy cannot start a run, or null. Every
 *  start path asks it through scopeStartProblem, so a schedule or a queued job
 *  is refused for the same reasons recon would refuse the run. */
export function ipHostnameStartProblem(project: ScopeFields): string | null {
  const mode = ipHostnameModeOf(project.ipHostnameMode)
  if (mode === 'scan_all' && project.engagementKind === 'third_party') {
    return 'Hostnames on target IPs is "Record + scan all", which is refused on a third-party ' +
      'engagement. Choose another hostname mode before scanning.'
  }
  if (mode === 'scan_all' && project.ipHostnameScanAllConfirmed !== true) {
    return 'Hostnames on target IPs is "Record + scan all" but it is not confirmed. Confirm it, or ' +
      'choose another hostname mode, before scanning.'
  }
  if (mode === 'record_filter' && parseEntries(project.ipHostnameInclude ?? []).patterns.length === 0) {
    return 'Hostnames on target IPs is "Record + scan matching" with no include entry. Add one ' +
      '(for example *.example.com), or choose another hostname mode, before scanning.'
  }
  return null
}

/** How far a mode reaches with names: ip_only and record_only scan none. */
const SCAN_REACH: Readonly<Record<IpHostnameMode, number>> = {
  ip_only: 0, record_only: 0, record_filter: 1, scan_all: 2,
}

interface Policy {
  mode: IpHostnameMode
  include: Pattern[]
  exclude: Pattern[]
  passiveExpand: boolean
  maxScanned: number
  passiveMaxNames: number
}

function policyOf(row: ScopeFields): Policy {
  const num = (v: unknown, d: number) => (typeof v === 'number' && Number.isFinite(v) ? v : d)
  return {
    mode: row.ipMode ? ipHostnameModeOf(row.ipHostnameMode ?? IP_HOSTNAME_DEFAULTS.ipHostnameMode) : 'ip_only',
    include: parseEntries(row.ipHostnameInclude ?? []).patterns,
    exclude: parseEntries(row.ipHostnameExclude ?? []).patterns,
    passiveExpand: row.ipHostnamePassiveExpand !== false,
    maxScanned: num(row.ipHostnameMaxScanned, IP_HOSTNAME_DEFAULTS.ipHostnameMaxScanned),
    passiveMaxNames: num(row.ipHostnamePassiveMaxNames, IP_HOSTNAME_DEFAULTS.ipHostnamePassiveMaxNames),
  }
}

/** Does pattern `q` admit every name pattern `p` admits? */
function covers(q: Pattern, p: Pattern): boolean {
  return q.token === p.token || (q.wildcard && p.host.endsWith(`.${q.host}`))
}

const tokenSet = (ps: readonly Pattern[]) => ps.map(p => p.token).sort().join('\n')

/** Whether any of the seven policy fields differs, lists compared as canonical
 *  token sets, so a re-save of the same policy in another spelling is no change. */
export function ipHostnamePolicyChanged(before: ScopeFields, after: ScopeFields): boolean {
  const b = policyOf({ ...before, ipMode: true })
  const a = policyOf({ ...after, ipMode: true })
  return a.mode !== b.mode || tokenSet(a.include) !== tokenSet(b.include)
    || tokenSet(a.exclude) !== tokenSet(b.exclude) || a.passiveExpand !== b.passiveExpand
    || a.maxScanned !== b.maxScanned || a.passiveMaxNames !== b.passiveMaxNames
    || (after.ipHostnameScanAllConfirmed === true) !== (before.ipHostnameScanAllConfirmed === true)
}

/**
 * What `after` may scan that `before` did not (design §9 "Widening"), one short
 * phrase each; [] when nothing widens. ip_only -> record_only is no widening: it
 * adds lookups about names, never traffic to a new target. A list or cap change
 * counts only where the mode on both sides scans by it.
 */
export function ipHostnameWidenings(before: ScopeFields, after: ScopeFields): string[] {
  const b = policyOf(before)
  const a = policyOf(after)
  const out: string[] = []
  if (SCAN_REACH[a.mode] > SCAN_REACH[b.mode]) out.push(`hostname mode ${b.mode} -> ${a.mode}`)
  if (a.mode === 'record_filter' && b.mode === 'record_filter') {
    for (const p of a.include) if (!b.include.some(q => covers(q, p))) out.push(`hostname include entry added: ${p.token}`)
    for (const e of b.exclude) if (!a.exclude.some(q => covers(q, e))) out.push(`hostname exclude entry removed: ${e.token}`)
    if (a.passiveExpand && !b.passiveExpand) out.push('passive search of the include domains turned on')
    if (a.passiveExpand && b.passiveExpand && a.passiveMaxNames > b.passiveMaxNames) {
      out.push(`ipHostnamePassiveMaxNames raised ${b.passiveMaxNames} -> ${a.passiveMaxNames}`)
    }
  }
  if (SCAN_REACH[a.mode] > 0 && SCAN_REACH[b.mode] > 0 && a.maxScanned > b.maxScanned) {
    out.push(`ipHostnameMaxScanned raised ${b.maxScanned} -> ${a.maxScanned}`)
  }
  return out
}

/**
 * True when `after` may no longer admit a name `before` scanned (design §6.3):
 * the mode loses reach (leaving IP mode included), an include entry is removed,
 * an exclude entry is added, or the scan cap is lowered. It decides when the
 * out_of_policy marker runs; one change can widen and narrow at once.
 */
export function ipHostnamePolicyNarrowed(before: ScopeFields, after: ScopeFields): boolean {
  const b = policyOf(before)
  if (SCAN_REACH[b.mode] === 0) return false
  const a = policyOf(after)
  if (SCAN_REACH[a.mode] < SCAN_REACH[b.mode]) return true
  if (a.mode === 'record_filter') {
    if (b.mode === 'record_filter' && b.include.some(p => !a.include.some(q => covers(q, p)))) return true
    if (a.exclude.some(e => !b.exclude.some(q => covers(q, e)))) return true
  }
  return a.maxScanned < b.maxScanned
}

/** The policy as preflight_scope_check and the project views report it. */
export function ipHostnamePolicySummary(row: ScopeFields) {
  return {
    ipHostnameMode: ipHostnameModeOf(row.ipHostnameMode),
    include: [...(row.ipHostnameInclude ?? [])],
    exclude: [...(row.ipHostnameExclude ?? [])],
    passiveExpand: row.ipHostnamePassiveExpand !== false,
    scanAllConfirmed: row.ipHostnameScanAllConfirmed === true,
    maxScanned: row.ipHostnameMaxScanned ?? IP_HOSTNAME_DEFAULTS.ipHostnameMaxScanned,
    passiveMaxNames: row.ipHostnamePassiveMaxNames ?? IP_HOSTNAME_DEFAULTS.ipHostnamePassiveMaxNames,
  }
}
