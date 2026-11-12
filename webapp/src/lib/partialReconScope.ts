/**
 * Partial recon: which scan roots a partial run is offered.
 *
 * The roots are the project's scope-group scan roots (resolveScopeGroups). The
 * orchestrator is the authority on scope: partial_project_roots() in
 * recon_orchestrator/batch_scope.py re-derives the roots from the project row
 * and refuses anything else. This is a mirror of it, used only to decide what
 * the modal shows and sends.
 */
import { GRAPH_DOMAIN_IS_ORG, type ScopeGroup, admitsHost, ipHostnameModeOf, resolveScopeGroups } from '@/lib/scopeGroups'
import { type IpHostnameMode, matches, normalizeName, parseEntries } from '@/lib/ipHostnameFilter'
import { ipHostnameModeLabel } from '@/lib/ipHostnameModeLabels'
import { isHardBlockedDomain } from '@/lib/hard-guardrail'

const ROOT_CHARSET = /^[a-z0-9.-]+$/

export type PartialScopeMode = 'ip' | 'batch' | 'single'

export interface ProjectTargetFields {
  ipMode?: boolean | null
  targetDomain?: string | null
  subdomainList?: readonly string[] | null
  domainBatchMode?: boolean | null
  domainBatchHosts?: readonly string[] | null
  /** The legacy stored record: read only when the caller did not select the
   *  host list, so a reader not yet migrated keeps working. */
  domainBatchGroups?: unknown
}

export interface ProjectRoots {
  mode: PartialScopeMode
  /** Every scan root the project scans, in project order. */
  roots: string[]
  /** The scan roots whose group ENUMERATES, in any mode. An EXACT group, single
   *  domain included, never runs subdomain discovery. */
  wildcardRoots: string[]
  /** The scope groups, when derivable from the stored target fields; empty in
   *  IP mode and on the legacy fallback. */
  groups: ScopeGroup[]
}

/** The name recon/main.py mints for IP mode's synthetic Domain node. */
export function ipModeRoot(projectId: string): string {
  return `ip-targets.${projectId}`
}

function usableRoot(root: string): boolean {
  // Checked lowercased but kept as stored: a single-domain target is saved
  // trimmed, not lowercased, and its Domain node carries exactly that name.
  const low = root.trim().toLowerCase()
  return low.length > 0 && ROOT_CHARSET.test(low) && !low.includes('..')
}

export function resolveProjectRoots(project: ProjectTargetFields, projectId: string): ProjectRoots {
  if (project.ipMode) {
    const root = ipModeRoot(projectId)
    return { mode: 'ip', roots: usableRoot(root) ? [root] : [], wildcardRoots: [], groups: [] }
  }
  const derivable = project.domainBatchMode ? project.domainBatchHosts != null : project.subdomainList != null
  if (derivable) {
    const { groups } = resolveScopeGroups(project)
    const enumerating = groups.filter(g => g.mode === 'enumerate').map(g => g.scanRoot)
    if (project.domainBatchMode) {
      const roots = groups.map(g => g.scanRoot).filter(usableRoot)
      return { mode: 'batch', roots, wildcardRoots: enumerating, groups }
    }
    // The stored spelling, as the orchestrator returns it: a legacy single-domain
    // Domain node carries the target exactly as it was typed.
    const target = String(project.targetDomain ?? '').trim()
    const roots = usableRoot(target) && groups.length ? [target] : []
    return { mode: 'single', roots, wildcardRoots: roots.length ? enumerating : [], groups }
  }
  if (project.domainBatchMode) {
    const roots: string[] = []
    const wildcardRoots: string[] = []
    const groups = Array.isArray(project.domainBatchGroups) ? project.domainBatchGroups : []
    for (const group of groups) {
      if (!group || typeof group !== 'object') continue
      const { rootDomain, prefixes } = group as { rootDomain?: unknown; prefixes?: unknown }
      const root = String(rootDomain ?? '').trim().toLowerCase()
      if (!usableRoot(root)) continue
      if (!roots.includes(root)) roots.push(root)
      if (Array.isArray(prefixes) && prefixes.includes('*') && !wildcardRoots.includes(root)) {
        wildcardRoots.push(root)
      }
    }
    return { mode: 'batch', roots, wildcardRoots, groups: [] }
  }
  const target = String(project.targetDomain ?? '').trim()
  return { mode: 'single', roots: usableRoot(target) ? [target] : [], wildcardRoots: [], groups: [] }
}

export interface GraphDomainRow {
  name: string
  /** The Domain has at least one Subdomain or resolves to an IP. */
  hasData: boolean
}

export interface PartialScopeFields {
  domain: string | null
  domains: string[]
  stale_domains: string[]
  empty_domains: string[]
}

const byName = (a: string, b: string) => a.localeCompare(b)

/** The Domain node a scan root's hosts hang off: its org, once the graph
 *  names Domains after the org; the root itself in IP mode or without groups. */
export function graphDomainOf(scope: ProjectRoots, root: string): string {
  const low = root.toLowerCase()
  if (!GRAPH_DOMAIN_IS_ORG) return low
  const group = scope.groups.find(g => g.scanRoot.toLowerCase() === low)
  return (group?.orgDomain ?? low).toLowerCase()
}

/**
 * The scope part of a graph-inputs response.
 *
 * `graph` is the project's Domain nodes, or null when Neo4j could not be read;
 * the roots are then offered as they are, and the orchestrator still decides.
 * A tool not yet able to cover several roots is offered only the first.
 * Domain nodes are orgs: a scan root is "in the graph" when its org Domain is,
 * and a Domain no current scan root hangs off is stale. `currentDomains` names
 * the other Domains that are not stale: in IP mode, the org Domains of the names
 * the current hostname policy still scans, which no scan root ever names.
 */
export function partialScopeFields(
  scope: ProjectRoots,
  graph: GraphDomainRow[] | null,
  currentDomains: readonly string[] = [],
): PartialScopeFields {
  const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase()
  const inGraph = (root: string) => (graph ?? []).some(row => same(row.name, graphDomainOf(scope, root)))

  let current = [...scope.roots]
  // IP mode's root exists only once a full recon has minted it. A domain root
  // is offered even without its node: partial discovery creates it.
  if (scope.mode === 'ip' && graph) current = current.filter(inGraph)
  current.sort(byName)

  const domains = current
  const graphNames = new Set([...scope.roots.map(root => graphDomainOf(scope, root)),
    ...currentDomains.map(d => d.toLowerCase())])
  const stale = (graph ?? [])
    .map(row => row.name)
    .filter(name => !graphNames.has(name.toLowerCase()))
    .sort(byName)
  const withData = new Set((graph ?? []).filter(row => row.hasData).map(row => row.name.toLowerCase()))
  const empty = graph ? domains.filter(root => !withData.has(graphDomainOf(scope, root))) : []

  return { domain: domains[0] ?? null, domains, stale_domains: stale, empty_domains: empty }
}

/** The roots a SubdomainDiscovery run may enumerate: only an ENUMERATE group,
 *  in a batch or a single domain (group_discovery_enabled in recon). The
 *  legacy fallback of a single domain cannot tell, and offers its target.
 *  IP mode offers none: its one root is `ip-targets.<project id>` (B-19). */
export function discoveryDomains(scope: ProjectRoots, domains: string[]): string[] {
  if (scope.mode === 'ip') return []
  if (scope.mode === 'single' && scope.groups.length === 0) return [...domains]
  const enumerating = new Set(scope.wildcardRoots.map(r => r.toLowerCase()))
  return domains.filter(root => enumerating.has(root.toLowerCase()))
}

/**
 * Whether a host the operator types may be scanned by a partial run (§4.6): a
 * strict subdomain of an ENUMERATE scan root, a listed host of an EXACT group,
 * or a scan root itself only when Root is on. Without scope groups (IP mode,
 * the legacy fallback) it is the plain under-a-root test.
 */
export function admitsPartialHost(scope: ProjectRoots, host: string): boolean {
  const h = host.trim().toLowerCase()
  if (scope.groups.length === 0) return underAnyRoot(h, scope.roots)
  return admitsHost(scope.groups, h)
}

/** True when `host` is one of the roots or sits under one (label boundary). */
export function underAnyRoot(host: string, roots: readonly string[]): boolean {
  const h = host.toLowerCase()
  return roots.some(r => {
    const root = r.toLowerCase()
    return h === root || h.endsWith('.' + root)
  })
}

/**
 * The parameters of the graph's positive scope test for a partial run over
 * `selected` scan roots (§4.6 partial-recon graph targets): a host is in scope
 * when its LONGEST scan root is one of them and that group admits it, i.e. an
 * EXACT group's listed host, a scan root with Root on, or a strict subdomain of
 * an ENUMERATE root. Lower-cased; the Cypher form is `graphHostInScopeCypher`.
 */
export interface GraphScopeParams {
  /** Listed hosts of the selected groups (EXACT hosts, roots with Root on). */
  listed: string[]
  /** Selected ENUMERATE scan roots. */
  enumRoots: string[]
  /** Every current scan root: a longer one claims its hosts from a shorter one. */
  allRoots: string[]
}

function longestRoot(host: string, roots: readonly string[]): string | undefined {
  return roots.filter(r => host === r || host.endsWith(`.${r}`)).sort((a, b) => b.length - a.length)[0]
}

export function graphScopeParams(scope: ProjectRoots, selected: readonly string[]): GraphScopeParams {
  const wanted = new Set(selected.map(r => r.toLowerCase()))
  const allRoots = [...new Set(scope.groups.map(g => g.scanRoot.toLowerCase()))]
  const listed: string[] = []
  const enumRoots: string[] = []
  for (const g of scope.groups) {
    const root = g.scanRoot.toLowerCase()
    if (!wanted.has(root)) continue
    if (g.mode === 'enumerate') enumRoots.push(root)
    for (const h of [...g.exactHosts, ...(g.includeRoot ? [g.scanRoot] : [])]) {
      const host = h.toLowerCase()
      if (longestRoot(host, allRoots) === root && !listed.includes(host)) listed.push(host)
    }
  }
  return { listed, enumRoots, allRoots }
}

/** `graphScopeParams`' test in TypeScript, the predicate the Cypher runs. */
export function graphHostInScope(params: GraphScopeParams, host: string): boolean {
  const h = host.toLowerCase()
  if (params.listed.includes(h)) return true
  return params.enumRoots.some(r => h.endsWith(`.${r}`)
    && !params.allRoots.some(x => x.length > r.length && (h === x || h.endsWith(`.${x}`))))
}

/** The same test on a lower-cased Cypher host expression, over $listed,
 *  $enumRoots and $allRoots. */
export function graphHostInScopeCypher(host: string): string {
  return `(${host} IN $listed OR ANY(r IN $enumRoots WHERE ${host} ENDS WITH '.' + r
    AND NOT ANY(x IN $allRoots WHERE size(x) > size(r) AND (${host} = x OR ${host} ENDS WITH '.' + x))))`
}

/**
 * The tools a partial run refuses in IP mode, and why (recon
 * partial_recon_modules/helpers.py IP_MODE_REFUSED_TOOLS, which the container
 * enforces): each looks up or enumerates names, and an IP-mode run's one root
 * is `ip-targets.<project id>`.
 */
export const IP_MODE_REFUSED_TOOLS: Readonly<Record<string, string>> = {
  SubdomainDiscovery: 'Subdomain discovery would enumerate the synthetic ip-targets root, which is the project id.',
  Urlscan: 'urlscan.io searches by domain, and the synthetic ip-targets root is the project id.',
  OriginDiscovery: 'Origin discovery probes candidate origin addresses, which are not targets.',
}

/**
 * The tools that work on hostnames only (recon helpers.py
 * IP_MODE_NAME_ONLY_TOOLS). With Hostnames on target IPs set to IP only or
 * Record hostnames no hostname is a target, so the container refuses them; in
 * the scanning modes they scan the names the policy admits.
 */
export const IP_MODE_NAME_ONLY_TOOLS: Readonly<Record<string, string>> = {
  Gau: 'It asks web archives about hostnames',
  ParamSpider: 'It asks web archives about hostnames',
  SubdomainTakeover: 'It checks hostnames for dangling DNS records',
}

const SCANNING_MODES: readonly IpHostnameMode[] = ['record_filter', 'scan_all']

/** Why an IP-mode project cannot run `toolId` as a partial recon, or null.
 *  `hostnameMode` is the saved Hostnames on target IPs mode; an unknown one
 *  reads as IP only, as the container reads it. */
export function ipModeRefusal(toolId: string | null | undefined, ipMode: boolean,
  hostnameMode?: unknown): string | null {
  if (!ipMode || !toolId) return null
  if (IP_MODE_REFUSED_TOOLS[toolId]) return IP_MODE_REFUSED_TOOLS[toolId]
  const mode = ipHostnameModeOf(hostnameMode)
  if (IP_MODE_NAME_ONLY_TOOLS[toolId] && !SCANNING_MODES.includes(mode)) {
    return `${IP_MODE_NAME_ONLY_TOOLS[toolId]}, and with Hostnames on target IPs set to `
      + `${ipHostnameModeLabel(mode)} no hostname is a target.`
  }
  return null
}

/** The saved hostname policy, as far as a typed name goes. */
export interface TypedHostnamePolicy {
  mode?: unknown
  include?: readonly unknown[] | null
  exclude?: readonly unknown[] | null
}

/**
 * Why a hostname typed for an IP-mode partial run is refused, or null: the
 * pattern half of the hostname rule (recon helpers.py typed_name_refusal and
 * batch_scope.ip_typed_name_refusal, which are the control). None in IP only
 * and Record hostnames; the include/exclude entries in Record + scan matching
 * (exclude wins, an unreadable list admits nothing); any name in Record + scan
 * all; the hard guardrail on each. Every address the name resolves to must
 * still be a target: the container checks that at run time.
 */
export function typedHostnameRefusal(name: string, policy: TypedHostnamePolicy): string | null {
  const mode = ipHostnameModeOf(policy.mode)
  if (!SCANNING_MODES.includes(mode)) {
    return `Hostnames on target IPs is ${ipHostnameModeLabel(mode)}: no typed hostname is scanned`
  }
  const canonical = normalizeName(name)
  if (canonical === null) return `${name} is not a hostname`
  const guard = isHardBlockedDomain(canonical)
  if (guard.blocked) return guard.reason
  if (mode === 'record_filter') {
    if (!Array.isArray(policy.include) || !Array.isArray(policy.exclude)) return 'The hostname filter cannot be read'
    const include = parseEntries(policy.include)
    const exclude = parseEntries(policy.exclude)
    if (include.invalid.length || exclude.invalid.length) return 'The hostname filter cannot be read'
    const verdict = matches(canonical, include.patterns, exclude.patterns)
    if (verdict.excluded) return `${canonical} matches an exclude entry of the hostname filter (${verdict.matchedBy})`
    if (!verdict.included) return `${canonical} matches no include entry of the hostname filter`
  }
  return null
}

/**
 * The graph-inputs route's IP-mode scope (the `$ipSubs` / `$ipHosts` of its
 * Cypher): the target labels and target addresses the graph holds, plus the
 * names the project's current policy admits among those a run scanned
 * (`names`, from admittedByCurrentPolicy). Lower-cased, deduplicated. The
 * container re-checks those names on live DNS, so a count built on them is
 * what the run may touch at most.
 */
export function ipModeScopeParams(
  targets: IpTargetMatcher, labels: readonly string[], hosts: readonly string[], names: readonly string[],
): { ipSubs: string[]; ipHosts: string[] } {
  const lower = (values: readonly string[]) => values.filter(v => typeof v === 'string' && v).map(v => v.toLowerCase())
  const admitted = lower(names)
  return {
    ipSubs: [...new Set([...lower(labels).filter(l => targets.isLabel(l)), ...admitted])],
    ipHosts: [...new Set([...lower(hosts).filter(h => targets.has(h)), ...admitted])],
  }
}

// Target membership as recon_settings/ip_hostnames.py TargetSet means it: an
// address is a target when it is listed, or a host of a listed CIDR (Python's
// network.hosts(), so a network or broadcast address is not one), in any IPv6
// spelling. The orchestrator and the recon container decide; this is the
// modal's early answer.

interface Address { version: 4 | 6; value: bigint }
interface Network { version: 4 | 6; base: bigint; prefix: number }

const BITS = { 4: 32, 6: 128 } as const

function parseV4(text: string): bigint | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  let value = 0n
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part) || (part.length > 1 && part[0] === '0') || Number(part) > 255) return null
    value = (value << 8n) | BigInt(part)
  }
  return value
}

function parseV6(text: string): bigint | null {
  const halves = text.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const last = tail.length ? tail : head
  if (last.length && last[last.length - 1].includes('.')) {
    const v4 = parseV4(last.pop()!)
    if (v4 === null) return null
    last.push((v4 >> 16n).toString(16), (v4 & 0xffffn).toString(16))
  }
  const given = head.length + tail.length
  if (halves.length === 1 ? given !== 8 : given > 7) return null
  if (![...head, ...tail].every(group => /^[0-9a-fA-F]{1,4}$/.test(group))) return null
  const words = [...head, ...new Array<string>(8 - given).fill('0'), ...tail]
  return words.reduce((value, group) => (value << 16n) | BigInt(parseInt(group, 16)), 0n)
}

function parseAddress(raw: string): Address | null {
  const text = raw.trim().replace(/^\[|\]$/g, '')
  const v4 = parseV4(text)
  if (v4 !== null) return { version: 4, value: v4 }
  const v6 = text.includes(':') ? parseV6(text) : null
  return v6 !== null ? { version: 6, value: v6 } : null
}

function parseNetwork(raw: string): Network | null {
  const [host, prefixText, ...rest] = raw.trim().split('/')
  const address = parseAddress(host)
  if (!address || rest.length || (prefixText !== undefined && !/^\d{1,3}$/.test(prefixText))) return null
  const bits = BITS[address.version]
  const prefix = prefixText === undefined ? bits : Number(prefixText)
  if (prefix > bits) return null
  const span = BigInt(bits - prefix)
  return { version: address.version, base: (address.value >> span) << span, prefix }
}

/** Python's network.hosts(): IPv4 drops the network and broadcast addresses
 *  below /31, IPv6 the subnet-router anycast (network) address below /127. */
function isHostOf(address: Address, network: Network): boolean {
  if (address.version !== network.version) return false
  const bits = BITS[network.version]
  const span = BigInt(bits - network.prefix)
  if ((address.value >> span) !== (network.base >> span)) return false
  if (network.prefix >= bits - 1) return true
  if (address.value === network.base) return false
  return network.version === 6 || address.value !== network.base + (1n << span) - 1n
}

function networkHosts(network: Network): bigint[] {
  const bits = BITS[network.version]
  const size = 1n << BigInt(bits - network.prefix)
  const out: bigint[] = []
  for (let offset = 0n; offset < size; offset += 1n) {
    const value = network.base + offset
    if (isHostOf({ version: network.version, value }, network)) out.push(value)
  }
  return out
}

export interface IpTargetMatcher {
  /** `address` (brackets allowed, any IPv6 spelling) is one of the targets. */
  has(address: string): boolean
  /** `name` is the IP-mode label of a target (`203-0-113-2`, `2001-db8--1`). */
  isLabel(name: string): boolean
  /** null when every address `entry` (an address or a CIDR) stands for is a
   *  target, else why not. */
  outside(entry: string): string | null
}

export function ipTargetMatcher(entries: readonly string[]): IpTargetMatcher {
  const networks = entries.map(parseNetwork).filter((n): n is Network => n !== null)
  const hasAddress = (address: Address | null) => !!address && networks.some(n => isHostOf(address, n))
  const has = (text: string) => hasAddress(parseAddress(text))
  return {
    has,
    isLabel(name: string) {
      const label = name.trim().toLowerCase()
      if (label.includes('.') || !label.includes('-')) return false
      const v4 = label.replace(/-/g, '.')
      return parseAddress(v4) ? has(v4) : has(label.replace(/-/g, ':'))
    },
    outside(entry: string) {
      const network = parseNetwork(entry)
      if (!network) return `${entry} is not an address or CIDR`
      const hosts = entry.includes('/') ? networkHosts(network) : [network.base]
      const misses = hosts.filter(value => !hasAddress({ version: network.version, value })).length
      if (!misses) return null
      return entry.includes('/')
        ? `${misses} of the ${hosts.length} addresses in ${entry} are not this project's target IPs`
        : `${entry} is not one of this project's target IPs`
    },
  }
}
