/**
 * Hostnames on target IPs: what the last run found on a project's IPs, and what
 * a policy would do with it (04_ui_spec.md §2 "Route", design §6 and §6.3).
 *
 * Read by GET /api/projects/[id]/ip-hostnames (the form preview, the partial
 * recon modal) and by MCP preflight_scope_check. One graph read per call; the
 * rule (ipHostnameFilter.evaluatePreview, the TS mirror of
 * recon_settings/ip_hostnames.py) runs here over every name, so the totals are
 * exact while only one page of rows goes back.
 *
 * Server only: the caller opens the Neo4j session and passes it in, so this
 * module never touches the driver itself.
 */
import type { Session } from 'neo4j-driver'
import { isHardBlockedDomain } from '@/lib/hard-guardrail'
import {
  type IpHostnameMode, type PreviewCandidate, type ReasonCode, canonicalIp, evaluatePreview, matches, parseEntries,
} from '@/lib/ipHostnameFilter'
import { isRoeExcluded } from '@/lib/roeScope'
import { IP_HOSTNAME_DEFAULTS, type ScopeFields, ipHostnameModeOf } from '@/lib/scopeGroups'

export const PREVIEW_PAGE_DEFAULT = 100
export const PREVIEW_PAGE_MAX = 500

/** The project row the preview judges by: the policy, the targets' RoE. */
export interface PreviewProjectRow extends ScopeFields {
  id: string
  userId: string
  ipMode?: boolean | null
  roeExcludedHosts?: readonly string[] | null
}

/** A policy the caller wants judged instead of the saved one (the form's
 *  unsaved edits). Each field left out falls back to the saved row. */
export interface PreviewPolicy {
  mode?: IpHostnameMode
  include?: readonly string[]
  exclude?: readonly string[]
  maxScanned?: number
}

export interface PreviewQuery {
  limit?: number
  /** The last name of the previous page; names sort by code point. */
  cursor?: string | null
  /** Only rows whose result is this reason code. */
  reason?: string | null
  /** Only names containing this text (case-insensitive). */
  q?: string | null
  /** Only this exact name (the node drawer's per-IP evidence). */
  name?: string | null
  policy?: PreviewPolicy
}

/** The evidence of one SEEN_ON edge: a recorded name seen on one target IP. */
export interface SeenOn {
  ip: string
  sources: string[]
  first_seen: string | null
  last_seen: string | null
  resolves_here: boolean | null
  cert_covers: boolean | null
}

/** One name the last run found on the target IPs. */
export interface PreviewName {
  name: string
  /** Target IPs it was seen on (recorded) or resolves to (scanned). */
  ips: string[]
  sources: string[]
  /** The reason the last run wrote. */
  reason: string | null
  last_seen: string | null
  /** recorded: an ExternalDomain; scanned: a Subdomain the selection made. */
  kind: 'recorded' | 'scanned'
  /** What the judged policy does with it now; null in ip_only, which looks nothing up. */
  result: ReasonCode | null
  /** Per target IP, the SEEN_ON evidence of a recorded name; [] for a scanned one. */
  seen: SeenOn[]
}

export interface PreviewTotals {
  /** Every name found last run (recorded and scanned). */
  found: number
  /** ExternalDomains: names the last run recorded and did not scan. */
  recorded: number
  /** Names the last run scanned that the SAVED policy still admits. */
  scanned: number
  /** Names the judged policy would scan, DNS permitting. */
  wouldScan: number
  /** Rows matching `reason` and `q`, for the pager. */
  matching: number
  byReason: Record<string, number>
  byIp: Record<string, number>
}

export interface IpHostnamePreview {
  /** The saved mode. */
  mode: IpHostnameMode
  /** The mode the results were judged under (the caller's, else the saved one). */
  evaluatedMode: IpHostnameMode
  /** The graph predates hostname recording: real names under the mock root, no SEEN_ON. */
  legacy: boolean
  /** The mode of the last full run when the graph records it; null when unknown. */
  lastRunMode: string | null
  /** The graph holds target IPs: some run has written it. */
  hasRun: boolean
  /** One page of names, sorted by name. */
  recorded: PreviewName[]
  /** The last run's scanned names the saved policy still admits (design §6.3). */
  scanned: { name: string; ips: string[] }[]
  /** When the last run judged these names; null when no name carries it. */
  evaluatedAt: string | null
  nextCursor: string | null
  totals: PreviewTotals
}

/** What the graph read returns, before any policy is applied. */
export interface PreviewGraph {
  names: (Omit<PreviewName, 'result' | 'seen'> & { org: string | null; evaluatedAt: string | null; seen?: SeenOn[] })[]
  sharedEdge: string[]
  attributionFailed: string[]
  /** How many target IPs carry an attribution tag; 0 means attribution never ran. */
  attributed: number
  ipCount: number
  lastRunMode: string | null
  legacyNames: number
  seenEdges: number
}

/**
 * The scanned names a reader may still call scanned (design §6.3): a name keeps
 * its scanned reason in the graph until the next full run, so after a
 * narrowing, a failed out_of_policy marker or a restored version only the
 * project's CURRENT policy says whether it is still a target. A filter that
 * cannot be read admits nothing, as in the rule.
 */
export function admittedByCurrentPolicy(
  names: readonly string[], row: (ScopeFields & { ipMode?: boolean | null }) | null | undefined,
): string[] {
  if (!row || row.ipMode !== true) return []
  const mode = ipHostnameModeOf(row.ipHostnameMode)
  if (mode === 'scan_all') return [...names]
  if (mode !== 'record_filter') return []
  const include = parseEntries(row.ipHostnameInclude ?? [])
  const exclude = parseEntries(row.ipHostnameExclude ?? [])
  if (include.invalid.length || exclude.invalid.length) return []
  return names.filter(name => matches(name, include.patterns, exclude.patterns).included)
}

const str = (v: unknown): string | null => (typeof v === 'string' && v ? v : v == null ? null : String(v))
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])

/** Every MATCH is keyed on both the owner's user_id and the project_id. */
const NAMES_QUERY = `
CALL {
  MATCH (ed:ExternalDomain {user_id: $uid, project_id: $pid})
  WHERE ed.ip_hostname_reason IS NOT NULL
  OPTIONAL MATCH (ed)-[r:SEEN_ON]->(i:IP {user_id: $uid, project_id: $pid})
  RETURN ed.domain AS name, ed.ip_hostname_reason AS reason, ed.ip_hostname_org AS org,
         coalesce(ed.sources, []) AS sources, collect(DISTINCT i.address) AS ips,
         max(r.last_seen) AS lastSeen, toString(ed.ip_hostname_evaluated_at) AS evaluatedAt, 'recorded' AS kind,
         [s IN collect({ip: i.address, sources: r.sources, first_seen: toString(r.first_seen),
                        last_seen: toString(r.last_seen), resolves_here: r.resolves_here,
                        cert_covers: r.cert_covers}) WHERE s.ip IS NOT NULL] AS seen
  UNION ALL
  MATCH (s:Subdomain {user_id: $uid, project_id: $pid, source: 'ip_hostname_selection'})
  WHERE s.ip_hostname_reason IN ['scanned', 'out_of_policy']
  OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP {user_id: $uid, project_id: $pid})
  OPTIONAL MATCH (s)-[:BELONGS_TO]->(d:Domain {user_id: $uid, project_id: $pid})
  RETURN s.name AS name, s.ip_hostname_reason AS reason, head(collect(DISTINCT d.name)) AS org,
         coalesce(s.ip_hostname_sources, []) AS sources, collect(DISTINCT i.address) AS ips,
         null AS lastSeen, toString(s.ip_hostname_evaluated_at) AS evaluatedAt, 'scanned' AS kind, [] AS seen
}
RETURN name, reason, org, sources, ips, lastSeen, evaluatedAt, kind, seen`

const CONTEXT_QUERY = `
OPTIONAL MATCH (i:IP {user_id: $uid, project_id: $pid})
WITH collect(i) AS ips
OPTIONAL MATCH (root:Domain {user_id: $uid, project_id: $pid, is_mock: true})
WITH ips, head(collect(root.ip_hostname_mode)) AS lastRunMode
OPTIONAL MATCH (old:Subdomain {user_id: $uid, project_id: $pid})
  WHERE old.name CONTAINS '.' AND coalesce(old.source, '') <> 'ip_hostname_selection'
WITH ips, lastRunMode, count(old) AS legacyNames
OPTIONAL MATCH (:ExternalDomain {user_id: $uid, project_id: $pid})-[seen:SEEN_ON]->(:IP {user_id: $uid, project_id: $pid})
RETURN size(ips) AS ipCount,
       [x IN ips WHERE x.ownership = 'shared_edge' | x.address] AS sharedEdge,
       [x IN ips WHERE 'attribution failed' IN coalesce(x.ownership_reasons, []) | x.address] AS attributionFailed,
       size([x IN ips WHERE x.ownership IS NOT NULL]) AS attributed,
       lastRunMode, legacyNames, count(seen) AS seenEdges`

const bool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null)

function seenList(v: unknown): SeenOn[] {
  if (!Array.isArray(v)) return []
  return v.filter(e => e && typeof e === 'object' && typeof (e as { ip?: unknown }).ip === 'string').map(e => {
    const x = e as Record<string, unknown>
    return {
      ip: canonicalIp(x.ip as string), sources: strList(x.sources), first_seen: str(x.first_seen),
      last_seen: str(x.last_seen), resolves_here: bool(x.resolves_here), cert_covers: bool(x.cert_covers),
    }
  })
}

const num = (v: unknown): number => {
  if (typeof v === 'number') return v
  if (v && typeof (v as { toNumber?: () => number }).toNumber === 'function') return (v as { toNumber: () => number }).toNumber()
  return Number(v) || 0
}

/**
 * The graph read: names found last run plus what the rule needs about the IPs.
 * Through session.run, never a managed transaction: getGraphSession puts its
 * server-side query timeout on run() only, and an unbounded read here would hold
 * the form's request and a pooled connection for as long as Neo4j takes.
 */
export async function readPreviewGraph(session: Session, userId: string, projectId: string): Promise<PreviewGraph> {
  const params = { uid: userId, pid: projectId }
  const namesRes = await session.run(NAMES_QUERY, params)
  const ctxRes = await session.run(CONTEXT_QUERY, params)
  const byName = new Map<string, PreviewGraph['names'][number]>()
  for (const r of namesRes.records) {
    const name = str(r.get('name'))
    if (!name) continue
    const kind = r.get('kind') === 'scanned' ? 'scanned' : 'recorded'
    // A name both recorded and selected (a partial run after a full one) is
    // shown once, as what the selection made of it.
    if (byName.get(name)?.kind === 'scanned' && kind === 'recorded') continue
    byName.set(name, {
      name,
      kind,
      ips: strList(r.get('ips')).map(canonicalIp),
      sources: strList(r.get('sources')),
      reason: str(r.get('reason')),
      last_seen: str(r.get('lastSeen')),
      org: str(r.get('org')),
      evaluatedAt: str(r.get('evaluatedAt')),
      seen: seenList(r.get('seen')),
    })
  }
  const c = ctxRes.records[0]
  return {
    names: [...byName.values()],
    sharedEdge: c ? strList(c.get('sharedEdge')) : [],
    attributionFailed: c ? strList(c.get('attributionFailed')) : [],
    attributed: c ? num(c.get('attributed')) : 0,
    ipCount: c ? num(c.get('ipCount')) : 0,
    lastRunMode: c ? str(c.get('lastRunMode')) : null,
    legacyNames: c ? num(c.get('legacyNames')) : 0,
    seenEdges: c ? num(c.get('seenEdges')) : 0,
  }
}

const RECORDING: ReadonlySet<string> = new Set(['record_only', 'record_filter', 'scan_all'])

/** Judge the names under the policy and cut the page. Pure. */
export function buildIpHostnamePreview(
  graph: PreviewGraph, row: PreviewProjectRow, query: PreviewQuery = {},
): IpHostnamePreview {
  const saved = ipHostnameModeOf(row.ipHostnameMode)
  const policy = query.policy ?? {}
  const evaluatedMode = policy.mode && (RECORDING.has(policy.mode) || policy.mode === 'ip_only') ? policy.mode : saved
  const include = policy.include ?? row.ipHostnameInclude ?? []
  const exclude = policy.exclude ?? row.ipHostnameExclude ?? []
  const cap = policy.maxScanned ?? row.ipHostnameMaxScanned ?? IP_HOSTNAME_DEFAULTS.ipHostnameMaxScanned
  const roe = row.roeExcludedHosts ?? []

  const names = [...graph.names].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  let results: Record<string, ReasonCode> = {}
  if (RECORDING.has(evaluatedMode)) {
    const candidates: PreviewCandidate[] = names.map(n => ({
      name: n.name, ipsSeen: n.ips, orgDomain: n.org, lastReason: n.reason,
    }))
    results = evaluatePreview(candidates, {
      mode: evaluatedMode,
      include,
      exclude,
      cap,
      // Attribution that never ran is unknown, and unknown refuses every
      // scan_all name (attribution_unavailable), as in the rule.
      sharedEdge: graph.attributed > 0 ? new Set(graph.sharedEdge) : null,
      attributionFailed: graph.attributed > 0 ? new Set(graph.attributionFailed) : null,
      // The last run's wildcard drops come back as its recorded reason.
      wildcardZone: new Set<string>(),
      hardBlocked: name => isHardBlockedDomain(name).blocked,
      roeExcluded: name => isRoeExcluded(name, roe),
    }).reasons
  }

  const all: PreviewName[] = names.map(n => ({
    name: n.name, ips: n.ips, sources: n.sources, reason: n.reason, last_seen: n.last_seen, kind: n.kind,
    result: results[n.name] ?? null, seen: n.seen ?? [],
  }))

  const byReason: Record<string, number> = {}
  const byIp: Record<string, number> = {}
  for (const n of all) {
    if (n.result) byReason[n.result] = (byReason[n.result] ?? 0) + 1
    for (const ip of n.ips) byIp[ip] = (byIp[ip] ?? 0) + 1
  }

  const q = (query.q ?? '').trim().toLowerCase()
  const filtered = all.filter(n => (!query.reason || n.result === query.reason) && (!q || n.name.includes(q))
    && (!query.name || n.name === query.name))
  const limit = Math.min(Math.max(Math.trunc(query.limit ?? PREVIEW_PAGE_DEFAULT) || PREVIEW_PAGE_DEFAULT, 1), PREVIEW_PAGE_MAX)
  const cursor = query.cursor ?? null
  const after = cursor === null ? filtered : filtered.filter(n => n.name > cursor)
  const page = after.slice(0, limit)

  const scannedNames = names.filter(n => n.kind === 'scanned' && n.reason === 'scanned')
  const admitted = new Set(admittedByCurrentPolicy(scannedNames.map(n => n.name), row))
  const scanned = scannedNames.filter(n => admitted.has(n.name)).map(n => ({ name: n.name, ips: n.ips }))

  const evaluatedAt = names.reduce<string | null>(
    (latest, n) => (n.evaluatedAt && (!latest || n.evaluatedAt > latest) ? n.evaluatedAt : latest), null)

  return {
    mode: saved,
    evaluatedMode,
    // A run since hostname recording stamps its mode on the IP-mode root: then
    // dotted Subdomains are this feature's, never a pre-feature graph's.
    legacy: graph.lastRunMode === null && graph.legacyNames > 0 && graph.seenEdges === 0 && names.length === 0,
    lastRunMode: graph.lastRunMode,
    hasRun: graph.ipCount > 0,
    recorded: page,
    scanned,
    evaluatedAt,
    nextCursor: after.length > limit ? page[page.length - 1].name : null,
    totals: {
      found: all.length,
      recorded: names.filter(n => n.kind === 'recorded').length,
      scanned: scanned.length,
      wouldScan: byReason.scanned ?? 0,
      matching: filtered.length,
      byReason,
      byIp,
    },
  }
}

/** The preview for a project row, through the caller's session. */
export async function loadIpHostnamePreview(
  session: Session, row: PreviewProjectRow, query: PreviewQuery = {},
): Promise<IpHostnamePreview> {
  return buildIpHostnamePreview(await readPreviewGraph(session, row.userId, row.id), row, query)
}

const LAST_RUN_TIMEOUT_MS = 5000

/**
 * preflight_scope_check's two last-run counts: every name the last run found
 * on the target IPs, and how many of them the saved policy would scan. Both null
 * until a run has recorded a name, and when the graph cannot answer in time:
 * preflight reports, it must not fail because Neo4j is slow or down.
 */
export async function lastRunCounts(
  openSession: () => Session, row: PreviewProjectRow,
): Promise<{ recordedLastRun: number | null; wouldScanLastRun: number | null }> {
  const none = { recordedLastRun: null, wouldScanLastRun: null }
  let session: Session | null = null
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    session = openSession()
    const timeout = new Promise<null>(resolve => { timer = setTimeout(() => resolve(null), LAST_RUN_TIMEOUT_MS) })
    const preview = await Promise.race([loadIpHostnamePreview(session, row, { limit: 1 }), timeout])
    if (!preview || preview.totals.found === 0) return none
    return { recordedLastRun: preview.totals.found, wouldScanLastRun: preview.totals.wouldScan }
  } catch {
    return none
  } finally {
    clearTimeout(timer)
    await session?.close().catch(() => {})
  }
}
