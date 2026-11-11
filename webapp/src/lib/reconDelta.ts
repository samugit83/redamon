/**
 * Scan Timeline - Recon Delta (Section 6): diff two versions of the recon graph.
 *
 * Both sides arrive as the UI `{nodes, links}` payload, but node ids are NOT
 * comparable across versions (a snapshot's ids are its own export ids; the live
 * graph's are Neo4j internal ids). So the diff is computed over a STABLE IDENTITY
 * KEY per node type - the properties that make an asset that asset (an IP is its
 * address, a Port is ip+number+proto, a Technology is its name, and so on).
 *
 * The key is used only here, read-only. Nothing writes it back to the graph.
 */
import type { FormattedGraphData, FormattedNode } from '@/app/api/graph/format'
import { TRIAGE_PROPERTIES } from '@/lib/triage/properties'
import { type CoverageGap, gapInScope, skippedHostInScope } from '@/lib/scanCoverage'
import { COVERAGE_STAMP_PROPERTIES } from '@/lib/coverageStamps'

/**
 * Identity properties per node label, most-specific first. A node matches across
 * versions when every listed property matches (missing ones are simply absent
 * from the key, which is why order matters for readability of the key string).
 */
export const IDENTITY_KEYS: Record<string, string[]> = {
  Domain: ['name'],
  Subdomain: ['name'],
  IP: ['address'],
  // A port only means something on a host, so the host is part of its identity.
  Port: ['ip_address', 'number', 'protocol'],
  Service: ['ip_address', 'port_number', 'name'],
  // `version` is deliberately NOT identity: a version bump is a CHANGE, which is
  // exactly the signal the technology-drift lens reports.
  Technology: ['name'],
  BaseURL: ['url'],
  URL: ['url'],
  Endpoint: ['url', 'method', 'path'],
  Parameter: ['url', 'name', 'position'],
  Vulnerability: ['template_id', 'matched_at', 'name'],
  CVE: ['id'],
  MitreData: ['cwe_id'],
  Capec: ['capec_id'],
  Certificate: ['cert_key', 'fingerprint_sha256', 'serial'],
  Header: ['url', 'name'],
  DNSRecord: ['name', 'type', 'value'],
  Email: ['address'],
  // A urlscan Secret stores neither: its value's HMAC (or, without the key,
  // where it was seen, masked) tells one secret from another.
  Secret: ['value', 'file', 'value_hmac', 'masked_url'],
  JsReconFinding: ['url', 'type', 'value'],
}

/** Generic fallbacks when a label has no explicit identity. */
const FALLBACK_KEYS = ['name', 'address', 'url', 'id', 'value', 'title', 'domain', 'subdomain']

/**
 * Properties that change on every scan without meaning anything changed. They are
 * excluded from field-level change detection so a re-scan does not report the
 * whole graph as "changed".
 */
export const VOLATILE_PROPERTIES = new Set([
  '_exportId',
  'created_at',
  'createdAt',
  'updated_at',
  'updatedAt',
  'last_seen',
  'lastSeen',
  'first_seen',
  'firstSeen',
  'discovered_at',
  'discoveredAt',
  'timestamp',
  'scan_id',
  'scanId',
  'run_id',
  'runId',
  'recon_run_id',
  'scan_time',
  'scanned_at',
  // Coverage record (circuit breakers): metadata about what a run could not
  // re-check, refreshed every run. It must not make a Domain read as "changed".
  'recon_coverage_at',
  'recon_coverage_gaps',
  'recon_skipped_hosts',
  'recon_nuclei_truncated',
  // Which scan roots stamped the org Domain this run, and the run that did.
  'recon_coverage_roots',
  'recon_coverage_run',
  // Per-tool run stamps on the org Domain: the latest run wins, so every run
  // read as "changed" while nothing about the target did.
  'scan_timestamp',
  'port_scan_timestamp',
  'http_probe_timestamp',
  'resource_enum_timestamp',
  'vuln_scan_timestamp',
  'gvm_scan_timestamp',
  // Per-source OpenAPI fetch status: carries the time of the last fetch, so it
  // changes every run without the Domain changing.
  'openapi_source_status',
  // The newest full links a finding was seen in (graph_db/display_only.py):
  // they follow the latest sighting, and a delta must not print a secret.
  'unmasked_url',
  'unmasked_urls',
  'unmasked_start_url',
  'unmasked_redirect_from_urls',
  'raw_context',
  // Triage and mute state: a run, a verdict or a review rewrites these on
  // every finding without the finding itself changing (C20).
  ...TRIAGE_PROPERTIES,
  'muted_at',
  // Jev's confidence in a page's label drifts between scans of an unchanged
  // page; a change of the label itself (page_class) still counts.
  'page_class_confidence',
  // Jev's assessment of a serialized-object candidate is an opinion recomputed
  // every run, and absent on a run without Jev: neither drift nor switching Jev
  // on or off changes the target. Its own state, deser_format, still counts.
  'deser_jev_format',
  'deser_jev_format_confidence',
  'deser_jev_exploitability',
  'deser_jev_source',
  // The route exposure scan restamps a route's anonymous status every run, and
  // Jev's opinions of a lead are recomputed (or absent) each time. anon_status
  // itself is NOT volatile: a route that went from 401 to 200 is the change.
  'anon_status_at',
  'route_jev_kind',
  'route_jev_kind_confidence',
  'route_jev_sensitivity',
  'route_jev_source',
  'route_jev_privacy',
  'anon_page_class',
  'anon_page_class_confidence',
  'anon_page_class_source',
  // Every IP-mode run re-evaluates every hostname seen on a target IP and
  // stamps when; the name's reason (ip_hostname_reason) is what changes.
  'ip_hostname_evaluated_at',
  // Per-host coverage stamps on BaseURL: every run restamps every host it
  // looked at, and a cut that moves between runs is the scan, not the target.
  ...COVERAGE_STAMP_PROPERTIES,
])

function stableString(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (Array.isArray(value)) return value.map(stableString).join(',')
  if (typeof value === 'object') {
    try {
      return JSON.stringify(value, Object.keys(value as object).sort())
    } catch {
      return String(value)
    }
  }
  return String(value)
}

/**
 * The cross-version identity of a node. Two nodes with the same key in different
 * versions are "the same asset".
 */
export function identityKey(node: FormattedNode): string {
  const type = node.type || 'Unknown'
  const props = node.properties || {}
  const keys = IDENTITY_KEYS[type] ?? FALLBACK_KEYS

  const parts: string[] = []
  for (const k of keys) {
    const v = props[k]
    if (v !== undefined && v !== null && v !== '') {
      parts.push(`${k}=${stableString(v)}`)
      // Generic fallbacks are "first one that exists wins" - an explicit identity
      // uses every property it lists.
      if (!IDENTITY_KEYS[type]) break
    }
  }

  // Nothing identifying at all: fall back to the rendered name, then to the whole
  // (non-volatile) property bag, so distinct nodes never collapse into one.
  if (parts.length === 0) {
    if (node.name) parts.push(`name=${node.name}`)
    else {
      const stable = Object.keys(props)
        .filter(k => !VOLATILE_PROPERTIES.has(k))
        .sort()
        .map(k => `${k}=${stableString(props[k])}`)
      parts.push(stable.join('|') || `id=${node.id}`)
    }
  }

  return `${type}::${parts.join('|')}`
}

export interface FieldChange {
  field: string
  from: unknown
  to: unknown
}

export interface DeltaNode {
  key: string
  type: string
  name: string
  properties: Record<string, unknown>
  /**
   * The asset's Neo4j internal id in the LIVE graph, or null. Only a side read
   * from the live graph can name one: a stored version keeps no internal ids,
   * and its nodes may have been deleted or recreated since.
   */
  nodeId: string | null
}

/**
 * Payload node id -> live Neo4j id, given for a side that was captured from
 * the live graph (`CapturedSnapshot.liveNodeIds`). A stored side passes none.
 */
export interface LiveNodeIds {
  from?: ReadonlyMap<string, string>
  to?: ReadonlyMap<string, string>
}

export interface ChangedNode extends DeltaNode {
  changes: FieldChange[]
  previousProperties: Record<string, unknown>
}

export interface DeltaLink {
  type: string
  sourceKey: string
  targetKey: string
  sourceName: string
  targetName: string
}

export interface TypeScore {
  type: string
  added: number
  removed: number
  changed: number
  fromCount: number
  toCount: number
}

export interface SecurityLenses {
  /** Ports present in `to` but not in `from`. */
  newlyExposedPorts: DeltaNode[]
  /** Ports that disappeared (closed / host gone). */
  closedPorts: DeltaNode[]
  newVulnerabilities: DeltaNode[]
  resolvedVulnerabilities: DeltaNode[]
  newCves: DeltaNode[]
  /** Technologies whose `version` property moved. */
  technologyVersionChanges: ChangedNode[]
  certificateChanges: Array<DeltaNode | ChangedNode>
  newParameters: DeltaNode[]
}

/**
 * What the newer version's run could not fully re-check (circuit breakers), read
 * from its `Domain` coverage record. `null` when no coverage was recorded or the
 * record could not be trusted (fail closed).
 */
export interface ReconCoverage {
  sources: string[]
  skippedHosts: number
  nucleiTruncated: boolean
}

export interface ReconDelta {
  addedNodes: DeltaNode[]
  removedNodes: DeltaNode[]
  changedNodes: ChangedNode[]
  addedLinks: DeltaLink[]
  removedLinks: DeltaLink[]
  scorecard: TypeScore[]
  totals: {
    fromNodes: number
    toNodes: number
    added: number
    removed: number
    changed: number
    stable: number
    addedLinks: number
    removedLinks: number
  }
  lenses: SecurityLenses
  coverage: ReconCoverage | null
}

/**
 * Aggregate the coverage record across the newer graph's `Domain` nodes.
 *
 * Returns `null` when no `Domain` carries `recon_coverage_gaps`, or when any of
 * them is not a JSON array of objects with a `source` string of <=64 chars -- an
 * imported snapshot is untrusted, so anything malformed fails closed rather than
 * being trusted.
 */
export function extractReconCoverage(
  to: FormattedGraphData, roots: ReadonlySet<string> | null = null,
): ReconCoverage | null {
  const domains = (to.nodes || []).filter(n => n.type === 'Domain')
  let sawRecord = false
  const sources = new Set<string>()
  const hosts = new Set<string>()
  let nucleiTruncated = false

  for (const d of domains) {
    const raw = (d.properties || {})['recon_coverage_gaps']
    if (raw === undefined || raw === null) continue
    sawRecord = true
    let parsed: unknown = raw
    if (typeof parsed === 'string') {
      try {
        parsed = JSON.parse(parsed)
      } catch {
        return null
      }
    }
    if (!Array.isArray(parsed)) return null
    for (const entry of parsed) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
      const source = (entry as { source?: unknown }).source
      if (typeof source !== 'string' || source.length === 0 || source.length > 64) return null
      if (gapInScope(entry as CoverageGap, roots)) sources.add(source)
    }
    const skipped = (d.properties || {})['recon_skipped_hosts']
    if (Array.isArray(skipped)) {
      for (const h of skipped) if (typeof h === 'string' && skippedHostInScope(h, roots)) hosts.add(h)
    }
    if ((d.properties || {})['recon_nuclei_truncated'] === true) nucleiTruncated = true
  }

  if (!sawRecord) return null
  return { sources: [...sources].sort(), skippedHosts: hosts.size, nucleiTruncated }
}

function toDeltaNode(node: FormattedNode, key: string, nodeId: string | null): DeltaNode {
  return { key, type: node.type || 'Unknown', name: node.name, properties: node.properties || {}, nodeId }
}

function liveId(ids: ReadonlyMap<string, string> | undefined, node: FormattedNode): string | null {
  return ids?.get(String(node.id)) ?? null
}

function diffProperties(
  before: Record<string, unknown>,
  after: Record<string, unknown>
): FieldChange[] {
  const changes: FieldChange[] = []
  const fields = new Set([...Object.keys(before || {}), ...Object.keys(after || {})])
  for (const field of fields) {
    if (VOLATILE_PROPERTIES.has(field)) continue
    const a = stableString(before?.[field])
    const b = stableString(after?.[field])
    if (a !== b) changes.push({ field, from: before?.[field] ?? null, to: after?.[field] ?? null })
  }
  return changes.sort((x, y) => x.field.localeCompare(y.field))
}

/** Index a payload by identity key. Later duplicates keep the first occurrence. */
function indexByIdentity(data: FormattedGraphData): {
  byKey: Map<string, FormattedNode>
  keyById: Map<string, string>
} {
  const byKey = new Map<string, FormattedNode>()
  const keyById = new Map<string, string>()
  for (const node of data.nodes) {
    const key = identityKey(node)
    keyById.set(node.id, key)
    if (!byKey.has(key)) byKey.set(key, node)
  }
  return { byKey, keyById }
}

function linkSignature(l: DeltaLink): string {
  return `${l.sourceKey}-[${l.type}]->${l.targetKey}`
}

function collectLinks(
  data: FormattedGraphData,
  keyById: Map<string, string>,
  byKey: Map<string, FormattedNode>
): Map<string, DeltaLink> {
  const out = new Map<string, DeltaLink>()
  for (const link of data.links) {
    const sourceKey = keyById.get(String(link.source))
    const targetKey = keyById.get(String(link.target))
    // A link whose endpoint is not in the payload cannot be compared by identity.
    if (!sourceKey || !targetKey) continue
    const dl: DeltaLink = {
      type: link.type,
      sourceKey,
      targetKey,
      sourceName: byKey.get(sourceKey)?.name ?? '',
      targetName: byKey.get(targetKey)?.name ?? '',
    }
    out.set(linkSignature(dl), dl)
  }
  return out
}

/**
 * Diff two rendered graph payloads. `from` is the older/base side.
 *
 * `live` names the side(s) read from the live graph, so a row can carry the
 * live node's id: an added node is the `to` node, a removed one the `from`
 * node, and a changed asset exists on both, so whichever side is live names
 * it. A row whose node is only in a stored version gets null.
 */
export function computeReconDelta(
  from: FormattedGraphData,
  to: FormattedGraphData,
  live: LiveNodeIds = {},
  scanRoots: ReadonlySet<string> | null = null,
): ReconDelta {
  const fromIdx = indexByIdentity(from)
  const toIdx = indexByIdentity(to)

  const addedNodes: DeltaNode[] = []
  const removedNodes: DeltaNode[] = []
  const changedNodes: ChangedNode[] = []
  let stable = 0

  for (const [key, node] of toIdx.byKey) {
    const before = fromIdx.byKey.get(key)
    if (!before) {
      addedNodes.push(toDeltaNode(node, key, liveId(live.to, node)))
      continue
    }
    const changes = diffProperties(before.properties || {}, node.properties || {})
    if (changes.length > 0) {
      changedNodes.push({
        ...toDeltaNode(node, key, liveId(live.to, node) ?? liveId(live.from, before)),
        changes,
        previousProperties: before.properties || {},
      })
    } else {
      stable += 1
    }
  }

  for (const [key, node] of fromIdx.byKey) {
    if (!toIdx.byKey.has(key)) removedNodes.push(toDeltaNode(node, key, liveId(live.from, node)))
  }

  const fromLinks = collectLinks(from, fromIdx.keyById, fromIdx.byKey)
  const toLinks = collectLinks(to, toIdx.keyById, toIdx.byKey)
  const addedLinks: DeltaLink[] = []
  const removedLinks: DeltaLink[] = []
  for (const [sig, link] of toLinks) if (!fromLinks.has(sig)) addedLinks.push(link)
  for (const [sig, link] of fromLinks) if (!toLinks.has(sig)) removedLinks.push(link)

  // --- scorecard ------------------------------------------------------------
  const scores = new Map<string, TypeScore>()
  const score = (type: string): TypeScore => {
    let s = scores.get(type)
    if (!s) {
      s = { type, added: 0, removed: 0, changed: 0, fromCount: 0, toCount: 0 }
      scores.set(type, s)
    }
    return s
  }
  for (const n of fromIdx.byKey.values()) score(n.type || 'Unknown').fromCount += 1
  for (const n of toIdx.byKey.values()) score(n.type || 'Unknown').toCount += 1
  for (const n of addedNodes) score(n.type).added += 1
  for (const n of removedNodes) score(n.type).removed += 1
  for (const n of changedNodes) score(n.type).changed += 1

  const scorecard = [...scores.values()].sort((a, b) => {
    const aChanged = a.added + a.removed + a.changed
    const bChanged = b.added + b.removed + b.changed
    if (aChanged !== bChanged) return bChanged - aChanged
    return a.type.localeCompare(b.type)
  })

  // --- security lenses ------------------------------------------------------
  const byType = (list: DeltaNode[], type: string) => list.filter(n => n.type === type)
  const lenses: SecurityLenses = {
    newlyExposedPorts: byType(addedNodes, 'Port'),
    closedPorts: byType(removedNodes, 'Port'),
    newVulnerabilities: byType(addedNodes, 'Vulnerability'),
    resolvedVulnerabilities: byType(removedNodes, 'Vulnerability'),
    newCves: byType(addedNodes, 'CVE'),
    technologyVersionChanges: changedNodes.filter(
      n => n.type === 'Technology' && n.changes.some(c => c.field === 'version')
    ),
    certificateChanges: [
      ...byType(addedNodes, 'Certificate'),
      ...changedNodes.filter(n => n.type === 'Certificate'),
    ],
    newParameters: byType(addedNodes, 'Parameter'),
  }

  return {
    addedNodes,
    removedNodes,
    changedNodes,
    addedLinks,
    removedLinks,
    scorecard,
    totals: {
      fromNodes: fromIdx.byKey.size,
      toNodes: toIdx.byKey.size,
      added: addedNodes.length,
      removed: removedNodes.length,
      changed: changedNodes.length,
      stable,
      addedLinks: addedLinks.length,
      removedLinks: removedLinks.length,
    },
    lenses,
    coverage: extractReconCoverage(to, scanRoots),
  }
}

export type DeltaState = 'added' | 'removed' | 'changed' | 'stable'

/**
 * Union of both payloads for the graph overlay (Section 6.3): every node carries
 * a `deltaState` the canvas colors by (green new / red removed / amber changed /
 * grey stable). Node ids are the identity keys so both sides merge cleanly.
 */
export function buildDeltaOverlay(
  from: FormattedGraphData,
  to: FormattedGraphData,
  delta: ReconDelta
): { nodes: Array<FormattedNode & { deltaState: DeltaState }>; links: FormattedGraphData['links'] } {
  const stateByKey = new Map<string, DeltaState>()
  for (const n of delta.addedNodes) stateByKey.set(n.key, 'added')
  for (const n of delta.removedNodes) stateByKey.set(n.key, 'removed')
  for (const n of delta.changedNodes) stateByKey.set(n.key, 'changed')

  const nodes = new Map<string, FormattedNode & { deltaState: DeltaState }>()
  const push = (data: FormattedGraphData) => {
    for (const n of data.nodes) {
      const key = identityKey(n)
      if (!nodes.has(key)) {
        nodes.set(key, { ...n, id: key, deltaState: stateByKey.get(key) ?? 'stable' })
      }
    }
  }
  // `to` first so a surviving node renders with its CURRENT properties.
  push(to)
  push(from)

  const links = new Map<string, { source: string; target: string; type: string }>()
  const pushLinks = (data: FormattedGraphData) => {
    const keyById = new Map<string, string>()
    for (const n of data.nodes) keyById.set(n.id, identityKey(n))
    for (const l of data.links) {
      const s = keyById.get(String(l.source))
      const t = keyById.get(String(l.target))
      if (!s || !t) continue
      links.set(`${s}-[${l.type}]->${t}`, { source: s, target: t, type: l.type })
    }
  }
  pushLinks(to)
  pushLinks(from)

  return { nodes: [...nodes.values()], links: [...links.values()] }
}
