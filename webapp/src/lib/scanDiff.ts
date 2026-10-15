/**
 * Scheduled-scan change detection (help-wanted: baseline storage + diff).
 *
 * The frozen ScanVersion snapshots are the baselines. This module diffs two
 * snapshots (old vs new) and reports new/removed subdomains, ports and CVEs —
 * the three signals the issue asks for. Pure functions only, so the scheduler
 * tick and the status poll can call them without I/O.
 *
 * Node-label contract (see graph_db/schema.py + webapp snapshot format):
 *   Subdomain nodes carry `name`; Port nodes carry a port number + host;
 *   CVE nodes carry `id` ("CVE-..."); Vulnerability nodes carry finding ids
 *   and often a `cve_ids` list. Tenant fields (`user_id`, `project_id`) and
 *   timestamps are ignored so a rescan of identical state diffs to empty.
 */

export interface DiffableNode {
  labels: string[]
  properties: Record<string, unknown>
}

export interface PortRef {
  host: string
  port: number
  protocol: string
}

export interface ScanDiff {
  newSubdomains: string[]
  removedSubdomains: string[]
  newPorts: PortRef[]
  removedPorts: PortRef[]
  newCves: string[]
  newVulnCount: number
  /** True when nothing meaningful changed. */
  empty: boolean
}

const TENANT_KEYS = new Set(['user_id', 'project_id', 'created_at', 'updated_at'])

function str(v: unknown): string {
  return typeof v === 'string' ? v : ''
}

function num(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v)
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v)
    if (Number.isFinite(n)) return Math.trunc(n)
  }
  return null
}

function hasLabel(node: DiffableNode, label: string): boolean {
  return node.labels.includes(label)
}

/** Subdomain identity: lowercased `name`. */
export function subdomainKey(node: DiffableNode): string | null {
  if (!hasLabel(node, 'Subdomain')) return null
  const name = str(node.properties['name']).trim().toLowerCase()
  return name || null
}

function hostOf(node: DiffableNode): string {
  for (const k of ['host', 'ip', 'address', 'target_ip', 'hostname', 'name']) {
    const v = str(node.properties[k]).trim()
    if (v) return v.toLowerCase()
  }
  return ''
}

/** Port identity: `host:port/proto`. Falls back to number-only when hostless. */
export function portKey(node: DiffableNode): string | null {
  if (!hasLabel(node, 'Port')) return null
  const p = num(node.properties['port'] ?? node.properties['number'] ?? node.properties['target_port'])
  if (p === null || p <= 0 || p > 65535) return null
  const proto = str(node.properties['protocol'] || 'tcp').toLowerCase() || 'tcp'
  const host = hostOf(node)
  return host ? `${host}:${p}/${proto}` : `:${p}/${proto}`
}

export function portRefFor(key: string): PortRef {
  const m = key.match(/^(.*):(\d+)\/(.+)$/)
  if (!m) return { host: '', port: 0, protocol: 'tcp' }
  return { host: m[1], port: Number(m[2]), protocol: m[3] }
}

/** CVE identities from CVE nodes + Vulnerability `cve_ids` lists. */
export function cveKeys(node: DiffableNode): string[] {
  const out: string[] = []
  if (hasLabel(node, 'CVE')) {
    const id = str(node.properties['id'] || node.properties['name']).trim().toUpperCase()
    if (/^CVE-\d{4}-\d+$/.test(id)) out.push(id)
    return out
  }
  if (hasLabel(node, 'Vulnerability')) {
    const raw = node.properties['cve_ids'] ?? node.properties['cves']
    if (Array.isArray(raw)) {
      for (const v of raw) {
        const id = String(v).trim().toUpperCase()
        if (/^CVE-\d{4}-\d+$/.test(id)) out.push(id)
      }
    }
    const single = str(node.properties['cve_id']).trim().toUpperCase()
    if (/^CVE-\d{4}-\d+$/.test(single)) out.push(single)
  }
  return out
}

function fingerprint(node: DiffableNode): string {
  const entries = Object.entries(node.properties)
    .filter(([k]) => !TENANT_KEYS.has(k))
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .sort()
  return `${[...node.labels].sort().join('+')}(${entries.join(',')})`
}

function toSet(nodes: DiffableNode[], pick: (n: DiffableNode) => string | null): Set<string> {
  const s = new Set<string>()
  for (const n of nodes) {
    const k = pick(n)
    if (k) s.add(k)
  }
  return s
}

function sortedDiff(before: Set<string>, after: Set<string>): { added: string[]; removed: string[] } {
  const added = [...after].filter(x => !before.has(x)).sort()
  const removed = [...before].filter(x => !after.has(x)).sort()
  return { added, removed }
}

/**
 * Diff two snapshots. `oldNodes` may be empty (first-ever scan → everything is
 * new, which callers usually suppress for alerting but still store).
 */
export function diffSnapshots(oldNodes: DiffableNode[], newNodes: DiffableNode[]): ScanDiff {
  const oldSubs = toSet(oldNodes, subdomainKey)
  const newSubs = toSet(newNodes, subdomainKey)
  const sub = sortedDiff(oldSubs, newSubs)

  const oldPorts = toSet(oldNodes, portKey)
  const newPorts = toSet(newNodes, portKey)
  const ports = sortedDiff(oldPorts, newPorts)

  const oldCves = new Set<string>()
  const newCves = new Set<string>()
  for (const n of oldNodes) for (const c of cveKeys(n)) oldCves.add(c)
  for (const n of newNodes) for (const c of cveKeys(n)) newCves.add(c)
  const cves = sortedDiff(oldCves, newCves)

  const oldPrints = new Set(oldNodes.map(fingerprint))
  let newVulnCount = 0
  for (const n of newNodes) {
    if (hasLabel(n, 'Vulnerability') && !oldPrints.has(fingerprint(n))) newVulnCount += 1
  }

  const empty =
    sub.added.length === 0 &&
    sub.removed.length === 0 &&
    ports.added.length === 0 &&
    ports.removed.length === 0 &&
    cves.added.length === 0 &&
    newVulnCount === 0

  return {
    newSubdomains: sub.added,
    removedSubdomains: sub.removed,
    newPorts: ports.added.map(portRefFor),
    removedPorts: ports.removed.map(portRefFor),
    newCves: cves.added,
    newVulnCount,
    empty,
  }
}

/** One-line human summary for Slack/webhook messages and the timeline badge. */
export function summarizeDiff(d: ScanDiff): string {
  if (d.empty) return 'No changes vs previous scan.'
  const bits: string[] = []
  if (d.newSubdomains.length) bits.push(`${d.newSubdomains.length} new subdomain(s)`)
  if (d.removedSubdomains.length) bits.push(`${d.removedSubdomains.length} removed subdomain(s)`)
  if (d.newPorts.length) bits.push(`${d.newPorts.length} new open port(s)`)
  if (d.removedPorts.length) bits.push(`${d.removedPorts.length} closed port(s)`)
  if (d.newCves.length) bits.push(`${d.newCves.length} new CVE(s)`)
  if (d.newVulnCount) bits.push(`${d.newVulnCount} new finding(s)`)
  return bits.join(', ') + '.'
}
