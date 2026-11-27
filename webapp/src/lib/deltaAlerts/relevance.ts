import { createHash } from 'node:crypto'
import type { DeltaNode, ReconDelta } from '@/lib/reconDelta'
import type {
  AlertSeverity,
  DeltaAlertSummaryPayload,
  DeltaAlertThresholds,
  DeltaAlertTopItem,
} from './types'

export const SEVERITY_RANK: Record<AlertSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

const HOST_NODE_TYPES = new Set(['Domain', 'Subdomain', 'IP'])
const MAX_TOP_ITEMS = 10

export function normalizeAlertSeverity(raw: unknown): AlertSeverity {
  if (typeof raw === 'string') {
    const lower = raw.trim().toLowerCase()
    if (lower === 'critical' || lower === 'high' || lower === 'medium' || lower === 'low' || lower === 'info') {
      return lower
    }
    if (lower === 'informational') return 'info'
  }
  return 'info'
}

function cveSeverity(node: DeltaNode): AlertSeverity {
  const props = node.properties ?? {}
  if (typeof props.severity === 'string') return normalizeAlertSeverity(props.severity)
  if (typeof props.cvss_severity === 'string') return normalizeAlertSeverity(props.cvss_severity)
  const score = Number(props.cvss ?? props.cvss_score ?? props.base_score)
  if (Number.isFinite(score)) {
    if (score >= 9.0) return 'critical'
    if (score >= 7.0) return 'high'
    if (score >= 4.0) return 'medium'
    if (score > 0) return 'low'
  }
  return 'info'
}

function safePortLabel(node: DeltaNode): string {
  const props = node.properties ?? {}
  const ip = typeof props.ip_address === 'string' ? props.ip_address : ''
  const num = props.number !== undefined ? String(props.number) : ''
  const proto = typeof props.protocol === 'string' ? props.protocol : 'tcp'
  if (ip && num) return `${ip}:${num}/${proto}`
  return node.name || 'port'
}

function safeTarget(node: DeltaNode): string | undefined {
  const props = node.properties ?? {}
  const candidates = [props.matched_at, props.url, props.ip_address, props.host, props.address]
  for (const c of candidates) {
    if (typeof c === 'string' && c.trim().length > 0) {
      return c.trim().slice(0, 160)
    }
  }
  return undefined
}

export interface EvaluatedDeltaRelevance {
  shouldAlert: boolean
  counts: {
    newVulnerabilities: number
    newCves: number
    newlyExposedPorts: number
    newHosts: number
  }
  topItems: DeltaAlertTopItem[]
  deltaHash: string
}

/**
 * Evaluates a `ReconDelta` against project alert thresholds and constructs a
 * secret-free summary + deterministic hash (`Secret` nodes, `raw_context`,
 * and `unmasked_*` fields are never inspected or forwarded).
 */
export function evaluateDeltaRelevance(
  delta: ReconDelta,
  thresholds: DeltaAlertThresholds,
): EvaluatedDeltaRelevance {
  const minRank = SEVERITY_RANK[thresholds.minVulnSeverity]

  const matchedVulns = delta.lenses.newVulnerabilities.filter((n) => {
    const sev = normalizeAlertSeverity(n.properties?.severity)
    return SEVERITY_RANK[sev] >= minRank
  })

  const matchedCves = delta.lenses.newCves.filter((n) => {
    const sev = cveSeverity(n)
    return SEVERITY_RANK[sev] >= minRank
  })

  const matchedPorts = thresholds.alertOnNewPorts ? delta.lenses.newlyExposedPorts : []

  const matchedHosts = thresholds.alertOnNewHosts
    ? delta.addedNodes.filter((n) => HOST_NODE_TYPES.has(n.type))
    : []

  const shouldAlert =
    matchedVulns.length > 0 ||
    matchedCves.length > 0 ||
    matchedPorts.length > 0 ||
    matchedHosts.length > 0

  const items: DeltaAlertTopItem[] = []

  for (const v of matchedVulns) {
    items.push({
      category: 'vulnerability',
      severity: normalizeAlertSeverity(v.properties?.severity),
      title: String(v.name || v.properties?.template_id || 'Vulnerability').slice(0, 160),
      target: safeTarget(v),
    })
  }
  for (const c of matchedCves) {
    items.push({
      category: 'cve',
      severity: cveSeverity(c),
      title: String(c.properties?.id || c.name || 'CVE').slice(0, 160),
    })
  }
  for (const p of matchedPorts) {
    items.push({
      category: 'port',
      severity: 'medium',
      title: `Exposed port ${safePortLabel(p)}`.slice(0, 160),
      target: typeof p.properties?.ip_address === 'string' ? p.properties.ip_address : undefined,
    })
  }
  for (const h of matchedHosts) {
    items.push({
      category: 'host',
      severity: 'info',
      title: `${h.type}: ${String(h.name || h.properties?.address || h.key)}`.slice(0, 160),
    })
  }

  items.sort((a, b) => {
    const rankDiff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
    if (rankDiff !== 0) return rankDiff
    return a.title.localeCompare(b.title)
  })

  const matchedKeys = [
    ...matchedVulns.map((n) => `v:${n.key}`),
    ...matchedCves.map((n) => `c:${n.key}`),
    ...matchedPorts.map((n) => `p:${n.key}`),
    ...matchedHosts.map((n) => `h:${n.key}`),
  ].sort()

  const deltaHash = createHash('sha256')
    .update(
      JSON.stringify({
        thresholds,
        keys: matchedKeys,
      }),
    )
    .digest('hex')
    .slice(0, 24)

  return {
    shouldAlert,
    counts: {
      newVulnerabilities: matchedVulns.length,
      newCves: matchedCves.length,
      newlyExposedPorts: matchedPorts.length,
      newHosts: matchedHosts.length,
    },
    topItems: items.slice(0, MAX_TOP_ITEMS),
    deltaHash,
  }
}

export function buildDedupKey(
  projectId: string,
  toVersionKey: string,
  deltaHash: string,
  channelId: string,
): string {
  return `${projectId}:${toVersionKey}:${deltaHash}:${channelId}`
}

export function buildDeltaAlertPayload(params: {
  event?: 'recon.delta' | 'recon.delta.test'
  projectId: string
  projectName: string
  scanJobId: string | null
  scheduleId: string | null
  fromVersionId: string | null
  toVersionId: string | null
  relevance: EvaluatedDeltaRelevance
  triggeredAt?: string
}): DeltaAlertSummaryPayload {
  const fromParam = encodeURIComponent(params.fromVersionId ?? '')
  const toParam = encodeURIComponent(params.toVersionId ?? 'current')
  const projectParam = encodeURIComponent(params.projectId)

  return {
    event: params.event ?? 'recon.delta',
    projectId: params.projectId,
    projectName: params.projectName,
    scanJobId: params.scanJobId,
    scheduleId: params.scheduleId,
    fromVersionId: params.fromVersionId,
    toVersionId: params.toVersionId,
    triggeredAt: params.triggeredAt ?? new Date().toISOString(),
    summary: { ...params.relevance.counts },
    topItems: params.relevance.topItems,
    deltaPath: `/graph?projectId=${projectParam}&deltaFrom=${fromParam}&deltaTo=${toParam}`,
  }
}

export function formatSlackPayload(summary: DeltaAlertSummaryPayload): Record<string, unknown> {
  const prefix = summary.event === 'recon.delta.test' ? '[TEST] ' : ''
  const headerText = `${prefix}RedAmon Recon Delta Alert — ${summary.projectName}`
  const countsLine = [
    `Vulns: ${summary.summary.newVulnerabilities}`,
    `CVEs: ${summary.summary.newCves}`,
    `Ports: ${summary.summary.newlyExposedPorts}`,
    `Hosts: ${summary.summary.newHosts}`,
  ].join(' | ')

  const itemLines = summary.topItems.map((item) => {
    const targetSuffix = item.target ? ` (${item.target})` : ''
    return `• [${item.severity.toUpperCase()}] ${item.title}${targetSuffix}`
  })

  const fallbackText = `${headerText} — ${countsLine}`
  const blocks: Array<Record<string, unknown>> = [
    {
      type: 'header',
      text: { type: 'plain_text', text: headerText.slice(0, 150) },
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Summary:* ${countsLine}\n*Delta:* \`${summary.deltaPath}\``,
      },
    },
  ]

  if (itemLines.length > 0) {
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Top Findings:*\n${itemLines.join('\n').slice(0, 2800)}`,
      },
    })
  }

  return { text: fallbackText, blocks }
}

export function computeBackoffMs(attempt: number): number {
  return Math.min(30_000 * 2 ** Math.max(0, attempt - 1), 3_600_000)
}
