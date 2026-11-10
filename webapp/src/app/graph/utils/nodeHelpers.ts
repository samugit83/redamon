import { GraphNode, GlowLevel } from '../types'
import { isHttpUrl } from '@/lib/url-utils'
import {
  NODE_COLORS,
  SEVERITY_COLORS_VULN,
  SEVERITY_COLORS_CVE,
  NODE_SIZES,
  SEVERITY_SIZE_MULTIPLIERS,
  GOAL_FINDING_TYPES,
  GOAL_FINDING_COLORS,
  CLUSTER_SIZE,
} from '../config'

const HOSTNAME_NODE_TYPES = new Set([
  'Domain',
  'Subdomain',
  'Host',
  'Hostname',
])

const IP_NODE_TYPES = new Set(['IP', 'IPAddress', 'IpAddress'])

/**
 * Build a browser-openable URL from a node type + name pair, or null if it
 * isn't web-addressable. https for hostnames, http for IPs, pass-through if
 * the name already includes a scheme.
 */
export const getUrlForTypeName = (type: string, name: string | null | undefined): string | null => {
  const trimmed = (name || '').trim()
  if (!trimmed) return null
  if (isHttpUrl(trimmed)) return trimmed
  if (HOSTNAME_NODE_TYPES.has(type)) return `https://${trimmed}`
  if (IP_NODE_TYPES.has(type)) return `http://${trimmed}`
  return null
}

/**
 * Build a browser-openable URL for an Endpoint node by combining its `baseurl`
 * with its `path` (or using `full_url` directly), or null if it isn't openable.
 *
 * Only GET endpoints are linkable - clicking a link issues a GET, so POST/PUT/etc.
 * endpoints aren't meaningfully reachable from a browser. The method is read from
 * the `method` property, falling back to the leading token of the name ("GET /x").
 */
const getEndpointUrl = (props: Record<string, unknown>, name: string): string | null => {
  const nameMethod = (name || '').trim().split(/\s+/)[0]?.toUpperCase()
  const method = (typeof props.method === 'string' ? props.method : nameMethod || '').toUpperCase()
  if (method && method !== 'GET') return null

  if (isHttpUrl(props.full_url)) return props.full_url

  const base = typeof props.baseurl === 'string' ? props.baseurl.trim().replace(/\/$/, '') : ''
  if (!isHttpUrl(base)) return null

  let path = typeof props.path === 'string' ? props.path : ''
  if (!path) {
    // Derive the path from the name: "GET /transactions/123" -> "/transactions/123"
    const parts = (name || '').trim().split(/\s+/)
    path = parts.length > 1 ? parts.slice(1).join(' ') : ''
  }
  if (path && !path.startsWith('/')) path = `/${path}`
  return `${base}${path}`
}

/**
 * Build a browser-openable URL for a node, or null if it's not web-addressable.
 * Prefers the full link recon kept with its secret in it (`unmasked_url`: a
 * leaked reset link, a URL that carried a key) so a click opens what was
 * found, then an explicit `url`/`endpoint`/`href` property, then handles
 * Endpoint nodes (baseurl + path), then derives one from the node type + name.
 */
export const getNodeUrl = (node: GraphNode): string | null => {
  const props = node.properties || {}
  const candidates = [props.unmasked_url, props.url, props.endpoint, props.href]
  for (const c of candidates) {
    if (isHttpUrl(c)) return c
  }
  if (node.type === 'Endpoint') return getEndpointUrl(props, node.name)
  return getUrlForTypeName(node.type, node.name)
}

/**
 * Get the severity level from a node's properties
 */
export const getNodeSeverity = (node: GraphNode): string => {
  return (node.properties?.severity as string)?.toLowerCase() || 'unknown'
}

/**
 * Check if a ChainFinding node represents a goal/outcome (exploit success, access gained, etc.)
 */
export const isGoalFinding = (node: GraphNode): boolean => {
  if (node.type !== 'ChainFinding') return false
  const findingType = (node.properties?.finding_type as string || '').toLowerCase()
  return GOAL_FINDING_TYPES.has(findingType)
}

/**
 * Get node color based on type and severity
 */
/**
 * Recon Delta overlay palette (Section 6.3): green = new, red = removed,
 * amber = changed, grey = unchanged.
 */
export const DELTA_STATE_COLORS: Record<string, string> = {
  added: '#059669',
  removed: '#ef4444',
  changed: '#f59e0b',
  stable: '#6b7280',
}

export const getNodeColor = (node: GraphNode): string => {
  // In compare mode the delta state is the ONLY thing the color should convey.
  if (node.deltaState) return DELTA_STATE_COLORS[node.deltaState] ?? DELTA_STATE_COLORS.stable
  if (node.isCluster && node.clusterColor) return node.clusterColor
  if (node.type === 'Vulnerability') {
    const severity = getNodeSeverity(node)
    return SEVERITY_COLORS_VULN[severity] || SEVERITY_COLORS_VULN.unknown
  }
  if (node.type === 'CVE') {
    const severity = getNodeSeverity(node)
    return SEVERITY_COLORS_CVE[severity] || SEVERITY_COLORS_CVE.unknown
  }
  // Goal ChainFindings get green (active color - canvas overrides for inactive)
  if (isGoalFinding(node)) {
    return GOAL_FINDING_COLORS.active
  }
  // A Multiscanner finding's colour carries its validation state: a credential
  // CONFIRMED live by the owning API is the single most actionable node on the
  // graph and must be unmistakable. One label cannot express that, and sixteen
  // labels would (the renderer draws labels[0]), so it resolves on
  // (type, validation_status) instead.
  if (node.type === 'MultiscannerFinding' && isValidatedFinding(node)) {
    return NODE_COLORS.Secret ?? NODE_COLORS.Default
  }
  return NODE_COLORS[node.type] || NODE_COLORS.Default
}

/** A finding the owning API confirmed is live. NOT the same as `verified`
 *  being false — that conflates "checked, dead" with "never checked". */
const isValidatedFinding = (node: GraphNode): boolean =>
  String((node as unknown as Record<string, unknown>).validation_status ?? '') === 'validated'

/**
 * Get node size multiplier based on type and severity
 */
export const getNodeSize = (node: GraphNode): number => {
  if (node.isCluster) {
    const count = node.clusterChildren?.length ?? 0
    // log10(count) scales gracefully: 30 -> ~1.5, 100 -> 2, 1000 -> 3
    const scaled = CLUSTER_SIZE.base + CLUSTER_SIZE.perDecade * Math.log10(Math.max(count, 1))
    return Math.min(scaled, CLUSTER_SIZE.max)
  }
  const baseSize = NODE_SIZES[node.type] || NODE_SIZES.Default

  if (node.type === 'Vulnerability' || node.type === 'CVE') {
    const severity = getNodeSeverity(node)
    const severityMultiplier = SEVERITY_SIZE_MULTIPLIERS[severity] || 1.0
    return baseSize * severityMultiplier
  }

  // Same rationale as the colour override: a live credential outranks every
  // other finding on the canvas.
  if (node.type === 'MultiscannerFinding' && isValidatedFinding(node)) {
    return baseSize * 1.8
  }

  return baseSize
}

/**
 * Check if a node should have glow effect (critical/high severity)
 * Returns: false, 'high', or 'critical'
 */
export const getGlowLevel = (node: GraphNode): GlowLevel => {
  // ExploitGvm and ChainFinding nodes always glow (confirmed compromise)
  if (node.type === 'ExploitGvm' || node.type === 'ChainFinding') return 'critical'
  if (node.type === 'Vulnerability' || node.type === 'CVE') {
    const severity = getNodeSeverity(node)
    if (severity === 'critical') return 'critical'
    if (severity === 'high') return 'high'
  }
  return false
}

/**
 * Check if a node is a high-severity vulnerability or CVE
 */
export const isHighSeverityNode = (node: GraphNode): boolean => {
  // ExploitGvm and ChainFinding nodes are always high-severity (confirmed compromise)
  if (node.type === 'ExploitGvm' || node.type === 'ChainFinding') return true
  if (node.type !== 'Vulnerability' && node.type !== 'CVE') return false
  const severity = getNodeSeverity(node)
  return severity === 'critical' || severity === 'high'
}

/**
 * Check if any nodes in the data have high severity
 */
export const hasHighSeverityNodes = (nodes: GraphNode[]): boolean => {
  return nodes.some(isHighSeverityNode)
}
