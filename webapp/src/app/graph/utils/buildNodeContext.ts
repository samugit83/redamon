import type { GraphData, GraphNode } from '../types'
import { HIDDEN_KEYS } from './hiddenKeys'
import { formatNeo4jDateTime } from './formatters'
import { getNodeId } from './linkHelpers'
import { getNodeSeverity, getNodeUrl } from './nodeHelpers'
import { TRIAGE_TEXT_PROPERTIES } from '@/lib/triage/properties'
import { DISPLAY_ONLY_PROPS } from '@/lib/secrets/secretProps'
import { type ScopeGroup, groupLabel } from '@/lib/scopeGroups'

// Text a review model or an external MCP agent wrote, and the JSON blobs that
// carry it. The agent this context goes to has tools, so none of it is handed
// over; the agent fences the rest as untrusted too (prompt_safety).
// A secret and a full link with its secret in it are for the operator's UI:
// the agent reads the masked fields, as its graph queries do.
const DROPPED_KEYS: ReadonlySet<string> = new Set([...TRIAGE_TEXT_PROPERTIES, ...DISPLAY_ONLY_PROPS])

/** The node as the agent may see it: no display-only property, so its URL is the masked one. */
function agentView(node: GraphNode): GraphNode {
  const properties = Object.fromEntries(
    Object.entries(node.properties || {}).filter(([key]) => !DISPLAY_ONLY_PROPS.has(key)))
  return { ...node, properties }
}

// The 30-per-type cap keeps a hub node (a Domain wired to hundreds of
// subdomains) from producing a context blob too large to be useful as a prompt.
const MAX_RELATIONS_PER_GROUP = 30
// A single blob property (a response body, a PEM chain) must not swamp the
// prompt; the agent can read the full value from the graph if it needs it.
const MAX_VALUE_CHARS = 4000
const BOTTOM_KEYS = ['created_at', 'updated_at']

function capValue(value: string): string {
  if (value.length <= MAX_VALUE_CHARS) return value
  return `${value.slice(0, MAX_VALUE_CHARS)}… [truncated, ${value.length} chars total]`
}

function scalar(value: unknown): string {
  const dt = formatNeo4jDateTime(value)
  if (dt) return dt
  if (value === null || value === undefined || value === '') return ''
  if (Array.isArray(value)) return value.map(scalar).filter(Boolean).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim()

export function nodeLabel(node: GraphNode): string {
  return `${node.type}: ${oneLine(node.name)}`
}

function propertyLines(node: GraphNode): string[] {
  const entries = Object.entries(node.properties || {})
    .filter(([key]) => !HIDDEN_KEYS.has(key) && !DROPPED_KEYS.has(key))
    .sort(([a], [b]) => {
      const aBottom = BOTTOM_KEYS.includes(a)
      const bBottom = BOTTOM_KEYS.includes(b)
      if (aBottom && !bBottom) return 1
      if (!aBottom && bBottom) return -1
      return 0
    })
  const lines: string[] = []
  for (const [key, raw] of entries) {
    const value = scalar(raw)
    if (value) lines.push(`- ${key}: ${capValue(value)}`)
  }
  return lines
}

interface Relation {
  relType: string
  direction: '->' | '<-'
  other: GraphNode
}

function collectRelations(node: GraphNode, data: GraphData): Relation[] {
  const byId = new Map(data.nodes.map(n => [n.id, n]))
  const relations: Relation[] = []
  for (const link of data.links) {
    const srcId = getNodeId(link.source)
    const tgtId = getNodeId(link.target)
    if (srcId === node.id) {
      const other = byId.get(tgtId)
      if (other) relations.push({ relType: link.type, direction: '->', other })
    } else if (tgtId === node.id) {
      const other = byId.get(srcId)
      if (other) relations.push({ relType: link.type, direction: '<-', other })
    }
  }
  return relations
}

function relationLines(relations: Relation[]): string[] {
  if (relations.length === 0) return ['- (none in the loaded graph)']

  // Group by direction + relationship + neighbour type so 200 subdomains
  // collapse to one Cypher-style heading with a bounded, counted list rather
  // than 200 flat lines. Cypher notation leaves no doubt about direction.
  const groups = new Map<string, { direction: string; relType: string; otherType: string; others: GraphNode[] }>()
  for (const r of relations) {
    const key = `${r.direction}|${r.relType}|${r.other.type}`
    let group = groups.get(key)
    if (!group) {
      group = { direction: r.direction, relType: r.relType, otherType: r.other.type, others: [] }
      groups.set(key, group)
    }
    group.others.push(r.other)
  }

  const lines: string[] = []
  for (const group of groups.values()) {
    const pattern = group.direction === '->'
      ? `(this)-[:${group.relType}]->(:${group.otherType})`
      : `(:${group.otherType})-[:${group.relType}]->(this)`
    lines.push(`- ${pattern} x${group.others.length}:`)
    const shown = group.others.slice(0, MAX_RELATIONS_PER_GROUP)
    for (const other of shown) {
      // Names alone collide (every root Endpoint is "GET /"), so add the graph
      // id the agent can query by, and the URL when it says something new.
      const name = oneLine(other.name)
      const extra = [`id ${other.id}`]
      const url = getNodeUrl(agentView(other))
      if (url && oneLine(url) !== name) extra.push(oneLine(url))
      lines.push(`    - ${name} (${extra.join(', ')})`)
    }
    if (group.others.length > shown.length) {
      lines.push(`    - ...and ${group.others.length - shown.length} more`)
    }
  }
  return lines
}

export interface NodeContextOptions {
  projectName?: string
  targetDomain?: string
  /** The project's current scope groups: the scope is stated from them, so a
   *  batch (empty targetDomain) or a deeper scan root is never misnamed. */
  scopeGroups?: readonly ScopeGroup[]
}

// A batch can hold 50 groups; the context names the first ones.
const SCOPE_LINES = 10

/**
 * Build an LLM-ready Markdown description of a graph node: its identity,
 * properties, and how it connects to the rest of the attack-surface graph.
 * Used both for the clipboard "copy for an external agent" action and as the
 * context prepended to the first message of a node-scoped agent session.
 */
export function buildNodeContext(
  node: GraphNode,
  data: GraphData | null | undefined,
  options: NodeContextOptions = {},
): string {
  const sections: string[] = []

  const header = ['# Attack-surface graph node']
  if (options.projectName) header.push(`Project: ${options.projectName}`)
  if (options.scopeGroups?.length) {
    const shown = options.scopeGroups.slice(0, SCOPE_LINES).map(g => `- ${groupLabel(g)}`)
    if (options.scopeGroups.length > SCOPE_LINES) shown.push(`- ...and ${options.scopeGroups.length - SCOPE_LINES} more`)
    header.push(`Scope (scan roots; the graph's Domain nodes are their registrable domains):\n${shown.join('\n')}`)
  } else if (options.targetDomain) {
    header.push(`Target: ${options.targetDomain}`)
  }
  sections.push(header.join('\n'))

  const severity = getNodeSeverity(node)
  const identity = [
    `Type: ${node.type}`,
    `Name: ${oneLine(node.name)}`,
    `Graph ID: ${node.id}`,
  ]
  if (severity && severity !== 'unknown') identity.push(`Severity: ${severity}`)
  const url = getNodeUrl(agentView(node))
  if (url) identity.push(`URL: ${url}`)
  sections.push(`## Node\n${identity.map(l => `- ${l}`).join('\n')}`)

  const props = propertyLines(node)
  sections.push(`## Properties\n${props.length ? props.join('\n') : '- (no additional properties)'}`)

  const relations = data ? collectRelations(node, data) : []
  sections.push(`## Relationships\n${relationLines(relations).join('\n')}`)

  return sections.join('\n\n')
}
