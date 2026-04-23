/**
 * Shared graph formatting utilities for Neo4j query results.
 *
 * Used by:
 *   - GET /api/graph (main graph data endpoint)
 *   - POST /api/graph-views/execute (graph view preview)
 */

export interface Neo4jNode {
  identity: { low: number; high: number }
  labels: string[]
  properties: Record<string, unknown>
}

export interface Neo4jRelationship {
  identity: { low: number; high: number }
  start: { low: number; high: number }
  end: { low: number; high: number }
  type: string
  properties: Record<string, unknown>
}

export interface FormattedNode {
  id: string
  name: string
  type: string
  properties: Record<string, unknown>
}

export interface FormattedGraphData {
  nodes: FormattedNode[]
  links: { source: string; target: string; type: string }[]
}

/**
 * Format raw Neo4j records into nodes + links for GraphCanvas.
 *
 * Supports two result shapes:
 *   1. Graph patterns — records contain Neo4j Node / Relationship objects
 *      (e.g. MATCH (n)-[r]->(m) RETURN n, r, m)
 *   2. Tabular / aggregation — records contain scalar values
 *      (e.g. RETURN s.name, count(i) AS ip_count)
 *
 * For shape 1 we extract nodes and links from every Node and Relationship
 * found in the record, regardless of the variable names used in the Cypher.
 * For shape 2 we synthesise a virtual node per row so the graph canvas has
 * something to render.
 */
export function formatGraphRecords(records: any[]): FormattedGraphData {
  const nodesMap = new Map<string, FormattedNode>()
  const links: { source: string; target: string; type: string }[] = []

  records.forEach((record, rowIdx) => {
    const keys = record.keys as string[]
    const nodes: Neo4jNode[] = []
    const rels: Neo4jRelationship[] = []
    let hasGraphObjects = false

    // Scan every field in the record for Node / Relationship objects
    for (const key of keys) {
      const val = record.get(key)
      if (val && typeof val === 'object' && 'labels' in val && 'identity' in val) {
        // Neo4j Node
        nodes.push(val as Neo4jNode)
        hasGraphObjects = true
      } else if (val && typeof val === 'object' && 'type' in val && 'start' in val && 'end' in val) {
        // Neo4j Relationship
        rels.push(val as Neo4jRelationship)
        hasGraphObjects = true
      }
    }

    if (hasGraphObjects) {
      // Shape 1: graph pattern — register all nodes and relationships
      for (const node of nodes) {
        const id = `${node.identity.low}`
        if (!nodesMap.has(id)) {
          nodesMap.set(id, {
            id,
            name: getNodeName(node),
            type: node.labels[0] || 'Unknown',
            properties: serializeProperties(node.properties),
          })
        }
      }

      for (const rel of rels) {
        links.push({
          source: `${rel.start.low}`,
          target: `${rel.end.low}`,
          type: rel.type,
        })
      }
    } else {
      // Shape 2: tabular / aggregation — build a virtual node from the row
      const props: Record<string, unknown> = {}
      const nameParts: string[] = []
      for (const key of keys) {
        const val = record.get(key)
        const serialized = val && typeof val === 'object' && 'low' in val
          ? (val as { low: number }).low
          : val
        props[key] = serialized
        nameParts.push(`${serialized}`)
      }
      const id = `row-${rowIdx}`
      nodesMap.set(id, {
        id,
        name: nameParts.join(' | '),
        type: 'QueryResult',
        properties: props,
      })
    }
  })

  return { nodes: Array.from(nodesMap.values()), links }
}

export function getNodeName(node: Neo4jNode): string {
  const props = node.properties
  const label = node.labels[0]

  // Special handling for DNS records - show TYPE and value
  if (label === 'DNSRecord' || label === 'DNS') {
    const recordType = props.type as string || props.record_type as string || ''
    const value = props.value as string || props.data as string || ''
    if (recordType && value) {
      return `${recordType}\n${value}`
    }
  }

  // Special handling for Port nodes - show port number and protocol
  if (label === 'Port') {
    const portNumber = props.number as number || props.port as number || ''
    const protocol = props.protocol as string || 'tcp'
    if (portNumber) {
      return `${portNumber}/${protocol}`
    }
  }

  // Special handling for Service nodes - show service name with port
  if (label === 'Service') {
    const serviceName = props.name as string || ''
    const portNumber = props.port_number as number || ''
    if (serviceName && portNumber) {
      return `${serviceName}:${portNumber}`
    }
    if (serviceName) {
      return serviceName
    }
  }

  // Special handling for URL nodes - show host + path
  if (label === 'URL') {
    const url = props.url as string || ''
    if (url) {
      try {
        const urlObj = new URL(url)
        return urlObj.host + (urlObj.pathname !== '/' ? urlObj.pathname : '') + urlObj.search
      } catch {
        return url
      }
    }
  }

  // Special handling for Technology nodes - show name and version
  if (label === 'Technology') {
    const techName = props.name as string || ''
    const version = props.version as string || ''
    if (techName && version) {
      return `${techName} v${version}`
    }
    if (techName) {
      return techName
    }
  }

  // Special handling for Header nodes - show header name
  if (label === 'Header') {
    const headerName = props.name as string || ''
    const headerValue = props.value as string || ''
    if (headerName) {
      const truncatedValue = headerValue.length > 30 ? headerValue.substring(0, 30) + '...' : headerValue
      return truncatedValue ? `${headerName}: ${truncatedValue}` : headerName
    }
  }

  // Special handling for CVE nodes - show CVE ID and severity
  if (label === 'CVE') {
    const cveId = props.id as string || ''
    const severity = props.severity as string || ''
    const cvss = props.cvss as number
    if (cveId) {
      if (severity && cvss) {
        return `${cveId}\n${severity} (${cvss})`
      }
      if (severity) {
        return `${cveId}\n${severity}`
      }
      return cveId
    }
  }

  // Special handling for MitreData nodes - show CWE ID and name
  if (label === 'MitreData') {
    const cweId = props.cwe_id as string || ''
    const cweName = props.cwe_name as string || ''
    if (cweId && cweName) {
      const truncatedName = cweName.length > 30 ? cweName.substring(0, 30) + '...' : cweName
      return `${cweId}\n${truncatedName}`
    }
    if (cweId) {
      return cweId
    }
  }

  // Special handling for Capec nodes - show CAPEC ID and name
  if (label === 'Capec') {
    const capecId = props.capec_id as string || ''
    const capecName = props.name as string || ''
    const severity = props.severity as string || ''
    if (capecId && capecName) {
      const truncatedName = capecName.length > 25 ? capecName.substring(0, 25) + '...' : capecName
      if (severity) {
        return `${capecId}\n${truncatedName}\n[${severity}]`
      }
      return `${capecId}\n${truncatedName}`
    }
    if (capecId) {
      return capecId
    }
  }

  // Special handling for BaseURL nodes - show scheme + host + port
  if (label === 'BaseURL') {
    const url = props.url as string || ''
    if (url) {
      try {
        const urlObj = new URL(url)
        const scheme = urlObj.protocol.replace(':', '')
        return `${scheme}://${urlObj.host}`
      } catch {
        return url
      }
    }
  }

  // Special handling for Endpoint nodes - show method and path
  if (label === 'Endpoint') {
    const method = props.method as string || ''
    const path = props.path as string || ''
    if (method && path) {
      return `${method} ${path}`
    }
    if (path) {
      return path
    }
  }

  // Special handling for Parameter nodes - show name and position
  if (label === 'Parameter') {
    const paramName = props.name as string || ''
    const position = props.position as string || ''
    if (paramName && position) {
      return `${paramName} (${position})`
    }
    if (paramName) {
      return paramName
    }
  }

  // Special handling for ExploitGvm nodes - show attack type and target
  if (label === 'ExploitGvm') {
    const targetIp = props.target_ip as string || ''
    const cves = props.cve_ids as string[] || []
    return `GVM EXPLOIT\n${cves[0] || ''}\n${targetIp}`
  }

  // Special handling for AttackChain nodes - show title and status
  if (label === 'AttackChain') {
    const title = props.title as string || ''
    const status = props.status as string || ''
    const truncatedTitle = title.length > 30 ? title.substring(0, 30) + '...' : title
    if (truncatedTitle && status) {
      return `Step 0\nChain\n${truncatedTitle}\n[${status}]`
    }
    return `Step 0\n${truncatedTitle || 'Attack Chain'}`
  }

  // Special handling for ChainStep nodes - show iteration, tool, and success
  if (label === 'ChainStep') {
    const iteration = props.iteration as number
    const toolName = props.tool_name as string || ''
    const success = props.success as boolean
    const failTag = success === false ? '\n[FAIL]' : ''
    if (toolName) {
      return `Step ${iteration ?? '?'}\n${toolName}${failTag}`
    }
    return `Step ${iteration ?? '?'}`
  }

  // Special handling for ChainFinding nodes - show step, finding type and severity
  if (label === 'ChainFinding') {
    const iteration = props.iteration as number
    const findingType = props.finding_type as string || ''
    const severity = props.severity as string || ''
    const title = props.title as string || ''
    const truncatedTitle = title.length > 30 ? title.substring(0, 30) + '...' : title
    const stepPrefix = iteration != null ? `Step ${iteration}\n` : ''
    if (truncatedTitle) {
      return `${stepPrefix}${truncatedTitle}\n[${severity.toUpperCase()}]`
    }
    return `${stepPrefix}${findingType}\n[${severity.toUpperCase()}]`
  }

  // Special handling for ChainDecision nodes - show step, decision type and direction
  if (label === 'ChainDecision') {
    const iteration = props.iteration as number
    const decisionType = props.decision_type as string || ''
    const fromState = props.from_state as string || ''
    const toState = props.to_state as string || ''
    const stepPrefix = iteration != null ? `Step ${iteration}\n` : ''
    if (fromState && toState) {
      return `${stepPrefix}${decisionType}\n${fromState} \u2192 ${toState}`
    }
    return `${stepPrefix}${decisionType || 'Decision'}`
  }

  // Special handling for ChainFailure nodes - show step, failure type and tool
  if (label === 'ChainFailure') {
    const iteration = props.iteration as number
    const failureType = props.failure_type as string || ''
    const toolName = props.tool_name as string || ''
    const stepPrefix = iteration != null ? `Step ${iteration}\n` : ''
    if (toolName) {
      return `${stepPrefix}${failureType}\n${toolName}`
    }
    return `${stepPrefix}${failureType || 'Failure'}`
  }

  // Special handling for Vulnerability nodes - show name and severity
  if (label === 'Vulnerability') {
    const vulnName = props.name as string || props.template_id as string || ''
    const severity = props.severity as string || ''
    if (vulnName && severity) {
      const truncatedName = vulnName.length > 30 ? vulnName.substring(0, 30) + '...' : vulnName
      return `${truncatedName}\n[${severity.toUpperCase()}]`
    }
    if (vulnName) {
      return vulnName
    }
  }

  return (
    (props.name as string) ||
    (props.address as string) ||
    (props.domain as string) ||
    (props.subdomain as string) ||
    (props.ip as string) ||
    (props.host as string) ||
    (props.url as string) ||
    (props.value as string) ||
    (props.title as string) ||
    label ||
    'Unknown'
  )
}

export function serializeProperties(props: Record<string, unknown>): Record<string, unknown> {
  const serialized: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(props)) {
    if (value && typeof value === 'object' && 'low' in value && 'high' in value) {
      serialized[key] = (value as { low: number; high: number }).low
    } else if (Array.isArray(value)) {
      serialized[key] = value.map(v =>
        v && typeof v === 'object' && 'low' in v ? (v as { low: number }).low : v
      )
    } else {
      serialized[key] = value
    }
  }
  return serialized
}
