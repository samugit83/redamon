import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/neo4j'

interface Neo4jNode {
  identity: { low: number; high: number }
  labels: string[]
  properties: Record<string, unknown>
}

interface Neo4jRelationship {
  identity: { low: number; high: number }
  start: { low: number; high: number }
  end: { low: number; high: number }
  type: string
  properties: Record<string, unknown>
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const projectId = searchParams.get('projectId')

  if (!projectId) {
    return NextResponse.json(
      { error: 'projectId is required' },
      { status: 400 }
    )
  }

  const session = getSession()

  try {
    const result = await session.run(
      `
      MATCH (n)-[r]->(m)
      WHERE n.project_id = $projectId OR m.project_id = $projectId
      RETURN n, r, m
      LIMIT 500
      `,
      { projectId }
    )

    const nodesMap = new Map<string, { id: string; name: string; type: string; properties: Record<string, unknown> }>()
    const links: { source: string; target: string; type: string }[] = []

    result.records.forEach((record) => {
      const sourceNode = record.get('n') as Neo4jNode
      const targetNode = record.get('m') as Neo4jNode
      const relationship = record.get('r') as Neo4jRelationship

      const sourceId = `${sourceNode.identity.low}`
      const targetId = `${targetNode.identity.low}`

      if (!nodesMap.has(sourceId)) {
        nodesMap.set(sourceId, {
          id: sourceId,
          name: getNodeName(sourceNode),
          type: sourceNode.labels[0] || 'Unknown',
          properties: serializeProperties(sourceNode.properties),
        })
      }

      if (!nodesMap.has(targetId)) {
        nodesMap.set(targetId, {
          id: targetId,
          name: getNodeName(targetNode),
          type: targetNode.labels[0] || 'Unknown',
          properties: serializeProperties(targetNode.properties),
        })
      }

      links.push({
        source: sourceId,
        target: targetId,
        type: relationship.type,
      })
    })

    const nodes = Array.from(nodesMap.values())

    return NextResponse.json({
      nodes,
      links,
      projectId,
    })
  } catch (error) {
    console.error('Graph query error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}

function getNodeName(node: Neo4jNode): string {
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
        // Show host + path (without protocol)
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
      // Truncate long header values
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
      // Truncate long CWE names
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
      // Truncate long CAPEC names
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

  // Special handling for BaseURL nodes - show URL
  if (label === 'BaseURL') {
    const url = props.url as string || ''
    if (url) {
      try {
        const urlObj = new URL(url)
        return urlObj.host + (urlObj.pathname !== '/' ? urlObj.pathname : '')
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

function serializeProperties(props: Record<string, unknown>): Record<string, unknown> {
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
