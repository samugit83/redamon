import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { DECLARED_ONLY } from '@/lib/declaredOnly'
import { ipVersionIs } from '@/lib/ipVersion'
import { internalError } from '@/lib/routeErrors'
import { currentDns } from '@/lib/graph/forwardDns'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    // Q1: Node counts by label
    const nodeCountsResult = await session.run(
      `MATCH (n {project_id: $pid}) WHERE ${notMuted('n')}
       RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC`,
      { pid: projectId }
    )
    const nodeCounts = nodeCountsResult.records.map(r => ({
      label: r.get('label') as string,
      count: toNum(r.get('count')),
    }))
    const totalNodes = nodeCounts.reduce((sum, n) => sum + n.count, 0)

    // Q2: Relationship counts by type
    const relCountsResult = await session.run(
      `MATCH (n {project_id: $pid})-[r]->(m) WHERE ${notMuted('n')} AND ${notMuted('m')}
       RETURN type(r) AS type, count(r) AS count ORDER BY count DESC`,
      { pid: projectId }
    )
    const relationshipCounts = relCountsResult.records.map(r => ({
      type: r.get('type') as string,
      count: toNum(r.get('count')),
    }))
    const totalRelationships = relationshipCounts.reduce((sum, r) => sum + r.count, 0)

    // Q3: Subdomain stats (Subdomain -[:BELONGS_TO]-> Domain)
    const subResult = await session.run(
      `MATCH (s:Subdomain {project_id: $pid})-[:BELONGS_TO]->(d:Domain)
       OPTIONAL MATCH (s)-[dnsr:RESOLVES_TO]->(i:IP) WHERE ${currentDns('dnsr')}
       RETURN count(DISTINCT s) AS total,
              count(DISTINCT CASE WHEN i IS NOT NULL THEN s END) AS resolved,
              count(DISTINCT i) AS uniqueIps`,
      { pid: projectId }
    )
    const subRec = subResult.records[0]
    const subdomainStats = subRec
      ? { total: toNum(subRec.get('total')), resolved: toNum(subRec.get('resolved')), uniqueIps: toNum(subRec.get('uniqueIps')) }
      : { total: 0, resolved: 0, uniqueIps: 0 }

    // Q4: Endpoint coverage. Observed only: an endpoint known only from an API
    // specification is counted apart, so the posture radar is not inflated.
    const epResult = await session.run(
      `MATCH (b:BaseURL {project_id: $pid})
       OPTIONAL MATCH (b)-[:HAS_ENDPOINT]->(e:Endpoint)
       OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(p:Parameter)
       WITH b, e, p, ${DECLARED_ONLY('e')} AS declared
       RETURN count(DISTINCT b) AS baseUrls,
              count(DISTINCT CASE WHEN NOT declared THEN e END) AS endpoints,
              count(DISTINCT CASE WHEN NOT declared THEN p END) AS parameters,
              count(DISTINCT CASE WHEN declared THEN e END) AS declaredEndpoints,
              count(DISTINCT CASE WHEN declared THEN p END) AS declaredParameters`,
      { pid: projectId }
    )
    const epRec = epResult.records[0]
    const endpointCoverage = epRec
      ? { baseUrls: toNum(epRec.get('baseUrls')), endpoints: toNum(epRec.get('endpoints')), parameters: toNum(epRec.get('parameters')),
          declaredEndpoints: toNum(epRec.get('declaredEndpoints')), declaredParameters: toNum(epRec.get('declaredParameters')) }
      : { baseUrls: 0, endpoints: 0, parameters: 0, declaredEndpoints: 0, declaredParameters: 0 }

    // Q5: Certificate health - match both BaseURL and IP certificate paths,
    // cast string not_after to datetime for correct comparison
    const certResult = await session.run(
      `MATCH (c:Certificate {project_id: $pid})
       WHERE (:BaseURL {project_id: $pid})-[:HAS_CERTIFICATE]->(c)
          OR (:IP {project_id: $pid})-[:HAS_CERTIFICATE]->(c)
       WITH DISTINCT c,
            CASE WHEN c.not_after IS NOT NULL
                 THEN datetime(replace(c.not_after, 'Z', '+00:00'))
                 ELSE null END AS expiry
       RETURN count(c) AS total,
              count(CASE WHEN expiry IS NOT NULL AND expiry < datetime() THEN 1 END) AS expired,
              count(CASE WHEN expiry IS NOT NULL AND expiry >= datetime()
                              AND expiry < datetime() + duration('P30D') THEN 1 END) AS expiringSoon,
              count(CASE WHEN c.self_signed = true THEN 1 END) AS selfSigned,
              count(CASE WHEN c.mismatched = true THEN 1 END) AS mismatched`,
      { pid: projectId }
    )
    const certRec = certResult.records[0]
    const certificateHealth = certRec
      ? { total: toNum(certRec.get('total')), expired: toNum(certRec.get('expired')), expiringSoon: toNum(certRec.get('expiringSoon')),
          selfSigned: toNum(certRec.get('selfSigned')), mismatched: toNum(certRec.get('mismatched')) }
      : { total: 0, expired: 0, expiringSoon: 0, selfSigned: 0, mismatched: 0 }

    // Q6: Degree centrality (top 15)
    const degResult = await session.run(
      `MATCH (n {project_id: $pid})
       WHERE ${notMuted('n')}
       WITH n, labels(n)[0] AS label,
            COALESCE(n.name, n.id, n.title, n.cve_id, n.address, n.url, n.subdomain, n.domain, n.capec_id, n.type, n.value, n.key, toString(n.number), labels(n)[0] + '#' + toString(elementId(n))) AS name,
            size([(n)-[]-() | 1]) AS degree
       RETURN label, name, degree ORDER BY degree DESC LIMIT 10`,
      { pid: projectId }
    )
    const topConnected = degResult.records.map(r => ({
      label: r.get('label') as string,
      name: (r.get('name') as string) || 'unknown',
      degree: toNum(r.get('degree')),
    }))

    // Q7: Infrastructure stats (IP breakdown)
    const infraResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})
       RETURN count(ip) AS total,
              count(CASE WHEN ${ipVersionIs('ip', 'ipv4')} THEN 1 END) AS ipv4,
              count(CASE WHEN ${ipVersionIs('ip', 'ipv6')} THEN 1 END) AS ipv6,
              count(CASE WHEN ip.is_cdn = true THEN 1 END) AS cdnCount,
              count(DISTINCT CASE WHEN ip.asn IS NOT NULL THEN ip.asn END) AS uniqueAsns,
              count(DISTINCT CASE WHEN ip.cdn_name IS NOT NULL THEN ip.cdn_name END) AS uniqueCdns`,
      { pid: projectId }
    )
    const infraRec = infraResult.records[0]
    const infrastructureStats = infraRec
      ? {
          totalIps: toNum(infraRec.get('total')),
          ipv4: toNum(infraRec.get('ipv4')),
          ipv6: toNum(infraRec.get('ipv6')),
          cdnCount: toNum(infraRec.get('cdnCount')),
          uniqueAsns: toNum(infraRec.get('uniqueAsns')),
          uniqueCdns: toNum(infraRec.get('uniqueCdns')),
        }
      : { totalIps: 0, ipv4: 0, ipv6: 0, cdnCount: 0, uniqueAsns: 0, uniqueCdns: 0 }

    return NextResponse.json({
      nodeCounts,
      relationshipCounts,
      totalNodes,
      totalRelationships,
      subdomainStats,
      endpointCoverage,
      certificateHealth,
      topConnected,
      infrastructureStats,
    })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Analytics graph-overview error' })
  } finally {
    await session.close()
  }
}
