import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { DECLARED_ONLY } from '@/lib/declaredOnly'
import { internalError } from '@/lib/routeErrors'
import { currentDns } from '@/lib/graph/forwardDns'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(projectId || '')
  if (__denied) return __denied
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    // Q1: Exposed services
    const svcResult = await session.run(
      `MATCH (:IP {project_id: $pid})-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
       RETURN s.name AS service, p.number AS port, count(DISTINCT p) AS count
       ORDER BY count DESC LIMIT 25`,
      { pid: projectId }
    )
    const services = svcResult.records.map(r => ({
      service: (r.get('service') as string) || 'unknown',
      port: toNum(r.get('port')),
      count: toNum(r.get('count')),
    }))

    // Q2: Port distribution
    const portResult = await session.run(
      `MATCH (:IP {project_id: $pid})-[:HAS_PORT]->(p:Port)
       RETURN p.number AS port, p.protocol AS protocol, count(p) AS count
       ORDER BY count DESC LIMIT 25`,
      { pid: projectId }
    )
    const ports = portResult.records.map(r => ({
      port: toNum(r.get('port')),
      protocol: (r.get('protocol') as string) || 'tcp',
      count: toNum(r.get('count')),
    }))

    // Q3: Technology breakdown with CVE counts
    const techResult = await session.run(
      `MATCH (:BaseURL {project_id: $pid})-[:USES_TECHNOLOGY]->(t:Technology)
       OPTIONAL MATCH (t)-[:HAS_KNOWN_CVE]->(c:CVE)
       RETURN t.name AS name, t.version AS version, count(DISTINCT c) AS cveCount
       ORDER BY cveCount DESC, name ASC`,
      { pid: projectId }
    )
    const technologies = techResult.records.map(r => ({
      name: (r.get('name') as string) || 'Unknown',
      version: r.get('version') as string | null,
      cveCount: toNum(r.get('cveCount')),
    }))

    // Q4: DNS record types
    const dnsResult = await session.run(
      `MATCH (:Subdomain {project_id: $pid})-[:HAS_DNS_RECORD]->(d:DNSRecord)
       RETURN d.type AS type, count(d) AS count ORDER BY count DESC`,
      { pid: projectId }
    )
    const dnsRecords = dnsResult.records.map(r => ({
      type: (r.get('type') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    // Q5: Security headers - actual headers from graph grouped by is_security_header
    const secHdrResult = await session.run(
      `MATCH (:BaseURL {project_id: $pid})-[:HAS_HEADER]->(h:Header)
       RETURN h.name AS name,
         COALESCE(h.is_security_header, false) AS isSecurity,
         count(h) AS count
       ORDER BY count DESC`,
      { pid: projectId }
    )
    const securityHeaders = secHdrResult.records.map(r => ({
      name: (r.get('name') as string) || 'unknown',
      isSecurity: r.get('isSecurity') as boolean,
      count: toNum(r.get('count')),
    }))

    // Q6: Header categories
    const hdrCatResult = await session.run(
      `MATCH (:BaseURL {project_id: $pid})-[:HAS_HEADER]->(h:Header)
       RETURN CASE
         WHEN h.is_security_header = true THEN 'Security'
         WHEN h.reveals_technology = true THEN 'Tech-Revealing'
         ELSE 'Informational'
       END AS category, count(DISTINCT h.name) AS count
       ORDER BY count DESC`,
      { pid: projectId }
    )
    const headerCategories = hdrCatResult.records.map(r => ({
      category: (r.get('category') as string) || 'Informational',
      count: toNum(r.get('count')),
    }))

    // An endpoint known only from an API specification is documented, not
    // observed: Q7-Q9 count it apart, so the surface (and the risk gauge and
    // posture radar built on Q9) is not inflated by declarations.

    // Q7: Endpoint categories
    const epCatResult = await session.run(
      `MATCH (:BaseURL {project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
       WITH e, ${DECLARED_ONLY('e')} AS declared
       RETURN COALESCE(e.category, 'other') AS category,
              count(CASE WHEN NOT declared THEN 1 END) AS count,
              count(CASE WHEN declared THEN 1 END) AS declared
       ORDER BY count DESC, declared DESC`,
      { pid: projectId }
    )
    const endpointCategories = epCatResult.records.map(r => ({
      category: (r.get('category') as string) || 'other',
      count: toNum(r.get('count')),
      declared: toNum(r.get('declared')),
    }))

    // Q8: Endpoint types (form / parameterized / static)
    const epTypeResult = await session.run(
      `MATCH (:BaseURL {project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
       WITH e, ${DECLARED_ONLY('e')} AS declared
       RETURN CASE
         WHEN e.is_form = true THEN 'Form'
         WHEN e.has_parameters = true THEN 'Parameterized'
         ELSE 'Static'
       END AS type,
       count(CASE WHEN NOT declared THEN 1 END) AS count,
       count(CASE WHEN declared THEN 1 END) AS declared
       ORDER BY count DESC, declared DESC`,
      { pid: projectId }
    )
    const endpointTypes = epTypeResult.records.map(r => ({
      type: (r.get('type') as string) || 'Static',
      count: toNum(r.get('count')),
      declared: toNum(r.get('declared')),
    }))

    // Q9: Parameter analysis by position
    const paramResult = await session.run(
      `MATCH (:BaseURL {project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_PARAMETER]->(p:Parameter)
       WITH e, p, ${DECLARED_ONLY('e')} AS declared
       RETURN COALESCE(p.position, 'unknown') AS position,
              count(CASE WHEN NOT declared THEN 1 END) AS total,
              count(CASE WHEN NOT declared AND p.is_injectable = true THEN 1 END) AS injectable,
              count(CASE WHEN declared THEN 1 END) AS declared
       ORDER BY total DESC, declared DESC`,
      { pid: projectId }
    )
    const parameterAnalysis = paramResult.records.map(r => ({
      position: (r.get('position') as string) || 'unknown',
      total: toNum(r.get('total')),
      injectable: toNum(r.get('injectable')),
      declared: toNum(r.get('declared')),
    }))

    // Q10: CDN distribution
    const cdnResult = await session.run(
      `MATCH (ip:IP {project_id: $pid})
       RETURN CASE WHEN ip.is_cdn = true THEN ip.cdn_name ELSE 'Direct (No CDN)' END AS segment,
              count(ip) AS count
       ORDER BY count DESC`,
      { pid: projectId }
    )
    const cdnDistribution = cdnResult.records.map(r => ({
      segment: (r.get('segment') as string) || 'Direct (No CDN)',
      count: toNum(r.get('count')),
    }))

    // Q11: IP concentration (subdomains per IP)
    const ipConcResult = await session.run(
      `MATCH (s:Subdomain {project_id: $pid})-[dnsr:RESOLVES_TO]->(ip:IP)
       WHERE ${currentDns('dnsr')}
       WITH ip.address AS ip, count(s) AS subCount,
            CASE WHEN ip.is_cdn = true THEN true ELSE false END AS isCdn
       RETURN ip, subCount, isCdn
       ORDER BY subCount DESC LIMIT 15`,
      { pid: projectId }
    )
    const ipConcentration = ipConcResult.records.map(r => ({
      ip: (r.get('ip') as string) || '',
      subCount: toNum(r.get('subCount')),
      isCdn: r.get('isCdn') as boolean,
    }))

    return NextResponse.json({
      services, ports, technologies, dnsRecords,
      securityHeaders, headerCategories,
      endpointCategories, endpointTypes, parameterAnalysis,
      cdnDistribution, ipConcentration,
    })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Analytics attack-surface error' })
  } finally {
    await session.close()
  }
}
