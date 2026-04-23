import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getSession()
  try {
    // Attack paths: Subdomain -> IP -> Port -> Service -> Technology -> CVE -> MitreData -> Capec
    // Aggregated per (subdomain, tech, cve) with CISA-KEV priority via ExploitGvm match.
    const result = await session.run(
      `MATCH (s:Subdomain {project_id: $pid})-[:RESOLVES_TO]->(ip:IP)
       OPTIONAL MATCH (ip)-[:HAS_PORT]->(p:Port)
       OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(svc:Service)
       OPTIONAL MATCH (svc)-[:USES_TECHNOLOGY]->(t:Technology)
       OPTIONAL MATCH (p)-[:HAS_TECHNOLOGY]->(t2:Technology)
       WITH s, ip, p, svc, coalesce(t, t2) AS tech
       WHERE tech IS NOT NULL
       MATCH (tech)-[:HAS_KNOWN_CVE]->(c:CVE)
       OPTIONAL MATCH (c)-[:HAS_CWE]->(m:MitreData)
       OPTIONAL MATCH (m)-[:HAS_CAPEC]->(cap:Capec)
       OPTIONAL MATCH (ex:ExploitGvm {project_id: $pid})-[:EXPLOITED_CVE]->(c)
       WITH s, ip, p, svc, tech, c, m, cap,
            CASE WHEN ex IS NOT NULL THEN true ELSE false END AS isKev
       RETURN s.name            AS subdomain,
              ip.address        AS ipAddress,
              p.number          AS port,
              p.protocol        AS protocol,
              svc.name          AS serviceName,
              svc.product       AS serviceProduct,
              svc.version       AS serviceVersion,
              tech.name         AS techName,
              tech.version      AS techVersion,
              c.id              AS cveId,
              toFloat(c.cvss)   AS cvss,
              c.severity        AS cveSeverity,
              isKev             AS cisaKev,
              m.cwe_id          AS cweId,
              m.cwe_name        AS cweName,
              cap.capec_id      AS capecId,
              cap.name          AS capecName,
              cap.severity      AS capecSeverity
       ORDER BY cisaKev DESC, cvss DESC
       LIMIT 500`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      subdomain: r.get('subdomain') as string | null,
      ipAddress: r.get('ipAddress') as string | null,
      port: r.get('port') != null ? toNum(r.get('port')) : null,
      protocol: r.get('protocol') as string | null,
      serviceName: r.get('serviceName') as string | null,
      serviceProduct: r.get('serviceProduct') as string | null,
      serviceVersion: r.get('serviceVersion') as string | null,
      techName: r.get('techName') as string | null,
      techVersion: r.get('techVersion') as string | null,
      cveId: (r.get('cveId') as string) || '',
      cvss: r.get('cvss') as number | null,
      cveSeverity: (r.get('cveSeverity') as string) || 'unknown',
      cisaKev: r.get('cisaKev') as boolean,
      cweId: r.get('cweId') as string | null,
      cweName: r.get('cweName') as string | null,
      capecId: r.get('capecId') as string | null,
      capecName: r.get('capecName') as string | null,
      capecSeverity: r.get('capecSeverity') as string | null,
    }))

    return NextResponse.json({
      rows,
      meta: {
        totalRows: rows.length,
        kevCount: rows.filter(r => r.cisaKev).length,
      },
    })
  } catch (error) {
    console.error('Red-zone killChain error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
