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
    const result = await session.run(
      `MATCH (t:Technology {project_id: $pid})-[:HAS_KNOWN_CVE]->(c:CVE)
       OPTIONAL MATCH (bu:BaseURL {project_id: $pid})-[:USES_TECHNOLOGY]->(t)
       OPTIONAL MATCH (svc:Service {project_id: $pid})-[:USES_TECHNOLOGY]->(t)
       OPTIONAL MATCH (p:Port {project_id: $pid})-[:HAS_TECHNOLOGY]->(t)
       OPTIONAL MATCH (ex:ExploitGvm {project_id: $pid})-[:EXPLOITED_CVE]->(c)
       WITH t,
            collect(DISTINCT c.id)            AS cveIds,
            collect(DISTINCT toFloat(c.cvss)) AS cvssVals,
            collect(DISTINCT c.severity)      AS severities,
            count(DISTINCT ex)                AS kevCount,
            collect(DISTINCT bu.url)          AS baseurls,
            collect(DISTINCT svc.ip_address)  AS svcIps,
            collect(DISTINCT p.ip_address)    AS portIps
       WITH t,
            cveIds,
            [x IN cvssVals WHERE x IS NOT NULL] AS cvssClean,
            [x IN severities WHERE x IS NOT NULL] AS sevClean,
            kevCount,
            [x IN baseurls WHERE x IS NOT NULL]   AS baseurlsClean,
            [x IN (svcIps + portIps) WHERE x IS NOT NULL] AS ipsClean
       RETURN t.name                              AS techName,
              t.version                           AS techVersion,
              size(cveIds)                        AS cveCount,
              CASE WHEN size(cvssClean) = 0 THEN null
                   ELSE reduce(mx = 0.0, v IN cvssClean | CASE WHEN v > mx THEN v ELSE mx END)
              END                                 AS maxCvss,
              kevCount                            AS kevCount,
              size(baseurlsClean)                 AS baseUrlCount,
              size(ipsClean)                      AS ipCount,
              sevClean                            AS severities,
              cveIds[0..5]                        AS topCveIds
       ORDER BY kevCount DESC, maxCvss DESC, cveCount DESC
       LIMIT 500`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      techName: (r.get('techName') as string) || 'Unknown',
      techVersion: r.get('techVersion') as string | null,
      cveCount: toNum(r.get('cveCount')),
      maxCvss: r.get('maxCvss') as number | null,
      kevCount: toNum(r.get('kevCount')),
      baseUrlCount: toNum(r.get('baseUrlCount')),
      ipCount: toNum(r.get('ipCount')),
      severities: (r.get('severities') as string[]) || [],
      topCveIds: (r.get('topCveIds') as string[]) || [],
    }))

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    console.error('Red-zone blastRadius error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
