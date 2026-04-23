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
    // Row = one (Parameter) that is either flagged injectable, OR reached by a DAST Vulnerability
    // via AFFECTS_PARAMETER. Join back to Endpoint + BaseURL + Subdomain for context.
    const result = await session.run(
      `MATCH (p:Parameter {project_id: $pid})
       OPTIONAL MATCH (ep:Endpoint)-[:HAS_PARAMETER]->(p)
       OPTIONAL MATCH (bu:BaseURL)-[:HAS_ENDPOINT]->(ep)
       OPTIONAL MATCH (sd:Subdomain)-[:HAS_BASE_URL]->(bu)
       OPTIONAL MATCH (v:Vulnerability)-[:AFFECTS_PARAMETER]->(p)
       WITH p, ep, bu, sd, collect(DISTINCT v) AS vulns
       WHERE p.is_injectable = true OR size(vulns) > 0
       UNWIND (CASE WHEN size(vulns) = 0 THEN [null] ELSE vulns END) AS v
       RETURN p.name                                  AS paramName,
              p.position                              AS position,
              p.endpoint_path                         AS endpointPath,
              p.baseurl                               AS paramBaseUrl,
              coalesce(p.sample_value, head(p.sample_values)) AS sampleValue,
              p.is_injectable                         AS isInjectable,
              p.type                                  AS paramType,
              p.category                              AS paramCategory,
              ep.method                               AS endpointMethod,
              ep.full_url                             AS endpointFullUrl,
              ep.category                             AS endpointCategory,
              bu.url                                  AS baseUrl,
              sd.name                                 AS subdomain,
              v.id                                    AS vulnId,
              v.template_id                           AS templateId,
              v.name                                  AS vulnName,
              v.severity                              AS vulnSeverity,
              v.source                                AS vulnSource,
              v.matcher_name                          AS matcherName,
              v.extractor_name                        AS extractorName,
              v.fuzzing_method                        AS fuzzingMethod,
              v.fuzzing_position                      AS fuzzingPosition,
              coalesce(v.matched_at, v.url)           AS matchedAt,
              v.cvss_score                            AS cvssScore
       ORDER BY
         CASE v.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
           WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
         p.is_injectable DESC
       LIMIT 1000`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      paramName: (r.get('paramName') as string) || '',
      position: (r.get('position') as string) || 'query',
      endpointPath: r.get('endpointPath') as string | null,
      paramBaseUrl: r.get('paramBaseUrl') as string | null,
      sampleValue: r.get('sampleValue') as string | null,
      isInjectable: (r.get('isInjectable') as boolean | null) ?? false,
      paramType: r.get('paramType') as string | null,
      paramCategory: r.get('paramCategory') as string | null,
      endpointMethod: r.get('endpointMethod') as string | null,
      endpointFullUrl: r.get('endpointFullUrl') as string | null,
      endpointCategory: r.get('endpointCategory') as string | null,
      baseUrl: r.get('baseUrl') as string | null,
      subdomain: r.get('subdomain') as string | null,
      vulnId: r.get('vulnId') as string | null,
      templateId: r.get('templateId') as string | null,
      vulnName: r.get('vulnName') as string | null,
      vulnSeverity: r.get('vulnSeverity') as string | null,
      vulnSource: r.get('vulnSource') as string | null,
      matcherName: r.get('matcherName') as string | null,
      extractorName: r.get('extractorName') as string | null,
      fuzzingMethod: r.get('fuzzingMethod') as string | null,
      fuzzingPosition: r.get('fuzzingPosition') as string | null,
      matchedAt: r.get('matchedAt') as string | null,
      cvssScore: r.get('cvssScore') as number | null,
    }))

    const injectableCount = rows.filter(r => r.isInjectable).length
    const withVulnCount = rows.filter(r => r.vulnId).length

    return NextResponse.json({
      rows,
      meta: {
        totalRows: rows.length,
        injectableCount,
        withVulnCount,
      },
    })
  } catch (error) {
    console.error('Red-zone paramMatrix error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
