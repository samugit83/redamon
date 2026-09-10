import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'

function toNum(val: unknown): number | null {
  if (val == null) return null
  if (typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : null
}

// Red-zone lens: web cache poisoning / deception findings.
// Vulnerability {source:'cache_poisoning'} nodes (written by graph_db/mixins/cache_mixin.py),
// linked to the affected Endpoint and/or BaseURL.
export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(projectId || '')
  if (__denied) return __denied
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    const result = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid, source: 'cache_poisoning'})
       WHERE ${notMuted('v')}
       OPTIONAL MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v)
       OPTIONAL MATCH (bu:BaseURL)-[:HAS_VULNERABILITY]->(v)
       WITH v,
            head([x IN collect(DISTINCT coalesce(e.full_url, e.url)) WHERE x IS NOT NULL]) AS epUrl,
            head([x IN collect(DISTINCT bu.url) WHERE x IS NOT NULL]) AS buUrl
       RETURN coalesce(epUrl, v.matched_at, v.endpoint, buUrl) AS endpointUrl,
              buUrl                       AS baseUrl,
              v.cache_header              AS cacheHeader,
              v.cache_param               AS cacheParam,
              v.cache_vector_type         AS vectorType,
              v.cache_impact              AS impact,
              v.severity                  AS severity,
              v.cvss_score                AS cvss,
              v.confidence                AS confidence,
              v.confidence_tier           AS tier,
              v.detection_mode            AS detectionMode,
              v.cache_technique           AS technique,
              v.source_engine             AS engine,
              v.cache_buster              AS cacheBuster,
              v.cross_vantage             AS crossVantage,
              v.poc_link                  AS pocLink,
              v.curl_verify               AS curlVerify,
              v.updated_at                AS updatedAt
       ORDER BY v.cvss_score DESC, v.confidence DESC
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      endpointUrl: r.get('endpointUrl') as string | null,
      baseUrl: r.get('baseUrl') as string | null,
      cacheHeader: r.get('cacheHeader') as string | null,
      cacheParam: r.get('cacheParam') as string | null,
      vectorType: r.get('vectorType') as string | null,
      impact: r.get('impact') as string | null,
      severity: r.get('severity') as string | null,
      cvss: toNum(r.get('cvss')),
      confidence: toNum(r.get('confidence')),
      tier: r.get('tier') as string | null,
      detectionMode: r.get('detectionMode') as string | null,
      technique: r.get('technique') as string | null,
      engine: r.get('engine') as string | null,
      cacheBuster: r.get('cacheBuster') as string | null,
      crossVantage: r.get('crossVantage') as boolean | null,
      pocLink: r.get('pocLink') as string | null,
      curlVerify: r.get('curlVerify') as string | null,
      updatedAt: r.get('updatedAt') ?? null,
    }))

    const tiers = rows.reduce<Record<string, number>>((acc, r) => {
      const t = (r.tier || 'Unknown')
      acc[t] = (acc[t] || 0) + 1
      return acc
    }, {})

    return NextResponse.json({ rows, meta: { totalRows: rows.length, tiers } })
  } catch (error) {
    console.error('Red-zone webCachePoison error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
