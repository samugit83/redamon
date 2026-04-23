import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

// JsReconFinding.finding_type values produced by the js_recon pipeline
// that carry supply-chain-specific attack signal. Match exactly the strings
// emitted by /recon/helpers/js_recon/*.py (see js_recon_mixin.py).
const SUPPLY_CHAIN_FINDING_TYPES = [
  'dependency_confusion',
  'source_map_exposure',
  'source_map_reference',
  'dev_comment',
  'framework',
  'cloud_asset',
]

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getSession()
  try {
    const result = await session.run(
      `MATCH (j:JsReconFinding {project_id: $pid})
       WHERE j.finding_type IN $types
       OPTIONAL MATCH (bu:BaseURL)-[:HAS_JS_FILE]->(parent:JsReconFinding {finding_type: 'js_file'})-[:HAS_JS_FINDING]->(j)
       OPTIONAL MATCH (buDirect:BaseURL)-[:HAS_JS_FILE]->(j)
       OPTIONAL MATCH (sd:Subdomain)-[:HAS_BASE_URL]->(bu)
       OPTIONAL MATCH (sdDirect:Subdomain)-[:HAS_BASE_URL]->(buDirect)
       WITH j,
            coalesce(bu, buDirect)           AS baseurl,
            coalesce(sd.name, sdDirect.name) AS subdomain,
            parent
       RETURN j.id                  AS id,
              j.finding_type        AS findingType,
              j.severity            AS severity,
              j.confidence          AS confidence,
              j.title               AS title,
              j.detail              AS detail,
              j.evidence            AS evidence,
              j.source_url          AS sourceUrl,
              j.base_url            AS baseUrlProp,
              j.name                AS packageName,
              j.version             AS version,
              j.cloud_provider      AS cloudProvider,
              j.cloud_asset_type    AS cloudAssetType,
              j.discovered_at       AS discoveredAt,
              baseurl.url           AS baseUrl,
              subdomain             AS subdomain,
              parent.source_url     AS parentJsUrl
       ORDER BY
         CASE j.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
           WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
         j.finding_type
       LIMIT 500`,
      { pid: projectId, types: SUPPLY_CHAIN_FINDING_TYPES }
    )

    const rows = result.records.map(r => ({
      id: (r.get('id') as string) || '',
      findingType: (r.get('findingType') as string) || 'unknown',
      severity: (r.get('severity') as string) || 'info',
      confidence: r.get('confidence') as string | null,
      title: r.get('title') as string | null,
      detail: r.get('detail') as string | null,
      evidence: r.get('evidence') as string | null,
      sourceUrl: r.get('sourceUrl') as string | null,
      baseUrlProp: r.get('baseUrlProp') as string | null,
      packageName: r.get('packageName') as string | null,
      version: r.get('version') as string | null,
      cloudProvider: r.get('cloudProvider') as string | null,
      cloudAssetType: r.get('cloudAssetType') as string | null,
      discoveredAt: r.get('discoveredAt') as string | null,
      baseUrl: (r.get('baseUrl') as string | null) ?? r.get('baseUrlProp') as string | null,
      subdomain: r.get('subdomain') as string | null,
      parentJsUrl: r.get('parentJsUrl') as string | null,
    }))

    const byType: Record<string, number> = {}
    for (const r of rows) byType[r.findingType] = (byType[r.findingType] || 0) + 1

    return NextResponse.json({
      rows,
      meta: {
        totalRows: rows.length,
        byType,
      },
    })
  } catch (error) {
    console.error('Red-zone supplyChain error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
