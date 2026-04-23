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
    // Secrets in RedAmon always live in the :Secret node. They can be attached via
    //   (BaseURL)-[:HAS_SECRET]->(Secret)              // resource_mixin
    //   (JsReconFinding {finding_type:'js_file'})-[:HAS_SECRET]->(Secret)  // js_recon_mixin
    // Union both traversals and keep each Secret once.
    const result = await session.run(
      `MATCH (s:Secret {project_id: $pid})
       OPTIONAL MATCH (buDirect:BaseURL)-[:HAS_SECRET]->(s)
       OPTIONAL MATCH (j:JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(s)
       OPTIONAL MATCH (buJs:BaseURL)-[:HAS_JS_FILE]->(j)
       WITH s, j, coalesce(buDirect, buJs) AS bu
       OPTIONAL MATCH (sd:Subdomain)-[:HAS_BASE_URL]->(bu)
       RETURN s.id                                      AS id,
              coalesce(s.secret_type, s.pattern)        AS secretType,
              s.sample                                  AS valueSample,
              s.matched_text                            AS matchedText,
              s.entropy                                 AS entropy,
              s.confidence                              AS confidence,
              s.severity                                AS severity,
              s.source                                  AS sourceModule,
              s.source_url                              AS sourceUrl,
              s.base_url                                AS secretBaseUrl,
              s.key_type                                AS keyType,
              s.detection_method                        AS detectionMethod,
              s.validation_status                       AS validationStatus,
              bu.url                                    AS baseUrl,
              sd.name                                   AS subdomain,
              j.source_url                              AS jsFileUrl,
              CASE WHEN j IS NOT NULL THEN 'JsReconFinding' ELSE 'Secret' END AS origin
       LIMIT 2000`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      origin: r.get('origin') as string,
      id: (r.get('id') as string) || '',
      secretType: (r.get('secretType') as string) || 'unknown',
      valueSample: r.get('valueSample') as string | null,
      matchedText: r.get('matchedText') as string | null,
      entropy: r.get('entropy') != null ? toNum(r.get('entropy')) : null,
      confidence: (r.get('confidence') as string | number | null) ?? null,
      severity: (r.get('severity') as string) || 'medium',
      sourceModule: r.get('sourceModule') as string | null,
      sourceUrl: r.get('sourceUrl') as string | null,
      secretBaseUrl: r.get('secretBaseUrl') as string | null,
      keyType: r.get('keyType') as string | null,
      detectionMethod: r.get('detectionMethod') as string | null,
      validationStatus: r.get('validationStatus') as string | null,
      baseUrl: r.get('baseUrl') as string | null,
      subdomain: r.get('subdomain') as string | null,
      jsFileUrl: r.get('jsFileUrl') as string | null,
    }))

    // Priority weighting. `secret_type` in RedAmon is the pattern-family name
    // (e.g. "AWS Secret Key", "GitHub Token Classic", "JWT Token", ...). Match
    // priority by keyword on the lower-cased label.
    const typePriority = (rawType: string): number => {
      const t = (rawType || '').toLowerCase()
      if (t.includes('aws') && (t.includes('secret') || t.includes('key'))) return 0
      if (t.includes('private') && t.includes('key')) return 0
      if (t.includes('gcp') || t.includes('azure')) return 1
      if (t.includes('github') && t.includes('token')) return 1
      if (t.includes('jwt') || t.includes('db') || t.includes('database')) return 2
      if (t.includes('api') && t.includes('key')) return 3
      if (t.includes('token') || t.includes('bearer')) return 3
      if (t.includes('password')) return 4
      return 5
    }

    // Prefer validated > format_validated > unvalidated, then by type priority,
    // then higher entropy first.
    const VALIDATION_RANK: Record<string, number> = {
      validated: 0, format_validated: 1, unvalidated: 2, skipped: 3, invalid: 4,
    }
    rows.sort((a, b) => {
      const va = VALIDATION_RANK[a.validationStatus ?? 'unvalidated'] ?? 2
      const vb = VALIDATION_RANK[b.validationStatus ?? 'unvalidated'] ?? 2
      if (va !== vb) return va - vb
      const ta = typePriority(a.secretType)
      const tb = typePriority(b.secretType)
      if (ta !== tb) return ta - tb
      return (b.entropy ?? 0) - (a.entropy ?? 0)
    })

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    console.error('Red-zone secrets error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
