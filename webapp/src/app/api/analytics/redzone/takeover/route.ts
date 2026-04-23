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
    // Vulnerabilities with source = takeover_scan (subjack + nuclei + baddns dedup output)
    const result = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid, source: 'takeover_scan'})
       OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY]->(v)
       RETURN v.id                   AS id,
              coalesce(v.hostname, v.host, parent.name) AS hostname,
              labels(parent)[0]     AS parentType,
              v.cname_target        AS cnameTarget,
              v.takeover_provider   AS provider,
              v.takeover_method     AS method,
              v.verdict             AS verdict,
              v.confidence          AS confidence,
              v.severity            AS severity,
              v.sources             AS sources,
              v.confirmation_count  AS confirmationCount,
              v.evidence            AS evidence,
              v.first_seen          AS firstSeen,
              v.last_seen           AS lastSeen,
              v.detected_at         AS detectedAt
       ORDER BY
         CASE v.verdict WHEN 'confirmed' THEN 0 WHEN 'likely' THEN 1 ELSE 2 END,
         v.confidence DESC
       LIMIT 500`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      id: (r.get('id') as string) || '',
      hostname: (r.get('hostname') as string) || '',
      parentType: (r.get('parentType') as string) || 'Subdomain',
      cnameTarget: r.get('cnameTarget') as string | null,
      provider: (r.get('provider') as string) || 'unknown',
      method: (r.get('method') as string) || 'unknown',
      verdict: (r.get('verdict') as string) || 'manual_review',
      confidence: r.get('confidence') != null ? toNum(r.get('confidence')) : null,
      severity: (r.get('severity') as string) || 'info',
      sources: (r.get('sources') as string[]) || [],
      confirmationCount: r.get('confirmationCount') != null ? toNum(r.get('confirmationCount')) : null,
      evidence: r.get('evidence') as string | null,
      firstSeen: r.get('firstSeen') as string | null,
      lastSeen: r.get('lastSeen') as string | null,
      detectedAt: r.get('detectedAt') as string | null,
    }))

    const summary = {
      confirmed: rows.filter(r => r.verdict === 'confirmed').length,
      likely: rows.filter(r => r.verdict === 'likely').length,
      manualReview: rows.filter(r => r.verdict === 'manual_review').length,
    }

    return NextResponse.json({ rows, meta: { totalRows: rows.length, ...summary } })
  } catch (error) {
    console.error('Red-zone takeover error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
