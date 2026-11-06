import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { reportCountable } from '@/lib/triage/reportable'
import { internalError } from '@/lib/routeErrors'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

/** Who found the row: the takeover scan, urlscan's history (a deleted-service
 *  page this scan's verdict kept) or a live Security Check (the same page,
 *  served now). */
const TAKEOVER_SOURCE_LABEL: Record<string, string> = {
  takeover_scan: 'takeover scan',
  urlscan_leak: 'urlscan history',
  security_check: 'live check',
}

/** A problem-page outcome on the takeover scan's verdict scale, so the
 *  summary buckets keep one meaning. */
const OUTCOME_VERDICT: Record<string, string> = {
  likely_takeover: 'likely',
  possible_takeover: 'manual_review',
  dangling_dns: 'manual_review',
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
    // The takeover scan's findings (subjack + nuclei + baddns dedup output),
    // plus item 5's deleted-service pages: urlscan's (only those this scan's
    // verdict kept are ever written) and the live Security Check's.
    const result = await session.run(
      `MATCH (v:Vulnerability {project_id: $pid})
       WHERE (v.source = 'takeover_scan'
              OR (v.source = 'urlscan_leak' AND v.type = 'takeover_page_seen')
              OR (v.source = 'security_check' AND v.type = 'takeover_error_page'))
         AND ${notMuted('v')} AND ${reportCountable('v')}
       OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY]->(v)
       RETURN toString(id(v))       AS nodeId,
              v.id                   AS id,
              v.source               AS source,
              coalesce(v.hostname, v.host, parent.name) AS hostname,
              labels(parent)[0]     AS parentType,
              coalesce(v.cname_target, v.cname) AS cnameTarget,
              coalesce(v.takeover_provider, v.provider) AS provider,
              coalesce(v.takeover_method, v.verdict_basis, CASE WHEN v.type = 'takeover_error_page' THEN 'live_page' END) AS method,
              v.verdict             AS verdict,
              v.outcome             AS outcome,
              v.confidence          AS confidence,
              v.severity            AS severity,
              v.sources             AS sources,
              v.confirmation_count  AS confirmationCount,
              coalesce(v.evidence, v.matched) AS evidence,
              v.first_seen          AS firstSeen,
              v.last_seen           AS lastSeen,
              v.detected_at         AS detectedAt,
              v.updated_at          AS updatedAt
       ORDER BY
         CASE v.verdict WHEN 'confirmed' THEN 0 WHEN 'likely' THEN 1 ELSE 2 END,
         v.confidence DESC
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      nodeId: (r.get('nodeId') as string | null) ?? null,
      id: (r.get('id') as string) || '',
      foundBy: TAKEOVER_SOURCE_LABEL[(r.get('source') as string) || ''] || 'takeover scan',
      hostname: (r.get('hostname') as string) || '',
      parentType: (r.get('parentType') as string) || 'Subdomain',
      cnameTarget: r.get('cnameTarget') as string | null,
      provider: (r.get('provider') as string) || 'unknown',
      method: (r.get('method') as string) || 'unknown',
      verdict: (r.get('verdict') as string) || OUTCOME_VERDICT[(r.get('outcome') as string) || ''] || 'manual_review',
      outcome: (r.get('outcome') as string | null) ?? null,
      confidence: r.get('confidence') != null ? toNum(r.get('confidence')) : null,
      severity: (r.get('severity') as string) || 'info',
      sources: (r.get('sources') as string[]) || [],
      confirmationCount: r.get('confirmationCount') != null ? toNum(r.get('confirmationCount')) : null,
      evidence: r.get('evidence') as string | null,
      firstSeen: r.get('firstSeen') as string | null,
      lastSeen: r.get('lastSeen') as string | null,
      detectedAt: r.get('detectedAt') as string | null,
      updatedAt: r.get('updatedAt') ?? null,
    }))

    const summary = {
      confirmed: rows.filter(r => r.verdict === 'confirmed').length,
      likely: rows.filter(r => r.verdict === 'likely').length,
      manualReview: rows.filter(r => r.verdict === 'manual_review').length,
    }

    return NextResponse.json({ rows, meta: { totalRows: rows.length, ...summary } })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Red-zone takeover error' })
  } finally {
    await session.close()
  }
}
