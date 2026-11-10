import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { reportCountable } from '@/lib/triage/reportable'
import { internalError } from '@/lib/routeErrors'

function toNum(val: unknown): number | null {
  if (val == null) return null
  if (typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : null
}

/** A string list as one cell: the filters and the exports read flat values. */
function toList(val: unknown): string {
  return Array.isArray(val) ? val.filter((v): v is string => typeof v === 'string').join(', ') : ''
}

function stringList(val: unknown): string[] {
  return Array.isArray(val) ? val.filter((v): v is string => typeof v === 'string') : []
}

// Red-zone lens: the route exposure scan's leads and signature findings.
// Vulnerability {source:'route_exposure'} nodes (graph_db/mixins/recon/route_exposure_mixin.py),
// linked from their Endpoint (leads) and BaseURL (every finding). A pending lead
// IS listed: this is a working view like the graph and the Priority Board; only
// the deliverables (report, Insights) hide it until the agent confirms it.
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
      `MATCH (v:Vulnerability {project_id: $pid, source: 'route_exposure'})
       WHERE ${notMuted('v')} AND ${reportCountable('v')}
       OPTIONAL MATCH (bu:BaseURL)-[:HAS_VULNERABILITY]->(v)
       WITH v, head([x IN collect(DISTINCT bu.url) WHERE x IS NOT NULL]) AS buUrl
       RETURN toString(id(v))                AS nodeId,
              coalesce(v.host, '')           AS host,
              coalesce(v.path, '')           AS path,
              coalesce(v.matched_at, buUrl)  AS url,
              v.exposure_kind                AS kind,
              v.route_class                  AS routeClass,
              v.severity                     AS severity,
              v.confidence                   AS confidence,
              CASE WHEN NOT coalesce(v.needs_agent_confirmation, false) THEN 'finding'
                   WHEN EXISTS { (:ChainFinding)-[:CONFIRMS]->(v) } THEN 'confirmed'
                   ELSE 'pending' END       AS status,
              v.anon_status                  AS anonStatus,
              v.authed_status                AS authedStatus,
              v.auth_expected_by             AS authExpectedBy,
              v.leak_signals                 AS leakSignals,
              v.pii_types                    AS piiTypes,
              v.signature                    AS signature,
              v.generated_by                 AS generatedBy,
              v.evidence_snippet             AS evidenceSnippet,
              v.secret_values                AS secretValues,
              v.secret_value_types           AS secretValueTypes,
              v.updated_at                   AS updatedAt
       ORDER BY CASE status WHEN 'pending' THEN 1 ELSE 0 END, v.confidence DESC, v.path
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      nodeId: (r.get('nodeId') as string | null) ?? null,
      host: r.get('host') as string,
      path: r.get('path') as string,
      url: r.get('url') as string | null,
      kind: r.get('kind') as string | null,
      routeClass: r.get('routeClass') as string | null,
      severity: r.get('severity') as string | null,
      confidence: toNum(r.get('confidence')),
      status: r.get('status') as 'pending' | 'confirmed' | 'finding',
      anonStatus: toNum(r.get('anonStatus')),
      authedStatus: toNum(r.get('authedStatus')),
      authExpectedBy: toList(r.get('authExpectedBy')),
      leakSignals: toList(r.get('leakSignals')),
      piiTypes: toList(r.get('piiTypes')),
      signature: r.get('signature') as string | null,
      generatedBy: r.get('generatedBy') as string | null,
      evidenceSnippet: r.get('evidenceSnippet') as string | null,
      // The secrets the anonymous answer held, shown as their last four
      // characters with a copy button; the types match index by index.
      secretValues: stringList(r.get('secretValues')),
      secretValueTypes: stringList(r.get('secretValueTypes')),
      updatedAt: r.get('updatedAt') ?? null,
    }))

    const pending = rows.filter(r => r.status === 'pending').length
    return NextResponse.json({ rows, meta: { totalRows: rows.length, pending } })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Red-zone routeExposure error' })
  } finally {
    await session.close()
  }
}
