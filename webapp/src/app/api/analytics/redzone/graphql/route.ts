import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { reportCountable } from '@/lib/triage/reportable'
import { internalError } from '@/lib/routeErrors'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'graph:read', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    const result = await session.run(
      `MATCH (ep:Endpoint {project_id: $pid})
       WHERE ep.is_graphql = true
       OPTIONAL MATCH (bu:BaseURL)-[:HAS_ENDPOINT]->(ep)
       OPTIONAL MATCH (sd:Subdomain)-[:HAS_BASE_URL]->(bu)
       OPTIONAL MATCH (ep)-[:HAS_VULNERABILITY]->(v:Vulnerability)
         WHERE v.source IN ['graphql_scan','graphql_cop']
           AND ${notMuted('v')} AND ${reportCountable('v')}
       RETURN toString(id(ep))                        AS nodeId,
              ep.full_url                             AS endpointUrl,
              ep.path                                 AS path,
              bu.url                                  AS baseUrl,
              sd.name                                 AS subdomain,
              ep.graphql_introspection_enabled        AS introspection,
              ep.graphql_graphiql_exposed             AS graphiqlExposed,
              ep.graphql_field_suggestions_enabled    AS fieldSuggestions,
              ep.graphql_get_allowed                  AS getAllowed,
              ep.graphql_batching_enabled             AS batching,
              ep.graphql_tracing_enabled              AS tracing,
              ep.graphql_queries_count                AS queriesCount,
              ep.graphql_mutations_count              AS mutationsCount,
              ep.graphql_subscriptions_count          AS subscriptionsCount,
              ep.graphql_schema_hash                  AS schemaHash,
              ep.graphql_schema_extracted_at          AS schemaExtractedAt,
              ep.graphql_cop_scanned_at               AS copScannedAt,
              ep.graphql_last_error                   AS lastError,
              ep.sensitive_fields_sample              AS sensitiveFieldsSample,
              collect(DISTINCT coalesce(v.vulnerability_type, v.graphql_cop_key, v.title)) AS vulnTypes,
              collect(DISTINCT v.severity)            AS vulnSeverities,
              ep.updated_at                           AS updatedAt
       ORDER BY
         CASE WHEN ep.graphql_introspection_enabled = true THEN 0 ELSE 1 END,
         CASE WHEN ep.graphql_graphiql_exposed = true THEN 0 ELSE 1 END,
         ep.graphql_mutations_count DESC
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      nodeId: (r.get('nodeId') as string | null) ?? null,
      endpointUrl: r.get('endpointUrl') as string | null,
      path: r.get('path') as string | null,
      baseUrl: r.get('baseUrl') as string | null,
      subdomain: r.get('subdomain') as string | null,
      introspection: r.get('introspection') as boolean | null,
      graphiqlExposed: r.get('graphiqlExposed') as boolean | null,
      fieldSuggestions: r.get('fieldSuggestions') as boolean | null,
      getAllowed: r.get('getAllowed') as boolean | null,
      batching: r.get('batching') as boolean | null,
      tracing: r.get('tracing') as boolean | null,
      queriesCount: r.get('queriesCount') != null ? toNum(r.get('queriesCount')) : null,
      mutationsCount: r.get('mutationsCount') != null ? toNum(r.get('mutationsCount')) : null,
      subscriptionsCount: r.get('subscriptionsCount') != null ? toNum(r.get('subscriptionsCount')) : null,
      schemaHash: r.get('schemaHash') as string | null,
      schemaExtractedAt: r.get('schemaExtractedAt') as string | null,
      copScannedAt: r.get('copScannedAt') as string | null,
      lastError: r.get('lastError') as string | null,
      sensitiveFieldsSample: r.get('sensitiveFieldsSample') as string | null,
      vulnTypes: ((r.get('vulnTypes') as string[]) || []).filter(Boolean),
      vulnSeverities: ((r.get('vulnSeverities') as string[]) || []).filter(Boolean),
      updatedAt: r.get('updatedAt') ?? null,
    }))

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    return internalError(error, 'Query failed', { log: 'Red-zone graphql error' })
  } finally {
    await session.close()
  }
}
