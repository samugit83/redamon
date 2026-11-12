import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

// GET /api/ai-attack-surface/{projectId}/targets
// The §2 node picker: selectable AI endpoints (chat/completion) recon annotated,
// enriched with the context the request template is built from (§2.3).
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId })
  if (auth instanceof NextResponse) return auth
  const session = getGraphSession()
  try {
    const res = await session.run(
      `MATCH (e:Endpoint {project_id: $pid})
       WHERE e.ai_interface_type IN ['llm-chat', 'llm-completion']
       RETURN e.baseurl AS baseUrl, e.path AS path,
              coalesce(e.method, 'POST') AS method,
              e.ai_interface_type AS interfaceType,
              e.ai_model_family_guess AS modelFamily,
              e.ai_model_ids AS modelIds,
              e.ai_supports_tools AS supportsTools,
              e.ai_supports_streaming AS streaming
       ORDER BY e.baseurl, e.path LIMIT 500`,
      { pid: projectId },
    )
    const targets = res.records.map((r: { get: (k: string) => unknown }) => ({
      baseUrl: r.get('baseUrl'),
      path: r.get('path'),
      method: r.get('method'),
      interfaceType: r.get('interfaceType'),
      modelFamily: r.get('modelFamily'),
      modelIds: (r.get('modelIds') as string[]) || [],
      supportsTools: r.get('supportsTools'),
      streaming: r.get('streaming'),
    }))
    return NextResponse.json({ targets, count: targets.length })
  } catch (error) {
    return internalError(error, 'Failed to load the LLM endpoints', {
      log: 'AI Attack Surface targets error', extra: { targets: [] },
    })
  } finally {
    await session.close()
  }
}
