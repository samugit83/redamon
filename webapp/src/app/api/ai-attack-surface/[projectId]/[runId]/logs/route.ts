import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

const FAILED = 'Failed to connect to AI Gauntlet log stream'

// GET /api/ai-attack-surface/{projectId}/{runId}/logs - proxy the SSE stream.
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId, runId } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId })
  if (auth instanceof NextResponse) return auth

  let response: Response
  try {
    response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/${runId}/logs`,
      { headers: { Accept: 'text/event-stream' }, signal: request.signal },
    )
  } catch (err) {
    // The browser closed the stream before the orchestrator answered: nobody is
    // left to read an error, and it is not an orchestrator failure to log.
    if (request.signal?.aborted) return new Response(null, { status: 499 })
    return upstreamFailureResponse('orchestrator', err, FAILED)
  }

  if (!response.ok) {
    return upstreamErrorResponse('orchestrator', response, FAILED, { forwardText: true })
  }

  return new Response(response.body, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    },
  })
}
