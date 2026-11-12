import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { upstreamErrorResponse, upstreamFailureResponse, withRouteErrors } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

export const GET = withRouteErrors('Failed to connect to partial recon log stream', async (request: NextRequest, { params }: RouteParams) => {
  const { projectId, runId } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId })
  if (auth instanceof NextResponse) return auth

  let response: Response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/${runId}/logs`, {
      headers: { 'Accept': 'text/event-stream' },
      signal: request.signal,
    })
  } catch (err) {
    return upstreamFailureResponse('orchestrator', err, 'Failed to connect to partial recon log stream')
  }

  if (!response.ok) {
    return upstreamErrorResponse('orchestrator', response, 'Failed to connect to partial recon log stream', { forwardText: true })
  }

  return new Response(response.body, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
    },
  })
})
