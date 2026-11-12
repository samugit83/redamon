import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

const UNAVAILABLE = 'AI Gauntlet status unavailable'

// GET /api/ai-attack-surface/{projectId}/{runId}/status
// The orchestrator answers `idle` itself for a run it does not know, so any
// failure here is a real one: a synthetic idle would make a live run look stopped.
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId, runId } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId })
  if (auth instanceof NextResponse) return auth
  let response: Response
  try {
    response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/${runId}/status`,
      { headers: { 'Content-Type': 'application/json' }, cache: 'no-store' },
    )
  } catch (err) {
    return upstreamFailureResponse('orchestrator', err, UNAVAILABLE)
  }
  if (!response.ok) {
    return upstreamErrorResponse('orchestrator', response, UNAVAILABLE, { forwardText: true })
  }
  try {
    return NextResponse.json(await response.json())
  } catch (err) {
    return internalError(err, UNAVAILABLE)
  }
}
