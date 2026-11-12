import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { reconcileRunScanJobs } from '@/lib/scanTimeline'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    // No answer is reported as such, never as an empty list: "no partial runs"
    // would hide a run that is still writing the graph.
    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/all`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      })
    } catch (err) {
      return upstreamFailureResponse('orchestrator', err, 'Partial recon list unavailable')
    }

    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, 'Failed to get partial recon list', { forwardText: true })
    }

    const data = await response.json()
    await reconcileRunScanJobs(projectId, 'partial_recon', data?.runs)
    return NextResponse.json(data)

  } catch (error) {
    return internalError(error, 'Failed to get partial recon list')
  }
}
