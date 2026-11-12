import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, runId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/${runId}/status`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      })
    } catch (err) {
      return upstreamFailureResponse('orchestrator', err, 'Partial recon status unavailable')
    }

    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, 'Failed to get partial recon status', { forwardText: true })
    }

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    return internalError(error, 'Failed to get partial recon status')
  }
}
