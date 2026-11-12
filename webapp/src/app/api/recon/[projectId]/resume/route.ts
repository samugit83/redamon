import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:scan', { projectId })
    if (auth instanceof NextResponse) return auth

    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/resume`, {
        method: 'POST',
      })
    } catch (err) {
      return upstreamFailureResponse('orchestrator', err, 'Failed to resume recon')
    }

    if (!response.ok) {
      // The orchestrator's refusals ("no running recon") are its own sentences.
      return upstreamErrorResponse('orchestrator', response, 'Failed to resume recon', { forwardText: true })
    }

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    return internalError(error, 'Failed to resume recon', { log: 'Error resuming recon' })
  }
}
