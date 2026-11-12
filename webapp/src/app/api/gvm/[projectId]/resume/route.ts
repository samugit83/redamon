import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const FAILED = 'Failed to resume GVM scan'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:gvm', { projectId })
    if (auth instanceof NextResponse) return auth

    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/gvm/${projectId}/resume`, {
        method: 'POST',
      })
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, FAILED)
    }

    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, FAILED, { forwardText: true })
    }

    const data = await response.json()
    return NextResponse.json(data)

  } catch (error) {
    return internalError(error, FAILED, { log: 'Error resuming GVM scan' })
  }
}
