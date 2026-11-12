import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const FAILED = 'Failed to pause Supply-Chain scan'

interface RouteParams { params: Promise<{ projectId: string }> }

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'scan:supply_chain', { projectId })
    if (auth instanceof NextResponse) return auth

    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/supply-chain/${projectId}/pause`, { method: 'POST' })
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, FAILED)
    }
    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, FAILED, { forwardText: true })
    }
    return NextResponse.json(await response.json())
  } catch (error) {
    return internalError(error, FAILED, { log: 'Error pausing Supply-Chain scan' })
  }
}
