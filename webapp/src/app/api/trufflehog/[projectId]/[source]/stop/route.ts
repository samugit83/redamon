import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const FAILED = 'Failed to stop Secret Multiscanner scan'

interface RouteParams {
  params: Promise<{ projectId: string; source: string }>
}

/** Stops ONE source's run; the project's other sources keep going. */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, source } = await params
    const auth = await requirePermission(request, 'scan:secrets', { projectId })
    if (auth instanceof NextResponse) return auth

    let response: Response
    try {
      response = await orchestratorFetch(
        `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/${encodeURIComponent(source)}/stop`,
        { method: 'POST' },
      )
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, FAILED)
    }

    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, FAILED, { forwardText: true })
    }

    return NextResponse.json(await response.json())
  } catch (error) {
    return internalError(error, FAILED, { log: 'Error stopping TruffleHog scan' })
  }
}
