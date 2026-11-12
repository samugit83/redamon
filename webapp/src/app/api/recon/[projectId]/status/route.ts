import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { reconcileScanJobStatus } from '@/lib/scanTimeline'
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

    // An orchestrator that does not answer is reported as such, never as an
    // idle recon: "idle" would enable Start over a scan that may be running.
    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/status`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })
    } catch (err) {
      return upstreamFailureResponse('orchestrator', err, 'Recon status unavailable')
    }

    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, 'Failed to get recon status', { forwardText: true })
    }

    const data = await response.json()

    // Scan Timeline: mirror a terminal orchestrator status onto the open ScanJob
    // history row. The orchestrator remains the source of truth for liveness;
    // this is best-effort bookkeeping and never affects the response.
    await reconcileScanJobStatus(projectId, data?.status)

    return NextResponse.json(data)

  } catch (error) {
    return internalError(error, 'Failed to get recon status', { log: 'Error getting recon status' })
  }
}
