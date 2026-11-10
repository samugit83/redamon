import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'
import { recordRunStopped } from '@/lib/scanTimeline'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, runId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/partial/${runId}/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
    } catch (err) {
      return upstreamFailureResponse('orchestrator', err, 'Failed to stop partial recon')
    }

    if (!response.ok) {
      // The orchestrator's refusals ("no running recon") are its own sentences.
      return upstreamErrorResponse('orchestrator', response, 'Failed to stop partial recon', { forwardText: true })
    }

    const data = await response.json()
    await recordRunStopped(projectId, 'partial_recon', runId, data?.status)
    return NextResponse.json(data)

  } catch (error) {
    return internalError(error, 'Failed to stop partial recon', { log: 'Error stopping partial recon' })
  }
}
