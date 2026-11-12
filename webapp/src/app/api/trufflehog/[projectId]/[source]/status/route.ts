import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { reconcileScanJobStatus } from '@/lib/scanTimeline'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const STATUS_UNAVAILABLE = 'Secret Multiscanner status unavailable'

interface RouteParams {
  params: Promise<{ projectId: string; source: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, source } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    let response: Response
    try {
      response = await orchestratorFetch(
        `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/${encodeURIComponent(source)}/status`,
        { method: 'GET', headers: { 'Content-Type': 'application/json' } },
      )
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, STATUS_UNAVAILABLE)
    }

    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, STATUS_UNAVAILABLE, { forwardText: true })
    }

    const data = await response.json()
    // The orchestrator owns liveness; this only mirrors a TERMINAL state onto
    // the history row. runId is the source, or this would close another
    // source's row instead of its own.
    await reconcileScanJobStatus(projectId, data?.status, { kind: 'trufflehog', runId: source })
    return NextResponse.json(data)
  } catch (error) {
    return internalError(error, 'Failed to get Secret Multiscanner status', { log: 'Error getting TruffleHog status' })
  }
}
