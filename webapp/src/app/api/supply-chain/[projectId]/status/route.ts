import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { reconcileScanJobStatus } from '@/lib/scanTimeline'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const STATUS_UNAVAILABLE = 'Supply-Chain status unavailable'

interface RouteParams { params: Promise<{ projectId: string }> }

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    // An orchestrator that does not answer leaves the scan's state unknown. It
    // used to be reported as a synthetic "idle", which made a running scan look
    // finished; the orchestrator itself answers "idle" when there is no run.
    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/supply-chain/${projectId}/status`, {
        method: 'GET', headers: { 'Content-Type': 'application/json' },
      })
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, STATUS_UNAVAILABLE)
    }
    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, STATUS_UNAVAILABLE, { forwardText: true })
    }
    const data = await response.json()
    // The orchestrator owns liveness; this only mirrors a TERMINAL state onto the
    // history row, so the run stops reading as running once it ends.
    await reconcileScanJobStatus(projectId, data?.status, { kind: 'supply_chain' })
    return NextResponse.json(data)
  } catch (error) {
    return internalError(error, 'Failed to get Supply-Chain status', { log: 'Error getting Supply-Chain status' })
  }
}
