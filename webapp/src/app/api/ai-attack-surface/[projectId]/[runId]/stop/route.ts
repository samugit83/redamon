import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { recordRunStopped } from '@/lib/scanTimeline'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

const FAILED = 'Failed to stop AI Gauntlet scan'

// POST /api/ai-attack-surface/{projectId}/{runId}/stop
export async function POST(request: NextRequest, { params }: RouteParams) {
  const { projectId, runId } = await params
  const auth = await requirePermission(request, 'scan:ai_attack', { projectId })
  if (auth instanceof NextResponse) return auth
  let response: Response
  try {
    response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/${runId}/stop`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' } },
    )
  } catch (err) {
    return upstreamFailureResponse('orchestrator', err, FAILED)
  }
  if (!response.ok) {
    return upstreamErrorResponse('orchestrator', response, FAILED, { forwardText: true })
  }
  try {
    const data = await response.json()
    // The orchestrator drops a stopped run from its listing in this same call,
    // so no list poll ever sees it end: this answer closes its row.
    await recordRunStopped(projectId, 'ai_attack', runId, data?.status)
    return NextResponse.json(data)
  } catch (err) {
    return internalError(err, FAILED)
  }
}
