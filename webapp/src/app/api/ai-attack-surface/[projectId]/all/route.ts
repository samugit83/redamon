import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { reconcileRunScanJobs } from '@/lib/scanTimeline'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

const UNAVAILABLE = 'AI Gauntlet runs unavailable'

// GET /api/ai-attack-surface/{projectId}/all - list all runs for a project.
// An orchestrator that cannot answer is a 503/504, never an empty list: the page
// re-attaches to an in-flight run from this list, and `runs: []` would read as
// "nothing running" and let a relaunch hit the orchestrator's 409.
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId })
  if (auth instanceof NextResponse) return auth
  let response: Response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/all`, {
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })
  } catch (err) {
    return upstreamFailureResponse('orchestrator', err, UNAVAILABLE)
  }
  if (!response.ok) {
    return upstreamErrorResponse('orchestrator', response, UNAVAILABLE, { forwardText: true })
  }
  try {
    const data = await response.json()
    await reconcileRunScanJobs(projectId, 'ai_attack', data?.runs)
    return NextResponse.json(data)
  } catch (err) {
    return internalError(err, UNAVAILABLE)
  }
}
