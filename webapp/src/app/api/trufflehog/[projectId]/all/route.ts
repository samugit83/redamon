import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { reconcileRunScanJobs } from '@/lib/scanTimeline'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const STATUS_UNAVAILABLE = 'Secret Multiscanner status unavailable'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

/**
 * Every TruffleHog run for a project, one row per source.
 *
 * The queue reconcile, the version-save guard and the graph activation guard all
 * read this instead of a project-level status. With N sources running in
 * parallel a single status can only describe one of them, so the other N-1 look
 * idle to every caller — which is how a version snapshot gets taken while a scan
 * is still writing findings.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    // Never an empty list on failure: "no runs" would let a caller treat a
    // source that is still writing findings as finished.
    let response: Response
    try {
      response = await orchestratorFetch(
        `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/all`,
        { method: 'GET', headers: { 'Content-Type': 'application/json' } },
      )
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, STATUS_UNAVAILABLE)
    }

    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, STATUS_UNAVAILABLE, { forwardText: true })
    }

    const data = await response.json()
    // Run-granular: closing "the project's open job" would end only the newest
    // of N parallel rows and leave the rest stuck at `running` forever.
    await reconcileRunScanJobs(projectId, 'trufflehog', data?.runs)
    return NextResponse.json(data)
  } catch (error) {
    return internalError(error, 'Failed to list Secret Multiscanner runs', { log: 'Error listing TruffleHog runs' })
  }
}
