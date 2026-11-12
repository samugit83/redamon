import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const FAILED = 'Failed to connect to Secret Multiscanner log stream'

interface RouteParams {
  params: Promise<{ projectId: string; source: string }>
}

/** Proxies one source's SSE log stream. The orchestrator redacts credentials
 *  before the lines leave it, so this is a plain pass-through. */
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, source } = await params
    const auth = await requirePermission(request, 'recon:read', { projectId })
    if (auth instanceof NextResponse) return auth

    let response: Response
    try {
      response = await orchestratorFetch(
        `${RECON_ORCHESTRATOR_URL}/trufflehog/${projectId}/${encodeURIComponent(source)}/logs`,
        { headers: { Accept: 'text/event-stream' }, signal: request.signal },
      )
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, FAILED)
    }

    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, FAILED, { forwardText: true })
    }

    return new Response(response.body, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
      },
    })
  } catch (error) {
    return internalError(error, FAILED)
  }
}
