import { NextResponse } from 'next/server'
import { orchestratorFetch } from '@/lib/orchestrator'
import { upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'
import { requireSession } from '@/lib/session'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

// Memory governor (Part 5): proxy the orchestrator's live memory/CPU stats for the
// top-bar RAM chip and bottom-bar htop meters. Read-only, no secrets.
export async function GET() {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/system/stats`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })
    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, 'Failed to fetch system stats', { status: 503 })
    }
    return NextResponse.json(await response.json())
  } catch (error) {
    return upstreamFailureResponse('orchestrator', error, 'Failed to connect to backend services')
  }
}
