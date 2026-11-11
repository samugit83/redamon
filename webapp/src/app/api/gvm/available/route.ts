import { NextResponse } from 'next/server'
import { orchestratorFetch } from '@/lib/orchestrator'
import { upstreamFailure } from '@/lib/routeErrors'
import { requireSession } from '@/lib/session'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

/**
 * Always 200 with `available`, so the GVM button's readers stay simple. `reason`
 * says why it is false: `gvm_absent` (the stack is not installed) reads very
 * differently from an orchestrator that did not answer, which says nothing
 * about GVM at all.
 */
export async function GET() {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  let response: Response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
  } catch (error) {
    const failure = upstreamFailure('orchestrator', error, 'GVM availability check failed')
    console.error('GVM availability check failed:', error)
    return NextResponse.json({
      available: false,
      reason: failure.body.code,
      ...(failure.body.cause ? { cause: failure.body.cause } : {}),
    })
  }

  if (!response.ok) {
    console.error(`GVM availability check failed: orchestrator /health answered HTTP ${response.status}`)
    return NextResponse.json({ available: false, reason: 'orchestrator_error', upstreamStatus: response.status })
  }

  try {
    const data = await response.json()
    const available = data?.gvm_available ?? false
    return NextResponse.json(available ? { available } : { available, reason: 'gvm_absent' })
  } catch (error) {
    console.error('GVM availability check failed: unreadable /health body:', error)
    return NextResponse.json({ available: false, reason: 'orchestrator_error', upstreamStatus: response.status })
  }
}
