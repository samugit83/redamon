import { NextResponse } from 'next/server'
import { orchestratorFetch } from '@/lib/orchestrator'
import { upstreamFailure } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

/**
 * Whether JS Recon can run TruffleHog: the orchestrator's /health reports
 * `trufflehog_available` when the `redamon-trufflehog:latest` image exists.
 *
 * Always 200 with `available` and `reason`, so the JS Recon form stays simple.
 * Only `image_missing` means the image is absent; the `orchestrator_*` reasons
 * say nothing about TruffleHog, so the form keeps the toggle usable for them.
 */
export async function GET() {
  let response: Response
  try {
    response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
  } catch (error) {
    const failure = upstreamFailure('orchestrator', error, 'TruffleHog availability check failed')
    console.error('TruffleHog availability check failed:', error)
    return NextResponse.json({
      available: false,
      reason: failure.body.code,
      ...(failure.body.cause ? { cause: failure.body.cause } : {}),
    })
  }

  if (!response.ok) {
    console.error(`TruffleHog availability check failed: orchestrator /health answered HTTP ${response.status}`)
    return NextResponse.json({ available: false, reason: 'orchestrator_error', upstreamStatus: response.status })
  }

  let data: unknown
  try {
    data = await response.json()
  } catch (error) {
    console.error('TruffleHog availability check failed: unreadable /health body:', error)
    return NextResponse.json({ available: false, reason: 'orchestrator_error', upstreamStatus: response.status })
  }

  // Unlike the GVM route, a missing field is not read as "not installed": an
  // orchestrator older than the field cannot tell, and calling that
  // image_missing would lock the toggle on a host that has the image.
  const available = (data as { trufflehog_available?: unknown } | null)?.trufflehog_available
  if (typeof available !== 'boolean') {
    console.error('TruffleHog availability check failed: /health has no trufflehog_available field')
    return NextResponse.json({ available: false, reason: 'orchestrator_error', upstreamStatus: response.status })
  }
  return NextResponse.json(available ? { available, reason: null } : { available, reason: 'image_missing' })
}
