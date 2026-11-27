/**
 * Internal outbox processor for scheduled scan delta alerts.
 * Driven periodically by `recon_orchestrator/scan_scheduler.py`.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { processAlertOutbox } from '@/lib/deltaAlerts'
import { internalError, withRouteErrors } from '@/lib/routeErrors'

export const runtime = 'nodejs'

export const POST = withRouteErrors('Failed to process delta alert outbox', async (request: NextRequest) => {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  let limit: number | undefined
  try {
    const body = await request.json().catch(() => null)
    if (body && typeof body === 'object' && typeof (body as { limit?: unknown }).limit === 'number') {
      limit = (body as { limit: number }).limit
    }
  } catch {
    // Empty body uses default batch limit.
  }

  try {
    const result = await processAlertOutbox({ limit })
    return NextResponse.json({ ok: true, ...result })
  } catch (err) {
    return internalError(err, 'Failed to process delta alert outbox', { log: '[deltaAlerts] outbox process failed' })
  }
})
