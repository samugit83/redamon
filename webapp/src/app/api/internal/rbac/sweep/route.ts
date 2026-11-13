/**
 * POST /api/internal/rbac/sweep: the RBAC expiry sweep (step 4.15; SH-14, DV-09, T19), what it
 * removes and audits is in lib/authz/expirySweep.ts. The orchestrator's reaper loop calls it every
 * RBAC_SWEEP_INTERVAL seconds (`_maybe_rbac_sweep`), as it calls /api/internal/mcp-tokens/prune;
 * the webapp has no scheduler of its own.
 *
 * The internal key is the only way in. With every switch off it reads nothing and answers 200, so
 * an install that never turned RBAC on logs nothing. A part that failed answers 500
 * `sweep_incomplete`, which the orchestrator logs as `[rbac] sweep failed status=500`; the parts
 * that ran stand, and the failed one is retried at the next sweep.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { sweepExpired } from '@/lib/authz/expirySweep'

export const runtime = 'nodejs'

export const POST = withRouteErrors('Could not run the RBAC expiry sweep', async (request: NextRequest) => {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const result = await sweepExpired()
  if (result.failed.length) {
    return NextResponse.json(
      { error: 'The expiry sweep did not finish every part', code: 'sweep_incomplete', ...result },
      { status: 500 },
    )
  }
  return NextResponse.json(result)
})
