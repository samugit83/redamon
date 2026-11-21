import { NextResponse, type NextRequest } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requirePermission } from '@/lib/authz/guards'
import { sandboxFailureResponse, sandboxStatus } from '@/lib/sandbox/gateway'
import type { SandboxStatusAnswer, SandboxView } from '@/lib/sandbox/contract'

const FAILED = 'Could not read the Kali sandbox status'

/**
 * When the signed-in person's own Kali sandbox stops, and whether it warns (group 1, B.10; OQ-G1-9:
 * the 8-hour warning is shown only to the sandbox's person). The person is the session's effective
 * user and the view the one that person works in (`act_as` for an admin acting as a member, TD-26),
 * never anything the request names. Only state, stop time, stop reason and warning: no token, host,
 * instance or project hash.
 */
export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  // The Sessions panel's banner: who may use shell sessions at all (§5.6).
  const auth = await requirePermission(request, 'agent:sessions')
  if (auth instanceof NextResponse) return auth
  const view: SandboxView = auth.actingAs ? 'act_as' : 'own'
  let status: SandboxStatusAnswer
  try {
    status = await sandboxStatus(auth.effective.userId)
  } catch (err) {
    return sandboxFailureResponse(err, FAILED)
  }
  const instances = status.instances
    .filter((i) => i.view === view)
    .map((i) => ({ state: i.state, stop_at: i.stop_at, stop_reason: i.stop_reason, warn: i.warn }))
  return NextResponse.json({ mode: status.mode, instances }, { headers: { 'Cache-Control': 'no-store' } })
})
