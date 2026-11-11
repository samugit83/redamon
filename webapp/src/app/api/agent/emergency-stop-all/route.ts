import { NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requireSession } from '@/lib/session'
import { loadPrincipal } from '@/lib/authz/principal'
import { sharedToolAccess, type SharedToolAccess } from '@/lib/authz/sharedTools'
import { writeAudit } from '@/lib/audit'
import { agentErrorResponse, callAgent } from '../agentProxy'

const FAILED = 'Failed to stop agents'

type Scope = 'all' | 'own'

interface Stopper {
  userId: string
  scope: Scope
  via: SharedToolAccess['via']
}

/**
 * Whose agent runs a press stops (HD-07). Stopping every user's runs on the shared
 * instance is a shared tool: an admin, or a pre-upgrade account under the escape hatch,
 * keeps it; anyone else stops only their own runs. The signed-in account is judged, as
 * the database holds it now. Only an admin can act as someone, and an admin takes the
 * global stop, so the user a member's stop names is always the effective user too.
 */
async function stopper(record: boolean): Promise<Stopper | NextResponse> {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  // Read, not swallowed: a failed read is a coded 500, never a stop of the wrong scope.
  const principal = await loadPrincipal(session.userId)
  if (!principal) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const access = await sharedToolAccess(principal, 'emergency_stop_all', { record })
  return { userId: principal.id, scope: access.allowed ? 'all' : 'own', via: access.via }
}

/** The scope a press would have, for the toolbar's tooltip. Asking is not a use of the tool. */
export const GET = withRouteErrors('Could not read the emergency stop scope', async () => {
  const who = await stopper(false)
  if (who instanceof NextResponse) return who
  return NextResponse.json({ scope: who.scope })
})

export const POST = withRouteErrors(FAILED, async () => {
  const who = await stopper(true)
  if (who instanceof NextResponse) return who
  // D7/S8: both agent routes require the master INTERNAL_API_KEY, which agentFetch
  // presents. The user to stop comes from the session, never from the request.
  const call = who.scope === 'all'
    ? await callAgent('/emergency-stop-all', { method: 'POST' }, FAILED)
    : await callAgent('/agent-sessions/stop-for', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: who.userId }),
    }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  const { stopped } = await call.res.json()
  const count = typeof stopped === 'number' ? stopped : 0
  await writeAudit({
    actorId: who.userId,
    action: 'agent.emergency_stop',
    targetType: who.scope === 'all' ? 'instance' : 'user',
    targetId: who.scope === 'all' ? null : who.userId,
    after: { scope: who.scope, count, via: who.via },
    source: 'ui',
  })
  return NextResponse.json({ scope: who.scope, stopped: count })
})
