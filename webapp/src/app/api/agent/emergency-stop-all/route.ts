import { NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { authzIdentityOf, requireSession } from '@/lib/session'
import { loadPrincipal } from '@/lib/authz/principal'
import { sharedToolAccess, type SharedToolAccess } from '@/lib/authz/sharedTools'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf, sessionActor } from '@/lib/auditActor'
import { agentErrorResponse, callAgent } from '../agentProxy'
import { navigatorRuns } from '@/lib/navigator/runRegistry'
import { sandboxEmergencyStop } from '@/lib/sandbox/lifecycle'

const FAILED = 'Failed to stop agents'

type Scope = 'all' | 'own'

interface Stopper {
  userId: string
  /** The account the presser acts as, whose act_as sandbox their own work runs in. */
  actingFor: string | null
  actorEmail: string | null
  scope: Scope
  via: SharedToolAccess['via']
}

/**
 * Whose agent runs a press stops (HD-07). Stopping every user's runs on the shared
 * instance is a shared tool, platform:emergency_stop (sharedTools.ts: every admin with
 * RBAC_PERMISSIONS_ENABLED off, a profile or an override holding it with it on, or a
 * pre-upgrade account under the escape hatch); anyone else stops only the runs of the
 * signed-in account, judged as the database holds it now. Under act-as that is the admin's
 * own runs and the runs and act_as sandbox of their work as the member, never the member's own:
 * only a custom admin profile can act as someone without holding the global stop.
 */
async function stopper(record: boolean): Promise<Stopper | NextResponse> {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  // Read, not swallowed: a failed read is a coded 500, never a stop of the wrong scope.
  const principal = await loadPrincipal(session.userId)
  if (!principal) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const access = await sharedToolAccess(principal, 'emergency_stop_all', { record })
  // Only a press (record) needs it: the toolbar's GET asks the scope alone.
  const actingFor = record && !access.allowed ? (await authzIdentityOf(session)).actingAs?.id ?? null : null
  return {
    userId: principal.id, actingFor, actorEmail: sessionActor(session).email,
    scope: access.allowed ? 'all' : 'own', via: access.via,
  }
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
      // include_acting: also the runs the presser started while acting as someone (keyed by that person).
      body: JSON.stringify({ user_id: who.userId, include_acting: true }),
    }, FAILED)
  // AI Navigator answers stop too: every one for the global scope, the person's own otherwise.
  const navigator = who.scope === 'all' ? navigatorRuns().abortAll() : navigatorRuns().abortFor({ personId: who.userId })
  const presser = auditActorOf({ id: who.userId, email: who.actorEmail })
  // The Kali sandboxes (group 1, D22) stop after the agent has ended the runs inside them, and also
  // when the agent could not be reached: a runaway shell must not outlive the press.
  const sandbox = await sandboxEmergencyStop(
    who.scope === 'all' ? { scope: 'all' } : { scope: 'own', userId: who.userId, actingFor: who.actingFor }, presser)
  const sandboxes = 'error' in sandbox ? { error: sandbox.error } : { stopped: sandbox.stopped }
  // The sandboxes stopped (or not) whatever the agent answered: a failed agent call still
  // tells the presser, who would otherwise read the error as "nothing was stopped".
  if (!call.ok) return withSandboxes(call.response, sandboxes)
  if (!call.res.ok) return withSandboxes(await agentErrorResponse(call.res, FAILED), sandboxes)
  const { stopped } = await call.res.json()
  const count = (typeof stopped === 'number' ? stopped : 0) + navigator
  await writeAudit({
    ...actorFields(presser),
    action: 'agent.emergency_stop',
    targetType: who.scope === 'all' ? 'instance' : 'user',
    targetId: who.scope === 'all' ? null : who.userId,
    after: { scope: who.scope, count, via: who.via, sandboxes },
    source: 'ui',
  })
  return NextResponse.json({ scope: who.scope, stopped: count, sandboxes })
})

type SandboxOutcome = { stopped: number } | { error: string }

async function withSandboxes(response: NextResponse, sandboxes: SandboxOutcome): Promise<NextResponse> {
  const body = await response.json().catch(() => null)
  const base = body && typeof body === 'object' && !Array.isArray(body) ? body : {}
  return NextResponse.json({ ...base, sandboxes }, { status: response.status })
}
