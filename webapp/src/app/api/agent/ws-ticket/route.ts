import { NextRequest, NextResponse } from 'next/server'
import { getAuthzIdentity, type AuthzIdentity } from '@/lib/session'
import { requireProjectAccess } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'
import { createWsTicket } from '@/lib/auth'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { withRouteErrors } from '@/lib/routeErrors'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf, signedInActor } from '@/lib/auditActor'
import { loadPrincipal } from '@/lib/authz/principal'
import { sharedToolAccess, type SharedToolAccess } from '@/lib/authz/sharedTools'
import { agentTicketCap } from '@/lib/authz/agentCap'
import { WS_SOCKETS, isWsSocket } from '@/lib/wsTicket'

/** The signed-in person, read fresh, when the effective user may see the project a terminal ticket names. */
async function terminalIdentity(projectId: string): Promise<AuthzIdentity | NextResponse> {
  const identity = await getAuthzIdentity({ fresh: true })
  if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const access = await requireProjectAccess({ userId: (identity.actingAs ?? identity.principal).id }, projectId)
  return access instanceof NextResponse ? access : identity
}

const TERMINAL_REFUSED =
  'The Kali terminal is open to whoever holds platform:kali_terminal, and to accounts that kept it at the upgrade.'

// POST /api/agent/ws-ticket  { projectId, sessionId, socket }
//
// STRIDE S6: mints a short-lived ticket the browser presents to one agent socket.
// The ticket binds the EFFECTIVE user (getAuthzIdentity) - a standard user's own id,
// or, when an admin is simulating user X, X - never a body-supplied or x-user-id
// value. So the agent acts as the impersonated user (fetches X's keys, tags the
// graph as X), and an admin can only mint a ticket for a project the simulated
// user owns. An internal-key caller has no cookie and cannot mint a ticket for anyone.
//
// The ticket names its socket (`aud`, HD-25); no `socket` is the chat socket, as a
// browser bundle from before the update sends. A `kali-terminal` ticket also needs
// the terminal (HD-04): a root shell in the one sandbox every project shares. The
// REAL signed-in account must hold it, so an admin's act-as never borrows a
// member's grant and a member never gets it by being the effective user.
//
// An `agent` ticket also carries `cap` (step 3.9b): which of the approval permissions
// the agent enforces the person holds on the project, under act-as only those both the
// admin and the account acted as hold (authz/agentCap.ts).
//
// Each socket is its permission on the ticket's project (step 3.9), read fresh: the chat
// `agent:chat`, CypherFix triage `triage:run`, CypherFix CodeFix `codefix:run`. The terminal
// needs the project (the effective user's, as for every socket) and its platform tool below.
export const POST = withRouteErrors('Could not issue a ticket for the agent connection', async (request: NextRequest) => {
  const body = await request.json().catch(() => ({}))
  const projectId = String(body.projectId ?? body.project_id ?? '')
  const sessionId = String(body.sessionId ?? body.session_id ?? '')
  if (!projectId || !sessionId) {
    return NextResponse.json(
      { error: 'projectId and sessionId are required' },
      { status: 400 }
    )
  }
  const socket = body.socket === undefined ? 'agent' : body.socket
  if (!isWsSocket(socket)) {
    return NextResponse.json(
      { error: `Unknown socket. Use one of: ${WS_SOCKETS.join(', ')}.`, code: 'unknown_socket' },
      { status: 400 }
    )
  }

  const identity = socket === 'agent'
    ? await requirePermission(request, 'agent:chat', { projectId, fresh: true })
    : socket === 'cypherfix-triage'
      ? await requirePermission(request, 'triage:run', { projectId, fresh: true })
      : socket === 'cypherfix-codefix'
        ? await requirePermission(request, 'codefix:run', { projectId, fresh: true })
        : await terminalIdentity(projectId)
  if (identity instanceof NextResponse) return identity
  const eff = { userId: (identity.actingAs ?? identity.principal).id }

  let actor: string | undefined
  let actorEmail: string | null = null
  let terminalVia: SharedToolAccess['via'] = null
  if (socket === 'kali-terminal') {
    // Read, not swallowed: a failed read is a coded 500, never a refusal or a grant.
    const signedIn = await signedInActor()
    actor = signedIn?.id
    actorEmail = signedIn?.email ?? null
    const real = actor ? await loadPrincipal(actor, { fresh: true }) : null
    if (!real) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    const grant = await sharedToolAccess(real, 'kali_terminal')
    if (!grant.allowed) {
      return NextResponse.json(
        { error: TERMINAL_REFUSED, code: 'forbidden', permission: 'platform:kali_terminal' },
        { status: 403 }
      )
    }
    terminalVia = grant.via
  } else {
    actor = identity.principal.id
  }

  // Scan Timeline 4A.3: the ticket is the chokepoint for starting an agent
  // session. Refuse to mint one while the project's live graph is being swapped -
  // the agent reasons over that graph, so it must not attach mid-swap.
  const activating = await assertGraphNotActivating(projectId)
  if (activating) return activating

  // Null when AGENT_WS_TICKET_SECRET is unset: the agent then refuses the socket.
  const realActor = actor && actor !== eff.userId ? actor : undefined
  let ticket: string | null
  if (socket === 'agent') {
    ticket = await createWsTicket(eff.userId, projectId, sessionId, socket, realActor, await agentTicketCap(identity, projectId))
  } else {
    ticket = realActor
      ? await createWsTicket(eff.userId, projectId, sessionId, socket, realActor)
      : await createWsTicket(eff.userId, projectId, sessionId, socket)
  }

  if (ticket && socket === 'kali-terminal' && actor) {
    await writeAudit({
      ...actorFields(auditActorOf({ id: actor, email: actorEmail }, eff.userId)),
      action: 'agent.terminal_opened',
      targetType: 'project',
      targetId: projectId,
      after: { via: terminalVia, ...(actor !== eff.userId ? { actingAsUserId: eff.userId } : {}) },
      source: 'ui',
    })
  }
  return NextResponse.json({ ticket })
})
