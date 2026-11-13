import { NextRequest, NextResponse } from 'next/server'
import { getAuthzIdentity, type AuthzIdentity } from '@/lib/session'
import { meetsLevel, projectAccess, type ProjectAccess } from '@/lib/authz/projectAccess'
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
import { secondWriterResponse } from '@/lib/authz/projectWriters'
import { sessionTicketRefusal } from '@/lib/authz/conversationRun'
import { recordOwnerCredentialSpend, type SpendFeature } from '@/lib/authz/ownerSpend'
import { safeErrorCode } from '@/lib/routeErrors'
import { agentRunQuotaRefusal } from '@/lib/authz/quotas'

/**
 * The sockets whose work spends the project owner's model and keys (step 5.6, C1): the chat's agent
 * runs, CodeFix, and a shell's `redagraph ask`. A triage run records its own spend when it starts
 * (/api/internal/triage-runs).
 */
const SPENDING_SOCKETS: Partial<Record<string, SpendFeature>> = {
  agent: 'agent_session',
  'cypherfix-codefix': 'codefix_session',
  'kali-terminal': 'shell_session',
}

/**
 * The signed-in person, read fresh, and the effective user's access, when it reaches Exploitation &
 * shells (`W+X`) on the project a terminal ticket names: the owner, or a collaborator whose Read +
 * Write share has that toggle (step 5.2; held at the owner by step 4.3 until the ticket named the
 * owner as the tenant the terminal's shell and run credential take, `ten`, step 5.3). Under act-as
 * the account's share reaches read and never more (D-22), as can() decides it. No route permission
 * backs this level, so it is checked here, beside the platform tool below.
 */
async function terminalIdentity(projectId: string): Promise<{ identity: AuthzIdentity; access: ProjectAccess } | NextResponse> {
  const identity = await getAuthzIdentity({ fresh: true })
  if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const acting = identity.actingAs !== null && identity.actingAs.id !== identity.principal.id
  const access = await projectAccess({ userId: (identity.actingAs ?? identity.principal).id }, projectId, {
    fresh: true, ...(acting ? { actingAs: true } : {}),
  })
  if (!access) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  if (!meetsLevel(access, 'W+X')) {
    return NextResponse.json(
      { error: TERMINAL_LEVEL, code: 'forbidden', permission: 'platform:kali_terminal', level: 'W+X' },
      { status: 403 },
    )
  }
  return { identity, access }
}

const TERMINAL_LEVEL =
  "Opening the Kali terminal on this project needs Exploitation & shells on it: the project's owner, " +
  'or a collaborator whose share includes it.'

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
// Every ticket names the project's owner as `ten` (step 5.3): the graph, the traffic and
// the credentials the socket's work uses are the owner's, while `sub` stays the person.
// The owner comes from the access the project check above read, never from the body.
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

  const checked = socket === 'agent'
    ? await requirePermission(request, 'agent:chat', { projectId, fresh: true })
    : socket === 'cypherfix-triage'
      ? await requirePermission(request, 'triage:run', { projectId, fresh: true })
      : socket === 'cypherfix-codefix'
        ? await requirePermission(request, 'codefix:run', { projectId, fresh: true })
        : await terminalIdentity(projectId)
  if (checked instanceof NextResponse) return checked
  const identity = 'identity' in checked ? checked.identity : checked
  const eff = { userId: (identity.actingAs ?? identity.principal).id }
  // Every check above named the project and read its access; one without an owner is a bug
  // there, and a ticket without its tenant is never minted (a coded 500, not a ticket for `sub`).
  const tenant = checked.access?.project.userId
  if (!tenant) throw new Error('[rbac] ws-ticket: the project check named no owner for the ticket tenant')
  // The session id comes from the body, and a reader of a shared project sees its attack-chain ids: a
  // session another person's or another project's conversation holds is refused (5.3 review); a new one is
  // allowed. A failed read throws: a coded 500, never a ticket.
  const sessionRefused = await sessionTicketRefusal({ sessionId, userId: eff.userId, projectId })
  if (sessionRefused) return sessionRefused

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

  // Step 5.11: the chat socket is where agent runs start, so another person writing the project
  // refuses its ticket, naming them; the same person reconnects as before. Triage keeps its
  // preflight, which already waits for agent sessions and the other writers.
  if (socket === 'agent') {
    const otherWriter = await secondWriterResponse({ projectId, personId: eff.userId, ownerId: tenant })
    if (otherWriter) return otherWriter
    // The session's person's maxConcurrentAgentRuns (step 6.8), counted by the agent as it keys runs
    // (`sub`); before any spend is recorded, so a refused ticket costs the owner nothing.
    const overQuota = await agentRunQuotaRefusal(eff.userId, projectId, sessionId)
    if (overQuota) return overQuota
  }

  // A collaborator's socket spends the owner's credentials, which its permission or level reached
  // only with the owner's consent: recorded as theirs before the ticket is minted (no row, no ticket).
  const feature = SPENDING_SOCKETS[socket]
  if (feature && tenant !== eff.userId) {
    try {
      await recordOwnerCredentialSpend({
        projectId, ownerId: tenant, userId: eff.userId, feature,
        actor: auditActorOf({ id: actor ?? eff.userId, email: actorEmail }, eff.userId),
        permission: 'permission' in checked ? checked.permission : 'platform:kali_terminal',
      })
    } catch (err) {
      console.error(`[rbac] credits.used not recorded project=${projectId} user=${eff.userId} feature=${feature}: ${safeErrorCode(err)}`)
      return NextResponse.json(
        { error: "This use of the project owner's credentials could not be recorded, so no connection was opened. Try again.", code: 'spend_not_recorded' },
        { status: 503 },
      )
    }
  }

  // Null when AGENT_WS_TICKET_SECRET is unset: the agent then refuses the socket.
  const realActor = actor && actor !== eff.userId ? actor : undefined
  let ticket: string | null
  if (socket === 'agent') {
    ticket = await createWsTicket(eff.userId, projectId, sessionId, socket, realActor, await agentTicketCap(identity, projectId), tenant)
  } else {
    ticket = await createWsTicket(eff.userId, projectId, sessionId, socket, realActor, undefined, tenant)
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
