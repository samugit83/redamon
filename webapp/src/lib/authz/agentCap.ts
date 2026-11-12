/**
 * The `cap` claim of an `agent` WebSocket ticket (step 3.9b; SH-34): which of the agent
 * permissions the agent itself enforces the person holds on the ticket's project. The agent keeps
 * it on the connection and refuses a phase approval without `agent:approve_phase`, a
 * dangerous-tool confirmation without `agent:approve_dangerous`, and a Fireteam member
 * confirmation without both `agent:fireteam` and `agent:approve_dangerous`
 * (agentic/websocket_api.py `_refused_without`). `agent:kali_exec` rides along for the agent's
 * later checks.
 *
 * Each permission is can()'s answer on that project, so under act-as it is held only when both the
 * admin and the account acted as hold it (§4.7), and with RBAC_PERMISSIONS_ENABLED off every
 * account holds all four, which is today's behaviour. Minting a ticket is a critical check: the
 * reads are fresh.
 */
import { can } from './can'
import type { CapabilityPrincipal } from './capabilities'
import type { PermissionId } from './permissions'

/** The same four, in the same order, as agentic/ws_ticket.py AGENT_CAPS. */
export const AGENT_TICKET_CAPS = [
  'agent:approve_phase',
  'agent:approve_dangerous',
  'agent:fireteam',
  'agent:kali_exec',
] as const satisfies readonly PermissionId[]

export type AgentTicketCap = (typeof AGENT_TICKET_CAPS)[number]

/**
 * The permissions of AGENT_TICKET_CAPS the person holds on `projectId`: `principal` the signed-in
 * account, `actingAs` the account an admin acts as (session.ts `getAuthzIdentity`). A project they
 * cannot see holds none; a failed read throws, it never yields a cap.
 */
export async function agentTicketCap(
  identity: { principal: CapabilityPrincipal; actingAs: CapabilityPrincipal | null },
  projectId: string,
): Promise<AgentTicketCap[]> {
  const held: AgentTicketCap[] = []
  for (const permission of AGENT_TICKET_CAPS) {
    const decision = await can(identity.principal, permission, { projectId, actingAs: identity.actingAs, fresh: true })
    if (decision.allowed) held.push(permission)
  }
  return held
}
