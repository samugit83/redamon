/**
 * What stays with the real person while an admin acts as someone (step 3.14, IM-08; feature
 * document §4.7 "Never allowed while impersonating"): their identity and secrets, where their keys
 * and data go, and their account. An attempt answers 403 `not_while_acting_as` naming the account
 * ("not available while acting as Marco") and writes an `act_as.refused` audit row with the action.
 *
 * Step 1.6 already refuses act-as writes to an account that can sign in (`own_account_only`): these
 * refusals matter for the passwordless managed accounts it lets an admin run, and for the admin's
 * own administration of the account it acts as (its password, email, deletion). With
 * RBAC_PERMISSIONS_ENABLED off nothing here refuses (Phase 2 behaviour).
 *
 * One helper, called by each route of the list (and by the agent-skill chokepoint,
 * userSkillWrites.ts): `refuseWhileActingAs({session, targetUserId}, action)`.
 */
import { NextResponse } from 'next/server'
import { writeAudit } from '@/lib/audit'
import { actAsInForce, getSession, type Session } from '@/lib/session'
import { rbacFlags } from './flags'
import { sessionPrincipal } from './sessionPrincipal'

export const NOT_WHILE_ACTING_AS = 'not_while_acting_as'

/** Each action of the list, as the 403 says it. */
const ACTIONS = {
  change_password: 'changing their password or resetting their credentials',
  change_email: 'changing their sign-in email',
  delete_account: 'deleting their account',
  mint_mcp_token: 'creating or widening an MCP token in their name',
  reveal_secret: 'revealing their stored secrets',
  use_github_token: 'using their GitHub token',
  write_agent_skills: 'writing their agent skills',
  write_chat_skills: 'writing their chat skills',
  change_shares: 'changing their project shares',
  transfer_projects: 'transferring their projects',
  add_mcp_server: 'adding an MCP server',
  change_mcp_endpoint: "changing where an MCP server sends their keys and data",
  change_llm_endpoint: "changing an LLM provider's endpoint, type or key",
} as const

export type ActingAsAction = keyof typeof ACTIONS
export const ACTING_AS_ACTIONS: readonly ActingAsAction[] = Object.freeze(Object.keys(ACTIONS) as ActingAsAction[])

export interface ActingAsRefusal {
  error: string
  code: typeof NOT_WHILE_ACTING_AS
  action: ActingAsAction
}

export interface ActingAsContext {
  /** The signed-in account, as the route read it. */
  session: Session
  /**
   * The account the action is on. Given, only acting as that account refuses (the admin may still
   * administer other accounts); left out, acting as anyone refuses.
   */
  targetUserId?: string
}

/**
 * The refusal when the session acts as the account (switch on), after writing its audit row; null
 * otherwise. For a writer that answers through its own error type; a route uses refuseWhileActingAs.
 */
export async function actingAsRefusal({ session, targetUserId }: ActingAsContext, action: ActingAsAction): Promise<ActingAsRefusal | null> {
  if (!rbacFlags().permissions) return null
  const inForce = await actAsInForce(session)
  if (!inForce || (targetUserId !== undefined && inForce.target.id !== targetUserId)) return null
  const { target } = inForce
  const email = sessionPrincipal(session)?.email
  // Best effort (writeAudit logs a failed insert): the refusal stands either way.
  await writeAudit({
    actorId: session.userId,
    onBehalfOfUserId: target.id,
    ...(email ? { actorEmail: email } : {}),
    action: 'act_as.refused',
    targetType: 'user',
    targetId: target.id,
    after: { action },
    source: 'api',
  })
  const who = target.name || target.email
  return {
    error: `Not available while acting as ${who}: ${ACTIONS[action]} stays with them. Stop acting as them first.`,
    code: NOT_WHILE_ACTING_AS,
    action,
  }
}

/**
 * For a writer that knows who wrote (`actorId`, the person signed in) and whose data it is: the
 * refusal when that person acts as the owner. Only a write of someone else's data can be acting, so
 * the session is read for those alone (a system write has no actor and is never refused here).
 */
export async function actingAsOwnerRefusal(
  ownerId: string,
  actorId: string | null | undefined,
  action: ActingAsAction,
): Promise<ActingAsRefusal | null> {
  if (!rbacFlags().permissions || !actorId || actorId === ownerId) return null
  const session = await getSession()
  if (!session || session.userId !== actorId) return null
  return actingAsRefusal({ session, targetUserId: ownerId }, action)
}

/**
 * refuseWhileActingAs for a route that holds no session object (it checked access with
 * requireUserAccess): the signed-in session is read, with the switch on only; an internal-key or
 * anonymous caller acts as nobody.
 */
export async function refuseWhileActingAsOn(targetUserId: string, action: ActingAsAction): Promise<NextResponse | null> {
  if (!rbacFlags().permissions) return null
  const session = await getSession()
  return session ? refuseWhileActingAs({ session, targetUserId }, action) : null
}

/** Null when allowed, else the 403 `{error, code: 'not_while_acting_as', action}` the route returns. */
export async function refuseWhileActingAs(ctx: ActingAsContext, action: ActingAsAction): Promise<NextResponse | null> {
  const refusal = await actingAsRefusal(ctx, action)
  return refusal ? NextResponse.json(refusal, { status: 403 }) : null
}
