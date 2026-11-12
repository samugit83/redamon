/**
 * Root's protections (step 2.5, ID-04, ID-06; feature document §4.3 "untouchable by anyone
 * else in the app", §4.4): with the identity switch on, no other account edits, demotes,
 * disables, enables, deletes, resets the password of, signs out or acts as Root. Each route
 * calls this right after it knows its target, before any step-up or write, so a refused
 * deletion tears nothing down. Root itself keeps today's answers on its own account, except
 * that it keeps the admin role until it transfers Root (`self`).
 *
 * Root's MCP tokens are protected the same way (`rootTokensRefusal`).
 *
 * The refusal is 403 `root_protected`, recorded as `rbac.root_protected_refused` (best effort:
 * the refusal stands when the row cannot be written). Root is read fresh, so a Root recorded
 * by the boot backfill or the host in another process is protected at once. An unconfirmed
 * Root is protected too. With the switch off nothing is read and nothing is refused (DV-30).
 */
import { NextResponse, type NextRequest } from 'next/server'
import { writeUserAudit } from '@/lib/userAudit'
import { getSession, isInternalRequest, type Session } from '@/lib/session'
import { rbacFlags } from './flags'
import { loadInstanceRoot } from './root'

export const ROOT_PROTECTED_ACTION = 'rbac.root_protected_refused'

export type RootProtectedAttempt =
  | 'edit' | 'role_change' | 'delete' | 'reset_password' | 'disable' | 'enable' | 'revoke_sessions' | 'act_as'
  | 'list_mcp_tokens' | 'edit_mcp_token' | 'delete_mcp_token'

const OTHERS = 'This account is the instance\'s Root: no other account can change it, disable it, delete it, ' +
  'reset its password, sign it out or act as it.'
const SELF = 'Root keeps the admin role. Transfer Root to another admin first.'

/**
 * 403 `root_protected` when `targetId` is Root and the actor may not do `attempted` to it;
 * null otherwise. `self: true` also refuses Root acting on itself (giving up the admin role).
 */
export async function rootProtectedRefusal(
  request: NextRequest,
  session: Session,
  targetId: string,
  attempted: RootProtectedAttempt,
  { self = false }: { self?: boolean } = {},
): Promise<NextResponse | null> {
  if (!rbacFlags().identity) return null
  const own = targetId === session.userId
  if (own && !self) return null
  const root = await loadInstanceRoot({ fresh: true })
  if (!root || root.userId !== targetId) return null
  return rootProtectedAnswer(request, session, targetId, attempted)
}

/**
 * The refusal itself, with its row: also for a write whose transaction found its target to be
 * Root after the check above passed (adminSet.ts `root`), so the answer is the same either way.
 */
export async function rootProtectedAnswer(
  request: NextRequest,
  session: Session,
  targetId: string,
  attempted: RootProtectedAttempt,
): Promise<NextResponse> {
  await writeUserAudit(request, session, { action: ROOT_PROTECTED_ACTION, targetId, after: { attempted } })
  const own = targetId === session.userId
  return NextResponse.json({ error: own ? SELF : OTHERS, code: 'root_protected' }, { status: 403 })
}

/**
 * Root's MCP tokens (review of step 2.5): the read rule lets an admin list, narrow and delete
 * another account's tokens during an incident (HD-23), but Root is untouchable by anyone else in
 * the app (§4.3), so with the switch on another person is refused on Root's tokens. Root itself
 * keeps full control, and so does the host; the internal key (a service, no person) still lists
 * them. Call it after the route's own access check: no session here means that check answered.
 */
export async function rootTokensRefusal(
  request: NextRequest,
  ownerId: string,
  attempted: 'list_mcp_tokens' | 'edit_mcp_token' | 'delete_mcp_token',
): Promise<NextResponse | null> {
  if (!rbacFlags().identity || isInternalRequest(request)) return null
  const session = await getSession()
  if (!session) return null
  return rootProtectedRefusal(request, session, ownerId, attempted)
}
