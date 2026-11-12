/**
 * Root's protections (step 2.5, ID-04, ID-06; feature document §4.3 "untouchable by anyone
 * else in the app", §4.4): with the identity switch on, no other account edits, demotes,
 * disables, enables, deletes, resets the password of, signs out or acts as Root. Each route
 * calls this right after it knows its target, before any step-up or write, so a refused
 * deletion tears nothing down. Root itself keeps today's answers on its own account, except
 * that it keeps the admin role until it transfers Root (`self`).
 *
 * The refusal is 403 `root_protected`, recorded as `rbac.root_protected_refused` (best effort:
 * the refusal stands when the row cannot be written). Root is read fresh, so a Root recorded
 * by the boot backfill or the host in another process is protected at once. An unconfirmed
 * Root is protected too. With the switch off nothing is read and nothing is refused (DV-30).
 */
import { NextResponse, type NextRequest } from 'next/server'
import { writeUserAudit } from '@/lib/userAudit'
import type { Session } from '@/lib/session'
import { rbacFlags } from './flags'
import { loadInstanceRoot } from './root'

export const ROOT_PROTECTED_ACTION = 'rbac.root_protected_refused'

export type RootProtectedAttempt =
  | 'edit' | 'role_change' | 'delete' | 'reset_password' | 'disable' | 'enable' | 'revoke_sessions' | 'act_as'

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
  await writeUserAudit(request, session, { action: ROOT_PROTECTED_ACTION, targetId, after: { attempted } })
  return NextResponse.json({ error: own ? SELF : OTHERS, code: 'root_protected' }, { status: 403 })
}
