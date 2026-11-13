import { NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { ROOT_ONLY_REFUSAL, forbiddenAs, routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { managedOf, managerOf } from '@/lib/authz/permissionAdmin'
import { canManage } from '@/lib/authz/hierarchy'
import { manageRefusal } from '@/lib/authz/rootPowers'
import { listDeviceSessions, ownDevicesRefusal } from '@/lib/authz/deviceSessionAdmin'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/users/[id]/sessions (step 6.10, GV-17): another account's device sessions, for the admin
 * console's user detail, to whoever may sign it out (users:revoke_sessions, and on an admin the
 * hierarchy's rule: the confirmed Root, or an admins:manage holder over a strict subset); nobody reads
 * Root's. The own account is under /api/account/sessions (400 `own_account`). Governance switch only
 * (404 without it, nothing read).
 */
export const GET = withRouteErrors('Could not read the account\'s sessions', async (_request: Request, { params }: RouteParams) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenAs(session, 'users:revoke_sessions')
  const denied = await requireSessionPermission(session, 'users:revoke_sessions', { fresh: true })
  if (denied) return denied
  const { id } = await params
  const own = ownDevicesRefusal(session.userId, id)
  if (own) return own
  const target = await managedOf(id)
  if (!target) return NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })
  const decision = canManage((await managerOf(session)).manager, target.managed, 'revoke_sessions')
  if (!decision.allowed) return manageRefusal(session, decision, ROOT_ONLY_REFUSAL.error)
  const sessions = await listDeviceSessions(id)
  if (!sessions) return NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })
  return NextResponse.json({ sessions }, { headers: { 'Cache-Control': 'no-store' } })
})
