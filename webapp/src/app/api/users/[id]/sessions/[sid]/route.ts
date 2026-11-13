import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { ROOT_ONLY_REFUSAL, forbiddenAs, routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { adminTargetGate } from '@/lib/authz/rootPowers'
import { isDeviceSessionId } from '@/lib/authz/deviceSessions'
import { ownDevicesRefusal, revokeAnswer, revokeDeviceSession, sessionNotFound } from '@/lib/authz/deviceSessionAdmin'

interface RouteParams {
  params: Promise<{ id: string; sid: string }>
}

/**
 * DELETE /api/users/[id]/sessions/[sid] (step 6.10, GV-17): sign one browser of another account out,
 * from its next request on; the account's other browsers stay signed in. Same rule as signing the
 * account out everywhere (users/[id]/revoke-sessions): users:revoke_sessions; another admin only by
 * the confirmed Root with Root's password, or an admins:manage holder over a strict subset with its
 * own (optional JSON body `{stepUpPassword}`); never Root (403 `root_protected`, audited); the own
 * account is under /api/account/sessions (400 `own_account`). Audited `user.session_revoked`; a
 * session already ended changes nothing (`changed: false`). Governance switch only (404 without it).
 */
export const DELETE = withRouteErrors('Could not end the session', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenAs(session, 'users:revoke_sessions')
  const denied = await requireSessionPermission(session, 'users:revoke_sessions', { fresh: true })
  if (denied) return denied
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const { id, sid } = await params
  const refused = ownDevicesRefusal(session.userId, id) ?? await rootProtectedRefusal(request, session, id, 'revoke_sessions')
  if (refused) return refused
  // A DELETE may carry no body: only an admin target needs the password.
  const body = await request.json().catch(() => null) as { stepUpPassword?: unknown } | null
  const gate = await adminTargetGate(request, session, id, body?.stepUpPassword, ROOT_ONLY_REFUSAL.error, 'revoke_sessions')
  if (gate instanceof NextResponse) return gate
  if (!isDeviceSessionId(sid)) return sessionNotFound()
  return revokeAnswer(sid, await revokeDeviceSession(request, session, id, sid, { by: 'admin' }))
})
