import { NextRequest, NextResponse } from 'next/server'
import { AUTH_COOKIE_NAME, ACT_AS_COOKIE_NAME } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { actorFields, auditActorOf, sessionActor } from '@/lib/auditActor'
import { getClientMeta } from '@/lib/requestMeta'
import { isSecureRequest } from '@/lib/cookieSecurity'
import { getSession } from '@/lib/session'
import { actingAsUserId, presentedActAsToken } from '@/lib/userAudit'
import { rbacFlags } from '@/lib/authz/flags'
import { actsAsOthers, endPresentedActAs } from '@/lib/authz/actAs'
import { endDeviceSessionAtSignOut, sessionDeviceId } from '@/lib/authz/deviceSessions'
import { safeErrorCode } from '@/lib/routeErrors'

export async function POST(request: NextRequest) {
  const meta = getClientMeta(request)
  // Signing out never fails: an unreadable account only leaves the row without an actor.
  const session = await getSession().catch(() => null)
  const actingAs = session ? await actingAsUserId(request, session).catch(() => null) : null
  await writeAudit({
    ...actorFields(auditActorOf(session && sessionActor(session), actingAs)),
    action: 'auth.logout', targetType: 'session',
    after: {
      ip: meta.ip, ipTrusted: meta.ipTrusted, userAgent: meta.userAgent,
      ...(actingAs ? { actingAsUserId: actingAs } : {}),
    },
  })
  // Permissions switch on: signing out ends the impersonation (`endedBy: 'logout'`, step 3.14).
  if (session && rbacFlags().permissions && actsAsOthers(session)) {
    try {
      await endPresentedActAs(session.userId, presentedActAsToken(request), 'logout')
    } catch (err) {
      console.error(`[rbac] act-as end not recorded at sign-out code=${safeErrorCode(err)}`)
    }
  }
  // Governance switch on: the browser's device session ends with it (step 6.10), so a copy of the
  // cookie is refused from now on and the Sessions list shows it signed out.
  const device = session && sessionDeviceId(session)
  if (session && device) await endDeviceSessionAtSignOut(device, session.userId)
  const response = NextResponse.json({ ok: true })
  const expire = {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: isSecureRequest(request), // S12
    path: '/',
    maxAge: 0,
  }
  response.cookies.set(AUTH_COOKIE_NAME, '', expire)
  // Also clear any admin impersonation so it can't silently resume on next login.
  response.cookies.set(ACT_AS_COOKIE_NAME, '', expire)
  return response
}
