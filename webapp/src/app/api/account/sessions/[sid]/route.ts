import { NextRequest, NextResponse } from 'next/server'
import { AUTH_COOKIE_NAME, ACT_AS_COOKIE_NAME } from '@/lib/auth'
import { requireSession } from '@/lib/session'
import { safeErrorCode, withRouteErrors } from '@/lib/routeErrors'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { isSecureRequest } from '@/lib/cookieSecurity'
import { presentedActAsToken } from '@/lib/userAudit'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { actsAsOthers, endPresentedActAs } from '@/lib/authz/actAs'
import { isDeviceSessionId, sessionDeviceId } from '@/lib/authz/deviceSessions'
import { revokeAnswer, revokeDeviceSession, sessionNotFound } from '@/lib/authz/deviceSessionAdmin'

interface RouteParams {
  params: Promise<{ sid: string }>
}

/**
 * DELETE /api/account/sessions/[sid] (step 6.10, GV-17): sign one of your own browsers out. It is
 * refused from its next request on; your other browsers stay signed in. Revoking the browser asking
 * is a sign-out: its cookies are cleared in this answer and its impersonation ends (`logout`). Audited
 * `user.session_revoked`; a session already ended changes nothing (`changed: false`). The real signed-in
 * account, never one acted as. Governance switch only (404 without it). Same-origin; no body.
 */
export const DELETE = withRouteErrors('Could not end the session', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const { sid } = await params
  if (!isDeviceSessionId(sid)) return sessionNotFound()
  const current = sid === sessionDeviceId(session)
  const outcome = await revokeDeviceSession(request, session, session.userId, sid, { by: 'self', current })
  const response = revokeAnswer(sid, outcome)
  if (!current || outcome.kind !== 'revoked') return response
  if (rbacFlags().permissions && actsAsOthers(session)) {
    try {
      await endPresentedActAs(session.userId, presentedActAsToken(request), 'logout')
    } catch (err) {
      console.error(`[rbac] act-as end not recorded at sign-out code=${safeErrorCode(err)}`)
    }
  }
  const expire = { httpOnly: true, sameSite: 'lax' as const, secure: isSecureRequest(request), path: '/', maxAge: 0 }
  response.cookies.set(AUTH_COOKIE_NAME, '', expire)
  response.cookies.set(ACT_AS_COOKIE_NAME, '', expire)
  return response
})
