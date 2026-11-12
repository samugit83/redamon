import { NextRequest, NextResponse } from 'next/server'
import { AUTH_COOKIE_NAME, ACT_AS_COOKIE_NAME } from '@/lib/auth'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { isSecureRequest } from '@/lib/cookieSecurity'
import { rbacFlags } from '@/lib/authz/flags'
import { revokeSessions, routeNotFound } from '@/lib/authz/accountStatus'

/**
 * POST: "sign out everywhere" for the signed-in account (ID-21): every login cookie of it
 * ends, this browser's included, its MCP tokens are revoked and its open sockets close. The
 * account is the real signed-in one, never an account an admin is acting as. Identity switch
 * only (404 without it). Body: a JSON object (`{}`).
 */
export const POST = withRouteErrors('Could not sign out everywhere', async (request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const response = await revokeSessions(request, session, session.userId)
  if (!response.ok) return response
  // The version this cookie carries is gone: clear it here, with any act-as, so the browser
  // goes to /login at once rather than at its next refused request.
  const expire = { httpOnly: true, sameSite: 'lax' as const, secure: isSecureRequest(request), path: '/', maxAge: 0 }
  response.cookies.set(AUTH_COOKIE_NAME, '', expire)
  response.cookies.set(ACT_AS_COOKIE_NAME, '', expire)
  return response
})
