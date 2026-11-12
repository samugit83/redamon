import { NextRequest, NextResponse } from 'next/server'
import { AUTH_COOKIE_NAME, ACT_AS_COOKIE_NAME } from '@/lib/auth'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { isSecureRequest } from '@/lib/cookieSecurity'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { acceptRootTransfer, transferForbidden } from '@/lib/authz/rootTransfer'

/**
 * POST `{stepUpPassword}`: the admin Root was offered to accepts it, with its own password
 * (step 2.6, ID-07). Root moves to it, confirmed; both accounts sign in again (their session
 * versions rise and their sockets close), so this browser's cookies are cleared on the answer.
 * Identity switch only (404 without it).
 */
export const POST = withRouteErrors('Could not accept Root', async (request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return transferForbidden(session)
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const result = await acceptRootTransfer(request, session, parsed.body.stepUpPassword)
  if (result instanceof NextResponse) return result
  const response = NextResponse.json({ transferred: true, ...result })
  const expire = { httpOnly: true, sameSite: 'lax' as const, secure: isSecureRequest(request), path: '/', maxAge: 0 }
  response.cookies.set(AUTH_COOKIE_NAME, '', expire)
  response.cookies.set(ACT_AS_COOKIE_NAME, '', expire)
  return response
})
