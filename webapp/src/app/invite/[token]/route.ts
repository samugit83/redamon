import { NextRequest, NextResponse } from 'next/server'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { takeLookup } from '@/lib/authz/inviteLimits'
import {
  clearInviteCookie,
  findLinkByToken,
  privateJson,
  setInviteCookie,
  signInviteCookie,
  withInviteErrors,
} from '@/lib/authz/invites'

interface RouteParams {
  params: Promise<{ token: string }>
}

/**
 * GET /invite/<token> (step 2.9, ID-15): the address a person was sent. Public. A valid token is
 * traded for a 30-minute httpOnly cookie naming the link; every token, valid or not, gets the
 * same 303 to `/invite` (a relative Location: behind a proxy the request URL names the bind
 * address), so the token leaves the address bar and the history. Lookups are capped per copy
 * whatever the client address (DV-05). Never cached, never sent on as a referrer. Identity
 * switch only (404 without it).
 */
export const GET = withInviteErrors('invite link lookup', 'Could not open the link. Try again in a moment.', async (
  request: NextRequest,
  { params }: RouteParams,
) => {
  if (!rbacFlags().identity) return routeNotFound()
  const limit = takeLookup()
  if (!limit.ok) {
    const res = privateJson({ error: 'Too many links opened. Try again in a minute.', code: 'rate_limited' }, 429)
    res.headers.set('Retry-After', String(limit.retryAfterSeconds))
    return res
  }
  const { token } = await params
  const link = await findLinkByToken(token)
  const res = new NextResponse(null, {
    status: 303,
    headers: { Location: '/invite', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' },
  })
  if (link) setInviteCookie(res, request, await signInviteCookie(link.id))
  else clearInviteCookie(res, request)
  return res
})
