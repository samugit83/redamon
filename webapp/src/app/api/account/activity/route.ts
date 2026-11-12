import { NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { accountActivity } from '@/lib/authz/accountActivity'

/**
 * GET /api/account/activity (step 2.11, UI-09): the signed-in account's notices and the safe
 * audit rows about it, for "My activity" on the My account page. The real signed-in account,
 * never one an admin is acting as. Identity switch only (404 without it, nothing read).
 */
export const GET = withRouteErrors('Could not read your activity', async () => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  return NextResponse.json(await accountActivity(session.userId), { headers: { 'Cache-Control': 'no-store' } })
})
