import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { parseSharesQuery, readSharesPage } from '@/lib/authz/adminShares'
import { sharingPolicyForRoutes } from '@/lib/authz/projectShares'

/**
 * The admin shares overview (step 6.4; GV-05, GV-20). 404 with RBAC_GOVERNANCE_ENABLED off.
 *
 * GET `?q&project&user&cursor&limit` (users:read): every share newest first, with the project, its
 * owner, the collaborator, the level, the toggles and the expiry (expired ones marked), and whether
 * the signed-in person may force-revoke (lib/authz/adminShares.ts). Only while sharing is in force
 * (404 otherwise, as the share routes answer, having read no share) and while Root's sharing policy
 * lets administrators see every share (403 `shares_hidden` otherwise, Root included: Root changes
 * the policy). An unknown value answers 400 `invalid_filter` naming the field.
 */
export const GET = withRouteErrors('Could not list the shares', async (request: NextRequest) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireSessionPermission(session, 'users:read')
  if (refused) return refused
  const policy = await sharingPolicyForRoutes()
  if (!policy) return routeNotFound()
  if (!policy.adminsSeeAllShares) {
    return NextResponse.json({
      error: "The instance sharing policy does not let administrators see every share.",
      code: 'shares_hidden',
    }, { status: 403 })
  }
  const filters = parseSharesQuery(request.nextUrl.searchParams)
  if ('code' in filters) return NextResponse.json(filters, { status: 400 })
  return NextResponse.json(await readSharesPage(session, filters), { headers: { 'Cache-Control': 'no-store' } })
})
