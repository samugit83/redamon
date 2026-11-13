import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { readUserDetail } from '@/lib/authz/userDirectory'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * One account in the admin console (step 6.2; GV-01, ID-27). 404 with RBAC_GOVERNANCE_ENABLED off.
 *
 * GET (users:read): the account's directory row (with the actions the signed-in person may take on
 * it), its own projects (names and dates; their scope only with projects:oversee, as
 * GET /api/users/[id]), the projects shared with it (only while sharing is in force and Root's
 * policy lets administrators see every share), and its latest audit rows as actor or target (only
 * with audit:read; otherwise the section says so). Its permissions, MCP tokens and the actions
 * themselves are the existing user routes', each asking its own permission.
 */
export const GET = withRouteErrors('Could not read the account', async (_request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireSessionPermission(session, 'users:read')
  if (refused) return refused
  const { id } = await params
  const detail = await readUserDetail(session, id)
  if (!detail) return NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })
  return NextResponse.json(detail)
})
