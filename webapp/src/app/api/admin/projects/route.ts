import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { parseProjectsQuery, readProjectsPage } from '@/lib/authz/adminProjects'

/**
 * The admin projects overview (step 6.4; GV-04). 404 with RBAC_GOVERNANCE_ENABLED off, as the
 * console's pages are.
 *
 * GET `?q&owner&cursor&limit` (projects:oversee): every project newest first, with its owner, scope,
 * live share count (null while sharing is not in force) and last activity, plus what the signed-in
 * person may do from the list (lib/authz/adminProjects.ts). Lists only: it reads no project content
 * and writes no audit row. An unknown value answers 400 `invalid_filter` naming the field.
 */
export const GET = withRouteErrors('Could not list the projects', async (request: NextRequest) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireSessionPermission(session, 'projects:oversee')
  if (refused) return refused
  const filters = parseProjectsQuery(request.nextUrl.searchParams)
  if ('code' in filters) return NextResponse.json(filters, { status: 400 })
  return NextResponse.json(await readProjectsPage(request, session, filters), { headers: { 'Cache-Control': 'no-store' } })
})
