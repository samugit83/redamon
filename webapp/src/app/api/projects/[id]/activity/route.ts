import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { rbacFlags } from '@/lib/authz/flags'
import { requirePermission } from '@/lib/authz/guards'
import { sharingPolicyForRoutes } from '@/lib/authz/projectShares'
import { oversightActivityAccess, parseActivityQuery, readProjectActivity } from '@/lib/authz/projectActivity'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/projects/[id]/activity?cursor&group (step 4.13): who did what on the project, newest
 * first, a page at a time (lib/authz/projectActivity.ts). The owner (project:share at Manage); after
 * that 403, an admin reading the project by oversight or Root by break-glass. Sharing in force only:
 * 404 otherwise, nothing read (DV-30).
 */
export const GET = withRouteErrors("Could not read the project's activity", async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const { id } = await params
  const policy = await sharingPolicyForRoutes()
  if (!policy) return routeNotFound()
  const auth = await requirePermission(request, 'project:share', { projectId: id })
  let hideShares = false
  if (auth instanceof NextResponse) {
    if (auth.status !== 403) return auth
    const overseer = await oversightActivityAccess(id, policy)
    if (!overseer) return auth
    hideShares = overseer.hideShares
  }
  const query = parseActivityQuery(request.nextUrl.searchParams)
  if (query instanceof NextResponse) return query
  return NextResponse.json(await readProjectActivity(id, query, { hideShares }), { headers: { 'Cache-Control': 'no-store' } })
})
