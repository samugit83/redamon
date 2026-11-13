import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { rbacFlags } from '@/lib/authz/flags'
import { requirePermission } from '@/lib/authz/guards'
import { sharingPolicyForRoutes } from '@/lib/authz/projectShares'
import { refuseWhileActing } from '@/lib/authz/breakGlass'
import { oversightProjects } from '@/lib/authz/oversight'

/**
 * GET /api/projects/oversight (step 4.14, SH-47): the projects page's "All projects (oversight)":
 * every project of the instance with its owner and the holder's own access to each (owner, share,
 * break-glass or oversight), in the rows GET /api/projects answers. projects:oversee; sharing in
 * force only (404 otherwise, nothing read); never while acting as someone. Listing writes no audit
 * row: opening a project is the oversight read, audited once a day (lib/authz/oversight.ts).
 */
export const GET = withRouteErrors('Could not list the projects', async (request: NextRequest) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const auth = await requirePermission(request, 'projects:oversee')
  if (auth instanceof NextResponse) return auth
  if (!(await sharingPolicyForRoutes())) return routeNotFound()
  const acting = await refuseWhileActing(auth.principal, auth.actingAs, 'oversight')
  if (acting) return acting
  const projects = await oversightProjects(auth.principal.id, auth.capabilities)
  return NextResponse.json(projects, { headers: { 'Cache-Control': 'no-store' } })
})
