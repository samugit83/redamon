import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { forceDeleteProject } from '@/lib/authz/adminProjects'
import { requireRootPower } from '@/lib/authz/rootPowers'

interface RouteParams {
  params: Promise<{ id: string }>
}

const ROOT_ONLY = "Only Root can delete another person's project."

/**
 * Root's forced delete of any project (step 6.4; SH-18, projects:administer). 404 with
 * RBAC_GOVERNANCE_ENABLED off. The confirmed Root with its password (`stepUpPassword`), else 403
 * root_only before any password is checked; same-origin JSON. It runs the owner's own teardown with
 * the owner as the tenant and is audited `project.delete` with `after.forced`
 * (lib/authz/adminProjects.ts). A new admin route rather than a Root branch on DELETE
 * /api/projects/[id], whose permission (`project:delete`, the owner's) stays as it is.
 */
export const DELETE = withRouteErrors('Could not delete the project', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const refusal = await requireRootPower(request, session, parsed.body.stepUpPassword, ROOT_ONLY)
  if (refusal) return refusal
  const { id } = await params
  return forceDeleteProject(request, session, id)
})
