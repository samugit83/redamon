import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { forceRevokeShare } from '@/lib/authz/adminShares'
import { sharingPolicyForRoutes } from '@/lib/authz/projectShares'
import { requireRootPower } from '@/lib/authz/rootPowers'

interface RouteParams {
  params: Promise<{ projectId: string; userId: string }>
}

const ROOT_ONLY = "Only Root can remove a share it did not grant."

/**
 * Root's force-revoke of one share (step 6.4; SH-18, projects:administer). 404 with
 * RBAC_GOVERNANCE_ENABLED off, and while sharing is not in force (no share is read; checked before
 * any password, so none is spent on it). The confirmed Root with its password (`stepUpPassword`),
 * else 403 root_only; same-origin JSON. Audited `project.share.revoke` with `after.forced`; the
 * collaborator's sockets on the project close after (lib/authz/adminShares.ts). Root's policy on
 * whether admins see every share does not limit it.
 */
export const DELETE = withRouteErrors('Could not revoke the share', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  if (!(await sharingPolicyForRoutes({ fresh: true }))) return routeNotFound()
  const refusal = await requireRootPower(request, session, parsed.body.stepUpPassword, ROOT_ONLY)
  if (refusal) return refusal
  const { projectId, userId } = await params
  return forceRevokeShare(request, session, projectId, userId)
})
