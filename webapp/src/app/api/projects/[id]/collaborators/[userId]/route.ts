import { NextRequest, NextResponse } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { refuseWhileActingAs } from '@/lib/authz/actAsRefusals'
import { rbacFlags } from '@/lib/authz/flags'
import { requirePermission } from '@/lib/authz/guards'
import { revokeShare, sharingPolicyForRoutes, updateShare } from '@/lib/authz/projectShares'

interface RouteParams {
  params: Promise<{ id: string; userId: string }>
}

/**
 * PATCH /api/projects/[id]/collaborators/[userId] (step 4.4): change a share's level, Raw data &
 * files, expiry or note; audited `project.share.update`. Read + Write and its toggles only with write
 * sharing in force, within what the person changing it holds; turning Exploitation & shells on takes
 * their password (step 5.14). Same-origin JSON; refused while acting as the owner. Sharing in force
 * only (404 otherwise).
 */
export const PATCH = withRouteErrors('Could not change the share', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const { id, userId } = await params
  const auth = await requirePermission(request, 'project:share', { projectId: id, fresh: true })
  if (auth instanceof NextResponse) return auth
  const policy = await sharingPolicyForRoutes({ fresh: true })
  if (!policy) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: auth.access?.project.userId }, 'change_shares')
  if (acting) return acting
  return updateShare(auth, policy, userId, parsed.body, request)
})

/**
 * DELETE /api/projects/[id]/collaborators/[userId] (step 4.4): revoke the share now, audited
 * `project.share.revoke`; the person's next request gets 404, and the agent closes their sockets on
 * the project (best effort: the revoke stands when the agent is down). Same origin; refused while
 * acting as the owner.
 */
export const DELETE = withRouteErrors('Could not revoke the share', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const { id, userId } = await params
  const auth = await requirePermission(request, 'project:share', { projectId: id, fresh: true })
  if (auth instanceof NextResponse) return auth
  const policy = await sharingPolicyForRoutes({ fresh: true })
  if (!policy) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: auth.access?.project.userId }, 'change_shares')
  if (acting) return acting
  return revokeShare(auth, userId)
})
