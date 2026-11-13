import { NextRequest, NextResponse } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import { rbacFlags } from '@/lib/authz/flags'
import { leaveShare, sharingPolicyForRoutes } from '@/lib/authz/projectShares'

/**
 * POST /api/projects/[id]/leave (step 4.4, SH-13): the person signed in gives up their own share of
 * the project, audited `project.share.leave`; the agent closes their sockets on it (best effort).
 * No permission: one's own share is always one's to leave; no share answers 404. Same-origin JSON
 * (`{}`); refused while an admin acts as the person. Sharing in force only (404 otherwise).
 */
export const POST = withRouteErrors('Could not leave the project', async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const policy = await sharingPolicyForRoutes({ fresh: true })
  if (!policy) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const acting = await refuseWhileActingAsOn(eff.userId, 'change_shares')
  if (acting) return acting
  const { id } = await params
  return leaveShare(eff, id)
})
