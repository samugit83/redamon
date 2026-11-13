import { NextRequest, NextResponse } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { getAuthzIdentity } from '@/lib/session'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { declineTransfer, transfersSwitchedOff, writeSharingInForce } from '@/lib/authz/ownershipTransfer'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/projects/[id]/transfer/decline (step 5.12, SH-15): the recipient turns the open offer down
 * (audited `project.transfer.decline`). An attempt that may have moved part of the graph is run back
 * first. The person signed in only, never an admin acting as them; same-origin; a project they cannot
 * see answers 404. Write sharing in force only.
 */
export const POST = withRouteErrors('Could not decline the project', async (request: NextRequest, { params }: RouteParams) => {
  if (transfersSwitchedOff()) return routeNotFound()
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  if (!(await writeSharingInForce({ fresh: true }))) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  // Same-origin JSON like every access change (an empty object will do): a browser form cannot send it.
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const identity = await getAuthzIdentity({ fresh: true })
  if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const { id } = await params
  return declineTransfer(identity, id)
})
