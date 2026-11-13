import { NextRequest, NextResponse } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requirePermission } from '@/lib/authz/guards'
import { cancelTransfer, transfersSwitchedOff, writeSharingInForce } from '@/lib/authz/ownershipTransfer'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/projects/[id]/transfer/cancel (step 5.12, SH-15): the owner withdraws the open offer
 * (audited `project.transfer.cancel`). An attempt that may have moved part of the graph is run back
 * first. Refused while an admin acts as the owner; same-origin. Write sharing in force only.
 */
export const POST = withRouteErrors('Could not cancel the transfer', async (request: NextRequest, { params }: RouteParams) => {
  if (transfersSwitchedOff()) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'project:transfer', { projectId: id, fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!(await writeSharingInForce({ fresh: true }))) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  // Same-origin JSON like every access change (an empty object will do): a browser form cannot send it.
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  return cancelTransfer(auth)
})
