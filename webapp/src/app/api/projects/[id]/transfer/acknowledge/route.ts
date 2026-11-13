import { NextRequest, NextResponse } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requirePermission } from '@/lib/authz/guards'
import { acknowledgeCleared, transfersSwitchedOff, writeSharingInForce } from '@/lib/authz/ownershipTransfer'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/projects/[id]/transfer/acknowledge (step 5.12): the new owner dismisses the list of settings
 * the transfer cleared for them to re-pick. The owner only; same-origin. Write sharing in force only.
 */
export const POST = withRouteErrors('Could not dismiss the cleared settings', async (request: NextRequest, { params }: RouteParams) => {
  if (transfersSwitchedOff()) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'project:transfer', { projectId: id })
  if (auth instanceof NextResponse) return auth
  if (!(await writeSharingInForce())) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  // Same-origin JSON like every access change (an empty object will do): a browser form cannot send it.
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  return acknowledgeCleared(auth)
})
