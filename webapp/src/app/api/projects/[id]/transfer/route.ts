import { NextRequest, NextResponse } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requirePermission } from '@/lib/authz/guards'
import { offerTransfer, transferStateFor, transfersSwitchedOff, writeSharingInForce } from '@/lib/authz/ownershipTransfer'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * GET /api/projects/[id]/transfer (step 5.12, SH-15): the ownership transfer offer as the asker may see
 * it. The owner gets their open offer and the settings a transfer to them cleared (to re-pick); the
 * recipient the offer made to them; any other person with access `role: 'none'`. A project the account
 * cannot see answers 404. Write sharing in force only (404 otherwise, nothing read).
 */
export const GET = withRouteErrors('Could not read the ownership transfer', async (_request: NextRequest, { params }: RouteParams) => {
  if (transfersSwitchedOff()) return routeNotFound()
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  if (!(await writeSharingInForce())) return routeNotFound()
  const { id } = await params
  return transferStateFor(eff.userId, id)
})

/**
 * POST /api/projects/[id]/transfer `{toUserId, oldOwnerRole: 'co-owner' | 'leave', stepUpPassword}` (step
 * 5.12, SH-15): the owner offers the project to one of its active collaborators, who has 7 days to accept
 * or decline (lib/authz/ownershipTransfer.ts). Same-origin JSON; the owner's password; refused while an
 * admin acts as the owner; one open offer at a time. Write sharing in force only.
 */
export const POST = withRouteErrors('Could not offer the project', async (request: NextRequest, { params }: RouteParams) => {
  if (transfersSwitchedOff()) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'project:transfer', { projectId: id, fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!(await writeSharingInForce({ fresh: true }))) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  return offerTransfer(request, auth, parsed.body)
})
