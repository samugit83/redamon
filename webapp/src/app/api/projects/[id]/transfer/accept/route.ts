import { NextRequest, NextResponse } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { getAuthzIdentity } from '@/lib/session'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { acceptTransfer, transfersSwitchedOff, writeSharingInForce } from '@/lib/authz/ownershipTransfer'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/projects/[id]/transfer/accept `{stepUpPassword}` (step 5.12; SH-15, DV-15): the recipient of
 * the open offer takes the project, with their own password. Refused with 409 `project_busy`, naming what
 * runs, while the project has live work (the offer stays open), and 409 `project_transfer_in_progress`
 * while another accept runs. The graph moves first, then Postgres in one transaction; a failure answers
 * its code and the offer can be accepted again (lib/authz/ownershipTransfer.ts). The person signed in
 * only, never an admin acting as them; a project they cannot see answers 404. Write sharing in force only.
 */
export const POST = withRouteErrors('Could not accept the project', async (request: NextRequest, { params }: RouteParams) => {
  if (transfersSwitchedOff()) return routeNotFound()
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  if (!(await writeSharingInForce({ fresh: true }))) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const identity = await getAuthzIdentity({ fresh: true })
  if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const { id } = await params
  return acceptTransfer(request, identity, id, parsed.body.stepUpPassword)
})
