import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { requireStepUp } from '@/lib/authz/stepUp'
import { enableAccount, forbiddenAs, isAdminAccount } from '@/lib/authz/accountStatus'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST: enable a disabled account again (ID-13): its password comes back and it can sign in.
 * Open whatever the identity switch, so an account disabled while the switch was on can
 * always be restored after it is turned off. With the switch on an admin target needs Root
 * (`root_only`); with it off the Phase 1 rule holds: another admin needs the acting admin's
 * own password (`{stepUpPassword}`, ID-25). Body: a JSON object.
 */
export const POST = withRouteErrors('Could not enable the account', async (request: NextRequest, { params }: RouteParams) => {
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenAs(session, 'users:disable')
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { id } = await params
  const identity = rbacFlags().identity
  if (!identity && id !== session.userId && await isAdminAccount(id)) {
    const refusal = await requireStepUp(request, parsed.body.stepUpPassword)
    if (refusal) return refusal
  }
  return enableAccount(request, session, id, { adminTarget: !identity })
})
