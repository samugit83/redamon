import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { adminTargetGate } from '@/lib/authz/rootPowers'
import { ROOT_ONLY_INVITE, resendInvite, forbiddenToInvite } from '@/lib/authz/invites'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/users/[id]/invite/resend (step 2.9, ID-14): a new link for an invited account, answered
 * once; the open one is cancelled. An invited admin (Root promoted it) is the confirmed Root's,
 * with its password (`{stepUpPassword}`). Identity switch only (404 without it).
 */
export const POST = withRouteErrors('Could not resend the invite', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenToInvite(session)
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { id } = await params
  const gate = await adminTargetGate(request, session, id, parsed.body.stepUpPassword, ROOT_ONLY_INVITE)
  if (gate instanceof NextResponse) return gate
  return resendInvite(request, session, id)
})
