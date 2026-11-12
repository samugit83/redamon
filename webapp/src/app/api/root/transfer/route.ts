import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { offerRootTransfer, pendingTransferFor, transferForbidden } from '@/lib/authz/rootTransfer'

/**
 * Root transfer (step 2.6, ID-07). GET: the pending offer, for Root and its recipient only
 * (`{offer: null}` for every other admin). POST `{targetUserId, stepUpPassword}`: the confirmed
 * Root offers Root to an admin who can sign in, with its own password; the offer lasts 24 hours
 * and replaces a pending one. Identity switch only (404 without it).
 */
export const GET = withRouteErrors('Could not read the Root transfer', async (_request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin()
  if (session instanceof NextResponse) return transferForbidden(session)
  return NextResponse.json({ offer: await pendingTransferFor(session) })
})

export const POST = withRouteErrors('Could not offer Root', async (request: NextRequest) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return transferForbidden(session)
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  return offerRootTransfer(request, session, parsed.body.targetUserId, parsed.body.stepUpPassword)
})
