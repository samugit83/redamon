import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { ROOT_ONLY_REFUSAL, disableAccount, forbiddenAs, ownAccountRefusal, routeNotFound } from '@/lib/authz/accountStatus'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { adminTargetGate } from '@/lib/authz/rootPowers'
import { requireSessionPermission } from '@/lib/authz/adminPermission'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST: disable a member's account (ID-13): it can no longer sign in, every session and MCP
 * token ends, its agent runs and sockets stop; its projects stay. Another admin's account only
 * by the confirmed Root, with Root's password (`{stepUpPassword}`, step 2.6), or with the
 * permissions switch on by an `admins:manage` holder over a strict subset, with its own (step
 * 3.11). Identity switch only (404 without it). Body: a JSON object (`{}`).
 */
export const POST = withRouteErrors('Could not disable the account', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenAs(session, 'users:disable')
  const denied = await requireSessionPermission(session, 'users:disable', { fresh: true })
  if (denied) return denied
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { id } = await params
  const refused = ownAccountRefusal(session, id, 'disable') ?? await rootProtectedRefusal(request, session, id, 'disable')
  if (refused) return refused
  const gate = await adminTargetGate(request, session, id, parsed.body.stepUpPassword, ROOT_ONLY_REFUSAL.error, 'disable')
  if (gate instanceof NextResponse) return gate
  return disableAccount(request, session, id, gate)
})
