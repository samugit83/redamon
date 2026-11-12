import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { ROOT_ONLY_REFUSAL, forbiddenAs, ownAccountRefusal, revokeSessions, routeNotFound } from '@/lib/authz/accountStatus'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { adminTargetGate } from '@/lib/authz/rootPowers'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST: sign a member out everywhere (ID-21): its login cookies and MCP tokens end and its
 * open sockets close; the account stays active. Another admin only by the confirmed Root, with
 * Root's password (`{stepUpPassword}`, step 2.6), or with the permissions switch on by an
 * `admins:manage` holder over a strict subset, with its own (step 3.11). Identity switch only
 * (404 without it). Body: a JSON object (`{}`).
 */
export const POST = withRouteErrors('Could not sign the account out', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenAs(session, 'users:revoke_sessions')
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { id } = await params
  const refused = ownAccountRefusal(session, id, 'revoke') ?? await rootProtectedRefusal(request, session, id, 'revoke_sessions')
  if (refused) return refused
  const gate = await adminTargetGate(request, session, id, parsed.body.stepUpPassword, ROOT_ONLY_REFUSAL.error, 'revoke_sessions')
  if (gate instanceof NextResponse) return gate
  return revokeSessions(request, session, id, gate)
})
