import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { disableAccount, forbiddenAs, ownAccountRefusal, routeNotFound } from '@/lib/authz/accountStatus'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST: disable a member's account (ID-13): it can no longer sign in, every session and MCP
 * token ends, its agent runs and sockets stop; its projects stay. Identity switch only (404
 * without it). Body: a JSON object (`{}`).
 */
export const POST = withRouteErrors('Could not disable the account', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().identity) return routeNotFound()
  const session = await requireAdmin({ fresh: true })
  if (session instanceof NextResponse) return forbiddenAs(session, 'users:disable')
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { id } = await params
  return ownAccountRefusal(session, id, 'disable')
    ?? await rootProtectedRefusal(request, session, id, 'disable')
    ?? disableAccount(request, session, id)
})
