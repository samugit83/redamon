import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { parseSandboxTarget, stopPersonSandbox } from '@/lib/authz/adminOperations'

/**
 * Stop one person's Kali sandboxes from the operations view (group 1, WI-S16-6), built like the
 * per-run stop: 404 with RBAC_GOVERNANCE_ENABLED off; same-origin JSON `{userId}`; the signed-in
 * person must hold platform:operations (the view that lists the sandbox) and platform:emergency_stop
 * (the permission that already stops every user's runs), both read fresh. Both views of the person
 * stop with reason `operator`; the gateway writes `sandbox.stopped` naming the admin when something
 * stopped (lib/authz/adminOperations.ts).
 */
export const POST = withRouteErrors('Could not stop the sandbox', async (request: NextRequest) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const refused = await requireSessionPermission(session, 'platform:operations', { fresh: true })
  if (refused) return refused
  const target = parseSandboxTarget(parsed.body)
  if ('code' in target) return NextResponse.json(target, { status: 400 })
  return stopPersonSandbox(request, session, target.userId)
})
