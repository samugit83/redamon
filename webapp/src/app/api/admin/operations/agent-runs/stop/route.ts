import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { parseRunTarget, stopAgentRun } from '@/lib/authz/adminOperations'

/**
 * Stop one agent run from the operations view (step 6.5; GV-06). 404 with RBAC_GOVERNANCE_ENABLED
 * off. Same-origin JSON `{userId, projectId, sessionId}`; the signed-in person must hold
 * platform:operations (the view that lists the run) and platform:emergency_stop (the permission that
 * already stops every user's runs), both read fresh. Audited `agent.run_stop` with the run's project
 * when a run stopped; `{stopped: false}` for a run already over (lib/authz/adminOperations.ts).
 */
export const POST = withRouteErrors('Could not stop the agent run', async (request: NextRequest) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const refused = await requireSessionPermission(session, 'platform:operations', { fresh: true })
  if (refused) return refused
  const target = parseRunTarget(parsed.body)
  if ('code' in target) return NextResponse.json(target, { status: 400 })
  return stopAgentRun(request, session, target)
})
