import { NextResponse, type NextRequest } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { readOperations } from '@/lib/authz/adminOperations'

/**
 * The admin operations view (step 6.5; GV-06, GV-18). 404 with RBAC_GOVERNANCE_ENABLED off, as the
 * console's pages are.
 *
 * GET (platform:operations): every running and queued scan with its project's owner and its actor,
 * every agent session with its person (and the admin behind an act-as run) and whether a run is
 * active, the live triage runs and the shell sessions with their project owners, plus whether the
 * signed-in person may stop runs (lib/authz/adminOperations.ts). A source that does not answer is
 * named by its code and the others still render. Names and ids only; writes no audit row.
 * /api/system/stats stays the members' memory meter.
 */
export const GET = withRouteErrors('Could not load the operations view', async (_request: NextRequest) => {
  if (!rbacFlags().governance) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireSessionPermission(session, 'platform:operations')
  if (refused) return refused
  return NextResponse.json(await readOperations(session), { headers: { 'Cache-Control': 'no-store' } })
})
