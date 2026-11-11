import { NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { resolveSessionsViewer, visibleSessions } from '@/lib/authz/agentSessionsAccess'
import { agentErrorResponse, callAgent } from '../agentProxy'

const FAILED = 'Failed to fetch sessions'

/** The shell sessions, jobs and listeners the caller may see (HD-01): own projects', or all with the grant. */
export const GET = withRouteErrors(FAILED, async () => {
  const viewer = await resolveSessionsViewer()
  if (viewer instanceof NextResponse) return viewer
  const call = await callAgent('/sessions', { cache: 'no-store' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await visibleSessions(await call.res.json(), viewer))
})
