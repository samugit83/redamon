import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requirePermission } from '@/lib/authz/guards'
import { resolveSessionsViewer } from '@/lib/authz/agentSessionsAccess'
import { agentErrorResponse, callAgent } from '../../../agentProxy'
import { auditDrive, driveRan, findDriveTarget } from '../../../sessions/sessionDrive'

const FAILED = 'Failed to kill job'

/** A background job (a handler) belongs to no project: only holders of every session see and kill it. */
export const POST = withRouteErrors(FAILED, async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  // Using shell sessions at all (§5.6); whose sessions the list holds is the viewer's rule below.
  const auth = await requirePermission(request, 'agent:sessions')
  if (auth instanceof NextResponse) return auth
  const viewer = await resolveSessionsViewer()
  if (viewer instanceof NextResponse) return viewer
  const { id } = await params
  const target = await findDriveTarget(viewer, 'job', id, FAILED)
  if (target instanceof NextResponse) return target
  const call = await callAgent(`/jobs/${encodeURIComponent(id)}/kill`, { method: 'POST' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  const body = await call.res.json()
  if (driveRan(body)) await auditDrive('agent.job_kill', 'job', id, viewer, target)
  return NextResponse.json(body)
})
