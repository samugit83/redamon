import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { resolveSessionsViewer } from '@/lib/authz/agentSessionsAccess'
import { agentErrorResponse, callAgent } from '../../../agentProxy'
import { auditDrive, driveRan, findDriveTarget } from '../../sessionDrive'

const FAILED = 'Failed to kill session'

export const POST = withRouteErrors(FAILED, async (
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const viewer = await resolveSessionsViewer()
  if (viewer instanceof NextResponse) return viewer
  const { id } = await params
  const target = await findDriveTarget(viewer, 'session', id, FAILED)
  if (target instanceof NextResponse) return target
  const call = await callAgent(`/sessions/${encodeURIComponent(id)}/kill`, { method: 'POST' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  const body = await call.res.json()
  if (driveRan(body)) await auditDrive('agent.session_kill', 'session', id, viewer, target)
  return NextResponse.json(body)
})
