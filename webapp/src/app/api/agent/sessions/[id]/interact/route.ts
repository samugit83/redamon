import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { resolveSessionsViewer } from '@/lib/authz/agentSessionsAccess'
import { agentErrorResponse, callAgent } from '../../../agentProxy'
import { auditDrive, driveRan, findDriveTarget } from '../../sessionDrive'

const FAILED = 'Failed to interact with session'

export const POST = withRouteErrors(FAILED, async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const viewer = await resolveSessionsViewer()
  if (viewer instanceof NextResponse) return viewer
  const { id } = await params
  const body = await request.json().catch(() => null)
  if (!body || typeof body !== 'object') {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  const target = await findDriveTarget(viewer, 'session', id, FAILED)
  if (target instanceof NextResponse) return target
  // The agent waits up to 40s on the session manager; ours must outlast it.
  const call = await callAgent(`/sessions/${encodeURIComponent(id)}/interact`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, FAILED, { timeoutMs: 45_000 })
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  const answer = await call.res.json()
  if (driveRan(answer)) await auditDrive('agent.session_interact', 'session', id, viewer, target)
  return NextResponse.json(answer)
})
