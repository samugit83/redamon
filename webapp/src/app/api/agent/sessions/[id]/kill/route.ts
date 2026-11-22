import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requirePermission } from '@/lib/authz/guards'
import { resolveSessionsViewer } from '@/lib/authz/agentSessionsAccess'
import { beginDriveAudit, drivePath, driveSandbox, findDriveTarget, forwardAuditedDrive } from '../../sessionDrive'

const FAILED = 'Failed to kill session'

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
  const sandbox = driveSandbox(request)
  if (sandbox instanceof NextResponse) return sandbox
  const target = await findDriveTarget(viewer, 'session', id, sandbox, FAILED)
  if (target instanceof NextResponse) return target
  const audit = await beginDriveAudit('agent.session_kill', 'session', id, sandbox, viewer, target)
  return forwardAuditedDrive(audit, drivePath('session', id, 'kill', sandbox), { method: 'POST' }, FAILED)
})
