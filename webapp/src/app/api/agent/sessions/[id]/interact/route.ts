import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { requirePermission } from '@/lib/authz/guards'
import { resolveSessionsViewer } from '@/lib/authz/agentSessionsAccess'
import { beginDriveAudit, drivePath, driveSandbox, findDriveTarget, forwardAuditedDrive } from '../../sessionDrive'

const FAILED = 'Failed to interact with session'

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
  const body = await request.json().catch(() => null)
  if (!body || typeof body !== 'object') {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  const target = await findDriveTarget(viewer, 'session', id, sandbox, FAILED)
  if (target instanceof NextResponse) return target
  const audit = await beginDriveAudit('agent.session_interact', 'session', id, sandbox, viewer, target)
  // The agent waits up to 40s on the session manager; ours must outlast it.
  return forwardAuditedDrive(audit, drivePath('session', id, 'interact', sandbox), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, FAILED, { timeoutMs: 45_000 })
})
