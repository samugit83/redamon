import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../../../agentProxy'

const FAILED = 'Failed to cancel job'

export const POST = withRouteErrors(FAILED, async (
  request: NextRequest,
  { params }: { params: Promise<{ jobId: string }> },
) => {
  const { jobId } = await params
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'workspace:write', { projectId: projectId || '' })
  if (auth instanceof NextResponse) return auth

  if (!projectId) {
    return NextResponse.json({ error: 'projectId required' }, { status: 400 })
  }
  if (!jobId) {
    return NextResponse.json({ error: 'jobId required' }, { status: 400 })
  }

  const call = await callAgent(
    `/workspace/jobs/${encodeURIComponent(jobId)}/cancel?projectId=${encodeURIComponent(projectId)}`,
    { method: 'POST' },
    FAILED,
  )
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
