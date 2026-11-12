import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../../agentProxy'

const FAILED = 'Failed to read job status'
const JOB_ID = /^[0-9a-f]{32}$/

export const GET = withRouteErrors(FAILED, async (
  request: NextRequest,
  { params }: { params: Promise<{ jobId: string }> },
) => {
  const { jobId } = await params
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'workspace:read', { projectId: projectId || '' })
  if (auth instanceof NextResponse) return auth

  if (!projectId) {
    return NextResponse.json({ error: 'projectId required' }, { status: 400 })
  }
  if (!JOB_ID.test(jobId || '')) {
    return NextResponse.json({ error: 'Not found.', code: 'not_found' }, { status: 404 })
  }

  const call = await callAgent(
    `/workspace/jobs/${jobId}?projectId=${encodeURIComponent(projectId)}`,
    { method: 'GET' },
    FAILED,
  )
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
