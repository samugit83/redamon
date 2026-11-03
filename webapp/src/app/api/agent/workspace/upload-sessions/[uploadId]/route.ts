import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { callAgent } from '../../../agentProxy'
import { codedAgentError } from '../../codedAgentError'

const FAILED = 'Failed to cancel the upload'
const UPLOAD_ID = /^[0-9a-f]{32}$/

export const DELETE = withRouteErrors(FAILED, async (
  request: NextRequest,
  { params }: { params: Promise<{ uploadId: string }> },
) => {
  const { uploadId } = await params
  const projectId = request.nextUrl.searchParams.get('projectId') || ''
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  if (!UPLOAD_ID.test(uploadId || '')) return NextResponse.json({ aborted: true })

  const call = await callAgent(
    `/workspace/upload-sessions/${uploadId}?projectId=${encodeURIComponent(projectId)}`,
    { method: 'DELETE' },
    FAILED,
  )
  if (!call.ok) return call.response
  if (!call.res.ok) return codedAgentError(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
