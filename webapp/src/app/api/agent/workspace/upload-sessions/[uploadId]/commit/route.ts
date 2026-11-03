import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { auditWorkspaceAction } from '@/lib/workspaceImport/audit'
import { callAgent } from '../../../../agentProxy'
import { codedAgentError } from '../../../codedAgentError'

const FAILED = 'Failed to finish the upload'
const UPLOAD_ID = /^[0-9a-f]{32}$/

interface CommitAnswer { jobId: string; destDir: string; name: string; kind: string; size: number }

export const POST = withRouteErrors(FAILED, async (
  request: NextRequest,
  { params }: { params: Promise<{ uploadId: string }> },
) => {
  const { uploadId } = await params
  let body: { projectId?: unknown }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body', code: 'invalid_request' }, { status: 400 })
  }
  const projectId = typeof body?.projectId === 'string' ? body.projectId : ''
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  if (!UPLOAD_ID.test(uploadId || '')) {
    return NextResponse.json({ error: 'Upload session not found', code: 'session_not_found' }, { status: 404 })
  }

  const call = await callAgent(`/workspace/upload-sessions/${uploadId}/commit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ projectId }),
  }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return codedAgentError(call.res, FAILED)
  const started = await call.res.json() as CommitAnswer
  await auditWorkspaceAction('workspace.upload', projectId, {
    kind: started.kind, destDir: started.destDir, name: started.name, size: started.size, jobId: started.jobId,
  })
  return NextResponse.json(started, { status: 202 })
})
