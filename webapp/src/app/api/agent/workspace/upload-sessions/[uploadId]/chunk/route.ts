import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { callAgent } from '../../../../agentProxy'
import { codedAgentError } from '../../../codedAgentError'

export const runtime = 'nodejs'
export const maxDuration = 60

const FAILED = 'Failed to upload a chunk'
const UPLOAD_ID = /^[0-9a-f]{32}$/
// The client sends 8 MiB; refuse anything past twice that before the agent
// sees it (the Next proxy itself caps a body at 60 MB).
const MAX_CHUNK_BYTES = 16 * 1024 * 1024

export const PUT = withRouteErrors(FAILED, async (
  request: NextRequest,
  { params }: { params: Promise<{ uploadId: string }> },
) => {
  const { uploadId } = await params
  const projectId = request.nextUrl.searchParams.get('projectId') || ''
  const offset = request.nextUrl.searchParams.get('offset') || ''
  const auth = await requirePermission(request, 'workspace:write', { projectId })
  if (auth instanceof NextResponse) return auth
  if (!UPLOAD_ID.test(uploadId || '')) {
    return NextResponse.json({ error: 'Upload session not found', code: 'session_not_found' }, { status: 404 })
  }
  if (!/^\d+$/.test(offset)) {
    return NextResponse.json({ error: 'offset required', code: 'invalid_request' }, { status: 400 })
  }
  const declared = Number(request.headers.get('content-length') || '0')
  if (declared > MAX_CHUNK_BYTES) {
    return NextResponse.json({ error: 'The chunk is larger than the server accepts.', code: 'chunk_too_large' }, { status: 413 })
  }
  const data = await request.arrayBuffer()
  if (data.byteLength > MAX_CHUNK_BYTES) {
    return NextResponse.json({ error: 'The chunk is larger than the server accepts.', code: 'chunk_too_large' }, { status: 413 })
  }

  const call = await callAgent(
    `/workspace/upload-sessions/${uploadId}/chunk?projectId=${encodeURIComponent(projectId)}&offset=${offset}`,
    { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: data },
    FAILED,
    { timeoutMs: 60_000 },
  )
  if (!call.ok) return call.response
  if (!call.res.ok) return codedAgentError(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
