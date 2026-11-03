import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse } from '../../agentProxy'
import { callAgentForDownload, safeDownloadName, streamDownload } from '../../downloadProxy'

export const runtime = 'nodejs'
export const maxDuration = 900

const FAILED = 'Failed to build archive'

export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  let body: { projectId?: string; paths?: string[]; format?: string; archiveName?: string }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  if (!body.projectId || !Array.isArray(body.paths) || body.paths.length === 0) {
    return NextResponse.json({ error: 'projectId + non-empty paths required' }, { status: 400 })
  }
  const __denied = await guardProject(body.projectId || '')
  if (__denied) return __denied

  // The agent builds the whole archive before its first byte.
  const call = await callAgentForDownload(request, '/workspace/bulk-archive', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, FAILED, 900_000)
  if (!call.ok) return call.response
  const resp = call.res
  if (!resp.ok) return agentErrorResponse(resp, FAILED)
  const ext = body.format === 'zip' ? 'zip' : 'tar.gz'
  return streamDownload(resp, `${safeDownloadName(body.archiveName, 'bundle')}.${ext}`)
})
