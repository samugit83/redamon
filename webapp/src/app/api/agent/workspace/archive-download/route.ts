import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse } from '../../agentProxy'
import { callAgentForDownload, safeDownloadName, streamDownload } from '../../downloadProxy'

const FAILED = 'Failed to download archive'

export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'workspace:read', { projectId: projectId || '' })
  if (auth instanceof NextResponse) return auth
  const path = request.nextUrl.searchParams.get('path')
  const format = request.nextUrl.searchParams.get('format') ?? 'tar.gz'

  if (!projectId || !path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }

  // The agent builds the whole archive before its first byte; a 2 GiB folder
  // takes far longer than a minute.
  const call = await callAgentForDownload(
    request,
    `/workspace/archive-download?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}&format=${encodeURIComponent(format)}`,
    {},
    FAILED,
    900_000,
  )
  if (!call.ok) return call.response
  const resp = call.res
  if (!resp.ok) return agentErrorResponse(resp, FAILED)
  const ext = format === 'zip' ? 'zip' : 'tar.gz'
  return streamDownload(resp, `${safeDownloadName(path, 'workspace')}.${ext}`)
})
