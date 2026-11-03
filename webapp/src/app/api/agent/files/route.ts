import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse } from '../agentProxy'
import { callAgentForDownload, safeDownloadName, streamDownload } from '../downloadProxy'

const FAILED = 'Failed to download file'

export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  const path = request.nextUrl.searchParams.get('path')
  const projectId = request.nextUrl.searchParams.get('projectId')
  // projectId is optional here: when present we enforce project ownership; when
  // absent this is the legacy /tmp-only in-chat download flow (session-gated by
  // middleware), which has no project to scope to.
  if (projectId) {
    const __denied = await guardProject(projectId)
    if (__denied) return __denied
  }

  if (!path) {
    return NextResponse.json({ error: 'Missing path parameter' }, { status: 400 })
  }

  // When projectId is provided, use the project-scoped workspace download
  // (direct bind-mount read, no kali_shell base64 round-trip). Falls back
  // to the legacy /files endpoint for the existing /tmp/-only flow so we
  // don't break in-chat downloads from older messages.
  const agentPath = projectId
    ? `/workspace/download?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}`
    : `/files?path=${encodeURIComponent(path)}`
  // The legacy /files endpoint requires the internal key (it was an
  // unauthenticated command-injection surface); agentFetch sends it on both.
  const call = await callAgentForDownload(request, agentPath, {}, FAILED, 60_000)
  if (!call.ok) return call.response
  const resp = call.res
  if (!resp.ok) return agentErrorResponse(resp, FAILED)
  return streamDownload(resp, safeDownloadName(path))
})
