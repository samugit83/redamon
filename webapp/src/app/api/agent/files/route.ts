import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse } from '../agentProxy'
import { callAgentForDownload, safeDownloadName, streamDownload } from '../downloadProxy'

const FAILED = 'Failed to download file'

/**
 * The workspace-relative path of `path` in project `projectId`'s workspace, or null when it points
 * anywhere else. A relative path is already workspace-relative; an absolute one must sit under
 * `/workspace/<projectId>/` (where the agent and kali-sandbox mount the project's workspace). No
 * `..` segment is accepted, so nothing climbs out before the agent's own confinement check.
 */
function projectWorkspacePath(projectId: string, path: string): string | null {
  const prefix = `/workspace/${projectId}/`
  const relative = path.startsWith('/') ? (path.startsWith(prefix) ? path.slice(prefix.length) : null) : path
  if (!relative) return null
  if (relative.split(/[\\/]/).some(segment => segment === '..')) return null
  return relative
}

/**
 * Download one file of a project's agent workspace. The caller names the project and needs
 * workspace:read (Raw data & files) on it; the agent reads the file from that project's workspace
 * only (`/workspace/download`). The in-chat flow that read any file under the shared sandbox's
 * `/tmp`, with no project or user scope, is refused: a file outside the project's workspace is not
 * a download this route makes.
 */
export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  const path = request.nextUrl.searchParams.get('path')
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'A download needs its projectId: files are read from that project\'s workspace only' }, { status: 400 })
  }
  const auth = await requirePermission(request, 'workspace:read', { projectId })
  if (auth instanceof NextResponse) return auth

  if (!path) {
    return NextResponse.json({ error: 'Missing path parameter' }, { status: 400 })
  }
  const relative = projectWorkspacePath(projectId, path)
  if (relative === null) {
    return NextResponse.json({ error: 'The file is outside this project\'s workspace' }, { status: 400 })
  }

  const agentPath = `/workspace/download?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(relative)}`
  const call = await callAgentForDownload(request, agentPath, {}, FAILED, 60_000)
  if (!call.ok) return call.response
  const resp = call.res
  if (!resp.ok) return agentErrorResponse(resp, FAILED)
  return streamDownload(resp, safeDownloadName(relative))
})
