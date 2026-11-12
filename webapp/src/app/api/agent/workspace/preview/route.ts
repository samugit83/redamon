import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'

const FAILED = 'Failed to preview'

export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'workspace:read', { projectId: projectId || '' })
  if (auth instanceof NextResponse) return auth
  const path = request.nextUrl.searchParams.get('path')
  const maxBytes = request.nextUrl.searchParams.get('maxBytes')

  if (!projectId || !path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }

  let url = `/workspace/preview?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}`
  if (maxBytes) url += `&maxBytes=${encodeURIComponent(maxBytes)}`
  const call = await callAgent(url, { cache: 'no-store' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
