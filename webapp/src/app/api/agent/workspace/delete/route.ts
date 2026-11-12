import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'
import { codedAgentError } from '../codedAgentError'

const FAILED = 'Failed to delete'

export const DELETE = withRouteErrors(FAILED, async (request: NextRequest) => {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const auth = await requirePermission(request, 'workspace:write', { projectId: projectId || '' })
  if (auth instanceof NextResponse) return auth
  const path = request.nextUrl.searchParams.get('path')
  const recursive = request.nextUrl.searchParams.get('recursive') === 'true'

  if (!projectId || !path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }

  const call = await callAgent(
    `/workspace?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}&recursive=${recursive}`,
    { method: 'DELETE' },
    FAILED,
  )
  if (!call.ok) return call.response
  // A 409 is the agent's coded busy answer: keep the id of the import that holds the folder.
  if (call.res.status === 409) return codedAgentError(call.res, FAILED)
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
