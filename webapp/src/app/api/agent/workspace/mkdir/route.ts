import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'
import { codedAgentError } from '../codedAgentError'

const FAILED = 'Failed to mkdir'

export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  let body: { projectId?: string; path?: string }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  if (!body.projectId || !body.path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }
  const __denied = await guardProject(body.projectId || '')
  if (__denied) return __denied

  const call = await callAgent('/workspace/mkdir', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, FAILED)
  if (!call.ok) return call.response
  // A 409 is the agent's coded busy answer: keep the id of the import that holds the folder.
  if (call.res.status === 409) return codedAgentError(call.res, FAILED)
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
