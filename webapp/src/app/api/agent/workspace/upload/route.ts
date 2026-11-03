import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'
import { codedAgentError } from '../codedAgentError'

// Increase body size limit so this proxy can stream large uploads.
export const runtime = 'nodejs'
export const maxDuration = 60

const FAILED = 'Failed to upload'

export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  // Pass the original multipart body straight through; FastAPI parses it.
  const formData = await request.formData()
  const projectId = formData.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId required' }, { status: 400 })
  }
  const __denied = await guardProject(String(projectId))
  if (__denied) return __denied
  const file = formData.get('file')
  if (!(file instanceof File)) {
    return NextResponse.json({ error: 'file required' }, { status: 400 })
  }

  // Re-encode as multipart for upstream. fetch() handles this for FormData;
  // a large file needs the same budget as the route.
  const call = await callAgent('/workspace/upload', {
    method: 'POST',
    body: formData,
  }, FAILED, { timeoutMs: 60_000 })
  if (!call.ok) return call.response
  // A 409 keeps the agent's code: `exists` becomes the drawer's overwrite prompt,
  // `busy` names the import that holds the folder.
  if (call.res.status === 409) return codedAgentError(call.res, FAILED)
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
