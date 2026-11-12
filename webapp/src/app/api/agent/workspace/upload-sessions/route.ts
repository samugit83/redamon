import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { callAgent } from '../../agentProxy'
import { codedAgentError } from '../codedAgentError'

const FAILED = 'Failed to start the upload'

export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body', code: 'invalid_request' }, { status: 400 })
  }
  const { projectId, destDir, name, size, kind, onConflict, entries } = body ?? {}
  if (typeof projectId !== 'string' || !projectId || typeof name !== 'string' || typeof kind !== 'string'
    || typeof size !== 'number' || !Number.isInteger(size)) {
    return NextResponse.json({ error: 'projectId, name, size and kind required', code: 'invalid_request' }, { status: 400 })
  }
  const auth = await requirePermission(request, 'workspace:write', { projectId })
  if (auth instanceof NextResponse) return auth

  const call = await callAgent('/workspace/upload-sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      projectId, name, size, kind,
      destDir: typeof destDir === 'string' ? destDir : '.',
      onConflict: typeof onConflict === 'string' ? onConflict : 'keep_both',
      ...(typeof entries === 'number' && Number.isInteger(entries) && entries >= 0 ? { entries } : {}),
    }),
  }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return codedAgentError(call.res, FAILED)
  return NextResponse.json(await call.res.json(), { status: 201 })
})
