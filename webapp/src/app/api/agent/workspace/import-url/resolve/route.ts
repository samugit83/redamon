import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { callAgent } from '../../../agentProxy'
import { codedAgentError } from '../../codedAgentError'
import { guardImport, tokenFor, urlProblem } from '../importUrlRequest'

const FAILED = 'Failed to check the link'

/** A preview: no audit row. */
export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  let body: { projectId?: unknown; url?: unknown; subpath?: unknown }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body', code: 'invalid_request' }, { status: 400 })
  }
  const guard = await guardImport(body?.projectId)
  if (!guard.ok) return guard.response
  const bad = urlProblem(body.url)
  if (bad) return bad
  const url = String(body.url).trim()
  const token = await tokenFor(guard, url)
  const call = await callAgent('/workspace/import-url/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      projectId: body.projectId, url,
      ...(typeof body.subpath === 'string' ? { subpath: body.subpath } : {}),
      ...(token ? { githubToken: token } : {}),
    }),
  }, FAILED, { timeoutMs: 30_000 })
  if (!call.ok) return call.response
  if (!call.res.ok) return codedAgentError(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
