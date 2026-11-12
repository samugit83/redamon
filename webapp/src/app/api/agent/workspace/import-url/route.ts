import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { auditWorkspaceAction } from '@/lib/workspaceImport/audit'
import { redactUrl } from '@/lib/workspaceImport/redactUrl'
import { callAgent } from '../../agentProxy'
import { codedAgentError } from '../codedAgentError'
import { requirePermission } from '@/lib/authz/guards'
import { importCaller, importProjectProblem, tokenFor, urlProblem } from './importUrlRequest'

const FAILED = 'Failed to start the import'

interface Started { jobId: string; kind: string; destDir: string; name: string }

export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body', code: 'invalid_request' }, { status: 400 })
  }
  const missing = importProjectProblem(body?.projectId)
  if (missing) return missing
  const auth = await requirePermission(request, 'workspace:import', { projectId: String(body.projectId) })
  if (auth instanceof NextResponse) return auth
  const guard = await importCaller(auth)
  const bad = urlProblem(body.url)
  if (bad) return bad
  const url = String(body.url).trim()
  const token = await tokenFor(guard, url)
  const call = await callAgent('/workspace/import-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      projectId: body.projectId,
      url,
      destDir: typeof body.destDir === 'string' ? body.destDir : '.',
      ...(typeof body.name === 'string' && body.name ? { name: body.name } : {}),
      onConflict: typeof body.onConflict === 'string' ? body.onConflict : 'keep_both',
      options: body.options && typeof body.options === 'object' ? body.options : {},
      ...(token ? { githubToken: token } : {}),
    }),
  }, FAILED, { timeoutMs: 30_000 })
  if (!call.ok) return call.response
  if (!call.res.ok) return codedAgentError(call.res, FAILED)
  const started = await call.res.json() as Started
  await auditWorkspaceAction('workspace.import', String(body.projectId), {
    kind: started.kind, destDir: started.destDir, name: started.name, url: redactUrl(url),
    jobId: started.jobId, tokenUsed: Boolean(token),
  })
  return NextResponse.json(started, { status: 202 })
})
