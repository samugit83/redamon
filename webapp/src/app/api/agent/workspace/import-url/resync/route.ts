import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { auditWorkspaceAction } from '@/lib/workspaceImport/audit'
import { isGithubFamilyHost } from '@/lib/workspaceImport/githubHosts'
import { githubTokenForImport } from '@/lib/workspaceImport/githubToken'
import { callAgent } from '../../../agentProxy'
import { codedAgentError } from '../../codedAgentError'
import { guardImport } from '../importUrlRequest'

const FAILED = 'Failed to start the re-sync'

interface ImportFacts { kind?: string; host?: string; sourcePath?: string }
interface Started { jobId: string; kind: string; destDir: string; name: string }

export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  let body: { projectId?: unknown; path?: unknown }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body', code: 'invalid_request' }, { status: 400 })
  }
  const guard = await guardImport(body?.projectId)
  if (!guard.ok) return guard.response
  if (typeof body.path !== 'string' || !body.path) {
    return NextResponse.json({ error: 'path required', code: 'invalid_request' }, { status: 400 })
  }
  const projectId = String(body.projectId)

  // The token only for a GitHub source, read from the folder's verified record.
  const props = await callAgent(
    `/workspace/properties?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(body.path)}`,
    { method: 'GET' }, FAILED,
  )
  if (!props.ok) return props.response
  if (!props.res.ok) return codedAgentError(props.res, FAILED)
  const facts = ((await props.res.json()) as { import?: ImportFacts }).import
  if (!facts) {
    return NextResponse.json({ error: 'This folder has no valid import record, so it cannot be re-synced.', code: 'not_imported' }, { status: 404 })
  }
  const token = !guard.actingAs && isGithubFamilyHost(facts.host)
    ? await githubTokenForImport(guard.userId, `https://${facts.host}/`)
    : ''

  const call = await callAgent('/workspace/import-url/resync', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ projectId, path: body.path, ...(token ? { githubToken: token } : {}) }),
  }, FAILED, { timeoutMs: 30_000 })
  if (!call.ok) return call.response
  if (!call.res.ok) return codedAgentError(call.res, FAILED)
  const started = await call.res.json() as Started
  await auditWorkspaceAction('workspace.resync', projectId, {
    kind: started.kind, destDir: started.destDir, name: started.name,
    url: `https://${facts.host || ''}${facts.sourcePath || ''}`, jobId: started.jobId, tokenUsed: Boolean(token),
  })
  return NextResponse.json(started, { status: 202 })
})
