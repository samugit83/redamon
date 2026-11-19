/**
 * GET /api/internal/navigator/tools: the tool manifest of one live AI Navigator run, for the agent to
 * bind (plan §7.7). The master key AND the run's credential: the credential names the run, whose
 * person, project and login are judged again now, and only the tools that person may use there now
 * are listed, so the model never sees a tool it cannot use.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { resolveCredential } from '@/lib/navigator/credential'
import { navigatorError, navigatorJson } from '@/lib/navigator/responses'
import { allowedTools, freshRunDecision } from '@/lib/navigator/tools/run'

export const runtime = 'nodejs'

export const GET = withRouteErrors('Could not list the AI Navigator tools', async (request: NextRequest) => {
  if (!isInternalRequest(request)) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const resolved = resolveCredential(request)
  if (!('run' in resolved)) return navigatorError('not_found', 404)
  const d = await freshRunDecision(resolved.run)
  if (!d.allowed) return navigatorJson({ tools: [] })
  const tools = await allowedTools(d, resolved.run.projectId)
  return navigatorJson({
    tools: tools.map((t) => ({ name: t.name, route: t.route, description: t.description, parameters: t.parameters })),
  })
})
