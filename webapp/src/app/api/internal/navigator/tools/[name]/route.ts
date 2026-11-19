/**
 * POST /api/internal/navigator/tools/:name `{args}`: one tool call of a live AI Navigator run (plan
 * §7.7). The master key only (never the scanner key), then the run's credential; every id the call
 * acts on comes from the run entry the credential resolves to, never from this request. The person,
 * the acting admin, every permission of the tool, the project level, the owner's policy, Root's
 * switch, the tenant and the login are all judged again, fresh (lib/navigator/tools/run.ts).
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { resolveCredential } from '@/lib/navigator/credential'
import { navigatorError, navigatorJson } from '@/lib/navigator/responses'
import { runNavigatorTool } from '@/lib/navigator/tools/run'

export const runtime = 'nodejs'

type Ctx = { params: Promise<{ name: string }> }

export const POST = withRouteErrors('Could not run the AI Navigator tool', async (request: NextRequest, { params }: Ctx) => {
  if (!isInternalRequest(request)) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const resolved = resolveCredential(request)
  if (!('run' in resolved)) return navigatorError('not_found', 404)
  const { name } = await params
  if (!/^[a-z_]{1,60}$/.test(name)) return navigatorError('tool_unknown', 404)
  const body = await request.json().catch(() => null) as { args?: unknown } | null
  const answer = await runNavigatorTool(resolved.run, name, body && typeof body === 'object' ? body.args : undefined)
  if (answer.ok) return navigatorJson(answer)
  return navigatorJson({ ok: false, code: answer.code, message: answer.message }, { status: answer.status })
})
