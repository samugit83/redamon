/**
 * GET /api/admin/navigator/health: whether AI Navigator's documentation is installed on this server
 * (the agent's wiki index), for the IAM → Instance panel. Root's `instance:settings`.
 */
import { NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { upstreamFailureResponse, withRouteErrors } from '@/lib/routeErrors'
import { navigatorJson } from '@/lib/navigator/responses'

export const GET = withRouteErrors('Could not read the AI Navigator health', async () => {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const denied = await requireSessionPermission(session, 'instance:settings')
  if (denied) return denied
  let res: Response
  try {
    res = await agentFetch('/navigator/health', { cache: 'no-store' }, { timeoutMs: 10_000 })
  } catch (err) {
    if (err instanceof AgentUnreachableError) return upstreamFailureResponse('agent', err.cause_, 'AI Navigator health')
    throw err
  }
  if (res.status === 404) return navigatorJson({ agentOutdated: true, wiki: null })
  const body = await res.json().catch(() => null) as { wiki?: unknown } | null
  if (!res.ok || !body) return navigatorJson({ wiki: null, error: `agent answered HTTP ${res.status}` })
  return navigatorJson({ wiki: body.wiki ?? null })
})
