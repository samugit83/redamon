/**
 * POST /api/mcp/reload - whoever holds platform:agent_mcp asks the agent to reload its MCP servers.
 *
 * The agent's MCP toolset is shared by every user, so this is an instance action
 * (HD-03). The request body is never forwarded: the agent reloads from the settings
 * it already holds, never from a list the caller sends (that replaced every user's
 * servers, stdio commands included). A user's own changes reload through the
 * /api/users/[id]/mcp writes.
 */
import { NextResponse } from 'next/server'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { requireAdmin, requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { rbacFlags } from '@/lib/authz/flags'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://agent:8080'

export const POST = withRouteErrors('Could not reload the MCP servers', async () => {
  // The permission decides, as for every platform tool (requirePluginAdmin): with RBAC_PERMISSIONS_ENABLED
  // on a member holding it through an override reloads too. Off, the administrator account answers, as
  // before (every admin holds it then, and a member gets today's 403).
  const session = rbacFlags().permissions ? await requireSession() : await requireAdmin()
  if (session instanceof NextResponse) return session
  const denied = await requireSessionPermission(session, 'platform:agent_mcp')
  if (denied) return denied
  try {
    const upstream = await fetch(`${AGENT_API_URL}/mcp/reload`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: '{}',
      signal: AbortSignal.timeout(60_000),
    })
    const data = await upstream.json().catch(() => ({}))
    return NextResponse.json(data, { status: upstream.status })
  } catch (error) {
    console.error('Failed to proxy /mcp/reload:', error)
    return NextResponse.json({ error: 'agent unreachable' }, { status: 502 })
  }
})
