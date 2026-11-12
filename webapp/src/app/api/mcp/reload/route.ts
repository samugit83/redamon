/**
 * POST /api/mcp/reload - an administrator holding platform:agent_mcp asks the agent to reload its MCP servers.
 *
 * The agent's MCP toolset is shared by every user, so this is an instance action
 * (HD-03). The request body is never forwarded: the agent reloads from the settings
 * it already holds, never from a list the caller sends (that replaced every user's
 * servers, stdio commands included). A user's own changes reload through the
 * /api/users/[id]/mcp writes.
 */
import { NextResponse } from 'next/server'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { requireAdmin } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { requireSessionPermission } from '@/lib/authz/adminPermission'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://agent:8080'

export const POST = withRouteErrors('Could not reload the MCP servers', async () => {
  const admin = await requireAdmin()
  if (admin instanceof NextResponse) return admin
  const denied = await requireSessionPermission(admin, 'platform:agent_mcp')
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
