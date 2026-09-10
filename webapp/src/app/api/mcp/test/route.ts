/** POST /api/mcp/test - proxy to agent's /mcp/test for live MCP draft validation.
 *
 * Body shape: { server: MCPServer, userId: string }.
 * userId is required (and explicit, not relying on middleware headers) so
 * we can restore a masked auth.token from the user's saved DB record. The
 * UI sends it from the same `userId` prop already used by the form's CRUD
 * endpoints - no JWT header juggling.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { MASK_PREFIX, type MCPServer } from '@/lib/mcp/schema'

export async function POST(request: NextRequest) {
  try {
    const payload = await request.json() as { server: MCPServer; userId?: string }
    const body = payload.server
    const userId = payload.userId

    if (!body) {
      return NextResponse.json(
        { ok: false, error: 'request body must include `server`', discovered_tools: [], warnings: [], elapsed_ms: 0 },
        { status: 400 },
      )
    }

    // The caller may only act on their OWN saved MCP secrets. Without this the
    // body-supplied userId could restore another user's token from the DB and
    // echo it to the agent test-spawn path (cross-tenant secret exposure).
    if (userId) {
      const denied = await requireUserAccess(request, userId)
      if (denied) return denied
    }

    // If the user clicked Test on a saved server, the token field is the
    // mask. Substitute the real token from the DB before forwarding.
    if (body.auth?.token?.startsWith(MASK_PREFIX)) {
      if (!userId) {
        return NextResponse.json({
          ok: false,
          error: 'token is masked but request did not include userId - cannot restore from DB',
          discovered_tools: [], warnings: [], elapsed_ms: 0,
        }, { status: 400 })
      }
      const settings = await prisma.userSettings.findUnique({
        where: { userId },
        select: { mcpServers: true },
      })
      const saved = (Array.isArray(settings?.mcpServers) ? settings!.mcpServers : []) as MCPServer[]
      const existing = saved.find(s => s.id === body.id)
      if (existing?.auth?.token && !existing.auth.token.startsWith(MASK_PREFIX)) {
        body.auth = { ...body.auth, token: existing.auth.token }
      } else {
        return NextResponse.json({
          ok: false,
          error: `token is masked and no saved literal for server '${body.id}' - paste the token again`,
          discovered_tools: [], warnings: [], elapsed_ms: 0,
        }, { status: 400 })
      }
    }

    const upstream = await agentFetch(
      '/mcp/test',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
      { timeoutMs: 35_000 },
    )
    const data = await upstream.json().catch(() => ({}))
    return NextResponse.json(data, { status: upstream.status })
  } catch (error) {
    // Same reasoning as the LLM-provider test route (issue #184): an agent
    // outage must not be reported as a fault in the server the user just
    // configured. 503, because the dependency is unavailable.
    if (error instanceof AgentUnreachableError) {
      console.error('MCP test: agent unreachable:', error.message, error.cause_)
      return NextResponse.json(
        { ok: false, error: error.message, discovered_tools: [], warnings: [], elapsed_ms: 0 },
        { status: 503 },
      )
    }
    console.error('Failed to proxy /mcp/test:', error)
    const message = error instanceof Error ? error.message : 'unknown error'
    return NextResponse.json(
      { ok: false, error: `proxy failed: ${message}`, discovered_tools: [], warnings: [], elapsed_ms: 0 },
      { status: 502 },
    )
  }
}
