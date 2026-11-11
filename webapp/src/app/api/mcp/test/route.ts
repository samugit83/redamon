/** POST /api/mcp/test - proxy to agent's /mcp/test for live MCP draft validation.
 *
 * Body shape: { server: MCPServer, userId?: string }. The account is the caller's
 * own: a `userId` must be one the caller may write (the UI sends its own), and none
 * means the caller. A masked auth.token is restored from that account's saved
 * record. The agent spawns a stdio draft's command, so a stdio draft needs an
 * administrator owner (NF-14), and no draft names an agent variable (OQ-R1).
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, requireSession, requireUserAccess } from '@/lib/session'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { MASK_PREFIX, isStdioServer, namesTokenEnvVar, type MCPServer } from '@/lib/mcp/schema'
import { ownerRunsStdio, stdioRefusal, tokenEnvVarRefusal } from '@/lib/mcp/userServerAccess'
import { internalError, readUpstreamBody, upstreamFailure } from '@/lib/routeErrors'
import { mcpServerSecretReentry, secretReentryResponse } from '@/lib/authz/secretEndpointRebind'

/** Every answer keeps the panel's shape: McpServersTab renders these fields unconditionally. */
const EMPTY_RESULT = { discovered_tools: [], warnings: [], elapsed_ms: 0 }

export async function POST(request: NextRequest) {
  try {
    const internal = isInternalRequest(request)
    let caller: string | null = null
    if (!internal) {
      const session = await requireSession()
      if (session instanceof NextResponse) return session
      caller = session.userId
    }
    const payload = await request.json() as { server: MCPServer; userId?: string }
    const body = payload.server
    const userId = (typeof payload.userId === 'string' && payload.userId) || caller

    if (!userId) {
      return NextResponse.json(
        { ok: false, error: 'request body must include `userId`', ...EMPTY_RESULT },
        { status: 400 },
      )
    }

    if (!body) {
      return NextResponse.json(
        { ok: false, error: 'request body must include `server`', discovered_tools: [], warnings: [], elapsed_ms: 0 },
        { status: 400 },
      )
    }

    // The caller may only act on their OWN saved MCP secrets. Without this the
    // body-supplied userId could restore another user's token from the DB and
    // echo it to the agent test-spawn path (cross-tenant secret exposure). The
    // write rule: an admin's read of another account never sends its token.
    const denied = await requireUserAccess(request, userId, { mode: 'write' })
    if (denied) return denied

    if (namesTokenEnvVar(body)) return tokenEnvVarRefusal({ ok: false, ...EMPTY_RESULT })
    if (isStdioServer(body) && !(await ownerRunsStdio(userId))) {
      return stdioRefusal({ actorId: caller, ownerId: userId, serverId: body.id, via: 'test' }, { ok: false, ...EMPTY_RESULT })
    }

    // If the user clicked Test on a saved server, the token field is the
    // mask. Substitute the real token from the DB before forwarding.
    if (body.auth?.token?.startsWith(MASK_PREFIX)) {
      const settings = await prisma.userSettings.findUnique({
        where: { userId },
        select: { mcpServers: true },
      })
      const saved = (Array.isArray(settings?.mcpServers) ? settings!.mcpServers : []) as MCPServer[]
      const existing = saved.find(s => s.id === body.id)
      // Only to the URL it was saved for (HD-24): a draft pointing elsewhere
      // needs the token pasted again. This route restores the token alone.
      const reentry = existing && mcpServerSecretReentry(existing, body as unknown as Record<string, unknown>, { headers: false })
      if (reentry) return secretReentryResponse(reentry, { ok: false, ...EMPTY_RESULT })
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
    // A test the agent ran answers `{ok, error, warnings}`, whatever the MCP
    // server did, and is passed through. Any other body is the agent itself
    // failing (FastAPI `{detail}` on a bad internal key, a plain-text 500); its
    // text can be an exception's own message, so only status and code go out.
    const answered = await readUpstreamBody(upstream)
    if (answered.json && typeof answered.json.ok === 'boolean') {
      return NextResponse.json({ ...EMPTY_RESULT, ...answered.json }, { status: upstream.status })
    }
    return NextResponse.json({
      ok: false,
      error: 'The agent could not run the MCP test',
      code: answered.code ?? 'agent_error',
      upstreamStatus: upstream.status,
      ...EMPTY_RESULT,
    }, { status: 502 })
  } catch (error) {
    // Same reasoning as the LLM-provider test route (issue #184): an agent
    // outage must not be reported as a fault in the server the user just
    // configured. 503 because the dependency is unavailable, 504 when it timed out.
    if (error instanceof AgentUnreachableError) {
      console.error('MCP test: agent unreachable:', error.message, error.cause_)
      const failure = upstreamFailure('agent', error.cause_, error.message)
      return NextResponse.json(
        { ok: false, ...failure.body, ...EMPTY_RESULT },
        { status: failure.status },
      )
    }
    return internalError(error, 'MCP test proxy failed', {
      status: 502, log: 'Failed to proxy /mcp/test', extra: { ok: false, ...EMPTY_RESULT },
    })
  }
}
