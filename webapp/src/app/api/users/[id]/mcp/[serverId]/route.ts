/**
 * PUT    /api/users/[id]/mcp/[serverId] - update one server
 * DELETE /api/users/[id]/mcp/[serverId] - delete one server
 *
 * Both ask the agent to reload after a successful write; a failed reload comes
 * back as `warnings`.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest, requireUserAccess } from '@/lib/session'
import prisma from '@/lib/prisma'
import { mcpServerSchema, validateMcpServers, type MCPServer } from '@/lib/mcp/schema'
import { maskMcpServersForApi, restoreMaskedToken } from '../route'
import { internalError } from '@/lib/routeErrors'
import { mcpServerEndpointChange, mcpServerSecretReentry, secretReentryResponse } from '@/lib/authz/secretEndpointRebind'
import { requireStepUp } from '@/lib/authz/stepUp'
import { reloadAgentMcp } from '../reload'

interface RouteParams {
  params: Promise<{ id: string; serverId: string }>
}

export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, serverId } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    // The step-up password rides with the save and is never part of the server.
    const { stepUpPassword, ...body } = await request.json()

    // Look up the existing record first so we can restore the literal auth
    // token if the user submitted a masked placeholder. This must happen
    // BEFORE schema validation so the at-least-one auth refine sees the
    // restored token, not the placeholder.
    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
      select: { mcpServers: true },
    })
    const current = (Array.isArray(existing?.mcpServers) ? existing!.mcpServers : []) as MCPServer[]
    const existingServer = current.find(s => s.id === serverId)

    // A new URL must come with the token and header values typed again (HD-24):
    // the masked ones restored below would otherwise follow the server there.
    if (existingServer) {
      const reentry = mcpServerSecretReentry(existingServer, body)
      if (reentry) return secretReentryResponse(reentry)
      // Re-pointing also takes the signed-in person's password (ID-25): a new token typed
      // for a new address passes the re-entry rule, yet the agent's tool calls follow it.
      if (!isInternalRequest(request) && mcpServerEndpointChange(existingServer, body)) {
        const refused = await requireStepUp(request, stepUpPassword)
        if (refused) return refused
      }
    }

    // Restore masked token (••••...) from the existing DB record.
    const restored = existingServer
      ? restoreMaskedToken(body as MCPServer, existingServer)
      : (body as MCPServer)

    const parsed = mcpServerSchema.safeParse(restored)
    if (!parsed.success) {
      return NextResponse.json({
        error: 'invalid MCP server',
        issues: parsed.error.issues.map(i => ({ path: i.path, message: i.message })),
      }, { status: 400 })
    }
    const updated: MCPServer = parsed.data

    if (updated.id !== serverId) {
      return NextResponse.json({ error: 'server id in path does not match body id' }, { status: 400 })
    }

    const idx = current.findIndex((s) => s.id === serverId)
    if (idx === -1) {
      return NextResponse.json({ error: `server '${serverId}' not found` }, { status: 404 })
    }

    const next = [...current]
    next[idx] = updated

    const { valid, errors } = validateMcpServers(next)
    if (errors.length > 0 || valid.length !== next.length) {
      return NextResponse.json({ error: 'cross-server validation failed', issues: errors }, { status: 400 })
    }

    await prisma.userSettings.update({
      where: { userId: id },
      data: { mcpServers: next as unknown as object },
    })

    const warnings = await reloadAgentMcp(next)
    const [returned] = maskMcpServersForApi([updated])
    return NextResponse.json({
      server: returned, servers: maskMcpServersForApi(next),
      ...(warnings.length ? { warnings } : {}),
    })
  } catch (error) {
    return internalError(error, 'Failed to update MCP server')
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, serverId } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied

    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
      select: { mcpServers: true },
    })
    const current = (Array.isArray(existing?.mcpServers) ? existing!.mcpServers : []) as MCPServer[]

    const next = current.filter((s) => s.id !== serverId)
    if (next.length === current.length) {
      return NextResponse.json({ error: `server '${serverId}' not found` }, { status: 404 })
    }

    await prisma.userSettings.update({
      where: { userId: id },
      data: { mcpServers: next as unknown as object },
    })

    const warnings = await reloadAgentMcp(next)
    // Masked like every other answer here: the remaining servers hold literal tokens.
    return NextResponse.json({ servers: maskMcpServersForApi(next), ...(warnings.length ? { warnings } : {}) })
  } catch (error) {
    return internalError(error, 'Failed to delete MCP server')
  }
}
