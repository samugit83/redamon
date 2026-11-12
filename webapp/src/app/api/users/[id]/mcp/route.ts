/**
 * GET  /api/users/[id]/mcp        - list user's MCP servers
 * POST /api/users/[id]/mcp        - add a new MCP server
 *
 * Asks the agent to reload (POST /mcp/reload) after a successful write so the
 * running agent picks up changes without manual intervention; a failed reload
 * comes back as `warnings` beside the saved server.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import prisma from '@/lib/prisma'
import { isStdioServer, mcpServerSchema, namesTokenEnvVar, validateMcpServers, type MCPServer } from '@/lib/mcp/schema'
import { maskMcpServersForApi, restoreMaskedToken } from '@/lib/mcp/mask'
import { actingAccount, ownerRunsStdio, stdioRefusal, tokenEnvVarRefusal } from '@/lib/mcp/userServerAccess'
import { internalError } from '@/lib/routeErrors'
import { reloadAgentMcp } from './reload'
import { requireSelfPermission } from '@/lib/authz/selfService'

// Re-exported for the per-server [serverId] route which imports from here.
export { maskMcpServersForApi, restoreMaskedToken }

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'read' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:mcp_servers')
    if (selfRefused) return selfRefused
    const settings = await prisma.userSettings.findUnique({
      where: { userId: id },
      select: { mcpServers: true },
    })
    const raw = (settings?.mcpServers as unknown) ?? []
    const servers = Array.isArray(raw) ? (raw as MCPServer[]) : []
    // The tab shows a member's saved stdio servers as not run, and offers stdio only to an admin.
    return NextResponse.json({ servers: maskMcpServersForApi(servers), stdioAllowed: await ownerRunsStdio(id) })
  } catch (error) {
    return internalError(error, 'Failed to list MCP servers')
  }
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const __denied = await requireUserAccess(request, id, { mode: 'write' })
    if (__denied) return __denied
    const selfRefused = await requireSelfPermission(request, id, 'self:mcp_servers')
    if (selfRefused) return selfRefused
    const body = await request.json()

    const refused = await refuseUserServer(request, id, body)
    if (refused) return refused

    const parsed = mcpServerSchema.safeParse(body)
    if (!parsed.success) {
      return NextResponse.json({
        error: 'invalid MCP server',
        issues: parsed.error.issues.map(i => ({ path: i.path, message: i.message })),
      }, { status: 400 })
    }
    const newServer: MCPServer = parsed.data

    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
      select: { mcpServers: true },
    })
    const current = (Array.isArray(existing?.mcpServers) ? existing!.mcpServers : []) as MCPServer[]

    if (current.some((s) => s.id === newServer.id)) {
      return NextResponse.json({ error: `server id '${newServer.id}' already exists` }, { status: 409 })
    }

    const next = [...current, newServer]

    // Re-validate with cross-server checks (tool-name collisions, etc.)
    const { valid, errors } = validateMcpServers(next)
    if (errors.length > 0 || valid.length !== next.length) {
      return NextResponse.json({ error: 'cross-server validation failed', issues: errors }, { status: 400 })
    }

    await prisma.userSettings.upsert({
      where: { userId: id },
      update: { mcpServers: next as unknown as object },
      create: { userId: id, mcpServers: next as unknown as object },
    })

    const warnings = await reloadAgentMcp(id, next)
    // Mask the literal token in the response so the UI shows the placeholder.
    const [returned] = maskMcpServersForApi([newServer])
    return NextResponse.json({
      server: returned, servers: maskMcpServersForApi(next),
      ...(warnings.length ? { warnings } : {}),
    }, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to add MCP server')
  }
}

/**
 * A server the account may not save, whatever else it holds: one naming an agent
 * variable as its bearer (OQ-R1, any owner) or a stdio server of a non-admin owner
 * (NF-14). Null when it may go on to validation.
 */
export async function refuseUserServer(request: NextRequest, ownerId: string, body: unknown): Promise<NextResponse | null> {
  if (namesTokenEnvVar(body)) return tokenEnvVarRefusal()
  if (isStdioServer(body) && !(await ownerRunsStdio(ownerId))) {
    const actor = await actingAccount(request)
    return stdioRefusal({
      actorId: actor?.id ?? null, actorEmail: actor?.email, ownerId, serverId: (body as { id?: unknown }).id, via: 'save',
    })
  }
  return null
}
