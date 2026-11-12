/**
 * GET /api/mcp/manifest - the caller's own MCP Tool Plugin servers, read from their
 * saved settings, secrets masked as the agent's view masks them (HD-15). No agent
 * call: the agent's manifest held the servers of whichever account's project it
 * loaded last. Same shape as the agent's answer (servers, errors, warnings,
 * system_server_ids), plus `stdioAllowed` (a member's stdio servers never run).
 */
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { SYSTEM_SERVER_IDS, type MCPServer } from '@/lib/mcp/schema'
import { maskMcpServersForApi } from '@/lib/mcp/mask'
import { ownerRunsStdio } from '@/lib/mcp/userServerAccess'
import { internalError } from '@/lib/routeErrors'

export async function GET(request: NextRequest) {
  try {
    const auth = await requirePermission(request, 'self:mcp_servers')
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective
    const settings = await prisma.userSettings.findUnique({
      where: { userId: eff.userId },
      select: { mcpServers: true },
    })
    const raw = settings?.mcpServers as unknown
    const servers = Array.isArray(raw) ? (raw as MCPServer[]) : []
    return NextResponse.json({
      servers: maskMcpServersForApi(servers),
      errors: [],
      warnings: [],
      system_server_ids: [...SYSTEM_SERVER_IDS].sort(),
      stdioAllowed: await ownerRunsStdio(eff.userId),
    })
  } catch (error) {
    return internalError(error, 'Failed to read your MCP servers')
  }
}
