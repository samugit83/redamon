/**
 * Who may run which MCP Tool Plugin servers (step 1.9). Server side only.
 *
 * A stdio server runs its command inside the agent container, which holds every
 * tenant's data and the master secrets, so only an administrator's (role read from
 * the database) is saved, tested or handed to the agent (NF-14, OQ-48; Phase 3
 * replaces the role with `platform:agent_mcp`). No legacy grant, no escape hatch.
 */
import { NextRequest, NextResponse } from 'next/server'
import { loadPrincipal } from '@/lib/authz/principal'
import { writeAudit } from '@/lib/audit'
import { getSession, isInternalRequest } from '@/lib/session'
import {
  STDIO_ADMIN_ONLY_CODE, STDIO_ADMIN_ONLY_MESSAGE, TOKEN_ENV_VAR_CODE, TOKEN_ENV_VAR_MESSAGE,
  isStdioServer,
} from '@/lib/mcp/schema'

/** Whether the account `userId` may own stdio servers that run. A gone account may not. */
export async function ownerRunsStdio(userId: string): Promise<boolean> {
  const owner = await loadPrincipal(userId)
  return owner?.role === 'admin'
}

/** The signed-in account behind a request, for the audit row; null for the internal key. */
export async function actingAccount(request: NextRequest): Promise<string | null> {
  if (isInternalRequest(request)) return null
  return (await getSession())?.userId ?? null
}

/** 403 `stdio_admin_only`, audited as `mcp_server.stdio_refused`. */
export async function stdioRefusal(
  { actorId, ownerId, serverId, via }: { actorId: string | null; ownerId: string; serverId: unknown; via: 'save' | 'test' },
  extra: Record<string, unknown> = {},
): Promise<NextResponse> {
  await writeAudit({
    actorId,
    action: 'mcp_server.stdio_refused',
    targetType: 'user',
    targetId: ownerId,
    after: { serverId: typeof serverId === 'string' ? serverId : null, via },
    source: 'ui',
  })
  return NextResponse.json(
    { ...extra, error: STDIO_ADMIN_ONLY_MESSAGE, code: STDIO_ADMIN_ONLY_CODE, field: 'transport' },
    { status: 403 },
  )
}

/** 422 `token_env_var_refused` (OQ-R1). */
export function tokenEnvVarRefusal(extra: Record<string, unknown> = {}): NextResponse {
  return NextResponse.json(
    { ...extra, error: TOKEN_ENV_VAR_MESSAGE, code: TOKEN_ENV_VAR_CODE, field: 'auth.token_env_var' },
    { status: 422 },
  )
}

/**
 * The owner's saved servers as the agent may load them: a non-admin owner's stdio
 * servers are left out, each logged. Anything that is not a list goes as stored.
 */
export function serversForAgent(ownerId: string, servers: unknown, runsStdio: boolean): unknown {
  if (runsStdio || !Array.isArray(servers)) return servers
  return servers.filter((srv) => {
    if (!isStdioServer(srv)) return true
    const id = (srv as { id?: unknown }).id
    console.warn(`[rbac] stdio mcp server skipped user=${ownerId} server=${typeof id === 'string' ? id : '-'}`)
    return false
  })
}
