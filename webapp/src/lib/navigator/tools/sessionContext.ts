/**
 * The session-to-McpContext adapter (plan §7.9): the inbound MCP server's read functions, called
 * for an AI Navigator run instead of a token.
 *
 * The scopes come from the TOOL, not from the person: the tool route has already decided each of
 * the tool's permissions with can(), fresh and with the act-as intersection, so the context carries
 * exactly the scopes that tool's function asks and nothing else (never `usableScopes`, which reads
 * the account's own permissions, not the intersection). The token id is per person, so the MCP
 * rate buckets count the person. The functions are called directly, never through server.ts's
 * handler(), which writes `mcp.*` audit rows and touches token usage.
 */
import type { McpContext } from '@/lib/mcp/tools'
import type { McpScope } from '@/lib/mcpAuth'

export function navigatorMcpContext(input: {
  personId: string
  projectId: string
  actorId: string | null
  scopes: readonly McpScope[]
}): McpContext {
  return {
    token: {
      tokenId: `navigator:${input.personId}`,
      userId: input.personId,
      tokenPrefix: 'navigator',
      name: 'AI Navigator',
      scopes: [...input.scopes],
      sharedProjects: { allowlist: [input.projectId] },
      actingAs: input.actorId !== null,
    },
  }
}
