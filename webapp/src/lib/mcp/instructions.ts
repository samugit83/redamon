/**
 * The `instructions` string the server sends at `initialize`.
 *
 * This is the ONLY onboarding most clients ever receive. Only the Claude family
 * and Codex load a `SKILL.md`; Cursor, Windsurf, Cline, Goose, Gemini CLI and
 * anything built on LangGraph, the OpenAI Agents SDK, CrewAI or n8n see the tool
 * list and nothing else. Without this they get thirty tool descriptions and none
 * of the judgement that spans them.
 *
 * Rendered from the same source as the downloadable pack, so the two cannot
 * teach different things.
 *
 * Two deliberate choices about WHERE this work happens:
 *
 *  - the profile is read HERE, not in `resolveMcpToken`. mcpAuth.ts owns
 *    resolution, scope checks and rate limiting, and it must not so much as
 *    mention a profile, or the field starts looking like an authorization input.
 *    profiles.test.ts asserts that. This is a separate, clearly editorial read.
 *  - it runs only on `initialize`. The transport is stateless, so the server is
 *    rebuilt for every request; doing this per tool call would add a database
 *    read and a tool-list build to every call, for a string nobody reads again.
 */
import type { Tool } from '@modelcontextprotocol/sdk/types.js'

import prisma from '@/lib/prisma'
import type { McpScope } from '@/lib/mcpAuth'
import { listAdvertisedTools } from '@/lib/mcp/apiReference'
import { renderInlineOnboarding } from '@/lib/mcp/onboarding'
import { profileOrDefault, type ProfileId } from '@/lib/mcp/profiles'

/**
 * The advertised tool list is fixed for the life of the process: registration is
 * static and `MCP_DISABLED_TOOLS` is read once at build time. Caching it keeps
 * `initialize` from constructing a throwaway server every time.
 */
const globalForTools = globalThis as unknown as { __mcpAdvertisedTools?: Tool[] }

async function advertisedTools(): Promise<Tool[]> {
  if (!globalForTools.__mcpAdvertisedTools) {
    globalForTools.__mcpAdvertisedTools = await listAdvertisedTools()
  }
  return globalForTools.__mcpAdvertisedTools
}

/** Test seam: the tool list is cached per process by design. */
export function __resetAdvertisedToolsCache(): void {
  globalForTools.__mcpAdvertisedTools = undefined
}

/**
 * The token's profile, for prose only.
 *
 * Never consulted by any authorization decision. A missing row, an unknown
 * value or a database failure all fall back to `custom`, because failing to
 * personalise a paragraph must never fail a connection.
 */
export async function profileForToken(tokenId: string): Promise<ProfileId> {
  try {
    const row = await prisma.mcpAccessToken.findUnique({
      where: { id: tokenId },
      select: { profile: true },
    })
    return profileOrDefault(row?.profile)
  } catch (err) {
    console.error('[mcp] could not read the token profile for onboarding:', err)
    return 'custom'
  }
}

/**
 * Build the instructions for a resolved token. Never throws: a client that
 * cannot be onboarded must still be able to connect.
 */
export async function buildInstructions(
  tokenId: string,
  scopes: readonly McpScope[]
): Promise<string | undefined> {
  try {
    const [tools, profile] = await Promise.all([advertisedTools(), profileForToken(tokenId)])
    return renderInlineOnboarding(tools, scopes, profile)
  } catch (err) {
    console.error('[mcp] could not build the connect-time instructions:', err)
    return undefined
  }
}
