import { agentFetch } from '@/lib/agentFetch'
import { ownerRunsStdio, serversForAgent } from '@/lib/mcp/userServerAccess'
import { followUpWarning, type SaveWarning } from '../settings/saveWarnings'

/**
 * Long enough for the agent to reconnect a handful of servers, short enough that
 * Save does not hang on a stuck one. A timeout is reported as `agent_timeout`:
 * the reload may still finish, the saved list is already in the database.
 */
const RELOAD_TIMEOUT_MS = 10_000

/**
 * Ask the running agent to pick up the saved MCP Tool Plugins. Awaited, so a
 * failed reload (agent down, internal key mismatch, a tool-name collision the
 * agent refuses) reaches the person instead of reading as applied. A non-admin
 * owner's stdio servers are never sent (NF-14): they stay saved, unrun.
 */
export async function reloadAgentMcp(ownerId: string, saved: unknown): Promise<SaveWarning[]> {
  const userMcpServers = serversForAgent(ownerId, saved, await ownerRunsStdio(ownerId))
  const warning = await followUpWarning('agent', 'The agent did not reload its MCP Tool Plugins', () =>
    agentFetch('/mcp/reload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userMcpServers }),
    }, { timeoutMs: RELOAD_TIMEOUT_MS }))
  return warning ? [warning] : []
}
