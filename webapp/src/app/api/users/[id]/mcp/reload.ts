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
 * The agent holds one user MCP toolset for every run (RBAC OQ-41). While another
 * owner's run on a different set is live it defers the reload (202): the list is
 * saved and loads when this owner's next run starts.
 */
const DEFERRED: SaveWarning = {
  service: 'agent',
  message: 'Your MCP Tool Plugins load at your next agent run: another user\'s run is using the agent now',
  code: 'mcp_toolset_busy',
}

async function isDeferral(res: Response): Promise<boolean> {
  if (res.status !== 202) return false
  const body = await res.json().catch(() => null) as { deferred?: unknown; code?: unknown } | null
  return body?.deferred === true && body.code === DEFERRED.code
}

/**
 * Ask the running agent to pick up the saved MCP Tool Plugins. Awaited, so a
 * failed reload (agent down, internal key mismatch, a tool-name collision the
 * agent refuses) reaches the person instead of reading as applied. A non-admin
 * owner's stdio servers are never sent (NF-14): they stay saved, unrun. The owner
 * is named so the agent can tell a change of another owner's set from their own.
 */
export async function reloadAgentMcp(ownerId: string, saved: unknown): Promise<SaveWarning[]> {
  const userMcpServers = serversForAgent(ownerId, saved, await ownerRunsStdio(ownerId))
  let answer = null as Response | null
  const warning = await followUpWarning('agent', 'The agent did not reload its MCP Tool Plugins', async () =>
    (answer = await agentFetch('/mcp/reload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ownerId, userMcpServers }),
    }, { timeoutMs: RELOAD_TIMEOUT_MS })))
  if (warning) return [warning]
  return answer && await isDeferral(answer) ? [DEFERRED] : []
}
