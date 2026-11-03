/**
 * Agent in the Loop: the pseudo-model `loop/mcp` makes an external MCP client
 * (Claude Code, Codex, ...) answer every model call of a chat run. Twin of
 * agentic/agent_in_the_loop/__init__.py; keep the prefix and the switch read in step.
 *
 * Safe to import in client components: only `agentInTheLoopEnabled` reads the
 * environment, and in the browser it always answers false.
 */

export const LOOP_PREFIX = 'loop/'
export const LOOP_MODEL_ID = 'loop/mcp'
export const LOOP_MODEL_LABEL = 'Agent in the Loop'
export const LOOP_MODEL_DESCRIPTION = 'Claude Code, Codex or another MCP agent answers each step'

export function isLoopModel(id: unknown): boolean {
  return typeof id === 'string' && id.trim().startsWith(LOOP_PREFIX)
}

export function agentInTheLoopEnabled(): boolean {
  const raw = (process.env.AGENT_IN_THE_LOOP_ENABLED ?? '').trim().toLowerCase()
  return raw === 'true' || raw === '1' || raw === 'yes'
}
