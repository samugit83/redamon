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
/** Project.agentOpenaiModel's schema @default, used where a loop model is replaced. */
export const SCHEMA_DEFAULT_AGENT_MODEL = 'claude-opus-4-6'
export const LOOP_MODEL_DESCRIPTION = 'Claude Code, Codex or another MCP agent answers each step'
/** The Agent Profile (lib/mcp/profiles.ts) whose pack teaches a client to drive a session. */
export const LOOP_PROFILE_ID = 'agent_in_the_loop'

/** Whether the token UI offers this Agent Profile (the loop profile only while the switch is on). */
export function profileOffered(profileId: string, loopOn: boolean): boolean {
  return loopOn || profileId !== LOOP_PROFILE_ID
}

export function isLoopModel(id: unknown): boolean {
  return typeof id === 'string' && id.trim().startsWith(LOOP_PREFIX)
}

/** A ModelPicker filter for every picker except the agent's own model. */
export function excludeLoop(id: string): boolean {
  return !isLoopModel(id)
}

export function agentInTheLoopEnabled(): boolean {
  const raw = (process.env.AGENT_IN_THE_LOOP_ENABLED ?? '').trim().toLowerCase()
  return raw === 'true' || raw === '1' || raw === 'yes'
}

/**
 * The model defaults a new project leaves behind for the next one, or null.
 * A loop model is never remembered: a default outlives the switch and is used
 * later without the person choosing the brain at that moment.
 */
export function rememberedDefaults(
  agentModel: unknown, pipelineModel: unknown,
): { defaultAgentModel?: string; defaultAiPipelineModel: string } | null {
  if (typeof pipelineModel !== 'string' || !pipelineModel) return null
  if (typeof agentModel !== 'string' || !agentModel) return null
  if (isLoopModel(agentModel)) return { defaultAiPipelineModel: pipelineModel }
  return { defaultAgentModel: agentModel, defaultAiPipelineModel: pipelineModel }
}

/**
 * Why a project create or update from the UI may not store these models, or
 * null. The recon AI hooks run outside any chat, so the pipeline model is never
 * a loop model; the agent model may be one only while the switch is on, so no
 * project is stored in a state that cannot run. Server routes only.
 */
export function projectModelProblem(data: Record<string, unknown>): string | null {
  if (isLoopModel(data.aiPipelineModel)) {
    return 'The recon AI model cannot be Agent in the Loop: recon runs outside any chat. Pick a provider model.'
  }
  if (isLoopModel(data.agentOpenaiModel) && !agentInTheLoopEnabled()) {
    return 'Agent in the Loop is turned off on this deployment.'
  }
  return null
}
