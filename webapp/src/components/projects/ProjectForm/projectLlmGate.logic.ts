/**
 * Pure decision logic for the project LLM provider/model gate.
 *
 * Extracted from ProjectForm so the rules can be unit-tested in isolation,
 * without rendering the (very large) form. Keep these functions side-effect
 * free - they take plain data and return plain data/booleans.
 */

import { isChatProvider } from '@/lib/llmProviderKinds'
import { isLoopModel } from '@/lib/agentInTheLoop'
import { isInstanceModel } from '@/lib/instanceProviders/rows'

/** Shape of the bits of the user record the gate cares about. */
export interface UserModelDefaults {
  defaultAgentModel?: string | null
  defaultAiPipelineModel?: string | null
}

export interface SeededModels {
  agentOpenaiModel: string
  aiPipelineModel: string
}

/**
 * Seed the two model fields for a NEW project from the user's remembered
 * choices, falling back to empty string (which forces an explicit pick via the
 * model gate). A null/undefined user (no record, or fetch failed) yields blanks.
 */
export function seedInitialModels(user: UserModelDefaults | null | undefined): SeededModels {
  return {
    agentOpenaiModel: user?.defaultAgentModel || '',
    aiPipelineModel: user?.defaultAiPipelineModel || '',
  }
}

/**
 * Whether the forced model-selection gate must open before saving.
 * Only applies on create; either model being blank (after trim) triggers it.
 */
export function needsModelGate(
  mode: 'create' | 'edit',
  agentModel: string | null | undefined,
  aiPipelineModel: string | null | undefined,
  pipelineOptional = false,
): boolean {
  if (mode !== 'create') return false
  return !bothModelsSelected(agentModel, aiPipelineModel, pipelineOptional)
}

/**
 * Whether the hard provider gate must block creation: true when the user has no
 * chat LLM provider configured. Callers pass the parsed list; anything that
 * isn't an array counts as missing. A non-chat row (a Jev provider) does
 * not count: no agent or pipeline model can run on it.
 */
export function hasNoConfiguredProvider(providers: unknown): boolean {
  if (!Array.isArray(providers)) return true
  return !providers.some(p =>
    typeof p === 'object' && p !== null
    && isChatProvider({ providerType: String((p as { providerType?: unknown }).providerType ?? '') }))
}

/**
 * Whether both models are chosen (gate satisfied). Mirrors the modal's
 * confirm-enabled condition so UI and logic can't drift.
 */
export function bothModelsSelected(
  agentModel: string | null | undefined,
  aiPipelineModel: string | null | undefined,
  pipelineOptional = false,
): boolean {
  return !!agentModel?.trim() && (pipelineOptional || !!aiPipelineModel?.trim())
}

/**
 * Whether the provider gate blocks creation. Agent in the Loop needs no
 * provider (the person's own Claude Code or Codex answers), so a loop agent
 * model passes while the deployment has it on. An instance provider an
 * administrator assigned to the person's sets (step 6.11) is a configured
 * provider too: its models are in the person's model list.
 */
export function providerGateApplies(
  providers: unknown,
  agentModel: string | null | undefined,
  loopAvailable: boolean,
  instanceAvailable = false,
): boolean {
  if (loopAvailable && isLoopModel(agentModel)) return false
  if (instanceAvailable) return false
  return hasNoConfiguredProvider(providers)
}

/**
 * With a loop agent model and no provider, the recon pipeline model may stay
 * unset: the schema default is stored, and every recon AI hook falls back to
 * its built-in choice when its model cannot be built (it never fails a scan).
 */
export function pipelineModelOptional(agentModel: string | null | undefined, noProvider: boolean): boolean {
  return noProvider && isLoopModel(agentModel)
}

/** Whether the model list offers Agent in the Loop (it does only while the switch is on). */
export function loopModelOffered(models: Record<string, { id: string }[]> | null | undefined): boolean {
  return Object.values(models ?? {}).some(list => list.some(m => isLoopModel(m.id)))
}

/**
 * Whether the model list offers an instance provider's model (`instance/<providerId>/<model>`): one
 * the person may use through a permission set they hold, offered only with RBAC_GOVERNANCE_ENABLED on.
 */
export function instanceModelOffered(models: Record<string, { id: string }[]> | null | undefined): boolean {
  return Object.values(models ?? {}).some(list => Array.isArray(list) && list.some(m => isInstanceModel(m.id)))
}

/**
 * Project fields holding an LLM model id that have a schema @default. A blank
 * value for these must never be persisted (it would override the default with
 * ""), so the server drops them and lets Prisma apply the default.
 */
export const MODEL_DEFAULT_FIELDS = new Set(['agentOpenaiModel', 'aiPipelineModel'])

/**
 * Server-side backstop for the client model-gate: true when a project field is
 * one of the model fields set to a blank string and must be dropped on create.
 */
export function isBlankModelField(key: string, value: unknown): boolean {
  return MODEL_DEFAULT_FIELDS.has(key) && typeof value === 'string' && value.trim() === ''
}
