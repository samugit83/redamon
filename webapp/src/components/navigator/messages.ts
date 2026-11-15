/**
 * Every AI Navigator code → sentence the panel shows (plan §9.14), in one place so the panel and
 * the tests read the same strings.
 */
import { featureModelMessage, readFeatureModelCode } from '@/lib/llmFeatures'

export const NAVIGATOR_MESSAGES: Readonly<Record<string, string>> = {
  busy: 'An answer is already being written for you on this project, maybe in another tab.',
  thread_full: 'This conversation is full. Start a new one.',
  too_many_threads: 'You have too many conversations on this project. Delete some in History.',
  project_busy: 'This project is being restored or transferred. Try again in a minute.',
  navigator_disabled: 'AI Navigator has been turned off on this server.',
  owner_disallowed: "The owner of this project hasn't enabled AI Navigator for collaborators.",
  navigator_not_available: "AI Navigator isn't available with this kind of access.",
  agent_unreachable: "AI Navigator's service isn't reachable right now.",
  agent_busy: 'AI Navigator is busy right now. Try again in a moment.',
  timeout: "AI Navigator's service isn't reachable right now.",
  agent_outdated: 'The agent is older than the web app. Rebuild it with ./redamon.sh update.',
  navigator_unavailable: "AI Navigator isn't configured on this server. Ask your administrator to run ./redamon.sh update.",
  agent_protocol: 'The answer could not be read.',
  answer_too_long: 'The answer was cut because it grew too long.',
  stopped: 'The answer was stopped.',
  invalid_message: 'The message must be between 1 and 4000 characters.',
  not_found: 'This conversation no longer exists.',
  model_error: 'The model call failed. Try again in a moment.',
  run_gone: 'This answer is no longer running.',
  model_no_tools: "This model can't call tools. Choose another model for AI Navigator.",
  llm_budget_exhausted: 'The daily budget of model calls on instance providers is used up.',
  loop_model_not_supported_here: "Agent in the Loop can't answer AI Navigator. Choose a provider model.",
  model_unavailable: 'Your model could not be used. Choose another model for AI Navigator.',
  providers_unreachable: "Couldn't load your LLM providers, try again.",
}

export const ACTING_AS_NO_MODEL = "The account you are acting as hasn't chosen an AI Navigator model."

export function navigatorMessage(code: string | null | undefined, extra: { retryAfterSeconds?: number; status?: number } = {}): string {
  if (!code) return `Something went wrong${extra.status ? ` (HTTP ${extra.status})` : ''}.`
  if (code === 'rate_limited') {
    return `You're sending messages too fast. Try again in ${extra.retryAfterSeconds ?? 60} s.`
  }
  const modelCode = readFeatureModelCode({ code })
  if (modelCode && !(code in NAVIGATOR_MESSAGES)) return featureModelMessage(modelCode)
  return NAVIGATOR_MESSAGES[code] ?? `Something went wrong (${code}).`
}

export const ROUTE_BADGES: Readonly<Record<string, { icon: string; label: string }>> = {
  docs: { icon: '📖', label: 'Docs' },
  graph: { icon: '🕸', label: 'Graph' },
  records: { icon: '🗄', label: 'Records' },
  workspace: { icon: '📁', label: 'Workspace' },
}

export const REFUSED_REASON_TEXT: Readonly<Record<string, string>> = {
  needs_raw_data: 'needs Raw data & files on this project',
  missing_permission: "you don't hold the permission that reads it here",
  tools_unavailable: "the project data service couldn't be reached",
  docs_missing: "the documentation isn't installed on this server",
  not_allowed: "isn't available to you on this project",
}
