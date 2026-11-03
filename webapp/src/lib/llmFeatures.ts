/**
 * The AI features that each run on their own per-user model ("Models by
 * feature"), and the error contract every route that runs one answers with.
 *
 * Imported by client components and server routes alike, so it must stay free
 * of server-only imports. The ids are the keys of `UserSettings.featureModels`:
 * renaming one orphans every model saved under the old key.
 */
import { isLoopModel } from '@/lib/agentInTheLoop'

export type FeatureId =
  | 'roe_parse'
  | 'preset_generator'
  | 'triage'
  | 'codefix'
  | 'command_whisperer'
  | 'tradecraft_section_picker'
  | 'report_narratives'
  | 'multi_mute'
  | 'skill_metadata'

/**
 * A plugin's own entry in Models by feature: `plugin:<pluginId>` (README.PLUGINS.md §7.3,
 * TD-10). A separate type, because FeatureId is the closed list of core features and the
 * agent pins its declaration's text (agentic/tests/test_feature_models.py). Plugin ids
 * never reach getLlmFeature or modelAllowedForFeature, which know only core features.
 */
export type PluginFeatureId = `plugin:${string}`

const PLUGIN_FEATURE_RE = /^plugin:[a-z][a-z0-9-]{1,39}$/

export function isPluginFeatureId(x: unknown): x is PluginFeatureId {
  return typeof x === 'string' && PLUGIN_FEATURE_RE.test(x)
}

export function pluginFeatureId(pluginId: string): PluginFeatureId {
  return `plugin:${pluginId}`
}

export interface LlmFeature {
  id: FeatureId
  label: string
  description: string
  hint: string
  /** Other places in the UI that edit this same per-user value. */
  alsoEditedIn: string[]
  /** Model-id prefixes this feature cannot run on; hidden from its pickers and refused on save. */
  excludeModelPrefixes: string[]
}

/** In the order the Models by feature grid shows them. */
export const LLM_FEATURES: readonly LlmFeature[] = [
  {
    id: 'triage',
    label: 'Triage review',
    description: "Checks each finding's evidence and words the fix list.",
    hint: 'A small or mid-size model is enough. Not needed when the review budget is 0.',
    alsoEditedIn: ['Project settings → CypherFix'],
    excludeModelPrefixes: [],
  },
  {
    id: 'codefix',
    label: 'CodeFix',
    description: 'The coding agent that writes the fix and opens the pull request.',
    // ModelOption carries no tool-calling capability flag, so this is advice,
    // not a filter.
    hint: 'Needs a strong model that supports tool calls.',
    alsoEditedIn: ['Project settings → CypherFix'],
    excludeModelPrefixes: [],
  },
  {
    id: 'multi_mute',
    label: 'Multi mute',
    description: 'Finds the findings like the one you mute and groups them.',
    hint: 'A small or mid-size model is enough.',
    alsoEditedIn: ['Multi mute dialog'],
    excludeModelPrefixes: [],
  },
  {
    id: 'report_narratives',
    label: 'Report narratives',
    description: 'Writes the prose sections of the pentest report.',
    hint: 'A mid-size model that writes well.',
    alsoEditedIn: ['Reports page'],
    excludeModelPrefixes: [],
  },
  {
    id: 'roe_parse',
    label: 'RoE parsing',
    description: 'Reads a Rules of Engagement document and fills the project settings.',
    hint: 'A strong model with a long context (documents up to 50,000 characters).',
    alsoEditedIn: ['RoE upload'],
    excludeModelPrefixes: [],
  },
  {
    id: 'preset_generator',
    label: 'Recon preset generator',
    description: 'Turns a plain description into a recon preset.',
    hint: "A mid-size model. AWS Bedrock isn't supported here.",
    alsoEditedIn: ['Generate preset dialog'],
    // presets/generate calls the provider directly and refuses Bedrock ids.
    excludeModelPrefixes: ['bedrock/'],
  },
  {
    id: 'command_whisperer',
    label: 'Command whisperer',
    description: 'Turns a plain-English request into a shell command in session terminals.',
    hint: 'A small model is enough.',
    alsoEditedIn: ['Session terminals'],
    excludeModelPrefixes: [],
  },
  {
    id: 'tradecraft_section_picker',
    label: 'Tradecraft section picker',
    description: 'Picks which page of a Tradecraft resource the agent reads.',
    hint: 'The smallest model is enough: it answers with one number. Not set: pages are picked by text match.',
    alsoEditedIn: ['Tradecraft resource form'],
    excludeModelPrefixes: [],
  },
  {
    id: 'skill_metadata',
    label: 'Skill names & descriptions',
    description: 'Writes the missing name and description of your agent skills, when you upload or edit them.',
    hint: 'A small or mid-size model is enough: it reads the start of each skill file.',
    alsoEditedIn: ['Upload agent skills dialog', 'Edit skill dialog'],
    excludeModelPrefixes: [],
  },
]

export const FEATURE_IDS: readonly FeatureId[] = LLM_FEATURES.map(f => f.id)

const FEATURE_BY_ID = new Map<FeatureId, LlmFeature>(LLM_FEATURES.map(f => [f.id, f]))

export function isFeatureId(x: unknown): x is FeatureId {
  return typeof x === 'string' && FEATURE_BY_ID.has(x as FeatureId)
}

export function getLlmFeature(id: FeatureId): LlmFeature {
  const feature = FEATURE_BY_ID.get(id)
  if (!feature) throw new Error(`Unknown LLM feature: ${id}`)
  return feature
}

export function modelAllowedForFeature(id: FeatureId, modelId: string): boolean {
  // Agent in the Loop answers only inside a chat run: no feature can run on it.
  if (isLoopModel(modelId)) return false
  return !getLlmFeature(id).excludeModelPrefixes.some(prefix => modelId.startsWith(prefix))
}

export const FEATURE_MODEL_MAX_LEN = 200

/**
 * Why a feature could not run on its model. The client decides on `code`,
 * never on the HTTP status: only the two GATE_CODES open the model picker, the
 * rest are shown as a message, because picking another model cannot fix them.
 */
export type FeatureModelCode =
  | 'model_required'
  | 'model_unavailable'
  | 'providers_unreachable'
  | 'agent_unreachable'
  | 'agent_timeout'
  | 'agent_outdated'

export const FEATURE_MODEL_STATUS: Record<FeatureModelCode, number> = {
  model_required: 409,
  model_unavailable: 503,
  providers_unreachable: 503,
  agent_unreachable: 503,
  agent_timeout: 504,
  agent_outdated: 502,
}

export const GATE_CODES: readonly FeatureModelCode[] = ['model_required', 'model_unavailable']

/** The body every route answers a FeatureModelCode with. */
export interface FeatureModelErrorBody {
  error: string
  code: FeatureModelCode
  featureId: FeatureId | PluginFeatureId
  model?: string
  /** The provider exception's class, when the failure came from the model provider. */
  errorClass?: string
  providerStatus?: number
}

/**
 * The text shown for a code. For model_unavailable it is fixed on purpose: the
 * provider's own error can quote key fragments, so it is logged, never shown.
 */
export function featureModelMessage(code: FeatureModelCode, model?: string): string {
  switch (code) {
    case 'model_required':
      return 'Choose a model for this feature first'
    case 'model_unavailable':
      return model ? `Your model ${model} could not be used` : 'Your model could not be used'
    case 'providers_unreachable':
      return "Couldn't load your LLM providers, try again"
    case 'agent_unreachable':
      return "The agent service isn't running"
    case 'agent_timeout':
      return 'The model took too long, try again'
    case 'agent_outdated':
      return 'The agent is older than the webapp: rebuild it'
  }
}

const CODES = new Set<string>(Object.keys(FEATURE_MODEL_STATUS))

export function readFeatureModelCode(body: unknown): FeatureModelCode | null {
  if (!body || typeof body !== 'object') return null
  const code = (body as { code?: unknown }).code
  return typeof code === 'string' && CODES.has(code) ? (code as FeatureModelCode) : null
}

const PROVIDER_CLASS = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/

/**
 * "RateLimitError · provider HTTP 429" from the safe provider facts an agent
 * answer carries (`error_class`, `provider_status`; camelCase once a route has
 * passed them on), or '' when there are none. The class and the status tell a
 * bad key from a rate limit or an overflowing context; the provider's own
 * message is never sent, because it can quote the key.
 */
export function providerFailureDetail(body: unknown): string {
  const facts = providerFacts(body)
  const parts: string[] = []
  if (facts.errorClass) parts.push(facts.errorClass)
  if (facts.providerStatus) parts.push(`provider HTTP ${facts.providerStatus}`)
  return parts.join(' · ')
}

/** The provider facts of an agent answer, validated and camelCased, for a route to pass on. */
export function providerFacts(body: unknown): { errorClass?: string; providerStatus?: number } {
  if (!body || typeof body !== 'object') return {}
  const b = body as Record<string, unknown>
  const cls = b.error_class ?? b.errorClass
  const status = b.provider_status ?? b.providerStatus
  return {
    ...(typeof cls === 'string' && PROVIDER_CLASS.test(cls) ? { errorClass: cls } : {}),
    ...(typeof status === 'number' && Number.isInteger(status) && status >= 100 && status <= 599 ? { providerStatus: status } : {}),
  }
}
