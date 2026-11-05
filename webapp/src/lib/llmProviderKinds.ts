/**
 * Provider-type facts with no UI dependency, so server routes can import them
 * without pulling in the icon set that llmProviderPresets.ts carries.
 */

/**
 * Provider types whose key is not for a chat model (direct or OpenRouter Jev). Every place
 * that treats "any provider row" as a chat LLM must skip them, or the token is
 * forwarded to the agent's model discovery and counted as a configured LLM.
 * Twin of NON_CHAT_PROVIDER_TYPES in agentic/llm_builder.py.
 */
export const NON_CHAT_PROVIDER_TYPES: ReadonlySet<string> = new Set(['jev', 'jev_openrouter'])

/** The Jev backends. Twin of the `JevProvider` check in agentic/jev_client.py. */
export const JEV_PROVIDER_TYPES = ['jev', 'jev_openrouter'] as const
export type JevProviderType = typeof JEV_PROVIDER_TYPES[number]
export const isJevProvider = (p: { providerType: string }): p is { providerType: JevProviderType } =>
  (JEV_PROVIDER_TYPES as readonly string[]).includes(p.providerType)

export const isChatProvider = (p: { providerType: string }): boolean =>
  !NON_CHAT_PROVIDER_TYPES.has(p.providerType)

/**
 * The Jev version every saved Jev row is pinned to. The recon hook thresholds
 * are calibrated against it, so moving on is a deliberate edit here and in
 * agentic/jev_client.py (JEV_MODEL), never an alias drift.
 */
export const JEV_MODEL = 'jev-1.13.0'
export const JEV_PROVIDER_NAME = 'TypeSafe AI (Jev)'
export const JEV_OPENROUTER_MODEL = 'typesafe/jev-1.13'

export const JEV_BACKENDS = {
  jev: { name: JEV_PROVIDER_NAME, baseUrl: 'https://api.typesafe.ai', modelIdentifier: JEV_MODEL },
  jev_openrouter: { name: 'OpenRouter (Jev)', baseUrl: 'https://openrouter.ai/api/v1', modelIdentifier: JEV_OPENROUTER_MODEL },
} as const

/** Transport settings are never derived from an operator's form or a stored legacy override. */
export function jevPinnedConfig(providerType: JevProviderType) {
  return {
    providerType,
    baseUrl: JEV_BACKENDS[providerType].baseUrl,
    modelIdentifier: JEV_BACKENDS[providerType].modelIdentifier,
    defaultHeaders: {},
    timeout: 5,
    sslVerify: true,
    temperature: 0,
    maxTokens: 16384,
    reasoningEnabled: false,
    reasoningEffort: 'high' as const,
    awsRegion: 'us-east-1',
    awsAccessKeyId: '',
    awsSecretKey: '',
    awsBearerToken: '',
  }
}
