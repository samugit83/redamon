import type { APIRequestContext } from '@playwright/test'

// webapp/src/lib/llmProviderKinds.ts JEV_PROVIDER_TYPES
const JEV_PROVIDER_TYPES = ['jev', 'jev_openrouter']

/**
 * The id of one of the owner's own Jev providers, or null when they have none. A project uses Jev
 * only through the provider it selects (jevProviderId, #227): a project selecting none keeps every
 * Jev control disabled whatever providers the owner holds.
 */
export async function ownerJevProviderId(api: APIRequestContext, userId: string): Promise<string | null> {
  const res = await api.get(`/api/users/${userId}/llm-providers`)
  if (!res.ok()) return null
  const providers = await res.json() as { id: string; providerType: string }[]
  return providers.find(p => JEV_PROVIDER_TYPES.includes(p.providerType))?.id ?? null
}
