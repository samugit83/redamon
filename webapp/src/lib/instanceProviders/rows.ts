/**
 * Instance LLM providers (step 6.11, GV-15, OQ-42): an LLM provider the confirmed Root adds for the
 * whole instance and assigns to permission sets. A person holding one of those sets may pick its
 * models; the key never leaves the webapp except to the agent, which builds a run's model from it.
 *
 * A provider row has the user provider row's shape (`UserLlmProvider`, schema.prisma) and is stored
 * the same way: the key fields in plaintext columns (no at-rest encryption in this run, OQ-52),
 * answered masked to every browser (lib/llmProviderMask.ts). Its secrets are `apiKey`,
 * `awsAccessKeyId`, `awsSecretKey`, `awsBearerToken` and every `defaultHeaders` value.
 *
 * Pure data and mapping, no database and no server import (the project form imports it): the store
 * (store.ts) reads the rows, entitlement.ts decides who may use which, admin.ts manages them.
 */
import { NON_CHAT_PROVIDER_TYPES } from '@/lib/llmProviderKinds'

/**
 * The `providerType` of the rows the agent receives for an instance provider: a marker, not a kind,
 * so no agent reader that picks "the account's openai key" or "the first custom provider" lands on
 * one; the kind travels in `instanceProviderType`. Twin of INSTANCE_ROW_TYPE in agentic/llm_builder.py.
 */
export const INSTANCE_ROW_TYPE = 'instance'

/** A model of an instance provider: `instance/<providerId>/<model>`, `<model>` the provider's own id. */
export const INSTANCE_MODEL_PREFIX = 'instance/'

/**
 * The kinds an instance provider may be: the chat providers the agent builds. The non-chat Jev kinds
 * are refused (their key is not for a chat model, llmProviderKinds.ts).
 */
export const INSTANCE_PROVIDER_KINDS = [
  'openai', 'anthropic', 'openrouter', 'deepseek', 'gemini', 'glm', 'kimi', 'qwen', 'xai', 'mistral',
  'bedrock', 'openai_compatible',
] as const
export type InstanceProviderKind = typeof INSTANCE_PROVIDER_KINDS[number]

export function isInstanceProviderKind(value: unknown): value is InstanceProviderKind {
  return typeof value === 'string' && !NON_CHAT_PROVIDER_TYPES.has(value)
    && (INSTANCE_PROVIDER_KINDS as readonly string[]).includes(value)
}

/** One stored instance provider (`InstanceLlmProvider`), secrets included: server code only. */
export interface InstanceLlmProviderRecord {
  id: string
  providerType: string
  name: string
  apiKey: string
  baseUrl: string
  modelIdentifier: string
  defaultHeaders: unknown
  timeout: number
  temperature: number
  maxTokens: number
  sslVerify: boolean
  reasoningEnabled: boolean
  reasoningEffort: string
  awsRegion: string
  awsAccessKeyId: string
  awsSecretKey: string
  awsBearerToken: string
  createdAt: Date
  updatedAt: Date
  createdById: string | null
  updatedById: string | null
}

/** One assignment (`PermissionSetProvider`): the provider is offered to whoever holds the set. */
export interface PermissionSetProviderRow {
  setId: string
  providerId: string
}

const AGENT_FIELDS = [
  'name', 'apiKey', 'baseUrl', 'modelIdentifier', 'defaultHeaders', 'timeout', 'temperature', 'maxTokens',
  'sslVerify', 'reasoningEnabled', 'reasoningEffort', 'awsRegion', 'awsAccessKeyId', 'awsSecretKey',
  'awsBearerToken',
] as const

/**
 * The row the agent receives in the owner's provider list (`?internal=true`, master key only):
 * the provider's settings and key, marked as an instance row. `userId` is the account whose list it
 * is, so the agent's client cache stays per owner (llm_setup.py `credential_owner`).
 */
export function agentRowOf(p: InstanceLlmProviderRecord, ownerId: string): Record<string, unknown> {
  const row: Record<string, unknown> = { id: p.id, providerType: INSTANCE_ROW_TYPE, instanceProviderType: p.providerType }
  for (const f of AGENT_FIELDS) row[f] = p[f]
  row.userId = ownerId
  return row
}

/**
 * The provider as the agent's model listing (`POST /models`) reads a user row, to list its models:
 * its own kind and id, so an OpenAI-compatible endpoint lists `custom/<providerId>`.
 */
export function listingRowOf(p: InstanceLlmProviderRecord): Record<string, unknown> {
  const row: Record<string, unknown> = { id: p.id, providerType: p.providerType }
  for (const f of AGENT_FIELDS) row[f] = p[f]
  return row
}

export function instanceModelId(providerId: string, model: string): string {
  return `${INSTANCE_MODEL_PREFIX}${providerId}/${model}`
}

/** `{providerId, model}` of an `instance/<providerId>/<model>` id, else null. */
export function splitInstanceModel(model: unknown): { providerId: string; model: string } | null {
  if (typeof model !== 'string' || !model.startsWith(INSTANCE_MODEL_PREFIX)) return null
  const rest = model.slice(INSTANCE_MODEL_PREFIX.length)
  const slash = rest.indexOf('/')
  if (slash <= 0 || slash === rest.length - 1) return null
  return { providerId: rest.slice(0, slash), model: rest.slice(slash + 1) }
}

export function isInstanceModel(model: unknown): boolean {
  return typeof model === 'string' && model.startsWith(INSTANCE_MODEL_PREFIX)
}

/** What a person who may use the provider sees of it: no key, no endpoint, no header. */
export interface InstanceProviderSummary {
  id: string
  name: string
  providerType: string
}

export function summaryOf(p: InstanceLlmProviderRecord): InstanceProviderSummary {
  return { id: p.id, name: p.name, providerType: p.providerType }
}
