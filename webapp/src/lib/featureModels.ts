/**
 * Server-side half of "Models by feature": reading a user's saved model for a
 * feature, validating a change to it, and answering with the shared error
 * contract of lib/llmFeatures.ts. Never import into a client component.
 */
import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isLoopModel } from '@/lib/agentInTheLoop'
import {
  FEATURE_MODEL_MAX_LEN,
  FEATURE_MODEL_STATUS,
  featureModelMessage,
  getLlmFeature,
  isFeatureId,
  isPluginFeatureId,
  modelAllowedForFeature,
  providerFacts,
  readFeatureModelCode,
  type FeatureId,
  type FeatureModelCode,
  type FeatureModelErrorBody,
  type PluginFeatureId,
} from '@/lib/llmFeatures'

/** A stored `featureModels` value as a plain map; anything malformed reads as empty. */
export function featureModelsMap(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === 'string') out[k] = v
  }
  return out
}

/** The model `userId` saved for `featureId` (a core feature or a plugin's), or '' when none is. */
export async function readFeatureModel(userId: string, featureId: FeatureId | PluginFeatureId): Promise<string> {
  const row = await prisma.userSettings.findUnique({
    where: { userId },
    select: { featureModels: true },
  })
  return featureModelsMap(row?.featureModels)[featureId] ?? ''
}

export interface FeatureModelsPatch {
  set: Record<string, string>
  removed: string[]
}

// Model ids end up in logs, audit rows and the UI; none legitimately holds a
// control character.
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/

/**
 * Validate a PUT's `featureModels` object. Every entry must pass before any is
 * applied, so one bad key refuses the whole change. '' removes the key.
 *
 * A plugin's key (`plugin:<id>`) is accepted with a model only when it is in
 * `pluginFeatureIds` (the plugins that qualify now, a database read the caller makes),
 * and cleared always, so a key an uninstalled plugin left behind can be removed. Plugin
 * keys never reach getLlmFeature or modelAllowedForFeature: they know only core features.
 */
export function parseFeatureModelsPatch(
  raw: unknown,
  opts: { pluginFeatureIds?: ReadonlySet<string> } = {},
): FeatureModelsPatch | { error: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { error: 'featureModels must be an object of feature id to model id' }
  }
  const set: Record<string, string> = {}
  const removed: string[] = []
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const plugin = isPluginFeatureId(key)
    if (!plugin && !isFeatureId(key)) return { error: `Unknown feature: ${key}` }
    if (typeof value !== 'string') return { error: `The model for ${key} must be a string` }
    const model = value.trim()
    if (!model) {
      removed.push(key)
      continue
    }
    if (plugin && !opts.pluginFeatureIds?.has(key)) return { error: `Unknown feature: ${key}` }
    if (model.length > FEATURE_MODEL_MAX_LEN) {
      return { error: `The model for ${key} is longer than ${FEATURE_MODEL_MAX_LEN} characters` }
    }
    if (CONTROL_CHARS.test(model)) return { error: `The model for ${key} contains a control character` }
    // Plugin features too: a plugin's model call has no chat run behind it either.
    if (isLoopModel(model)) {
      return { error: `Agent in the Loop answers only inside a chat run; pick a provider model for ${key}` }
    }
    if (!plugin && !modelAllowedForFeature(key as FeatureId, model)) {
      return { error: `${getLlmFeature(key as FeatureId).label} cannot run on ${model}` }
    }
    set[key] = model
  }
  return { set, removed }
}

export function featureModelErrorResponse(
  code: FeatureModelCode,
  featureId: FeatureId | PluginFeatureId,
  opts: { model?: string; error?: string; agentBody?: unknown } = {},
): NextResponse {
  const body: FeatureModelErrorBody = {
    error: opts.error ?? featureModelMessage(code, opts.model),
    code,
    featureId,
    ...(opts.model ? { model: opts.model } : {}),
    ...providerFacts(opts.agentBody),
  }
  return NextResponse.json(body, { status: FEATURE_MODEL_STATUS[code] })
}

/**
 * Classify an agentFetch rejection. agentFetch wraps every transport failure in
 * AgentUnreachableError and keeps the original in `cause_`; only the
 * AbortSignal.timeout firing is a TimeoutError, so that alone means the model
 * was slow rather than the agent absent.
 */
export function agentFailureCode(err: unknown): 'agent_timeout' | 'agent_unreachable' {
  const nameOf = (e: unknown) => (e && typeof e === 'object' ? (e as { name?: unknown }).name : undefined)
  const cause = err && typeof err === 'object' ? (err as { cause_?: unknown }).cause_ : undefined
  return nameOf(cause) === 'TimeoutError' || nameOf(err) === 'TimeoutError' ? 'agent_timeout' : 'agent_unreachable'
}

/**
 * The version marker: an agent that knows about per-feature models echoes the
 * model it ran on as `model_used`. An older agent ignores the model it was sent
 * and runs on whatever it used before, so a missing or different echo means
 * the answer came from the wrong model.
 */
export function modelUsedMismatch(body: unknown, sent: string): boolean {
  if (!body || typeof body !== 'object') return true
  const used = (body as { model_used?: unknown }).model_used
  return typeof used !== 'string' || used !== sent
}

const AGENT_PASSTHROUGH_CODES = new Set<FeatureModelCode>(['model_unavailable', 'providers_unreachable', 'agent_timeout'])

/**
 * Turn the agent's own coded error into the same code for the browser, with
 * the fixed message: the agent's text for model_unavailable can quote a
 * provider error, which is never forwarded. null when the answer is not one of
 * those codes, so the route handles it as it would any other status.
 */
export function agentCodedError(
  status: number,
  body: unknown,
  featureId: FeatureId | PluginFeatureId,
  sentModel: string,
): NextResponse | null {
  if (status >= 200 && status < 300) return null
  const code = readFeatureModelCode(body)
  if (!code || !AGENT_PASSTHROUGH_CODES.has(code)) return null
  return featureModelErrorResponse(code, featureId, { ...(code === 'model_unavailable' ? { model: sentModel } : {}), agentBody: body })
}
