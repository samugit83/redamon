import type { NextRequest } from 'next/server'
import { callFeatureAgent } from '@/lib/featureAgentCall'
import { readFeatureModel } from '@/lib/featureModels'
import { pluginFeatureId } from '@/lib/llmFeatures'
import { GATEWAY_BODY_MAX_BYTES, GatewayError, gatewayError, withGateway, type GatewayContext } from '@/lib/plugins/gateway'
import { chargeLlmCall, recordLlmUsage } from '@/lib/plugins/llmBudget'
import { OWNER_MODEL_REQUIRED, OWNER_MODEL_TEXT } from '@/lib/plugins/actions'
import { auditActorOf } from '@/lib/auditActor'
import { meetsLevel } from '@/lib/authz/projectAccess'
import { recordOwnerCredentialSpend } from '@/lib/authz/ownerSpend'
import { safeErrorCode } from '@/lib/routeErrors'

/**
 * POST /api/plugin-gateway/v1/llm/invoke (`sdk.llm.invoke`, needs `llm:invoke`): one call
 * of the model the user chose for this plugin in Models by feature, through the agent's
 * `/plugins/llm/invoke` (master key), so a provider key never reaches the runner. The
 * request names messages and two options, never a model or a user. Each call is charged
 * to the plugin's own daily cap before it is made (lib/plugins/llmBudget.ts).
 *
 * On a project shared with the token's user (step 5.10, C1) the call spends the project owner's
 * model choice and keys (`user_id` is the tenant), only while the person's access holds Use AI
 * agent (which counts only with the owner's consent; the Gateway frame already asked it), and each
 * call writes its `credits.used` row first (no row, no call). The cap and the usage stay the person's.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

// The agent applies the same limits; checked here first so a malformed call costs nothing.
const MAX_MESSAGES = 50
const MAX_TOTAL_CHARS = 1_000_000
const MAX_TOKENS = 16_000
const ROLES = new Set(['system', 'user', 'assistant'])
// A slow model and a long answer; the action's own timeout bounds the whole call anyway.
const AGENT_TIMEOUT_MS = 300_000

interface Message {
  role: string
  content: string
}

function checkedCall(body: Record<string, unknown>): { messages: Message[]; options: Record<string, number> } {
  const raw = body.messages
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new GatewayError(422, 'invalid_messages', 'messages must be a non-empty list')
  }
  if (raw.length > MAX_MESSAGES) throw new GatewayError(413, 'too_many_messages', `at most ${MAX_MESSAGES} messages per call`)
  let total = 0
  const messages: Message[] = []
  for (const m of raw) {
    const msg = m as Record<string, unknown> | null
    if (!msg || typeof msg !== 'object' || !ROLES.has(msg.role as string) || typeof msg.content !== 'string') {
      throw new GatewayError(422, 'invalid_messages', 'each message is {role: system|user|assistant, content: text}')
    }
    total += msg.content.length
    messages.push({ role: msg.role as string, content: msg.content })
  }
  if (total > MAX_TOTAL_CHARS) throw new GatewayError(413, 'messages_too_large', `at most ${MAX_TOTAL_CHARS} characters per call`)
  const options: Record<string, number> = {}
  const { max_tokens: maxTokens, temperature } = body
  if (maxTokens !== undefined && maxTokens !== null) {
    if (typeof maxTokens !== 'number' || !Number.isInteger(maxTokens) || maxTokens < 1 || maxTokens > MAX_TOKENS) {
      throw new GatewayError(422, 'invalid_options', `max_tokens is 1 to ${MAX_TOKENS}`)
    }
    options.max_tokens = maxTokens
  }
  if (temperature !== undefined && temperature !== null) {
    if (typeof temperature !== 'number' || !Number.isFinite(temperature) || temperature < 0 || temperature > 2) {
      throw new GatewayError(422, 'invalid_options', 'temperature is 0 to 2')
    }
    options.temperature = temperature
  }
  return { messages, options }
}

async function invoke(ctx: GatewayContext) {
  const started = Date.now()
  const { messages, options } = checkedCall(ctx.body)
  const featureId = pluginFeatureId(ctx.pluginId)
  const spendsOwners = ctx.tenantId !== ctx.userId
  // The frame checked the plugin's levels; asked again here because this call is the spend.
  if (spendsOwners && (!ctx.access || !meetsLevel(ctx.access, 'W+A'))) throw new GatewayError(404, 'not_found', 'Not found')
  const model = await readFeatureModel(ctx.tenantId, featureId)
  if (!model) {
    if (spendsOwners) throw new GatewayError(409, OWNER_MODEL_REQUIRED, OWNER_MODEL_TEXT, { featureId })
    throw new GatewayError(409, 'model_required', 'Choose a model for this plugin in Models by feature.', { featureId })
  }
  const charge = await chargeLlmCall(ctx.pluginId, ctx.userId)
  if (!charge.allowed) {
    console.warn(`[plugins] llm plugin=${ctx.pluginId} user=${ctx.userId} refused: daily cap ${charge.cap} reached`)
    throw new GatewayError(429, 'plugin_llm_cap', 'This plugin reached its daily model-call limit.')
  }
  if (spendsOwners) {
    try {
      await recordOwnerCredentialSpend({
        projectId: ctx.projectId!,
        ownerId: ctx.tenantId,
        userId: ctx.userId,
        actor: auditActorOf({ id: ctx.actorId ?? ctx.userId }, ctx.userId),
        feature: 'plugin_llm',
        permission: 'plugins:use',
      })
    } catch (err) {
      console.error(`[rbac] credits.used not recorded project=${ctx.projectId} user=${ctx.userId} feature=plugin_llm: ${safeErrorCode(err)}`)
      throw new GatewayError(503, 'spend_not_recorded', "This use of the project owner's credentials could not be recorded, so nothing was spent. Try again.")
    }
  }

  const result = await callFeatureAgent({
    featureId,
    path: '/plugins/llm/invoke',
    model,
    body: { user_id: ctx.tenantId, plugin_id: ctx.pluginId, model, messages, ...options },
    timeoutMs: AGENT_TIMEOUT_MS,
    notFoundIsOutdated: true,
  })
  if (!result.ok) {
    const failed = (await result.response.json().catch(() => ({}))) as Record<string, unknown>
    const code = typeof failed.code === 'string' ? failed.code : result.code ?? 'llm_call_failed'
    console.warn(
      `[plugins] llm plugin=${ctx.pluginId} user=${ctx.userId} model=${model} status=${result.response.status} code=${code} ms=${Date.now() - started}`,
    )
    const rest = { ...failed }
    delete rest.error
    delete rest.code
    return gatewayError(result.response.status, code, typeof failed.error === 'string' ? failed.error : 'The model call failed.', rest)
  }

  const usage = (result.body.usage ?? {}) as Record<string, unknown>
  const inputTokens = Number(usage.input_tokens) || 0
  const outputTokens = Number(usage.output_tokens) || 0
  // The call was made and charged: a failure to add its tokens must not lose the answer.
  await recordLlmUsage(ctx.pluginId, ctx.userId, charge.key, { inputTokens, outputTokens, model }).catch((e) =>
    console.error(`[plugins] llm plugin=${ctx.pluginId} user=${ctx.userId} usage not recorded:`, e instanceof Error ? e.message : e),
  )
  console.log(
    `[plugins] llm plugin=${ctx.pluginId} user=${ctx.userId} model=${model} in=${inputTokens} out=${outputTokens} ms=${Date.now() - started}`,
  )
  return {
    content: typeof result.body.content === 'string' ? result.body.content : '',
    model_used: model,
    usage: { input_tokens: inputTokens, output_tokens: outputTokens, estimated: usage.estimated === true },
  }
}

export function POST(request: NextRequest) {
  return withGateway(request, { op: 'llm/invoke', permission: 'llm:invoke', maxBodyBytes: GATEWAY_BODY_MAX_BYTES }, invoke)
}
