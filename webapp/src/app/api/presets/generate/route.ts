import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { reconPresetSchema, extractJson, RECON_PARAMETER_CATALOG } from '@/lib/recon-preset-schema'
import { assertSafeLlmBaseUrl, BaseUrlValidationError } from '@/lib/llm-url-guard'

// ---------------------------------------------------------------------------
// POST /api/presets/generate
// Calls the user's configured LLM to generate a recon preset from a natural
// language description.  Validates the output with Zod before returning.
//
// Provider resolution mirrors the agent chat path
// (agentic/orchestrator_helpers/llm_setup.py + agentic/api.py:_pick_custom_provider):
//   - "custom/<id>"        → lookup UserLlmProvider by id, use modelIdentifier
//   - "openrouter/...","bedrock/...","deepseek/...", etc. → match providerType
//   - "claude-*"           → anthropic
//   - everything else      → openai
// This is what makes "Generate Recon Preset with AI" work with any configured
// provider - including OpenAI-compatible deployments like Microsoft Foundry.
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are a recon pipeline configuration expert for RedAmon, an AI-powered red-team reconnaissance platform.

Given a user's natural-language description, produce a JSON object whose keys are recon pipeline parameters and whose values configure the scan strategy.

RULES:
- Output ONLY a raw JSON object. No markdown, no explanation, no wrapping.
- Only include parameters you explicitly want to change. Omitted parameters keep their defaults.
- Booleans must be true or false (not strings).
- Numbers must be plain integers or floats (not strings).
- Arrays must use JSON array syntax.
- Do NOT include target-specific fields (targetDomain, subdomainList, ipMode, etc.).
- Do NOT include OpenAPI source URLs or fetch/discovery headers; they are target-specific and may contain credentials.
- Do NOT include agent behaviour, attack skills, RoE, or CypherFix fields.
- Focus on enabling/disabling tools and tuning their numeric settings to match the user's intent.

AVAILABLE PARAMETERS:

${RECON_PARAMETER_CATALOG}
`

type Resolved =
  | { kind: 'custom'; providerId: string }
  | { kind: 'builtin'; providerType: string; modelId: string }

/**
 * Resolve a model string to either a specific custom provider id or a builtin
 * provider type + api model id. Mirrors agent backend semantics:
 * - "custom/<cuid>" is a *provider id* (NOT an api model name). The actual
 *   api model name lives in UserLlmProvider.modelIdentifier.
 * - All other prefixes encode the api model name after the prefix.
 */
function resolveModel(model: string): Resolved {
  if (model.startsWith('custom/')) {
    return { kind: 'custom', providerId: model.slice('custom/'.length) }
  }
  const prefixMap: Record<string, string> = {
    'openrouter/': 'openrouter',
    'bedrock/': 'bedrock',
    'deepseek/': 'deepseek',
    'gemini/': 'gemini',
    'glm/': 'glm',
    'kimi/': 'kimi',
    'qwen/': 'qwen',
    'xai/': 'xai',
    'mistral/': 'mistral',
  }
  for (const [prefix, type] of Object.entries(prefixMap)) {
    if (model.startsWith(prefix)) {
      return { kind: 'builtin', providerType: type, modelId: model.slice(prefix.length) }
    }
  }
  if (model.startsWith('claude-')) {
    return { kind: 'builtin', providerType: 'anthropic', modelId: model }
  }
  return { kind: 'builtin', providerType: 'openai', modelId: model }
}

/**
 * Returns the OpenAI-compatible base URL for each builtin provider type.
 * Mirrors agentic/orchestrator_helpers/llm_setup.py setup_llm branches.
 */
function defaultBaseUrlFor(providerType: string): string {
  switch (providerType) {
    case 'openai': return 'https://api.openai.com/v1'
    case 'openrouter': return 'https://openrouter.ai/api/v1'
    case 'deepseek': return 'https://api.deepseek.com/v1'
    case 'gemini': return 'https://generativelanguage.googleapis.com/v1beta/openai'
    case 'glm': return 'https://open.bigmodel.cn/api/paas/v4'
    case 'kimi': return 'https://api.moonshot.ai/v1'
    case 'qwen': return 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'
    case 'xai': return 'https://api.x.ai/v1'
    case 'mistral': return 'https://api.mistral.ai/v1'
    default: return 'https://api.openai.com/v1'
  }
}

interface OpenAICompatOptions {
  baseUrl: string
  apiKey: string
  modelId: string
  systemPrompt: string
  userPrompt: string
  extraHeaders?: Record<string, string>
  timeout?: number
  temperature?: number
  maxTokens?: number
  sslVerify?: boolean
}

/**
 * Call an OpenAI-compatible chat completions endpoint. Honors the provider's
 * temperature/maxTokens/headers/sslVerify so behavior matches what the agent
 * chat does for the same provider record.
 */
async function callOpenAICompatible(opts: OpenAICompatOptions): Promise<string> {
  // SSRF guard (I15) + TLS-off-on-public guard (I16). Localhost/LAN self-hosted
  // endpoints stay allowed; cloud metadata and public-host TLS bypass are rejected.
  await assertSafeLlmBaseUrl(opts.baseUrl, { sslVerify: opts.sslVerify })

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), (opts.timeout || 120) * 1000)

  const init: RequestInit & { dispatcher?: unknown } = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${opts.apiKey}`,
      ...opts.extraHeaders,
    },
    body: JSON.stringify({
      model: opts.modelId,
      messages: [
        { role: 'system', content: opts.systemPrompt },
        { role: 'user', content: opts.userPrompt },
      ],
      temperature: opts.temperature ?? 0.3,
      max_tokens: opts.maxTokens ?? 4096,
      response_format: { type: 'json_object' },
    }),
    signal: controller.signal,
  }

  // SSL bypass for internal endpoints with self-signed certs (mirrors
  // llm_setup.py's `if not custom_llm_config.get("sslVerify", True)` branch).
  if (opts.sslVerify === false) {
    const { Agent } = await import('undici')
    init.dispatcher = new Agent({ connect: { rejectUnauthorized: false } })
  }

  try {
    const res = await fetch(`${opts.baseUrl}/chat/completions`, init)

    if (!res.ok) {
      const errText = await res.text().catch(() => 'Unknown error')
      throw new Error(`LLM API returned ${res.status}: ${errText}`)
    }

    const data = await res.json()
    return data.choices?.[0]?.message?.content ?? ''
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Call the Anthropic Messages API.
 */
async function callAnthropic(
  apiKey: string,
  modelId: string,
  systemPrompt: string,
  userPrompt: string,
  timeout?: number,
  maxTokens?: number,
  temperature?: number,
): Promise<string> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), (timeout || 120) * 1000)

  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: modelId,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
        max_tokens: maxTokens ?? 4096,
        temperature: temperature ?? 0.3,
      }),
      signal: controller.signal,
    })

    if (!res.ok) {
      const errText = await res.text().catch(() => 'Unknown error')
      throw new Error(`Anthropic API returned ${res.status}: ${errText}`)
    }

    const data = await res.json()
    const textBlock = data.content?.find((b: { type: string }) => b.type === 'text')
    return textBlock?.text ?? ''
  } finally {
    clearTimeout(timer)
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { userId, model, prompt } = body as {
      userId?: string
      model?: string
      prompt?: string
    }

    if (!userId) {
      return NextResponse.json({ error: 'userId is required' }, { status: 400 })
    }
    if (!model) {
      return NextResponse.json({ error: 'model is required' }, { status: 400 })
    }
    if (!prompt || !prompt.trim()) {
      return NextResponse.json({ error: 'prompt is required' }, { status: 400 })
    }

    const resolved = resolveModel(model)

    if (resolved.kind === 'builtin' && resolved.providerType === 'bedrock') {
      return NextResponse.json(
        { error: 'AWS Bedrock is not yet supported for preset generation. Use an OpenAI, Anthropic, OpenAI-Compatible, or other provider.' },
        { status: 400 },
      )
    }

    const providers = await prisma.userLlmProvider.findMany({ where: { userId } })

    let rawResponse: string

    if (resolved.kind === 'custom') {
      // Lookup by provider id (the suffix in "custom/<id>" is a CUID, not a
      // model name). The actual api model name is on the provider record.
      const provider = providers.find((p) => p.id === resolved.providerId)
      if (!provider) {
        return NextResponse.json(
          {
            error: `No custom provider with id "${resolved.providerId}" found. Reconfigure the LLM Model in Agent Behaviour, or add the provider in Global Settings.`,
          },
          { status: 400 },
        )
      }

      const apiModel = provider.modelIdentifier?.trim()
      if (!apiModel) {
        return NextResponse.json(
          {
            error: `Custom provider "${provider.name}" has no Model Identifier set. Open Global Settings → LLM Providers and configure it.`,
          },
          { status: 400 },
        )
      }

      // custom/ is only emitted by the agent for openai_compatible providers
      // (see agentic/orchestrator_helpers/model_providers.py). Route through
      // the OpenAI-compatible client.
      const baseUrl = (provider.baseUrl || '').replace(/\/+$/, '')
      if (!baseUrl) {
        return NextResponse.json(
          {
            error: `Custom provider "${provider.name}" has no Base URL set. Open Global Settings → LLM Providers and configure it.`,
          },
          { status: 400 },
        )
      }

      const extraHeaders = (provider.defaultHeaders && typeof provider.defaultHeaders === 'object')
        ? provider.defaultHeaders as Record<string, string>
        : undefined

      rawResponse = await callOpenAICompatible({
        baseUrl,
        apiKey: provider.apiKey,
        modelId: apiModel,
        systemPrompt: SYSTEM_PROMPT,
        userPrompt: prompt.trim(),
        extraHeaders,
        timeout: provider.timeout,
        temperature: provider.temperature,
        maxTokens: provider.maxTokens,
        sslVerify: provider.sslVerify,
      })
    } else {
      const { providerType, modelId } = resolved
      const provider = providers.find((p) => p.providerType === providerType)

      if (!provider) {
        const friendlyNames: Record<string, string> = {
          anthropic: 'Anthropic',
          openai: 'OpenAI',
          openrouter: 'OpenRouter',
          deepseek: 'DeepSeek',
          gemini: 'Google Gemini',
          glm: 'GLM (Zhipu AI)',
          kimi: 'Kimi (Moonshot)',
          qwen: 'Qwen (Alibaba)',
          xai: 'xAI (Grok)',
          mistral: 'Mistral AI',
        }
        return NextResponse.json(
          {
            error: `No ${friendlyNames[providerType] || providerType} provider configured. Add one in Global Settings to use model "${model}".`,
          },
          { status: 400 },
        )
      }

      if (providerType === 'anthropic') {
        rawResponse = await callAnthropic(
          provider.apiKey,
          modelId,
          SYSTEM_PROMPT,
          prompt.trim(),
          provider.timeout,
          provider.maxTokens,
          provider.temperature,
        )
      } else {
        const baseUrl = (provider.baseUrl || defaultBaseUrlFor(providerType)).replace(/\/+$/, '')

        const extraHeaders = (provider.defaultHeaders && typeof provider.defaultHeaders === 'object')
          ? provider.defaultHeaders as Record<string, string>
          : undefined

        rawResponse = await callOpenAICompatible({
          baseUrl,
          apiKey: provider.apiKey,
          modelId,
          systemPrompt: SYSTEM_PROMPT,
          userPrompt: prompt.trim(),
          extraHeaders,
          timeout: provider.timeout,
          temperature: provider.temperature,
          maxTokens: provider.maxTokens,
          sslVerify: provider.sslVerify,
        })
      }
    }

    if (!rawResponse) {
      return NextResponse.json(
        { error: 'LLM returned an empty response' },
        { status: 502 },
      )
    }

    const jsonStr = extractJson(rawResponse)
    let parsed: unknown
    try {
      parsed = JSON.parse(jsonStr)
    } catch {
      return NextResponse.json(
        { error: 'LLM returned invalid JSON. Please try again with a clearer description.' },
        { status: 422 },
      )
    }

    const result = reconPresetSchema.safeParse(parsed)
    if (!result.success) {
      const issues = result.error.issues.slice(0, 5).map((i) => `${i.path.join('.')}: ${i.message}`)
      return NextResponse.json(
        {
          error: 'Generated preset has invalid fields',
          details: issues,
        },
        { status: 422 },
      )
    }

    return NextResponse.json({ parameters: result.data })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error'

    if (error instanceof BaseUrlValidationError) {
      return NextResponse.json({ error: message }, { status: 400 })
    }

    if (error instanceof Error && error.name === 'AbortError') {
      return NextResponse.json(
        { error: 'LLM request timed out. Try a simpler description or check your provider settings.' },
        { status: 504 },
      )
    }

    console.error('Preset generation failed:', message)
    return NextResponse.json(
      { error: `Failed to generate preset: ${message}` },
      { status: 502 },
    )
  }
}
