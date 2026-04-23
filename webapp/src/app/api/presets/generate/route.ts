import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { reconPresetSchema, extractJson, RECON_PARAMETER_CATALOG } from '@/lib/recon-preset-schema'

// ---------------------------------------------------------------------------
// POST /api/presets/generate
// Calls the user's configured LLM to generate a recon preset from a natural
// language description.  Validates the output with Zod before returning.
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
- Do NOT include agent behaviour, attack skills, RoE, or CypherFix fields.
- Focus on enabling/disabling tools and tuning their numeric settings to match the user's intent.

AVAILABLE PARAMETERS:

${RECON_PARAMETER_CATALOG}
`

/**
 * Resolve provider type from model name, mirroring the Python logic in
 * agentic/orchestrator_helpers/llm_setup.py:parse_model_provider()
 */
function resolveProviderType(model: string): { providerType: string; modelId: string } {
  if (model.startsWith('custom/')) {
    return { providerType: 'openai_compatible', modelId: model.slice('custom/'.length) }
  }
  if (model.startsWith('openrouter/')) {
    return { providerType: 'openrouter', modelId: model.slice('openrouter/'.length) }
  }
  if (model.startsWith('bedrock/')) {
    return { providerType: 'bedrock', modelId: model.slice('bedrock/'.length) }
  }
  if (model.startsWith('claude-')) {
    return { providerType: 'anthropic', modelId: model }
  }
  // Default: OpenAI
  return { providerType: 'openai', modelId: model }
}

/**
 * Call an OpenAI-compatible chat completions endpoint.
 */
async function callOpenAICompatible(
  baseUrl: string,
  apiKey: string,
  modelId: string,
  systemPrompt: string,
  userPrompt: string,
  extraHeaders?: Record<string, string>,
  timeout?: number,
): Promise<string> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), (timeout || 120) * 1000)

  try {
    const res = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        ...extraHeaders,
      },
      body: JSON.stringify({
        model: modelId,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.3,
        max_tokens: 4096,
        response_format: { type: 'json_object' },
      }),
      signal: controller.signal,
    })

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
        max_tokens: 4096,
        temperature: 0.3,
      }),
      signal: controller.signal,
    })

    if (!res.ok) {
      const errText = await res.text().catch(() => 'Unknown error')
      throw new Error(`Anthropic API returned ${res.status}: ${errText}`)
    }

    const data = await res.json()
    // Anthropic returns content as an array of blocks
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

    // 1. Resolve provider type from model name
    const { providerType, modelId } = resolveProviderType(model)

    if (providerType === 'bedrock') {
      return NextResponse.json(
        { error: 'AWS Bedrock is not yet supported for preset generation. Please configure an OpenAI, Anthropic, or OpenRouter provider.' },
        { status: 400 },
      )
    }

    // 2. Find matching provider in user's configured LLM providers
    const providers = await prisma.userLlmProvider.findMany({
      where: { userId },
    })

    const provider = providers.find((p) => p.providerType === providerType)

    if (!provider) {
      const friendlyNames: Record<string, string> = {
        anthropic: 'Anthropic',
        openai: 'OpenAI',
        openrouter: 'OpenRouter',
        openai_compatible: 'OpenAI-Compatible',
      }
      return NextResponse.json(
        {
          error: `No ${friendlyNames[providerType] || providerType} provider configured. Add one in Global Settings to use model "${model}".`,
        },
        { status: 400 },
      )
    }

    // 3. Call the LLM
    let rawResponse: string

    if (providerType === 'anthropic') {
      rawResponse = await callAnthropic(
        provider.apiKey,
        modelId,
        SYSTEM_PROMPT,
        prompt.trim(),
        provider.timeout,
      )
    } else {
      // OpenAI, OpenRouter, OpenAI-compatible
      let baseUrl = provider.baseUrl || 'https://api.openai.com/v1'
      if (providerType === 'openrouter' && !provider.baseUrl) {
        baseUrl = 'https://openrouter.ai/api/v1'
      }
      // Remove trailing slash
      baseUrl = baseUrl.replace(/\/+$/, '')

      const extraHeaders = (provider.defaultHeaders && typeof provider.defaultHeaders === 'object')
        ? provider.defaultHeaders as Record<string, string>
        : undefined

      rawResponse = await callOpenAICompatible(
        baseUrl,
        provider.apiKey,
        modelId,
        SYSTEM_PROMPT,
        prompt.trim(),
        extraHeaders,
        provider.timeout,
      )
    }

    if (!rawResponse) {
      return NextResponse.json(
        { error: 'LLM returned an empty response' },
        { status: 502 },
      )
    }

    // 4. Parse JSON from response
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

    // 5. Validate with Zod
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

    // Distinguish abort (timeout) from other errors
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
