/**
 * drift-map #14: preset generation never sends `temperature` to a model that
 * rejects it, using the agent's rules (src/lib/llmTemperature.ts), and heals a
 * provider 400 that names the parameter with ONE retry without it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockProviders = vi.fn()
const mockSettings = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userLlmProvider: { findMany: (...a: unknown[]) => mockProviders(...a) },
    userSettings: { findUnique: (...a: unknown[]) => mockSettings(...a) },
  },
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => ({ userId: 'alice' }) }))
vi.mock('@/lib/llm-url-guard', async (orig) => ({
  ...(await orig<typeof import('@/lib/llm-url-guard')>()),
  assertSafeLlmBaseUrl: async () => {},
}))

import { POST } from './route'

const ANTHROPIC = { providerType: 'anthropic', apiKey: 'sk-ant-alice', timeout: 30, maxTokens: 4096, temperature: 0.2 }
const OPENAI = { providerType: 'openai', apiKey: 'sk-alice', baseUrl: '', timeout: 30, maxTokens: 4096, temperature: 0.2 }
const KIMI = { providerType: 'kimi', apiKey: 'sk-kimi', baseUrl: '', timeout: 30, maxTokens: 4096, temperature: 0.2 }
const CUSTOM = {
  id: 'row1', providerType: 'openai_compatible', apiKey: 'sk-c', baseUrl: 'http://llm.lab.example/v1',
  modelIdentifier: 'llama3.1:8b', timeout: 30, maxTokens: 4096, temperature: 0.2, sslVerify: true,
}

const fetchMock = vi.fn()

const anthropicOk = () => new Response(JSON.stringify({
  content: [{ type: 'text', text: '{"naabuEnabled": true}' }],
}), { status: 200 })
const openaiOk = () => new Response(JSON.stringify({
  choices: [{ message: { content: '{"naabuEnabled": true}' } }],
}), { status: 200 })

function generate() {
  return POST(new NextRequest('http://localhost/api/presets/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt: 'stealthy' }),
  }))
}

function saved(model: string) {
  mockSettings.mockResolvedValue({ featureModels: { preset_generator: model } })
}

const sentBody = (call: number) =>
  JSON.parse((fetchMock.mock.calls[call][1] as RequestInit).body as string) as Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  mockProviders.mockResolvedValue([ANTHROPIC, OPENAI, KIMI, CUSTOM])
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => vi.unstubAllGlobals())

describe('temperature is left out for a model that rejects it', () => {
  test.each([
    ['claude-opus-4-8', anthropicOk],
    ['claude-sonnet-5-20261001', anthropicOk],
    ['gpt-5', openaiOk],
    ['o3-mini', openaiOk],
    ['kimi/kimi-k3', openaiOk],
  ])('%s', async (model, ok) => {
    saved(model)
    fetchMock.mockResolvedValueOnce(ok())
    const res = await generate()
    expect(res.status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(sentBody(0)).not.toHaveProperty('temperature')
  })

  test('a custom row whose model rejects it', async () => {
    mockProviders.mockResolvedValue([{ ...CUSTOM, modelIdentifier: 'openai/gpt-6-luna' }])
    saved('custom/row1')
    fetchMock.mockResolvedValueOnce(openaiOk())
    expect((await generate()).status).toBe(200)
    expect(sentBody(0)).not.toHaveProperty('temperature')
  })
})

describe('temperature is sent, with the provider\'s value, to a model that takes it', () => {
  test.each([
    ['claude-opus-4-6', anthropicOk],
    ['gpt-4o', openaiOk],
    ['gpt-5-chat-latest', openaiOk],
    ['custom/row1', openaiOk],
  ])('%s', async (model, ok) => {
    saved(model)
    fetchMock.mockResolvedValueOnce(ok())
    expect((await generate()).status).toBe(200)
    expect(sentBody(0).temperature).toBe(0.2)
  })
})

describe('a 400 that names temperature is retried once without it', () => {
  test('Anthropic: the retry drops temperature and the preset comes back', async () => {
    saved('claude-opus-4-6')
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        type: 'error', error: { type: 'invalid_request_error', message: '`temperature` is deprecated for this model.' },
      }), { status: 400 }))
      .mockResolvedValueOnce(anthropicOk())
    const res = await generate()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ parameters: { naabuEnabled: true } })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(sentBody(0).temperature).toBe(0.2)
    expect(sentBody(1)).not.toHaveProperty('temperature')
    expect(sentBody(1).model).toBe('claude-opus-4-6')
  })

  test('OpenAI-compatible: the retry goes to the same endpoint with the same key', async () => {
    saved('custom/row1')
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: { message: "Unsupported value: 'temperature' does not support 0.2 with this model.", param: 'temperature' },
      }), { status: 400 }))
      .mockResolvedValueOnce(openaiOk())
    expect((await generate()).status).toBe(200)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[1][0]).toBe(fetchMock.mock.calls[0][0])
    expect((fetchMock.mock.calls[1][1] as RequestInit).headers)
      .toEqual((fetchMock.mock.calls[0][1] as RequestInit).headers)
    expect(sentBody(1)).not.toHaveProperty('temperature')
  })

  test('only once: a second refusal is the answer', async () => {
    saved('claude-opus-4-6')
    const refusal = () => new Response(JSON.stringify({
      type: 'error', error: { type: 'invalid_request_error', message: 'temperature is not supported' },
    }), { status: 400 })
    fetchMock.mockResolvedValueOnce(refusal()).mockResolvedValueOnce(refusal()).mockResolvedValue(anthropicOk())
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await generate()
    expect(res.status).toBe(502)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  test('a 400 about something else is not retried', async () => {
    saved('claude-opus-4-6')
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({
      type: 'error', error: { type: 'invalid_request_error', message: 'max_tokens: too large' },
    }), { status: 400 }))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await generate()
    expect(res.status).toBe(502)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('a model sent without temperature is never retried', async () => {
    saved('claude-opus-5')
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({
      type: 'error', error: { type: 'invalid_request_error', message: 'temperature something' },
    }), { status: 400 }))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect((await generate()).status).toBe(502)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
