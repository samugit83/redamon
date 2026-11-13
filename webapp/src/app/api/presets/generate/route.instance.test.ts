/**
 * The preset generator on an instance provider's model (step 6.11, GV-15). It is built from that
 * provider's row alone, and only while the person may use it (entitlement.ts). A model whose
 * instance provider is gone, not assigned to the person or switched off is model_unavailable: it is
 * never resolved as a bare OpenAI model and sent with the person's own key (the agent refuses the
 * same id, agentic/llm_builder.py).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/presets/generate/route.instance.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const OWN_KEY = 'sk-OWN-openai-key'
const INSTANCE_KEY = 'sk-INSTANCE-canary'
const mockProviders = vi.fn()
const mockSettings = vi.fn()
const entitled = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userLlmProvider: { findMany: (...a: unknown[]) => mockProviders(...a) },
    userSettings: { findUnique: (...a: unknown[]) => mockSettings(...a) },
  },
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => ({ userId: 'alice' }) }))
const withheld = vi.fn(async (_id: string) => false)
vi.mock('@/lib/instanceProviders/entitlement', () => ({
  entitledInstanceProviders: (id: string) => entitled(id),
  ownProvidersWithheld: (id: string) => withheld(id),
}))

import { POST } from './route'

const OWN_OPENAI = { id: 'own-1', providerType: 'openai', apiKey: OWN_KEY, baseUrl: '', timeout: 30, maxTokens: 4096, temperature: 0 }
const instance = (over: Record<string, unknown> = {}) => ({
  id: 'inst-1', providerType: 'openai', name: 'Shared', apiKey: INSTANCE_KEY, baseUrl: '', modelIdentifier: '',
  defaultHeaders: {}, timeout: 30, temperature: 0, maxTokens: 4096, sslVerify: true, ...over,
})
const fetchMock = vi.fn()

function generate() {
  return POST(new NextRequest('http://localhost/api/presets/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt: 'stealthy' }),
  }))
}
const saved = (model: string) => mockSettings.mockResolvedValue({ featureModels: { preset_generator: model } })
const sentAuth = () => (fetchMock.mock.calls[0][1] as RequestInit).headers as Record<string, string>

beforeEach(() => {
  vi.clearAllMocks()
  mockProviders.mockResolvedValue([OWN_OPENAI])
  entitled.mockResolvedValue([instance()])
  withheld.mockResolvedValue(false)
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockResolvedValue(new Response(JSON.stringify({
    choices: [{ message: { content: '{"naabuEnabled": true}' } }],
  }), { status: 200 }))
})
afterEach(() => vi.unstubAllGlobals())

describe('an instance provider model', () => {
  test('is built from the instance row alone: its key, the bare model id', async () => {
    saved('instance/inst-1/gpt-5')
    const res = await generate()
    expect(res.status).toBe(200)
    expect(fetchMock.mock.calls[0][0]).toBe('https://api.openai.com/v1/chat/completions')
    expect(sentAuth().Authorization).toBe(`Bearer ${INSTANCE_KEY}`)
    expect(JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string).model).toBe('gpt-5')
    expect(mockProviders).not.toHaveBeenCalled()
    expect(entitled).toHaveBeenCalledWith('alice')
  })

  test('an OpenAI-compatible instance endpoint serves its own custom id', async () => {
    entitled.mockResolvedValue([instance({ providerType: 'openai_compatible', baseUrl: 'http://8.8.8.8:8000/v1', modelIdentifier: 'qwen' })])
    saved('instance/inst-1/custom/inst-1')
    expect((await generate()).status).toBe(200)
    expect(fetchMock.mock.calls[0][0]).toBe('http://8.8.8.8:8000/v1/chat/completions')
    expect(sentAuth().Authorization).toBe(`Bearer ${INSTANCE_KEY}`)
  })

  test.each([
    ['not entitled (switch off, unassigned, deleted)', 'instance/inst-1/gpt-5', []],
    ['another provider than the one entitled', 'instance/inst-2/gpt-5', null],
    ['a model of another kind', 'instance/inst-1/claude-opus-4-6', null],
    ['an endpoint naming another custom id', 'instance/inst-1/custom/own-1', null],
    ['a malformed id', 'instance/inst-1', null],
    ['a loop id behind the prefix (agent-in-the-loop: never outside a chat run)', 'instance/inst-1/loop/mcp', null],
    ['a nested instance id', 'instance/inst-1/instance/inst-1/gpt-5', null],
    ['a legacy openai_compat id behind the prefix', 'instance/inst-1/openai_compat/llama3', null],
  ])('%s → model_unavailable, never sent with the own key', async (_name, model, rows) => {
    if (rows) entitled.mockResolvedValue(rows)
    saved(model)
    const res = await generate()
    expect(res.status).toBe(503)
    expect(await res.json()).toMatchObject({ code: 'model_unavailable', model })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('byoLlmForbidden (fix of the 6.11 review, finding 1)', () => {
  test('withheld own providers: a model on them is model_unavailable, the own rows are never read or sent', async () => {
    withheld.mockResolvedValue(true)
    saved('gpt-5')
    const res = await generate()
    expect(res.status).toBe(503)
    expect(await res.json()).toMatchObject({ code: 'model_unavailable', model: 'gpt-5' })
    expect(withheld).toHaveBeenCalledWith('alice')
    expect(mockProviders).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('an instance model is not the account\'s own provider: it still works while the own ones are withheld', async () => {
    withheld.mockResolvedValue(true)
    saved('instance/inst-1/gpt-5')
    expect((await generate()).status).toBe(200)
    expect(sentAuth().Authorization).toBe(`Bearer ${INSTANCE_KEY}`)
  })

  test('a legacy openai_compat model is refused, never sent to OpenAI with the own key', async () => {
    saved('openai_compat/llama3')
    const res = await generate()
    expect(res.status).toBe(503)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
