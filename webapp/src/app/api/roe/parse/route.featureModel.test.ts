/**
 * `/api/roe/parse` runs on the caller's own "RoE parsing" model and keys:
 * 401 with no effective user, `model_required` when none is saved, and the
 * model from the settings, never from the upload form.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockEff = vi.fn()
const mockSettings = vi.fn()
const mockAgentFetch = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => mockEff() }))
vi.mock('@/lib/prisma', () => ({
  default: { userSettings: { findUnique: (...a: unknown[]) => mockSettings(...a) } },
}))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))

import { POST } from './route'
import { REGISTRY_DIGEST } from '@/lib/reconSettings/registryDigest.generated'

function upload(extra: Record<string, string> = {}) {
  const form = new FormData()
  form.append('file', new File(['Scope: example.com only'], 'roe.txt', { type: 'text/plain' }))
  for (const [k, v] of Object.entries(extra)) form.append(k, v)
  return POST(new NextRequest('http://x/api/roe/parse', { method: 'POST', body: form }))
}

function sentToAgent() {
  return JSON.parse((mockAgentFetch.mock.calls[0][1] as RequestInit).body as string)
}

beforeEach(() => {
  vi.clearAllMocks()
  mockEff.mockResolvedValue({ userId: 'alice' })
  mockSettings.mockResolvedValue({ featureModels: { roe_parse: 'gpt-5' } })
  mockAgentFetch.mockResolvedValue(new Response(JSON.stringify({
    fields: {}, unknownKeys: [], registryDigest: REGISTRY_DIGEST, model_used: 'gpt-5',
  }), { status: 200 }))
})

describe('/api/roe/parse and Models by feature', () => {
  test('no effective user is 401 and reaches no agent', async () => {
    mockEff.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    const res = await upload()
    expect(res.status).toBe(401)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('no saved model is model_required', async () => {
    mockSettings.mockResolvedValue(null)
    const res = await upload()
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'model_required', featureId: 'roe_parse' })
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('the saved model and the caller id are sent; a form model is ignored', async () => {
    await upload({ model: 'claude-opus-4-6' })
    expect(mockAgentFetch.mock.calls[0][0]).toBe('/roe/parse')
    expect(sentToAgent()).toMatchObject({ model: 'gpt-5', user_id: 'alice' })
  })

  test('an agent that ignores the model is agent_outdated', async () => {
    mockAgentFetch.mockResolvedValue(new Response(JSON.stringify({ fields: {} }), { status: 200 }))
    const res = await upload()
    expect(res.status).toBe(502)
    expect((await res.json()).code).toBe('agent_outdated')
  })

  test('model_unavailable from the agent reaches the client as a code', async () => {
    mockAgentFetch.mockResolvedValue(new Response(JSON.stringify({
      code: 'model_unavailable', error: 'x', model_used: 'gpt-5',
    }), { status: 503 }))
    const res = await upload()
    expect(await res.json()).toMatchObject({ code: 'model_unavailable', model: 'gpt-5' })
  })
})
