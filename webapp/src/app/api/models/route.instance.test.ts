/**
 * POST /api/models with instance providers (step 6.11, GV-15). The answer adds one group per instance
 * provider the effective user may use, its ids `instance/<providerId>/<model>`; a person WITHOUT
 * self:llm_providers gets those groups alone (the Phase 6 kickoff's assumption (d)). With
 * RBAC_GOVERNANCE_ENABLED off such a person is refused as before, and the answer is exactly the own
 * providers' (DV-30). An instance key goes to the agent in a POST body only, never in the answer.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/models/route.instance.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const INSTANCE_KEY = 'sk-INSTANCE-CANARY-models'
const h = vi.hoisted(() => ({
  holds: true,
  governance: true,
  actingAs: null as { id: string } | null,
}))
const entitled = vi.fn()
const findMany = vi.fn()
const agentFetch = vi.fn()

vi.mock('@/lib/authz/guards', () => ({
  requirePermission: async () => (h.holds
    ? { effective: { userId: h.actingAs?.id ?? 'u1' } }
    : NextResponse.json({ error: 'no', code: 'forbidden', permission: 'self:llm_providers' }, { status: 403 })),
}))
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => ({ session: { userId: 'u1' }, principal: { id: 'u1' }, actingAs: h.actingAs }),
}))
vi.mock('@/lib/instanceProviders/entitlement', () => ({
  instanceProvidersInForce: () => h.governance,
  entitledInstanceProviders: (id: string) => entitled(id),
}))
vi.mock('@/lib/prisma', () => ({ default: { userLlmProvider: { findMany: (...a: unknown[]) => findMany(...a) } } }))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  agentFetch: (...a: unknown[]) => agentFetch(...a),
}))

import { POST } from './route'

const INSTANCE = {
  id: 'inst-1', providerType: 'openai', name: 'Shared', apiKey: INSTANCE_KEY, baseUrl: '', modelIdentifier: '',
  defaultHeaders: {}, timeout: 120, temperature: 0, maxTokens: 16384, sslVerify: true, reasoningEnabled: false,
  reasoningEffort: 'high', awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '',
  createdAt: new Date(0), updatedAt: new Date(0), createdById: null, updatedById: null,
}
const OWN = { id: 'own-1', userId: 'u1', providerType: 'anthropic', name: 'Mine', apiKey: 'sk-own' }

const post = (body: unknown = { userId: 'u1' }) =>
  POST(new Request('http://x/api/models', { method: 'POST', body: JSON.stringify(body) }) as never)

function agentAnswers() {
  agentFetch.mockImplementation(async (_path: string, init: RequestInit) => {
    const { providers } = JSON.parse(String(init.body)) as { providers: Array<{ id: string; providerType: string }> | null }
    const groups: Record<string, unknown[]> = { 'Agent in the Loop': [{ id: 'loop/mcp', name: 'Agent in the Loop' }] }
    for (const p of providers ?? []) groups[`${p.providerType} (${p.id})`] = [{ id: p.providerType === 'openai' ? 'gpt-5' : 'claude-x', name: 'm' }]
    return new Response(JSON.stringify(groups), { status: 200 })
  })
}

beforeEach(() => {
  h.holds = true
  h.governance = true
  h.actingAs = null
  entitled.mockReset().mockResolvedValue([INSTANCE])
  findMany.mockReset().mockResolvedValue([OWN])
  agentFetch.mockReset()
  agentAnswers()
})

describe('instance models in the pickers', () => {
  test('a holder gets the own groups and one group per instance provider, ids prefixed', async () => {
    const res = await post()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toEqual({
      'Agent in the Loop': [{ id: 'loop/mcp', name: 'Agent in the Loop' }],
      'anthropic (own-1)': [{ id: 'claude-x', name: 'm' }],
      'Instance: Shared': [{ id: 'instance/inst-1/gpt-5', name: 'm' }],
    })
    expect(JSON.stringify(body)).not.toContain(INSTANCE_KEY)
    // The instance provider is listed in its own POST body, as its own kind.
    const instanceCall = agentFetch.mock.calls.find(([, init]) => String(init.body).includes('inst-1'))!
    expect(instanceCall[0]).toBe('/models')
    expect(JSON.parse(String(instanceCall[1].body)).providers).toEqual([expect.objectContaining({ id: 'inst-1', providerType: 'openai', apiKey: INSTANCE_KEY })])
  })

  test('a member without self:llm_providers gets the instance groups alone, no own row read', async () => {
    h.holds = false
    const res = await post()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ 'Instance: Shared': [{ id: 'instance/inst-1/gpt-5', name: 'm' }] })
    expect(findMany).not.toHaveBeenCalled()
    expect(entitled).toHaveBeenCalledWith('u1')
  })

  test('under act-as the account acted as decides', async () => {
    h.holds = false
    h.actingAs = { id: 'member-9' }
    await post()
    expect(entitled).toHaveBeenCalledWith('member-9')
  })

  test('switch off → not offered: a non-holder is refused as before, a holder gets the own groups only', async () => {
    h.governance = false
    entitled.mockResolvedValue([])
    h.holds = false
    const refused = await post()
    expect(refused.status).toBe(403)
    expect(await refused.json()).toMatchObject({ code: 'forbidden', permission: 'self:llm_providers' })
    h.holds = true
    const body = await (await post()).json()
    expect(Object.keys(body).sort()).toEqual(['Agent in the Loop', 'anthropic (own-1)'])
  })

  test('the agent unreachable while listing an instance provider answers the agent failure', async () => {
    const { AgentUnreachableError } = await import('@/lib/agentFetch')
    agentFetch.mockImplementation(async (_p: string, init: RequestInit) => {
      if (String(init.body).includes('inst-1')) throw new AgentUnreachableError(new Error('ECONNREFUSED'))
      return new Response('{}', { status: 200 })
    })
    const res = await post()
    expect(res.status).toBeGreaterThanOrEqual(500)
  })
})
