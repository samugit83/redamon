/**
 * The triage preflight's "does the model have a key" with instance providers (step 6.11, GV-15): an
 * instance provider's model has one only while the project's owner may use that provider (the agent
 * builds it from that provider alone), whatever own keys the owner holds; any other model keeps the
 * rule before (a chat provider row with a key).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/triage/preflight.instance.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  model: '' as string,
  own: [] as { providerType: string; apiKey: string }[],
  entitled: [] as { id: string }[],
  entitledFails: false,
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: async () => ({ name: 'P', userId: 'owner-1', cypherfixDefaultRepo: '', triageReviewBudget: 10 }) },
    triageRun: { findFirst: async () => null },
    remediation: { groupBy: async () => [] },
    userLlmProvider: { findMany: async () => h.own },
    mcpAccessToken: { findUnique: async () => null },
  },
}))
vi.mock('@/lib/featureModels', () => ({ readFeatureModel: async () => h.model }))
vi.mock('@/lib/triageRun', () => ({
  findLiveTriageRun: async () => null,
  mcpRunBudget: async () => ({ runsToday: 0, nextAllowedAt: null, reason: null }),
  MCP_RUNS_PER_DAY: 5,
}))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: async () => false }))
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: async () => null }))
vi.mock('@/lib/triage/actions', () => ({
  agentTriage: async () => ({ reviewable: 24 }),
  TriageActionError: class extends Error {},
}))
vi.mock('@/lib/instanceProviders/entitlement', () => ({
  entitledInstanceProviders: async (id: string) => {
    if (h.entitledFails) throw new Error('db down')
    return id === 'owner-1' ? h.entitled : []
  },
}))

import { computePreflight } from './preflight'

const caller = { projectId: 'p1', userId: 'owner-1' } as never

beforeEach(() => {
  h.model = ''
  h.own = []
  h.entitled = []
  h.entitledFails = false
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('hasModelKey with instance providers', () => {
  test('an instance model has a key while the owner may use its provider, and only then', async () => {
    h.model = 'instance/inst-1/gpt-5'
    h.entitled = [{ id: 'inst-1' }]
    const yes = await computePreflight(caller)
    expect(yes?.hasModelKey).toBe(true)
    expect(yes?.estimatedAiCalls).toBe(1)
    h.entitled = [{ id: 'inst-2' }]
    h.own = [{ providerType: 'openai', apiKey: 'sk-own' }]
    expect((await computePreflight(caller))?.hasModelKey).toBe(false)
  })

  test('the providers unreadable: no key (guidance only), logged', async () => {
    h.model = 'instance/inst-1/gpt-5'
    h.entitledFails = true
    expect((await computePreflight(caller))?.hasModelKey).toBe(false)
  })

  test('any other model keeps the rule before', async () => {
    h.model = 'gpt-5'
    h.entitled = [{ id: 'inst-1' }]
    expect((await computePreflight(caller))?.hasModelKey).toBe(false)
    h.own = [{ providerType: 'openai', apiKey: 'sk-own' }]
    expect((await computePreflight(caller))?.hasModelKey).toBe(true)
  })
})
