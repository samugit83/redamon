/**
 * `/api/triage/preflight` reads the project's real review budget and the
 * owner's "Triage review" model. A budget above 0 with no model answers
 * `model_required` (the run dialog opens the picker); budget 0 needs no model.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockProject = vi.fn()
const mockSettings = vi.fn()
const mockProviders = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overProjectOwner()))
vi.mock('@/lib/triageClient', () => ({
  requireProjectOwner: async (projectId: string) => ({ userId: 'alice', projectId }),
}))
const mockAgentTriage = vi.hoisted(() => vi.fn())
vi.mock('@/lib/triage/actions', () => {
  class TriageActionError extends Error {
    constructor(message: string, public readonly code: string, public readonly status = 500) { super(message) }
  }
  return { agentTriage: (...a: unknown[]) => mockAgentTriage(...a), TriageActionError }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProject(...a) },
    userSettings: { findUnique: (...a: unknown[]) => mockSettings(...a) },
    triageRun: { findFirst: async () => null },
    remediation: { groupBy: async () => [] },
    userLlmProvider: { findMany: (...a: unknown[]) => mockProviders(...a) },
  },
}))
vi.mock('@/lib/triageRun', () => ({
  findLiveTriageRun: async () => null,
  mcpRunBudget: async () => ({ runsToday: 0, nextAllowedAt: null, reason: null }),
  MCP_RUNS_PER_DAY: 12,
}))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: async () => false }))
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: async () => null }))

import { GET } from './route'

const get = () => GET(new NextRequest('http://x/api/triage/preflight?projectId=p1'))

function project(budget: number) {
  mockProject.mockResolvedValue({ name: 'P', userId: 'alice', cypherfixDefaultRepo: '', triageReviewBudget: budget })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockAgentTriage.mockResolvedValue({ in_scope: 40, reviewable: 30 })
  mockSettings.mockResolvedValue({ featureModels: { triage: 'gpt-5-mini' } })
  mockProviders.mockResolvedValue([{ providerType: 'openai', apiKey: 'sk' }])
})

describe('preflight and the Triage review model', () => {
  test('the budget is selected from the project, not hardcoded', async () => {
    project(25)
    const body = await (await get()).json()
    expect(mockProject.mock.calls[0][0].select.triageReviewBudget).toBe(true)
    expect(body.reviewBudget).toBe(25)
    expect(body.estimatedReviewed).toBe(25)
  })

  test('the model is the owner\'s triage model', async () => {
    project(25)
    const body = await (await get()).json()
    expect(body.model).toBe('gpt-5-mini')
    expect(mockSettings.mock.calls[0][0]).toMatchObject({ where: { userId: 'alice' } })
  })

  test('a budget with no model is model_required', async () => {
    project(150)
    mockSettings.mockResolvedValue(null)
    const res = await get()
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'model_required', featureId: 'triage' })
  })

  test('a stored budget above the run\'s ceiling is reported as what will run (U10)', async () => {
    project(5000)
    const body = await (await get()).json()
    expect(body.reviewBudget).toBe(1000)
  })

  test('budget 0 with no model is allowed and estimates no AI calls', async () => {
    project(0)
    mockSettings.mockResolvedValue(null)
    const res = await get()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.model).toBe('')
    expect(body.estimatedAiCalls).toBe(0)
  })
})

describe('preflight and a TypeSafe Jev token', () => {
  test('a Jev key alone is not a model key: no AI calls are estimated', async () => {
    project(25)
    mockProviders.mockResolvedValue([{ providerType: 'jev', apiKey: 'apikey_x_y' }])
    const body = await (await get()).json()
    expect(body.hasModelKey).toBe(false)
    expect(body.estimatedAiCalls).toBe(0)
  })

  test('a chat key next to the Jev key still counts', async () => {
    project(25)
    mockProviders.mockResolvedValue([
      { providerType: 'jev', apiKey: 'apikey_x_y' }, { providerType: 'openai', apiKey: 'sk' },
    ])
    const body = await (await get()).json()
    expect(body.hasModelKey).toBe(true)
  })
})

describe('a preflight that cannot be answered says why (G-31, G-32)', () => {
  test('counts the agent could not give are flagged, not presented as zero', async () => {
    project(25)
    const { TriageActionError } = await import('@/lib/triage/actions')
    mockAgentTriage.mockRejectedValue(new TriageActionError('The findings service is unavailable.', 'agent_unreachable', 503))
    const body = await (await get()).json()
    expect(body.countsUnavailable).toBe('agent_unreachable')
    expect(body.inScope).toBe(0)
  })

  test('readable counts carry no flag', async () => {
    project(25)
    expect((await (await get()).json()).countsUnavailable).toBeNull()
  })

  test('a database failure answers a fixed text and its code, not an empty 500', async () => {
    mockProject.mockRejectedValue(Object.assign(new Error('Cannot reach database at db:5432 for project p1'),
      { code: 'P1001' }))
    const res = await get()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'The project could not be checked.', code: 'P1001' })
  })
})
