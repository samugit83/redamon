/**
 * Integration test for the server-side model-guard in POST /api/projects.
 *
 * Run: npx vitest run "src/app/api/projects/route.modelGuard.integration.test.ts"
 *
 * Exercises the real route handler (real Prisma DMMF-based sanitizer + real
 * isBlankModelField) with prisma and Neo4j mocked. Proves the regression fix:
 * a blank agentOpenaiModel/aiPipelineModel is DROPPED on create so the schema
 * @default("claude-opus-4-6") applies, instead of persisting "" — the
 * server-side backstop for the client model-gate.
 *
 * Uses ipMode:true (skips targetDomain requirement + the Neo4j Domain node) and
 * targetGuardrailEnabled:false (skips the soft-guardrail fetch) to keep the
 * handler's collaborators minimal.
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const mockUserFindUnique = vi.fn()
const mockProjectCreate = vi.fn()
const mockProjectUpdate = vi.fn()
const mockGetSession = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => mockUserFindUnique(...a) },
    project: {
      create: (...a: unknown[]) => mockProjectCreate(...a),
      update: (...a: unknown[]) => mockProjectUpdate(...a),
    },
  },
}))

// Neo4j session — not reached in ipMode, but mocked so the import resolves.
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: (...a: unknown[]) => mockGetSession(...a),
}))

// Effective-user guard — ownership is exercised in the dedicated BOLA tests; here
// we return the same owner the test expects so it stays focused on the model guard.
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { POST } from './route'

function postReq(body: Record<string, unknown>) {
  return new Request('http://localhost/api/projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }) as never
}

const BASE = {
  userId: 'user-1',
  name: 'Test Project',
  ipMode: true,
  targetGuardrailEnabled: false,
}

beforeEach(() => {
  mockUserFindUnique.mockReset()
  mockProjectCreate.mockReset()
  mockProjectUpdate.mockReset()
  mockGetSession.mockReset()
  mockUserFindUnique.mockResolvedValue({ id: 'user-1' })
  // Echo the create data back as the created project.
  mockProjectCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({
    id: 'proj-1',
    ...data,
  }))
})

function createdData() {
  expect(mockProjectCreate).toHaveBeenCalledTimes(1)
  return mockProjectCreate.mock.calls[0][0].data as Record<string, unknown>
}

describe('POST /api/projects — model-field guard', () => {
  test('REGRESSION: blank agentOpenaiModel is dropped (schema default applies)', async () => {
    const res = await POST(postReq({ ...BASE, agentOpenaiModel: '' }))
    expect(res.status).toBe(201)
    expect('agentOpenaiModel' in createdData()).toBe(false)
  })

  test('REGRESSION: blank aiPipelineModel is dropped', async () => {
    const res = await POST(postReq({ ...BASE, aiPipelineModel: '   ' }))
    expect(res.status).toBe(201)
    expect('aiPipelineModel' in createdData()).toBe(false)
  })

  test('REGRESSION: both blank models dropped together', async () => {
    await POST(postReq({ ...BASE, agentOpenaiModel: '', aiPipelineModel: '' }))
    const data = createdData()
    expect('agentOpenaiModel' in data).toBe(false)
    expect('aiPipelineModel' in data).toBe(false)
  })

  test('a real agent model IS persisted', async () => {
    await POST(postReq({ ...BASE, agentOpenaiModel: 'deepseek/deepseek-chat' }))
    expect(createdData().agentOpenaiModel).toBe('deepseek/deepseek-chat')
  })

  test('a real pipeline model IS persisted', async () => {
    await POST(postReq({ ...BASE, aiPipelineModel: 'deepseek/deepseek-reasoner' }))
    expect(createdData().aiPipelineModel).toBe('deepseek/deepseek-reasoner')
  })

  test('mixed: real agent model kept, blank pipeline dropped', async () => {
    await POST(
      postReq({ ...BASE, agentOpenaiModel: 'deepseek/deepseek-chat', aiPipelineModel: '' }),
    )
    const data = createdData()
    expect(data.agentOpenaiModel).toBe('deepseek/deepseek-chat')
    expect('aiPipelineModel' in data).toBe(false)
  })
})

describe('Agent in the Loop on create', () => {
  afterEach(() => vi.unstubAllEnvs())

  test('a loop agent model is saved from the UI while the switch is on', async () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
    await POST(postReq({ ...BASE, agentOpenaiModel: 'loop/mcp' }))
    expect(createdData().agentOpenaiModel).toBe('loop/mcp')
  })

  test('a loop agent model is refused while the switch is off', async () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'false')
    const res = await POST(postReq({ ...BASE, agentOpenaiModel: 'loop/mcp' }))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'Agent in the Loop is turned off on this deployment.',
      code: 'loop_model_not_allowed' })
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('a loop pipeline model is always refused', async () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
    const res = await POST(postReq({ ...BASE, aiPipelineModel: 'loop/mcp' }))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('loop_model_not_allowed')
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })
})
