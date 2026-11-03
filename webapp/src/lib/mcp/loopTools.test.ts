/**
 * The Agent in the Loop MCP tool bodies.
 *
 * What is pinned: the check order (scope, switch, the owned-projects read, the
 * driver-token rule, arguments, rate), that the agent only ever receives the
 * caller's own projects and identity, and that no refusal reaches the agent.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProjects: vi.fn(),
  findConversation: vi.fn(),
  wait: vi.fn(),
  get: vi.fn(),
  answer: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findMany: (...a: unknown[]) => h.findProjects(...a) },
    conversation: { findFirst: (...a: unknown[]) => h.findConversation(...a) },
  },
}))
vi.mock('@/lib/mcp/loopClient', () => ({
  loopWait: (...a: unknown[]) => h.wait(...a),
  loopGet: (...a: unknown[]) => h.get(...a),
  loopAnswer: (...a: unknown[]) => h.answer(...a),
}))

import { McpScopeError, __resetRateLimiter, type McpScope } from '@/lib/mcpAuth'
import { MAX_LOOP_PROJECT_IDS, loopGetStep, loopSubmitStep, loopWaitStep } from './loopTools'
import { loopTokenProblem } from './loopScopes'
import type { McpContext } from './tools'

const STEP = 'f'.repeat(32)
const ctx = (scopes: string[] = ['agent:loop', 'recon:read']): McpContext => ({
  token: { tokenId: 'tok1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa', name: 'laptop',
    scopes: scopes as McpScope[] },
})
const view = { stepId: STEP, projectId: 'p1', sessionId: 'session_a', purpose: 'think' }

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  h.findProjects.mockResolvedValue([
    { id: 'p1', agentOpenaiModel: 'loop/mcp' },
    { id: 'p2', agentOpenaiModel: 'claude-opus-4-6' },
  ])
  h.findConversation.mockResolvedValue({ id: 'c1' })
  h.wait.mockResolvedValue({ step: view, sessions: [], hint: 'Answer this step' })
  h.get.mockResolvedValue({ step: view })
  h.answer.mockResolvedValue({ ok: true, projectId: 'p1', sessionId: 'session_a', purpose: 'think', iteration: 2 })
})

afterEach(() => vi.unstubAllEnvs())

const noAgentCall = () => {
  expect(h.wait).not.toHaveBeenCalled()
  expect(h.get).not.toHaveBeenCalled()
  expect(h.answer).not.toHaveBeenCalled()
}

describe('the project list sent to the agent', () => {
  test('only projects a loop run can be in: on a loop model, or with a chat running', async () => {
    await loopWaitStep(ctx(), {})
    const where = h.findProjects.mock.calls[0][0].where
    expect(where.userId).toBe('owner')
    expect(where.OR).toEqual([
      { agentOpenaiModel: { startsWith: 'loop/' } },
      { conversations: { some: { agentRunning: true } } },
    ])
    expect(h.wait.mock.calls[0][0].projectIds).toEqual(['p1', 'p2'])
  })

  test('more projects than the agent accepts is a clear refusal, never an opaque 422', async () => {
    h.findProjects.mockResolvedValue(
      Array.from({ length: MAX_LOOP_PROJECT_IDS + 1 }, (_, i) => ({ id: `p${i}`, agentOpenaiModel: 'loop/mcp' })))
    await expect(loopWaitStep(ctx(), {})).rejects.toMatchObject({ code: 'too_many_loop_projects' })
    expect(h.findProjects.mock.calls[0][0].take).toBe(MAX_LOOP_PROJECT_IDS + 1)
    noAgentCall()
  })
})

describe('refusals before the agent', () => {
  test('a token without agent:loop', async () => {
    await expect(loopWaitStep(ctx(['recon:read']), {})).rejects.toBeInstanceOf(McpScopeError)
    await expect(loopWaitStep(ctx(['recon:read']), {})).rejects.toThrow(/agent:loop/)
    noAgentCall()
  })

  test('the switch off', async () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'false')
    await expect(loopWaitStep(ctx(), {})).rejects.toMatchObject({ code: 'disabled' })
    noAgentCall()
  })

  test('a token that can also write or exec names the extra scopes', async () => {
    const err = await loopWaitStep(ctx(['agent:loop', 'recon:read', 'kali:exec', 'recon:scan']), {})
      .catch((e) => e)
    expect(err.code).toBe('loop_token_too_broad')
    expect(err.message).toMatch(/kali:exec, recon:scan/)
    noAgentCall()
  })

  test('a token with an unknown scope fails closed', async () => {
    const err = await loopGetStep(ctx(['agent:loop', 'made:up']), { stepId: STEP }).catch((e) => e)
    expect(err.code).toBe('loop_token_too_broad')
    noAgentCall()
  })

  test('a foreign or unknown sessionId', async () => {
    h.findConversation.mockResolvedValue(null)
    await expect(loopWaitStep(ctx(), { sessionId: 'session_x' })).rejects.toMatchObject({ code: 'not_found' })
    expect(h.findConversation).toHaveBeenCalledWith(expect.objectContaining({
      where: { sessionId: 'session_x', userId: 'owner' } }))
    noAgentCall()
  })

  test('a user with no project at all gets the hint, not the agent', async () => {
    h.findProjects.mockResolvedValue([])
    const out = await loopWaitStep(ctx(), {})
    expect(out).toEqual({ step: null, sessions: [], hint: expect.stringMatching(/No project of yours uses Agent in the Loop/) })
    await expect(loopGetStep(ctx(), { stepId: STEP })).rejects.toMatchObject({ code: 'not_found' })
    await expect(loopSubmitStep(ctx(), { stepId: STEP, answer: 'x' })).rejects.toMatchObject({ code: 'step_closed' })
    noAgentCall()
  })
})

describe('what reaches the agent', () => {
  test('the owned project ids, the token identity, and the driver name', async () => {
    await loopWaitStep(ctx(), { driver: 'cc-amber', waitSeconds: 30 })
    expect(h.findProjects.mock.calls[0][0]).toMatchObject({ where: { userId: 'owner' },
      select: { id: true, agentOpenaiModel: true } })
    expect(h.wait).toHaveBeenCalledWith({
      userId: 'owner', driverId: 'tok1', driverName: 'cc-amber', projectIds: ['p1', 'p2'],
      sessionId: undefined, waitSeconds: 30, delivery: 'dedup',
    })
  })

  test('no driver name forces full delivery', async () => {
    await loopWaitStep(ctx(), { delivery: 'dedup' })
    expect(h.wait.mock.calls[0][0]).toMatchObject({ delivery: 'full', driverName: undefined, waitSeconds: 50 })
  })

  test('a deleted project is simply absent from the ids', async () => {
    h.findProjects.mockResolvedValue([{ id: 'p2', agentOpenaiModel: 'loop/mcp' }])
    await loopGetStep(ctx(), { stepId: STEP, cursor: 40000, full: true, driver: 'cc' })
    expect(h.get).toHaveBeenCalledWith({ userId: 'owner', driverId: 'tok1', driverName: 'cc',
      projectIds: ['p2'], stepId: STEP, cursor: 40000, full: true })
  })

  test('the answer carries the display prefix and name, never the token', async () => {
    const out = await loopSubmitStep(ctx(), { stepId: STEP, answer: '{"action":"complete"}', driver: 'cc' })
    expect(out.projectId).toBe('p1')
    const sent = h.answer.mock.calls[0][0]
    expect(sent).toMatchObject({ answer: '{"action":"complete"}', projectIds: ['p1', 'p2'],
      answeredBy: { tokenPrefix: 'rdmn_mcp_aaaaaaaa', tokenName: 'laptop' } })
    expect(sent).not.toHaveProperty('declined')
  })

  test('a decline carries the reason and no answer', async () => {
    await loopSubmitStep(ctx(), { stepId: STEP, declined: true, reason: 'out of scope' })
    expect(h.answer.mock.calls[0][0]).toMatchObject({ declined: true, reason: 'out of scope' })
    expect(h.answer.mock.calls[0][0]).not.toHaveProperty('answer')
  })
})

describe('the hint when no project uses the loop', () => {
  beforeEach(() => h.findProjects.mockResolvedValue([{ id: 'p2', agentOpenaiModel: 'gpt-5' }]))

  test('nothing came back: the hint says why', async () => {
    h.wait.mockResolvedValue({ step: null, sessions: [], hint: 'No RedAmon chat' })
    const out = await loopWaitStep(ctx(), {})
    expect(out.hint).toMatch(/No project of yours uses Agent in the Loop/)
  })

  test('a step of a project switched away mid-turn is still served', async () => {
    const out = await loopWaitStep(ctx(), {})
    expect(out.step).toEqual(view)
    expect(out.hint).toBe('Answer this step')
  })
})

describe('submit arguments', () => {
  test.each([
    [{ stepId: STEP }],
    [{ stepId: STEP, answer: 'x', declined: true }],
    [{ stepId: STEP, answer: '   ' }],
    [{ stepId: STEP, declined: true, reason: 'r'.repeat(301) }],
  ])('%j is bad_args', async (input) => {
    await expect(loopSubmitStep(ctx(), input)).rejects.toMatchObject({ code: 'bad_args' })
    noAgentCall()
  })

  test('an oversized answer is refused before the agent', async () => {
    await expect(loopSubmitStep(ctx(), { stepId: STEP, answer: 'x'.repeat(262_145) }))
      .rejects.toMatchObject({ code: 'answer_too_large' })
    noAgentCall()
  })

  test('a malformed step id', async () => {
    await expect(loopSubmitStep(ctx(), { stepId: 'nope', answer: 'x' })).rejects.toMatchObject({ code: 'step_closed' })
    await expect(loopGetStep(ctx(), { stepId: 'nope' })).rejects.toMatchObject({ code: 'not_found' })
    noAgentCall()
  })
})

describe('the rate bucket', () => {
  test('rate_limited once the loop bucket is spent', async () => {
    vi.stubEnv('MCP_RATE_LOOP_PER_MIN', '2')
    await loopGetStep(ctx(), { stepId: STEP })
    await loopGetStep(ctx(), { stepId: STEP })
    await expect(loopGetStep(ctx(), { stepId: STEP })).rejects.toMatchObject({ code: 'rate_limited' })
    expect(h.get).toHaveBeenCalledTimes(2)
  })
})

describe('loopTokenProblem', () => {
  test.each([
    [['agent:loop', 'recon:read'], []],
    [['agent:loop', 'recon:read', 'triage:read', 'graph:cypher'], []],
    [['agent:loop', 'kali:exec'], ['kali:exec']],
    [['agent:loop', 'recon:scan', 'triage:mute'], ['recon:scan', 'triage:mute']],
    [['agent:loop', 'made:up'], ['made:up']],
  ])('%j -> %j', (scopes, expected) => {
    expect(loopTokenProblem(scopes)).toEqual(expected)
  })
})
