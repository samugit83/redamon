/**
 * Agent in the Loop on projects shared with the token's user (step 5.10, SH-43, SH-44): the project
 * list a driver sends the agent is "the projects where I may use the loop": the user's own, and,
 * only with the token's opt-in to shared projects (step 4.10, narrowed by its allowlist), those
 * shared with them where `agent:loop`'s level (W+A: Use AI agent, which counts only with the owner's
 * consent) holds through `projectAccess()`. The agent's broker serves only the steps of runs the
 * token's user started (`_claimable` matches the person; agentic/tests/test_loop_broker.py), so the
 * driver is always identified as that user, never the project's owner: another person's steps on a
 * shared project are never claimable. Approvals stay a person's: no loop tool answers one.
 *
 * Prisma, the agent client and the policy answer are doubled; the token rule, the level table and the
 * loop tools are real.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  owned: [] as Array<{ id: string; agentOpenaiModel: string }>,
  shared: [] as Array<{ id: string; agentOpenaiModel: string }>,
  findProjects: vi.fn(),
  wait: vi.fn(),
  get: vi.fn(),
  answer: vi.fn(),
  withShares: true,
  access: new Map<string, unknown>(),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findMany: (...a: unknown[]) => h.findProjects(...a) },
    conversation: { findFirst: async () => ({ id: 'c1' }) },
  },
}))
vi.mock('@/lib/mcp/loopClient', () => ({
  loopWait: (...a: unknown[]) => h.wait(...a),
  loopGet: (...a: unknown[]) => h.get(...a),
  loopAnswer: (...a: unknown[]) => h.answer(...a),
}))
vi.mock('@/lib/authz/visibleProjects', () => ({
  visibleProjects: async (subject: { userId: string }) => h.withShares
    ? { where: { OR: [{ userId: subject.userId }, { sharedWith: subject.userId }] }, withShares: true }
    : { where: { userId: subject.userId }, withShares: false },
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async (_subject: unknown, projectId: string) => h.access.get(projectId) ?? null,
}))

import { __resetRateLimiter, type McpScope, type ResolvedMcpToken } from '@/lib/mcpAuth'
import { loopGetStep, loopSubmitStep, loopWaitStep } from './loopTools'
import type { McpContext } from './tools'

const ME = 'collab'
const STEP = 'f'.repeat(32)
const share = (projectId: string, toggles: Record<string, boolean>, level: 'read' | 'write' = 'write', via = 'share') => ({
  project: { id: projectId, userId: 'owner' }, level, toggles: { rawData: level === 'write', ...toggles }, via,
})
const ctx = (sharedProjects: ResolvedMcpToken['sharedProjects'] = { allowlist: [] }): McpContext => ({
  token: { tokenId: 'tok-c', userId: ME, tokenPrefix: 'rdmn_mcp_cccccccc', name: 'laptop',
    scopes: ['agent:loop', 'recon:read'] as McpScope[], sharedProjects },
})

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  h.withShares = true
  h.owned = [{ id: 'mine', agentOpenaiModel: 'loop/mcp' }]
  h.shared = [
    { id: 'p-agent', agentOpenaiModel: 'loop/mcp' },
    { id: 'p-noagent', agentOpenaiModel: 'loop/mcp' },
    { id: 'p-read', agentOpenaiModel: 'loop/mcp' },
    { id: 'p-oversight', agentOpenaiModel: 'loop/mcp' },
  ]
  h.access = new Map<string, unknown>([
    ['p-agent', share('p-agent', { useAgent: true })],
    ['p-noagent', share('p-noagent', { useAgent: false, runScans: true, exploit: true, manage: true })],
    ['p-read', share('p-read', { rawData: true }, 'read')],
    ['p-oversight', share('p-oversight', {}, 'read', 'oversight')],
  ])
  h.findProjects.mockImplementation(async (args: { where: Record<string, unknown> }) =>
    'AND' in args.where ? h.shared : h.owned)
  h.wait.mockResolvedValue({ step: null, sessions: [] })
  h.get.mockResolvedValue({ step: { stepId: STEP } })
  h.answer.mockResolvedValue({ ok: true, projectId: 'p-agent', sessionId: 's', purpose: 'think', iteration: 1 })
})
afterEach(() => vi.unstubAllEnvs())

describe('project list by permission', () => {
  test("the user's own and the shared ones where Use AI agent holds; never a share without it, a read share or oversight", async () => {
    await loopWaitStep(ctx(), {})
    expect(h.wait.mock.calls[0][0].projectIds).toEqual(['mine', 'p-agent'])
  })

  test('the shared candidates are read through the visible-projects filter, not the owner filter, loop projects only', async () => {
    await loopWaitStep(ctx(), {})
    const where = h.findProjects.mock.calls[1][0].where
    expect(where.AND).toEqual([
      { OR: [{ userId: ME }, { sharedWith: ME }] },
      { NOT: { userId: ME } },
      { OR: [{ agentOpenaiModel: { startsWith: 'loop/' } }, { conversations: { some: { agentRunning: true } } }] },
    ])
  })

  test("the token's allowlist narrows the shared projects", async () => {
    await loopWaitStep(ctx({ allowlist: ['p-agent'] }), {})
    expect(h.findProjects.mock.calls[1][0].where.AND).toContainEqual({ id: { in: ['p-agent'] } })
  })

  test('a token that did not opt in sends its own projects only, and reads no share', async () => {
    await loopWaitStep(ctx(null), {})
    expect(h.findProjects).toHaveBeenCalledTimes(1)
    expect(h.wait.mock.calls[0][0].projectIds).toEqual(['mine'])
  })

  test('sharing not in force: own projects only', async () => {
    h.withShares = false
    await loopWaitStep(ctx(), {})
    expect(h.findProjects).toHaveBeenCalledTimes(1)
    expect(h.wait.mock.calls[0][0].projectIds).toEqual(['mine'])
  })

  test('a share whose Use AI agent is withdrawn leaves the list at the next call', async () => {
    await loopWaitStep(ctx(), {})
    h.access.set('p-agent', share('p-agent', { useAgent: false }))
    await loopWaitStep(ctx(), {})
    expect(h.wait.mock.calls.map((c) => c[0].projectIds)).toEqual([['mine', 'p-agent'], ['mine']])
  })

  test('only shared projects: the list still reaches the agent', async () => {
    h.owned = []
    await loopGetStep(ctx(), { stepId: STEP })
    expect(h.get.mock.calls[0][0].projectIds).toEqual(['p-agent'])
  })
})

describe('steps of another person never claimable', () => {
  test("the driver is the token's user on every call, never the shared project's owner", async () => {
    await loopWaitStep(ctx(), { driver: 'cc' })
    await loopGetStep(ctx(), { stepId: STEP, driver: 'cc' })
    await loopSubmitStep(ctx(), { stepId: STEP, answer: '{"action":"complete"}', driver: 'cc' })
    for (const call of [h.wait, h.get, h.answer]) {
      expect(call.mock.calls[0][0]).toMatchObject({ userId: ME, driverId: 'tok-c', projectIds: ['mine', 'p-agent'] })
      expect(call.mock.calls[0][0].userId).not.toBe('owner')
    }
  })
})
