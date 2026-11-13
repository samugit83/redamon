/**
 * start_triage_run and stop_triage_run on a project shared with the token's user (step 5.10; the
 * 5.2b pending: "the owner's alone until the run records its person"). Both ask triage:run's level,
 * W+A (Use AI agent, which counts only with the owner's consent), through the token's rule (step 4.10
 * opt-in). The run reads the owner's graph (the tenant) and names the token's user as its person
 * (`actor_user_id`), whom the webapp checks again and records as spending the owner's model when the
 * agent reports the start (internal/triage-runs, step 5.6). The owner's start is unchanged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  access: null as unknown,
  startRun: vi.fn(),
  stopRun: vi.fn(),
  liveRun: vi.fn(),
  budget: vi.fn(),
  preflight: vi.fn(),
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async () => h.access,
}))
vi.mock('@/lib/mcp/tools', async (orig) => ({ ...(await orig<typeof import('./tools')>()), enforceRate: () => {} }))
vi.mock('@/lib/triage/actions', async (orig) => ({
  ...(await orig<typeof import('@/lib/triage/actions')>()),
  startRun: (...a: unknown[]) => h.startRun(...a),
  stopRun: (...a: unknown[]) => h.stopRun(...a),
}))
vi.mock('@/lib/triage/preflight', () => ({
  computePreflight: (...a: unknown[]) => h.preflight(...a),
  MAX_REVIEW_BUDGET: 1000,
  RUN_BLOCKS: [],
}))
vi.mock('@/lib/triageRun', () => ({
  findLiveTriageRun: (...a: unknown[]) => h.liveRun(...a),
  latestTriageRuns: async () => [],
  mcpRunBudget: (...a: unknown[]) => h.budget(...a),
  MCP_RUN_COOLDOWN_MS: 30 * 60 * 1000,
  MCP_RUNS_PER_DAY: 12,
}))

import { McpAccessDenied, McpLevelDenied } from '@/lib/mcpAuth'
import { startTriageRun, stopTriageRun } from './triageTools'
import type { McpContext } from './tools'

const P = 'p1'
const tokenOf = (userId: string, sharedProjects: { allowlist: string[] } | null = { allowlist: [] }): McpContext => ({
  token: { tokenId: `tok-${userId}`, userId, tokenPrefix: 'rdmn_mcp_0a1b2c3d', name: 'agent', scopes: ['triage:run'] as never, sharedProjects },
})
const access = (level: 'owner' | 'write' | 'read', toggles: Record<string, boolean> = {}, via = level === 'owner' ? 'owner' : 'share') => ({
  project: { id: P, userId: 'owner' }, level, toggles: { rawData: level !== 'read', ...toggles }, via,
})

beforeEach(() => {
  vi.clearAllMocks()
  h.access = access('write', { useAgent: true })
  h.liveRun.mockResolvedValue(null)
  h.budget.mockResolvedValue({ reason: null, runsToday: 0, nextAllowedAt: null })
  h.preflight.mockResolvedValue({ model: 'openai/m', reviewBudget: 10, liveRun: null, blockedReason: null })
  h.startRun.mockResolvedValue({ runId: 'run-1', attached: false })
  h.stopRun.mockResolvedValue({ stopped: true, runId: 'run-0' })
})

describe('a collaborator with Use AI agent', () => {
  test("starts a run on the owner's graph that names them as its person", async () => {
    h.access = access('write', { useAgent: true })
    const out = await startTriageRun(tokenOf('collab'), P)
    expect(out).toMatchObject({ projectId: P, runId: 'run-1' })
    expect(h.preflight).toHaveBeenCalledWith({ userId: 'owner', projectId: P }, 'mcp')
    expect(h.startRun).toHaveBeenCalledWith({ userId: 'owner', projectId: P }, {
      trigger: 'mcp', tokenId: 'tok-collab', maxReviewBudget: 1000, actorUserId: 'collab',
    })
  })

  test("stops the project's run", async () => {
    h.liveRun.mockResolvedValue({ id: 'run-0', status: 'running', trigger: 'app' })
    expect(await stopTriageRun(tokenOf('collab'), P)).toMatchObject({ stopped: true })
    expect(h.stopRun).toHaveBeenCalledWith({ userId: 'owner', projectId: P }, 'mcp')
  })
})

describe('below W+A', () => {
  test.each([
    ['Read + Write without Use AI agent', access('write', { runScans: true, exploit: true, manage: true }), McpLevelDenied],
    ['a read share', access('read', { rawData: true }), McpLevelDenied],
    ['oversight', access('read', {}, 'oversight'), McpAccessDenied],
  ])('%s: refused before any run state is read or a run starts or stops', async (_what, reached, kind) => {
    h.access = reached
    await expect(startTriageRun(tokenOf('collab'), P)).rejects.toBeInstanceOf(kind)
    await expect(stopTriageRun(tokenOf('collab'), P)).rejects.toBeInstanceOf(kind)
    expect(h.liveRun).not.toHaveBeenCalled()
    expect(h.startRun).not.toHaveBeenCalled()
    expect(h.stopRun).not.toHaveBeenCalled()
  })

  test('a token that did not opt in to shared projects: not found', async () => {
    await expect(startTriageRun(tokenOf('collab', null), P)).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.startRun).not.toHaveBeenCalled()
  })
})

describe("the owner's start", () => {
  test('is unchanged: no person beside the tenant is sent', async () => {
    h.access = access('owner')
    await startTriageRun(tokenOf('owner', null), P)
    expect(h.startRun).toHaveBeenCalledWith({ userId: 'owner', projectId: P }, { trigger: 'mcp', tokenId: 'tok-owner', maxReviewBudget: 1000 })
  })
})
