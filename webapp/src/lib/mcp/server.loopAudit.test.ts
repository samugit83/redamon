/**
 * What the Agent in the Loop tools leave in the audit log, through the real MCP
 * server.
 *
 * An idle driver polls loop_wait_step about seventy times an hour, so an idle
 * poll writes NO row; a claim and an answer each write one, filed under the
 * step's project with the step's ids. An answer is the agent's next decision
 * and a reason or a driver name is a client's free text: none of them may reach
 * a row, which is also printed as a console line.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ audit: vi.fn(), wait: vi.fn(), get: vi.fn(), answer: vi.fn() }))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findMany: async () => [{ id: 'p1', agentOpenaiModel: 'loop/mcp' }] },
    conversation: { findFirst: async () => ({ id: 'c1' }) },
    mcpAccessToken: { update: () => Promise.resolve() },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/mcp/loopClient', () => ({
  loopWait: (...a: unknown[]) => h.wait(...a),
  loopGet: (...a: unknown[]) => h.get(...a),
  loopAnswer: (...a: unknown[]) => h.answer(...a),
}))

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'

import { __resetRateLimiter, type McpScope } from '@/lib/mcpAuth'
import { buildMcpServer } from './server'

const STEP = 'b'.repeat(32)
const MARKERS = /ANSWER-MARKER|REASON-MARKER|DRIVER-MARKER/
const STEP_VIEW = { stepId: STEP, projectId: 'p1', sessionId: 'session_a', purpose: 'think',
  iteration: 3, prompt: 'PROMPT-MARKER', page: { cursor: 0, nextCursor: null, totalChars: 13 } }

async function call(name: string, args: Record<string, unknown>, scopes: string[] = ['agent:loop', 'recon:read']) {
  const server = buildMcpServer({ token: { tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'driver', scopes: scopes as McpScope[] } })
  const client = new Client({ name: 'loop-audit-test', version: '1.0.0' }, { capabilities: {} })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  try {
    const result = await client.callTool({ name, arguments: args })
    await new Promise((resolve) => setTimeout(resolve, 0))
    return result
  } finally {
    await client.close()
    await server.close()
  }
}

const rows = (action: string) => h.audit.mock.calls
  .map((c) => c[0] as Record<string, unknown>)
  .filter((r) => r.action === action)

let logs: string[]

beforeEach(() => {
  vi.clearAllMocks()
  __resetRateLimiter()
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  logs = []
  for (const level of ['log', 'info', 'warn', 'error'] as const) {
    vi.spyOn(console, level).mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')) })
  }
  h.wait.mockResolvedValue({ step: null, sessions: [], hint: 'RedAmon is preparing the next step' })
  h.get.mockResolvedValue({ step: STEP_VIEW })
  h.answer.mockResolvedValue({ ok: true, projectId: 'p1', sessionId: 'session_a', purpose: 'think', iteration: 3 })
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
})

describe('mcp.loop_* audit rows', () => {
  test('an idle wait writes no row', async () => {
    const result = await call('loop_wait_step', { driver: 'DRIVER-MARKER', waitSeconds: 1 })
    expect(result.isError).toBeFalsy()
    expect(rows('mcp.loop_wait_step')).toEqual([])
  })

  test('a claim writes one row under the step project, with ids and no text', async () => {
    h.wait.mockResolvedValue({ step: STEP_VIEW, sessions: [], hint: 'Answer this step' })
    await call('loop_wait_step', { driver: 'DRIVER-MARKER', waitSeconds: 1 })
    const [row, ...more] = rows('mcp.loop_wait_step')
    expect(more).toEqual([])
    expect(row.targetType).toBe('project')
    expect(row.targetId).toBe('p1')
    expect(row.after).toMatchObject({ outcome: 'ok', stepId: STEP, sessionId: 'session_a',
      purpose: 'think', iteration: 3 })
    expect(JSON.stringify(row)).not.toMatch(/DRIVER-MARKER|PROMPT-MARKER/)
  })

  test('a page read writes no row', async () => {
    await call('loop_get_step', { stepId: STEP, driver: 'DRIVER-MARKER' })
    expect(rows('mcp.loop_get_step')).toEqual([])
  })

  test('an answer writes one row and never the answer', async () => {
    const result = await call('loop_submit_step', { stepId: STEP, answer: '{"x":"ANSWER-MARKER"}',
      driver: 'DRIVER-MARKER' })
    expect(result.isError).toBeFalsy()
    const [row] = rows('mcp.loop_submit_step')
    expect(row.targetType).toBe('project')
    expect(row.targetId).toBe('p1')
    expect(row.after).toMatchObject({ outcome: 'ok', stepId: STEP, sessionId: 'session_a', purpose: 'think' })
    expect(JSON.stringify(h.audit.mock.calls)).not.toMatch(MARKERS)
    expect(logs.join('\n')).not.toMatch(MARKERS)
  })

  test('a decline writes one row and never the reason', async () => {
    await call('loop_submit_step', { stepId: STEP, declined: true, reason: 'REASON-MARKER out of scope' })
    expect(rows('mcp.loop_submit_step')).toHaveLength(1)
    expect(JSON.stringify(h.audit.mock.calls)).not.toMatch(MARKERS)
  })

  test('a refusal is always audited, even for an idle-shaped call', async () => {
    const result = await call('loop_wait_step', { waitSeconds: 1 }, ['agent:loop', 'kali:exec'])
    expect(result.isError).toBe(true)
    const [row] = rows('mcp.loop_wait_step')
    expect(row.after).toMatchObject({ outcome: 'loop_token_too_broad' })
    expect(h.wait).not.toHaveBeenCalled()
  })

  test('another tool still writes one row per call (regression)', async () => {
    await call('list_projects', {}, ['recon:read'])
    expect(rows('mcp.list_projects')).toHaveLength(1)
  })
})
