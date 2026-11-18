/**
 * cancelUserTradecraftJobs: the flag on every unfinished job of the account, then one call to
 * the agent; never throws.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'
import { json, refused, stubAgent } from './__testing__/agentDouble'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { cancelUserTradecraftJobs } from './deleteCleanup'

const flagged = () => h.db.rows('tradecraftIngestionJob', { cancelRequested: true }).map(j => j.id).sort()

beforeEach(() => {
  h.db = createTradecraftDb()
  for (const [id, userId, status] of [['a1', 'alice', 'queued'], ['a2', 'alice', 'running'], ['a3', 'alice', 'cancelled'], ['b1', 'bob', 'running']]) {
    h.db.seed('tradecraftIngestionJob', { id, userId, kind: 'refresh', status })
  }
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('cancelUserTradecraftJobs', () => {
  test("flags the account's unfinished jobs only, then asks the agent once", async () => {
    const agent = stubAgent((path) => json({ cancelled: path.endsWith('/alice/cancel') ? 2 : 0 }))
    expect(await cancelUserTradecraftJobs('alice')).toEqual({ flagged: 2, agent: 2 })
    expect(flagged()).toEqual(['a1', 'a2'])
    expect(agent.calls.map(c => c.path)).toEqual(['/tradecraft/v2/users/alice/cancel'])
  })

  test('twice (two deletes, a disable then a delete): nothing breaks, the flags stay', async () => {
    stubAgent()
    await cancelUserTradecraftJobs('alice')
    expect((await cancelUserTradecraftJobs('alice')).flagged).toBe(2)
    expect(flagged()).toEqual(['a1', 'a2'])
  })

  test('nothing unfinished: the agent is not asked', async () => {
    const agent = stubAgent()
    expect(await cancelUserTradecraftJobs('nobody')).toEqual({ flagged: 0, agent: 0 })
    expect(agent.calls).toEqual([])
  })

  test.each([
    ['unreachable', () => refused(), 'agent_unreachable'],
    ['an error answer', () => json({ detail: 'x' }, 500), 'agent_http_500'],
    ['an answer the contract does not know', () => json({ ok: true }), 'agent_bad_answer'],
  ])('the agent %s: reported and logged with its code, never raised', async (_name, answer, code) => {
    stubAgent(answer)
    expect(await cancelUserTradecraftJobs('alice')).toEqual({ flagged: 2, agent: { error: code } })
    const logged = (console.error as unknown as { mock: { calls: unknown[][] } }).mock.calls.flat().join(' ')
    expect(logged).toContain(`[tradecraft] user_cancel_agent_failed user=alice code=${code}`)
  })

  test('a flag that cannot be written is reported and logged; the agent is not asked', async () => {
    const agent = stubAgent()
    h.db.failNext('tradecraftIngestionJob.updateMany', Object.assign(new Error('db down'), { code: 'P1001' }))
    expect(await cancelUserTradecraftJobs('alice')).toEqual({ flagged: { error: 'P1001' }, agent: 0 })
    expect(agent.calls).toHaveLength(0)
    const logged = (console.error as unknown as { mock: { calls: unknown[][] } }).mock.calls.flat().join(' ')
    expect(logged).toContain('[tradecraft] user_cancel_flag_failed user=alice code=P1001')
  })
})
