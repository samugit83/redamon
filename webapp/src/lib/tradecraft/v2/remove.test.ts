/**
 * Deleting a 2.0 resource: its job cancelled first, then everything it holds (R-196).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from '../__testing__/tradecraftDb'
import { refused, stubAgent } from '../__testing__/agentDouble'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { setNowForTests } from '@/lib/authz/clock'
import { removeResourceV2 } from './remove'

const T0 = Date.parse('2026-11-16T10:00:00Z')

beforeEach(() => {
  h.db = createTradecraftDb()
  setNowForTests(() => new Date(T0))
  for (const id of ['r1', 'r2']) {
    h.db.seed('userTradecraftResource', { id, userId: 'owner', name: id, slug: id, url: `https://${id}.example.test/` })
    h.db.seed('tradecraftPageId', { id: `p-${id}`, resourceId: id, url: `https://${id}.example.test/a` })
    h.db.seed('tradecraftEntry', { id: `e-${id}`, userId: 'owner', resourceId: id, generation: 0, pageId: `p-${id}`, url: `https://${id}.example.test/a`, storedText: 't' })
    h.db.seed('tradecraftSection', { id: `s-${id}`, userId: 'owner', resourceId: id, entryId: `e-${id}`, ord: 0, text: 't' })
    h.db.seed('tradecraftCuration', { id: `c-${id}`, resourceId: id, url: `https://${id}.example.test/b`, blocked: true })
    h.db.seed('tradecraftProjectChoice', { projectId: 'p1', resourceId: id })
  }
  h.db.seed('tradecraftIngestionJob', { id: 'j-run', userId: 'owner', resourceId: 'r1', kind: 'refresh', status: 'running', leaseUntil: new Date(T0 + 30_000) })
  h.db.rows('userTradecraftResource', { id: 'r1' })[0].activeJobId = 'j-run'
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { setNowForTests(null); vi.restoreAllMocks() })

const left = (resourceId: string) => Object.fromEntries(
  ['tradecraftIngestionJob', 'tradecraftPageId', 'tradecraftEntry', 'tradecraftSection', 'tradecraftCuration', 'tradecraftProjectChoice']
    .map(t => [t, h.db.rows(t, { resourceId }).length]),
)

describe('removeResourceV2', () => {
  test('the running job is cancelled first, then the row and everything it holds go; the other resource keeps all', async () => {
    const agent = stubAgent()
    const res = await removeResourceV2({ ownerId: 'owner', resourceId: 'r1' })
    expect(await res.json()).toEqual({ success: true, cancelledJob: 'j-run' })
    expect(agent.calls.map(c => c.path)).toEqual(['/tradecraft/v2/jobs/j-run/cancel'])
    const cancelAt = h.db.calls.indexOf('tradecraftIngestionJob.update')
    expect(cancelAt).toBeGreaterThanOrEqual(0)
    expect(cancelAt).toBeLessThan(h.db.calls.indexOf('userTradecraftResource.deleteMany'))
    expect(h.db.rows('userTradecraftResource', { id: 'r1' })).toHaveLength(0)
    expect(left('r1')).toEqual({ tradecraftIngestionJob: 0, tradecraftPageId: 0, tradecraftEntry: 0, tradecraftSection: 0, tradecraftCuration: 0, tradecraftProjectChoice: 0 })
    expect(left('r2')).toEqual({ tradecraftIngestionJob: 0, tradecraftPageId: 1, tradecraftEntry: 1, tradecraftSection: 1, tradecraftCuration: 1, tradecraftProjectChoice: 1 })
  })

  test('an agent that cannot be told still loses the resource: the flag and the cascade suffice', async () => {
    stubAgent(() => refused())
    expect((await removeResourceV2({ ownerId: 'owner', resourceId: 'r1' })).status).toBe(200)
    expect(h.db.rows('userTradecraftResource', { id: 'r1' })).toHaveLength(0)
  })

  test("another account's resource: 404, nothing deleted, nothing cancelled", async () => {
    const agent = stubAgent()
    expect((await removeResourceV2({ ownerId: 'other', resourceId: 'r1' })).status).toBe(404)
    expect(h.db.rows('userTradecraftResource')).toHaveLength(2)
    expect(h.db.rows('tradecraftIngestionJob', { id: 'j-run' })[0].cancelRequested).toBe(false)
    expect(agent.calls).toHaveLength(0)
  })
})
