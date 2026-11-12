/**
 * One active job per (plugin, action, user, session) is enforced by the database, not by a
 * read-then-create (TD-22, RV-22, R-21): the job is created under a lock row whose insert
 * fails on the unique index when a job is already active. Two first clicks at once make
 * one job; a lock left behind by a job that ended or never existed is replaced.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown> }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSessionEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  getEffectiveUser: async () => ({ userId: 'user-alice' }),
  getSession: async () => ({ userId: 'user-alice', role: 'standard' }),
}))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ALICE, ALICE_PROJECT, ALICE_SESSION, CALL_SECRET, answer, seedWorld } from './__testing__/gatewayHarness'
import { actionParams, actionRequest, startEchoRunner } from './__testing__/actionsHarness'
import type { FakeRunner } from './__testing__/fakeRunner'
import { JOB_LOCKS_COLLECTION, JOBS_COLLECTION } from './jobs'
import { POST as runAction } from '@/app/api/plugins/[pluginId]/actions/[actionId]/route'

let db: FakePrisma
let runner: FakeRunner

beforeEach(async () => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', CALL_SECRET)
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  runner = await startEchoRunner({ 'echo/sleep': () => new Promise(() => {}) })
})
afterEach(async () => {
  await runner.close()
  delete process.env.PLUGIN_RUNNER_URL
  delete process.env.PLUGIN_RUNNER_KEY
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

const SLEEP = { context: { projectId: ALICE_PROJECT, sessionId: ALICE_SESSION }, params: {} }
const start = async () => answer(await runAction(actionRequest('echo', 'sleep', SLEEP), actionParams('echo', 'sleep')))
const rows = (collection: string) => db.rows('pluginData').filter((r) => r.collection === collection)

function lockRow(jobId: string, over: Record<string, unknown> = {}) {
  return {
    pluginId: 'echo',
    namespace: 'live',
    ownerType: 'user',
    ownerId: ALICE,
    userId: ALICE,
    collection: JOB_LOCKS_COLLECTION,
    key: `sleep:${ALICE_PROJECT}:${ALICE_SESSION}`,
    value: { jobId },
    sizeBytes: 10,
    expiresAt: new Date(Date.now() + 3_600_000),
    ...over,
  }
}

test('two first clicks at once: one job, one runner call; the other click gets that job', async () => {
  const [a, b] = await Promise.all([start(), start()])
  expect([a.status, b.status].sort()).toEqual([200, 202])
  expect(a.body.jobId).toBe(b.body.jobId)
  expect(runner.actionCalls).toHaveLength(1)
  expect(rows(JOBS_COLLECTION)).toHaveLength(1)
  expect(rows(JOB_LOCKS_COLLECTION)).toHaveLength(1)
})

test('ten clicks at once: still one job', async () => {
  const all = await Promise.all(Array.from({ length: 10 }, () => start()))
  expect(new Set(all.map((r) => r.body.jobId)).size).toBe(1)
  expect(all.filter((r) => r.status === 202)).toHaveLength(1)
  expect(runner.actionCalls).toHaveLength(1)
  expect(rows(JOBS_COLLECTION)).toHaveLength(1)
})

describe('a lock left behind', () => {
  test('pointing at a job that does not exist: replaced, the click starts a job', async () => {
    db.seed('pluginData', [lockRow('00000000-0000-0000-0000-000000000000')])
    const r = await start()
    expect(r.status).toBe(202)
    expect(rows(JOB_LOCKS_COLLECTION).map((l) => (l.value as { jobId: string }).jobId)).toEqual([r.body.jobId])
  })

  test('pointing at a job that ended: replaced', async () => {
    const first = await start()
    const job = rows(JOBS_COLLECTION)[0]
    await db.pluginData.update({ where: { id: job.id }, data: { value: { ...(job.value as object), status: 'succeeded' } } })
    const r = await start()
    expect(r.status).toBe(202)
    expect(r.body.jobId).not.toBe(first.body.jobId)
    expect(rows(JOB_LOCKS_COLLECTION)).toHaveLength(1)
  })

  test('expired: replaced', async () => {
    const first = await start()
    const lock = rows(JOB_LOCKS_COLLECTION)[0]
    await db.pluginData.update({ where: { id: lock.id }, data: { expiresAt: new Date(Date.now() - 1000) } })
    const r = await start()
    expect(r.status).toBe(202)
    expect(r.body.jobId).not.toBe(first.body.jobId)
  })
})
