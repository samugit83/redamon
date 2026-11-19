/**
 * The claim of a resource on a real Postgres (TD-8, D-18, D-42, D-45): two starts at once, a
 * start racing an edit that a running job would undo, and the takeover of a claim no agent
 * renews. The unit tests prove the logic on a double that runs transactions one at a time; these
 * prove that the row lock of `lockOwnResource` gives the same order on Postgres: without it the
 * second of two starts at once fails on the changed claim instead of answering job_running.
 *
 * Run through the disposable harness, on the session's own database:
 *   TC_PG_DB=tc_<session> tooling/scripts/tradecraft_pg_testdb.sh web src/lib/tradecraft/jobs.pg.integration.test.ts
 * Skipped without TRADECRAFT_PG_TEST_URL (or PLUGINS_PG_TEST_URL).
 *
 * @vitest-environment node
 */
import { afterAll, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { stubAgent } from './__testing__/agentDouble'

const URL_ = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL
vi.mock('@/lib/prisma', async () => {
  const { PrismaClient } = await import('@prisma/client')
  const url = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL || 'postgresql://unused@127.0.0.1:1/unused'
  return { default: new PrismaClient({ datasources: { db: { url } } }) }
})

import db from '@/lib/prisma'
import { START_LEASE_MS, startJob, sweepLostJobs } from './jobs'
import { updateResourceV2 } from './v2/update'

const MARKER = 'plugins_pg_integration_test_marker'
const RUN = `tcj${process.pid}${Date.now().toString(36)}`
let n = 0

async function resource(extra: Record<string, unknown> = {}) {
  n += 1
  const userId = `${RUN}-${n}-u`
  await db.user.create({ data: { id: userId, name: `u${n}`, email: `${userId}@example.invalid` } })
  const row = await db.userTradecraftResource.create({
    data: { userId, name: `r${n}`, slug: `r${n}`, url: `https://r${n}.example.invalid/`, llmModel: 'gpt-4o', ...extra },
  })
  return { userId, resourceId: row.id, actor: { actorUserId: userId, realActorUserId: null } }
}

describe.skipIf(!URL_)('the resource claim on a real Postgres', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    if (!marked) await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(() => { stubAgent() })

  afterAll(async () => {
    await db.$executeRawUnsafe(`DELETE FROM users WHERE id LIKE '${RUN}-%'`)
    await db.$disconnect()
  })

  test('concurrent_claim: eight starts at once give one job and seven refusals', async () => {
    const { userId, resourceId, actor } = await resource()
    const outs = await Promise.all(Array.from({ length: 8 }, () => startJob({ ownerId: userId, resourceId, kind: 'refresh', actor })))
    expect(outs.filter(o => o.kind === 'started')).toHaveLength(1)
    expect(outs.filter(o => o.kind === 'job_running')).toHaveLength(7)
    const jobs = await db.tradecraftIngestionJob.findMany({ where: { resourceId } })
    expect(jobs).toHaveLength(1)
    const row = await db.userTradecraftResource.findUnique({ where: { id: resourceId }, select: { activeJobId: true } })
    expect(row?.activeJobId).toBe(jobs[0].id)
    expect(jobs[0].leaseUntil!.getTime()).toBeGreaterThan(Date.now() + START_LEASE_MS - 10_000)
  })

  test('a start and a URL change at once: the edit lands only when it came first (D-45)', async () => {
    const { userId, resourceId, actor } = await resource()
    const [start, edit] = await Promise.all([
      startJob({ ownerId: userId, resourceId, kind: 'refresh', actor }),
      updateResourceV2({ ownerId: userId, resourceId, body: { url: 'https://moved.example.invalid/' }, actor }),
    ])
    const row = await db.userTradecraftResource.findUnique({ where: { id: resourceId }, select: { url: true } })
    if (edit.status === 409) {
      expect(start.kind).toBe('started')
      expect(row?.url).not.toBe('https://moved.example.invalid/')
    } else {
      expect(edit.status).toBe(200)
      expect(row?.url).toBe('https://moved.example.invalid/')
    }
    const live = await db.tradecraftIngestionJob.count({ where: { resourceId, status: { in: ['queued', 'running'] } } })
    expect(live).toBe(1)
  })

  test('stale_claim_taken_over: a running job whose lease expired fails agent_lost in the start that takes over', async () => {
    const { userId, resourceId, actor } = await resource()
    const lost = await db.tradecraftIngestionJob.create({
      data: { userId, resourceId, kind: 'refresh', status: 'running', leaseUntil: new Date(Date.now() - 1_000), actorUserId: userId },
    })
    await db.userTradecraftResource.update({ where: { id: resourceId }, data: { activeJobId: lost.id } })
    const out = await startJob({ ownerId: userId, resourceId, kind: 'refresh', actor })
    expect(out.kind).toBe('started')
    expect(await db.tradecraftIngestionJob.findUnique({ where: { id: lost.id }, select: { status: true, errorCode: true } }))
      .toEqual({ status: 'failed', errorCode: 'agent_lost' })
  })

  test('two sweeps at once end a lost add once, free its claim and write its 1.x columns in the same transaction (TD-18)', async () => {
    const { userId, resourceId } = await resource({ summary: 'kept' })
    const lost = await db.tradecraftIngestionJob.create({ data: { userId, resourceId, kind: 'add', status: 'running', leaseUntil: new Date(Date.now() - 1_000) } })
    await db.userTradecraftResource.update({ where: { id: resourceId }, data: { activeJobId: lost.id } })
    const ended = await Promise.all([sweepLostJobs(userId), sweepLostJobs(userId)])
    expect(ended.sort()).toEqual([0, 1])
    expect(await db.tradecraftIngestionJob.findUnique({ where: { id: lost.id }, select: { status: true, errorCode: true } }))
      .toEqual({ status: 'failed', errorCode: 'agent_lost' })
    const row = await db.userTradecraftResource.findUnique({ where: { id: resourceId } })
    expect(row).toMatchObject({ activeJobId: null, lastError: 'verify failed (agent_lost)', summary: 'kept' })
    expect(row?.lastVerifiedAt).not.toBeNull()
  })

  test('a job the agent ended meanwhile is left as it ended, and so is its resource', async () => {
    const { userId, resourceId } = await resource({ lastError: '' })
    const done = await db.tradecraftIngestionJob.create({ data: { userId, resourceId, kind: 'refresh', status: 'running', leaseUntil: new Date(Date.now() - 1_000) } })
    await db.tradecraftIngestionJob.update({ where: { id: done.id }, data: { status: 'succeeded' } })
    expect(await sweepLostJobs(userId)).toBe(0)
    expect((await db.userTradecraftResource.findUnique({ where: { id: resourceId } }))?.lastError).toBe('')
  })

  test("the lock is keyed by the account: another account's id claims nothing", async () => {
    const { resourceId, actor } = await resource()
    const other = await resource()
    expect(await startJob({ ownerId: other.userId, resourceId, kind: 'refresh', actor })).toEqual({ kind: 'not_found' })
    expect(await db.tradecraftIngestionJob.count({ where: { resourceId } })).toBe(0)
  })
})
