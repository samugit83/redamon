/**
 * S11's writes and reads on a real Postgres with the real Prisma client (driver note 8): the search
 * settings and the synonym pairs (one upsert of two JSON columns, a reset that keeps the pairs),
 * a resource's priority, Save & refresh all's bulk jobs (one claim each, one bulkId, a running
 * resource skipped), and the project view's librarian model.
 *
 * Run through the disposable harness, on the session's own database:
 *   TC_PG_DB=tc_s11 tooling/scripts/tradecraft_pg_testdb.sh web src/lib/tradecraft/s11.pg.integration.test.ts
 * Skipped without TRADECRAFT_PG_TEST_URL (or PLUGINS_PG_TEST_URL).
 *
 * @vitest-environment node
 */
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest'
import { NextResponse } from 'next/server'

const URL_ = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL
vi.mock('@/lib/prisma', async () => {
  const { PrismaClient } = await import('@prisma/client')
  const url = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL || 'postgresql://unused@127.0.0.1:1/unused'
  return { default: new PrismaClient({ datasources: { db: { url } } }) }
})
vi.mock('@/lib/authz/actAsRefusals', () => ({
  refuseWhileActingAsOn: vi.fn(async () => null as NextResponse | null),
  actingAsOn: vi.fn(async () => false),
}))

import db from '@/lib/prisma'
import { readSearchSettings, resetSearchSettings, saveSearchSettings } from './userSettings'
import { updateResourceV2 } from './v2/update'
import { startBulkJobs } from './jobs'
import { projectTradecraftView } from './projectView'
import { stubAgent } from './__testing__/agentDouble'

const MARKER = 'plugins_pg_integration_test_marker'
const RUN = `tcs11${process.pid}${Date.now().toString(36)}`
let n = 0

async function account(): Promise<string> {
  n += 1
  const userId = `${RUN}-${n}-u`
  await db.user.create({ data: { id: userId, name: `u${n}`, email: `${userId}@example.invalid` } })
  await db.tradecraftUserSettings.create({ data: { userId, v2Enabled: true } })
  return userId
}

async function resourceOf(userId: string, i: number) {
  return db.userTradecraftResource.create({
    data: { userId, name: `R${i}`, slug: `r-${n}-${i}`, url: `https://r${n}-${i}.example.invalid/`, llmModel: 'gpt-4o', generation: 1 },
  })
}

describe.skipIf(!URL_)('S11 on a real Postgres', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    if (!marked) await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  afterAll(async () => {
    await db.$executeRawUnsafe(`DELETE FROM audit_log WHERE actor_id LIKE '${RUN}-%'`)
    await db.$executeRawUnsafe(`DELETE FROM users WHERE id LIKE '${RUN}-%'`)
    await db.$disconnect()
  })

  test('search settings and my synonyms: saved together, read back, reset keeps the pairs; another account untouched', async () => {
    const userId = await account()
    const other = await account()
    const saved = await saveSearchSettings(userId, { 'search.results': 12, 'librarian.use': 'search_only', synonyms: [{ term: 'PATT', expansion: 'PayloadsAllTheThings' }] })
    expect(saved.ok).toBe(true)
    const row = await db.tradecraftUserSettings.findUnique({ where: { userId } })
    expect(row).toMatchObject({ v2Enabled: true, search: { 'search.results': 12, 'librarian.use': 'search_only' }, synonyms: [{ term: 'PATT', expansions: ['PayloadsAllTheThings'] }] })
    expect((await readSearchSettings(userId)).synonyms).toEqual([{ term: 'PATT', expansion: 'PayloadsAllTheThings' }])
    await resetSearchSettings(userId)
    expect(await db.tradecraftUserSettings.findUnique({ where: { userId }, select: { search: true, synonyms: true } }))
      .toEqual({ search: {}, synonyms: [{ term: 'PATT', expansions: ['PayloadsAllTheThings'] }] })
    expect(await db.tradecraftUserSettings.findUnique({ where: { userId: other }, select: { search: true, synonyms: true } })).toEqual({ search: {}, synonyms: [] })
    // An account with no settings row yet gets one from the save.
    const fresh = `${RUN}-fresh-u`
    await db.user.create({ data: { id: fresh, name: 'fresh', email: `${fresh}@example.invalid` } })
    expect((await saveSearchSettings(fresh, { 'search.results': 4 })).ok).toBe(true)
    expect(await db.tradecraftUserSettings.findUnique({ where: { userId: fresh }, select: { search: true, v2Enabled: true } })).toEqual({ search: { 'search.results': 4 }, v2Enabled: false })
  })

  test('a priority is written on its resource, with no job and no change of the settings hash', async () => {
    const userId = await account()
    const r = await resourceOf(userId, 1)
    const res = await updateResourceV2({ ownerId: userId, resourceId: r.id, body: { priority: 'high' }, actor: { actorUserId: userId, realActorUserId: null } })
    expect(res.status).toBe(200)
    const after = await db.userTradecraftResource.findUnique({ where: { id: r.id } })
    expect(after).toMatchObject({ priority: 'high', settingsHash: r.settingsHash, activeJobId: null })
    expect(await db.tradecraftIngestionJob.count({ where: { resourceId: r.id } })).toBe(0)
  })

  test('Save & refresh all: one bulk job per resource with the one bulkId, each claimed; a running resource skipped', async () => {
    const userId = await account()
    const rs = await Promise.all([1, 2, 3].map(i => resourceOf(userId, i)))
    const agent = stubAgent()
    const first = await startBulkJobs({ ownerId: userId, resourceIds: [rs[0].id], actor: { actorUserId: userId, realActorUserId: null }, bulkId: `${RUN}-b1` })
    expect(first.started).toHaveLength(1)
    const out = await startBulkJobs({ ownerId: userId, resourceIds: rs.map(r => r.id), actor: { actorUserId: userId, realActorUserId: null }, bulkId: `${RUN}-b2` })
    expect(out.skipped).toEqual([{ resourceId: rs[0].id, reason: 'job_running' }])
    expect(out.started.map(s => s.resourceId)).toEqual([rs[1].id, rs[2].id])
    const jobs = await db.tradecraftIngestionJob.findMany({ where: { bulkId: `${RUN}-b2` }, orderBy: { createdAt: 'asc' } })
    expect(jobs.map(j => [j.resourceId, j.kind, j.status])).toEqual([[rs[1].id, 'bulk', 'queued'], [rs[2].id, 'bulk', 'queued']])
    for (const j of jobs) expect((await db.userTradecraftResource.findUnique({ where: { id: j.resourceId! } }))!.activeJobId).toBe(j.id)
    expect(agent.calls.filter(c => c.path === '/tradecraft/v2/jobs')).toHaveLength(2)
  })

  test('the project view names the librarian model to the owner only', async () => {
    const owner = await account()
    await db.userSettings.create({ data: { userId: owner, featureModels: { tradecraft_librarian: 'openai/gpt-4o-mini' } } })
    const project = await db.project.create({ data: { userId: owner, name: `${RUN}-p`, targetDomain: 'example.invalid' } })
    const asOwner = await projectTradecraftView({ projectId: project.id, ownerId: owner, viewer: { personId: owner, actorId: null }, viewerIsOwner: true })
    expect(asOwner).toMatchObject({ ownerId: owner, librarian: { use: 'agent', set: true, model: 'openai/gpt-4o-mini' } })
    const asOther = await projectTradecraftView({ projectId: project.id, ownerId: owner, viewer: { personId: `${RUN}-x`, actorId: null }, viewerIsOwner: false })
    expect(asOther.librarian).toEqual({ use: 'agent', set: true, model: null })
    expect(asOther).not.toHaveProperty('ownerId')
  })
})
