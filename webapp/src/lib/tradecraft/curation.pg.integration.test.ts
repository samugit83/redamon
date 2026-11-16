/**
 * S09's writes and reads on a real Postgres with the real Prisma client (driver note 8: a double
 * can accept what the client refuses): the Map view's search (insensitive `contains`, array
 * `has`, `notIn`, a BigInt cursor), the curation writes (`createMany` with `skipDuplicates`,
 * compound-key upserts, the stored text and sections deleted at once, the report's counts), a
 * site login written with its audit row inside `auditedTransaction`, and the focus recipes and
 * skill topics on real rows.
 *
 * Run through the disposable harness, on the session's own database:
 *   TC_PG_DB=tc_<session> tooling/scripts/tradecraft_pg_testdb.sh web src/lib/tradecraft/curation.pg.integration.test.ts
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
import { curate, readMap, type MapResource } from './curation'
import { createResourceV2 } from './v2/create'
import { updateResourceV2 } from './v2/update'
import { editRecipes, readRecipes } from './userSettings'
import { foreignSkillTopics } from './v2/focusFields'

const MARKER = 'plugins_pg_integration_test_marker'
const RUN = `tcc${process.pid}${Date.now().toString(36)}`
let n = 0

async function account() {
  n += 1
  const userId = `${RUN}-${n}-u`
  await db.user.create({ data: { id: userId, name: `u${n}`, email: `${userId}@example.invalid` } })
  return userId
}

async function mapResource(): Promise<MapResource & { userId: string }> {
  const userId = await account()
  const row = await db.userTradecraftResource.create({
    data: {
      userId, name: 'Wiki', slug: `wiki-${n}`, url: `https://wiki${n}.example.invalid/`, llmModel: 'gpt-4o', generation: 2, storageMode: 'stored',
      ingestionReport: { visited: 4, kept: 3, stored: { pages: 3, bytes: 30, notStoredQuota: 0, notStoredSize: 0 } },
    },
  })
  const pages = [
    { path: 'sqli', title: 'SQL Injection payloads', topics: ['sql_injection'], kinds: ['payloads'], text: 'union select' },
    { path: 'bypass', title: 'sqli filter BYPASS', topics: ['sql_injection'], kinds: ['bypasses'], text: 'bypass' },
    { path: 'xss', title: 'XSS cheat sheet', topics: ['xss'], kinds: ['payloads'], text: 'xss' },
    { path: 'news', title: 'Company news', topics: [], kinds: [], text: null, status: 'dropped', dropReason: 'news' },
  ]
  for (const [i, p] of pages.entries()) {
    const url = `${row.url}${p.path}`
    const page = await db.tradecraftPageId.create({ data: { resourceId: row.id, url } })
    const entry = await db.tradecraftEntry.create({
      data: {
        userId, resourceId: row.id, generation: 2, pageId: page.id, url, title: p.title, topics: p.topics, kinds: p.kinds,
        status: p.status ?? 'kept', dropReason: p.dropReason ?? '', storedText: p.text, storedBytes: p.text ? 10 : 0,
      },
    })
    if (p.text) await db.tradecraftSection.create({ data: { entryId: entry.id, resourceId: row.id, userId, generation: 2, ord: i, level: 1, text: p.text } })
  }
  return { ...row, userId }
}

describe.skipIf(!URL_)('S09 on a real Postgres', () => {
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

  test('the Map view: an insensitive search, a tag, the blocked list apart, a BigInt cursor', async () => {
    const r = await mapResource()
    expect((await readMap(r, { query: 'SQLI' })).entries.map(e => e.title)).toEqual(['SQL Injection payloads', 'sqli filter BYPASS'])
    expect((await readMap(r, { tag: 'payloads' })).total).toBe(2)
    const first = await readMap(r, { limit: 1 })
    expect(first.nextCursor).toMatch(/^[0-9]+$/)
    expect((await readMap(r, { limit: 5, cursor: first.nextCursor })).entries).toHaveLength(2)
    await curate(r, { op: 'block', urls: [`${r.url}xss`] }, r.userId)
    expect((await readMap(r, {})).entries.map(e => e.title)).toEqual(['SQL Injection payloads', 'sqli filter BYPASS'])
    expect((await readMap(r, { status: 'blocked' })).entries).toEqual([expect.objectContaining({ url: `${r.url}xss`, status: 'blocked', stored: false })])
  })

  test('block matching: the count check, the curation rows twice (no duplicate), text and sections gone, the report lowered', async () => {
    const r = await mapResource()
    expect(await curate(r, { op: 'block', matching: { query: 'sql' }, expectedCount: 9 }, r.userId)).toMatchObject({ ok: false, status: 409, count: 2 })
    await curate(r, { op: 'rename', url: `${r.url}sqli`, title: 'Union payloads' }, r.userId)
    expect(await curate(r, { op: 'block', matching: { query: 'sql' }, expectedCount: 2 }, r.userId)).toEqual({ ok: true, op: 'block', count: 2 })
    const rows = await db.tradecraftCuration.findMany({ where: { resourceId: r.id }, orderBy: { url: 'asc' } })
    expect(rows.map(c => [c.url, c.blocked, c.renamedTitle])).toEqual([[`${r.url}bypass`, true, null], [`${r.url}sqli`, true, 'Union payloads']])
    const entries = await db.tradecraftEntry.findMany({ where: { resourceId: r.id, url: { in: [`${r.url}sqli`, `${r.url}bypass`] } } })
    expect(entries.every(e => e.storedText === null && e.storedBytes === 0)).toBe(true)
    expect(await db.tradecraftSection.count({ where: { resourceId: r.id } })).toBe(1)
    const after = await db.userTradecraftResource.findUnique({ where: { id: r.id }, select: { ingestionReport: true } })
    expect((after!.ingestionReport as { stored: { pages: number; bytes: number } }).stored).toMatchObject({ pages: 1, bytes: 10 })
    expect(await curate(r, { op: 'unblock', urls: [`${r.url}bypass`, `${r.url}sqli`] }, r.userId)).toEqual({ ok: true, op: 'unblock', count: 2 })
    expect((await db.tradecraftCuration.findMany({ where: { resourceId: r.id } })).map(c => c.url)).toEqual([`${r.url}sqli`])
  })

  test('restore pins a dropped page; pin records a typed URL; both are compound-key upserts', async () => {
    const r = await mapResource()
    expect(await curate(r, { op: 'restore', url: `${r.url}news` }, r.userId)).toEqual({ ok: true, op: 'restore', count: 1 })
    expect(await db.tradecraftEntry.findFirst({ where: { resourceId: r.id, url: `${r.url}news` }, select: { status: true } })).toEqual({ status: 'kept' })
    expect(await curate(r, { op: 'pin', url: `${r.url}new-page` }, r.userId)).toMatchObject({ ok: true })
    expect(await curate(r, { op: 'pin', url: `${r.url}new-page` }, r.userId)).toMatchObject({ ok: true })
    const rows = await db.tradecraftCuration.findMany({ where: { resourceId: r.id }, orderBy: { url: 'asc' } })
    expect(rows.map(c => [c.url, c.pinned, c.restoredFromDrop, c.createdById])).toEqual([
      [`${r.url}new-page`, true, false, r.userId], [`${r.url}news`, true, true, r.userId],
    ])
  })

  test('a site login: stored in the contract\'s shape, the flag set, its audit row in the same transaction', async () => {
    const userId = await account()
    const actor = { actorUserId: userId, realActorUserId: null }
    const login = { cookie: 'session=fake-pg', headers: [{ name: 'X-Api-Key', value: 'fake-pg-key' }], basic_auth: null }
    const res = await createResourceV2({ ownerId: userId, body: { name: 'KB', url: `https://kb${n}.example.invalid/`, llmModel: 'gpt-4o', credentials: login }, actor, skipVerify: true })
    expect(res.status).toBe(201)
    const row = await db.userTradecraftResource.findFirst({ where: { userId }, select: { id: true, credentials: true, hasLogin: true } })
    expect(row).toMatchObject({ credentials: login, hasLogin: true })
    const upd = await updateResourceV2({ ownerId: userId, resourceId: row!.id, body: { credentials: { cookie: 'set', headers: [] } }, actor })
    expect(upd.status).toBe(200)
    expect(await db.userTradecraftResource.findUnique({ where: { id: row!.id }, select: { credentials: true, hasLogin: true } }))
      .toEqual({ credentials: { cookie: 'session=fake-pg', headers: [], basic_auth: null }, hasLogin: true })
    const audits = await db.auditLog.findMany({ where: { actorId: userId, action: 'tradecraft.credentials_changed' }, orderBy: { createdAt: 'asc' } })
    expect(audits.map(a => (a.after as { changed: string[] }).changed)).toEqual([['cookie', 'header:X-Api-Key'], ['header:X-Api-Key']])
    expect(JSON.stringify(audits)).not.toMatch(/fake-pg/)
  })

  test('the focus recipes as a JSON list, and a skill topic checked against real skills', async () => {
    const userId = await account()
    const other = await account()
    const mine = await db.userAttackSkill.create({ data: { userId, name: 'Mine', content: 'x' } })
    const theirs = await db.userAttackSkill.create({ data: { userId: other, name: 'Theirs', content: 'x' } })
    expect(await foreignSkillTopics(userId, [`user_skill:${mine.id}`, `user_skill:${theirs.id}`, 'xss'])).toEqual([`user_skill:${theirs.id}`])
    expect(await editRecipes(userId, { add: { name: 'Mine', topics: [`user_skill:${mine.id}`], kinds: ['poc'] } })).toMatchObject({ ok: true })
    const [recipe] = await readRecipes(userId)
    expect(await editRecipes(userId, { rename: { id: recipe.id, name: 'Mine 2' } })).toMatchObject({ ok: true, recipes: [{ name: 'Mine 2' }] })
    expect(await editRecipes(userId, { delete: recipe.id })).toEqual({ ok: true, recipes: [] })
  })
})
