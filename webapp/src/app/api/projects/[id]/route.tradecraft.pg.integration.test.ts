/**
 * PUT /api/projects/[id] on a real Postgres with the real Prisma client (M2's failure): the chat
 * drawer's autosave sends only the tradecraft switches and the version, so the save carries no
 * project column. The real client refuses queries a double answers (an empty `select`), so the
 * route's whole path runs here: the choices are written, the version moves, a stale version is
 * refused, a collaborator's save is judged and written (AC-30, AC-27, R-064, R-065).
 *
 * The guard answers the context a test sets; the audit, the graph and the agent are doubles.
 *
 * Run through the disposable harness, on the session's own database:
 *   TC_PG_DB=tc_<session> tooling/scripts/tradecraft_pg_testdb.sh web 'src/app/api/projects/[id]/route.tradecraft.pg.integration.test.ts'
 * Without TRADECRAFT_PG_TEST_URL (or PLUGINS_PG_TEST_URL) it is skipped. It refuses a database
 * that holds users without the harness's marker table.
 *
 * @vitest-environment node
 */
import { afterAll, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { NextRequest } from 'next/server'

const URL_ = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL
const h = vi.hoisted(() => ({ ctx: null as null | Record<string, unknown> }))

vi.mock('@/lib/prisma', async () => {
  const { PrismaClient } = await import('@prisma/client')
  const url = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL || 'postgresql://unused@127.0.0.1:1/unused'
  return { default: new PrismaClient({ datasources: { db: { url } } }) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphSeedDomains', async orig => ({
  ...(await orig<typeof import('@/lib/graphSeedDomains')>()),
  seedProjectDomains: vi.fn(async () => true),
}))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', async () => ({
  ...(await vi.importActual<typeof import('@/lib/authz/guards')>('@/lib/authz/guards')),
  requirePermission: async (_req: unknown, permission: string) => ({ ...h.ctx, permission }),
}))

import db from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { PUT } from './route'

const MARKER = 'plugins_pg_integration_test_marker'
const RUN = `tcp${process.pid}${Date.now().toString(36)}`
const OWNER = `${RUN}-owner`
const COLLAB = `${RUN}-collab`
const P = `${RUN}-p`
// A fixed past version, so that the version a save writes (Prisma's @updatedAt) is always later.
const READ_AT = new Date('2026-01-01T10:00:00.000Z')

function as(person: string) {
  const owner = person === OWNER
  h.ctx = {
    session: { userId: person }, principal: { id: person, role: 'standard' }, actingAs: null, effective: { userId: person },
    capabilities: { has: () => true },
    access: { project: { id: P, userId: OWNER }, level: owner ? 'owner' : 'write', via: owner ? 'owner' : 'share', toggles: { rawData: true } },
  }
}

async function put(body: Record<string, unknown>) {
  const res = await PUT(new NextRequest(`http://localhost/api/projects/${P}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }), { params: Promise.resolve({ id: P }) })
  return { status: res.status, body: await res.json() }
}

const version = async () => (await db.project.findUniqueOrThrow({ where: { id: P }, select: { updatedAt: true } })).updatedAt
const off = async () => (await db.tradecraftProjectChoice.findMany({ where: { projectId: P }, select: { resourceId: true } }))
  .map(c => c.resourceId).sort()

describe.skipIf(!URL_)('the project save of the tradecraft switches alone, on a real Postgres', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    if (!marked) await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
    for (const id of [OWNER, COLLAB]) await db.user.create({ data: { id, name: id, email: `${id}@example.invalid` } })
  })

  beforeEach(async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.mocked(writeAudit).mockClear()
    await db.project.deleteMany({ where: { id: P } })
    await db.userTradecraftResource.deleteMany({ where: { userId: OWNER } })
    await db.project.create({
      data: {
        id: P, userId: OWNER, name: 'tradecraft switches', targetDomain: 'switches.example.invalid',
        attackSkillConfig: { builtIn: { xss: true }, user: {} }, updatedAt: READ_AT,
      },
    })
    for (const slug of ['r1', 'r2']) {
      await db.userTradecraftResource.create({
        data: { id: `${RUN}-${slug}`, userId: OWNER, name: slug, slug, url: `https://${slug}.example.invalid/` },
      })
    }
    await db.tradecraftProjectChoice.create({ data: { projectId: P, resourceId: `${RUN}-r2`, createdById: OWNER } })
    as(OWNER)
  })

  afterAll(async () => {
    await db.$executeRawUnsafe(`DELETE FROM users WHERE id LIKE '${RUN}-%'`)
    await db.$disconnect()
  })

  test.each([
    ['the switches alone', () => ({ tradecraftOff: [`${RUN}-r1`] })],
    ['the switches with the version (the drawer)', () => ({ tradecraftOff: [`${RUN}-r1`], updatedAt: READ_AT.toISOString() })],
    ['the switches with the skill map sent back unchanged', () => ({ tradecraftOff: [`${RUN}-r1`], attackSkillConfig: { builtIn: { xss: true }, user: {} } })],
  ])('a save with no project column, %s, is written and moves the version (AC-30, R-064)', async (_name, body) => {
    expect(await version()).toEqual(READ_AT)
    const res = await put(body())
    expect(res.status, JSON.stringify(res.body)).toBe(200)
    expect(res.body.tradecraftOff).toEqual([`${RUN}-r1`])
    expect(await off()).toEqual([`${RUN}-r1`])
    expect((await version()).getTime()).toBeGreaterThan(READ_AT.getTime())
    expect(writeAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'project.update', after: { changed: ['tradecraftOff'], values: { tradecraftOff: [`${RUN}-r1`] } },
    }))
  })

  test('a version read before another save is refused, and no choice changes (AC-27)', async () => {
    // Another writer saved meanwhile.
    await db.project.update({ where: { id: P }, data: { name: 'renamed elsewhere', updatedAt: new Date(READ_AT.getTime() + 60_000) } })
    const res = await put({ tradecraftOff: [`${RUN}-r1`], updatedAt: READ_AT.toISOString() })
    expect(res.status).toBe(409)
    expect(res.body.code).toBe('stale_save')
    expect(await off()).toEqual([`${RUN}-r2`])
  })

  test("a Read + Write collaborator's save of the switches alone is judged and written (R-065)", async () => {
    as(COLLAB)
    const res = await put({ tradecraftOff: [], updatedAt: READ_AT.toISOString() })
    expect(res.status, JSON.stringify(res.body)).toBe(200)
    expect(await off()).toEqual([])
  })
})
