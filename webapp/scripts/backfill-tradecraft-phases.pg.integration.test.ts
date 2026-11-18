/**
 * The Tradecraft row of existing projects moves from the old default to the new one (owner decision
 * 2026-11-17, FIX-PHASES; R-321), on a real Postgres.
 *
 * Only a row that still EQUALS the old default, exploitation and post-exploitation as a set, gets
 * all three phases; its other tools and keys stay as they are and its `updatedAt` moves, so a form
 * opened before the upgrade gets a stale-save refusal instead of writing the old row back. A row a
 * person changed, a map with no row, a value that is not a list of phases, a map that is not an
 * object and a project created after the new code first started keep exactly what they hold. It runs
 * once (an AuditLog marker carrying the count and the moved ids, written in the same transaction,
 * under an advisory lock), so a person who puts the old phases back afterwards keeps them; those ids
 * are the way back (R-K3). A project created after the change with no map of its own gets all three
 * phases.
 *
 * Needs a DISPOSABLE database holding the webapp schema; it empties `audit_log`, `projects` and
 * `users` (CASCADE) between tests. Run:
 *   TC_PG_DB=tc_mine tooling/scripts/tradecraft_pg_testdb.sh web scripts/backfill-tradecraft-phases.pg.integration.test.ts
 * Without PLUGINS_PG_TEST_URL it is skipped. It refuses a database that already holds users unless
 * that database carries the pg-integration marker table.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'
import { backfillTradecraftPhases, CUTOFF_ACTION, MARKER_ACTION } from './backfill-tradecraft-phases.mjs'

const URL = process.env.PLUGINS_PG_TEST_URL
const MARKER = 'plugins_pg_integration_test_marker'
const client = () => new PrismaClient({ datasources: { db: { url: URL } } })
const db = URL ? client() : (null as unknown as PrismaClient)

const T0 = new Date('2026-01-01T00:00:00.000Z')
const OLD = ['exploitation', 'post_exploitation']
const ALL = ['informational', 'exploitation', 'post_exploitation']
const OTHERS = { query_graph: ALL, metasploit_console: OLD, google_dork: ['informational'] }

/** Every kind of stored row: the three that hold the old default move, the rest stay. */
const MOVES: Record<string, unknown> = {
  'old-default': { ...OTHERS, tradecraft_lookup: OLD },
  'old-reversed': { ...OTHERS, tradecraft_lookup: ['post_exploitation', 'exploitation'] },
  'old-repeated': { ...OTHERS, tradecraft_lookup: ['exploitation', 'post_exploitation', 'exploitation'] },
}
const STAYS: Record<string, unknown> = {
  'person-exploitation': { ...OTHERS, tradecraft_lookup: ['exploitation'] },
  'person-post': { ...OTHERS, tradecraft_lookup: ['post_exploitation'] },
  'person-off': { ...OTHERS, tradecraft_lookup: [] },
  'person-info-expl': { ...OTHERS, tradecraft_lookup: ['informational', 'exploitation'] },
  'already-all': { ...OTHERS, tradecraft_lookup: ALL },
  'no-row': { ...OTHERS },
  'old-plus-unknown': { ...OTHERS, tradecraft_lookup: [...OLD, 'Informational'] },
  'nested-list': { ...OTHERS, tradecraft_lookup: ['exploitation', ['post_exploitation']] },
  'text-row': { ...OTHERS, tradecraft_lookup: 'exploitation,post_exploitation' },
  'map-as-text': JSON.stringify({ ...OTHERS, tradecraft_lookup: OLD }),
  'map-as-list': [{ tradecraft_lookup: OLD }],
}
const MOVED_IDS = Object.keys(MOVES).sort()

/**
 * The way back (R-K3), as FIX-PHASES's progress-log entry states it: the projects the marker names
 * that still hold exactly all three phases get the old row again. A moved project whose person
 * re-ticked all three afterwards cannot be told apart; one the marker does not name is never touched.
 */
const WAY_BACK = `
  UPDATE projects
     SET agent_tool_phase_map = jsonb_set(agent_tool_phase_map, '{tradecraft_lookup}', '["exploitation","post_exploitation"]'::jsonb),
         updated_at = now()
   WHERE id IN (SELECT jsonb_array_elements_text(after -> 'ids') FROM audit_log WHERE action = 'system.tradecraft_phases_backfill')
     AND agent_tool_phase_map -> 'tradecraft_lookup' @> '["informational","exploitation","post_exploitation"]'::jsonb
     AND agent_tool_phase_map -> 'tradecraft_lookup' <@ '["informational","exploitation","post_exploitation"]'::jsonb`

async function project(id: string, map: unknown, createdAt = T0) {
  await db.project.create({ data: { id, userId: 'alice', name: id, agentToolPhaseMap: map as never } })
  // Known past timestamps, so a write by the backfill is visible.
  await db.$executeRaw`UPDATE projects SET updated_at = ${T0}, created_at = ${createdAt} WHERE id = ${id}`
}

const read = async (id: string) => {
  const p = await db.project.findUniqueOrThrow({ where: { id }, select: { agentToolPhaseMap: true, updatedAt: true } })
  return { map: p.agentToolPhaseMap, updatedAt: p.updatedAt }
}
const markers = () => db.auditLog.findMany({ where: { action: MARKER_ACTION } })

describe.skipIf(!URL)('backfillTradecraftPhases on a real Postgres (PLUGINS_PG_TEST_URL)', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(async () => {
    await db.$executeRawUnsafe('TRUNCATE audit_log, projects, users CASCADE')
    await db.user.create({ data: { id: 'alice', name: 'alice', email: 'alice@example.invalid' } })
    for (const [id, map] of Object.entries({ ...MOVES, ...STAYS })) await project(id, map)
  })

  afterAll(async () => { await db?.$disconnect() })

  test('only the rows that still hold the old default move, and the marker records how many', async () => {
    const result = await backfillTradecraftPhases(db)
    expect(result).toEqual({ done: true, projects: MOVED_IDS.length, ids: MOVED_IDS })
    for (const [id, map] of Object.entries(MOVES)) {
      const row = await read(id)
      expect(row.map, id).toEqual({ ...(map as object), tradecraft_lookup: ALL })
      expect(row.updatedAt.getTime(), id).toBeGreaterThan(T0.getTime())
    }
    for (const [id, map] of Object.entries(STAYS)) {
      expect(await read(id), id).toEqual({ map, updatedAt: T0 })
    }
    const [marker] = await markers()
    // Exactly the moved projects' ids, and no other key (no name, no setting).
    expect(marker).toMatchObject({ targetType: 'system', source: 'system', actorId: null })
    expect(marker.after).toEqual({ projects: 3, ids: MOVED_IDS })
    expect(await db.auditLog.count({ where: { action: CUTOFF_ACTION } })).toBe(1)
  })

  test('it runs once: a later start changes nothing, and a person who puts the old phases back keeps them', async () => {
    await backfillTradecraftPhases(db)
    const after = Object.fromEntries(await Promise.all(Object.keys({ ...MOVES, ...STAYS }).map(async (id) => [id, await read(id)])))
    expect(await backfillTradecraftPhases(db)).toEqual({ done: false })
    for (const id of Object.keys(after)) expect(await read(id), id).toEqual(after[id])

    await db.project.update({ where: { id: 'old-default' }, data: { agentToolPhaseMap: { ...OTHERS, tradecraft_lookup: OLD } } })
    const chosen = await read('old-default')
    expect(await backfillTradecraftPhases(db)).toEqual({ done: false })
    expect(await read('old-default')).toEqual(chosen)
    expect(await markers()).toHaveLength(1)
  })

  test('two webapp copies starting together move each row once and write one marker', async () => {
    const [a, b] = [client(), client()]
    try {
      const results = await Promise.all([backfillTradecraftPhases(a), backfillTradecraftPhases(b)])
      expect(results).toContainEqual({ done: true, projects: 3, ids: MOVED_IDS })
      expect(results).toContainEqual({ done: false })
    } finally {
      await Promise.all([a.$disconnect(), b.$disconnect()])
    }
    expect(await markers()).toHaveLength(1)
    expect(await db.auditLog.count({ where: { action: CUTOFF_ACTION } })).toBe(1)
    for (const id of Object.keys(MOVES)) expect((await read(id)).map, id).toMatchObject({ tradecraft_lookup: ALL })
  })

  test('a project created after the new code first started keeps what it holds', async () => {
    // The first start records the cut-off and fails before its marker (here: no backfill yet).
    await db.auditLog.create({ data: { action: CUTOFF_ACTION, targetType: 'system', source: 'system', createdAt: new Date('2026-06-01T00:00:00.000Z') } })
    await project('late-old', { ...OTHERS, tradecraft_lookup: OLD }, new Date('2026-07-01T00:00:00.000Z'))
    expect(await backfillTradecraftPhases(db)).toEqual({ done: true, projects: 3, ids: MOVED_IDS })
    expect((await markers())[0].after).toEqual({ projects: 3, ids: MOVED_IDS })
    expect(await read('late-old')).toEqual({ map: { ...OTHERS, tradecraft_lookup: OLD }, updatedAt: T0 })
    expect(await db.auditLog.count({ where: { action: CUTOFF_ACTION } })).toBe(1)
  })

  test('the way back puts the moved rows back, and keeps a later choice and every row it did not move', async () => {
    await backfillTradecraftPhases(db)
    // After the move: a person narrows one moved project; one never moved already held all three.
    await db.project.update({ where: { id: 'old-reversed' }, data: { agentToolPhaseMap: { ...OTHERS, tradecraft_lookup: ['exploitation'] } } })
    await db.$executeRaw`UPDATE projects SET updated_at = ${T0}`
    const before = Object.fromEntries(await Promise.all(Object.keys({ ...MOVES, ...STAYS }).map(async (id) => [id, await read(id)])))
    expect(await db.$executeRawUnsafe(WAY_BACK)).toBe(2)
    for (const id of ['old-default', 'old-repeated']) {
      const row = await read(id)
      expect(row.map, id).toEqual({ ...OTHERS, tradecraft_lookup: OLD })
      expect(row.updatedAt.getTime(), id).toBeGreaterThan(T0.getTime())
    }
    for (const id of Object.keys(before).filter((id) => !['old-default', 'old-repeated'].includes(id))) {
      expect(await read(id), id).toEqual(before[id])
    }
    // The marker stays, so the next start does not move them again.
    expect(await backfillTradecraftPhases(db)).toEqual({ done: false })
  })

  test('a project created after the change with no map of its own gets all three phases', async () => {
    // Every webapp create path goes through Prisma, whose client fills the @default itself.
    await db.project.create({ data: { id: 'new', userId: 'alice', name: 'new' } })
    const { map } = await read('new')
    expect((map as Record<string, unknown>).tradecraft_lookup,
      'the Prisma client was generated from an older schema.prisma: run npx prisma generate').toEqual(ALL)
    await backfillTradecraftPhases(db)
    expect((await read('new')).map).toEqual(map)
  })
})
