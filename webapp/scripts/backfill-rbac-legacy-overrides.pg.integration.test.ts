/**
 * The conversion of the legacy grants (step 3.15, HD-02, OQ-26) on a real Postgres: a grant whose
 * latest review decision is Keep becomes an override grant of its platform permission ("kept
 * from 7.7.x", 90 days), the rest lapse, `users.legacy_grants` is never written, three copies
 * booting together convert once, a dropped override table (a downgrade) is filled again with the
 * first conversion's end, and nothing runs with the switch off.
 *
 * Needs a DISPOSABLE database holding the webapp schema (`prisma db push`); it empties
 * `audit_log`, `user_permission_overrides` and `users` (CASCADE) between tests. Run:
 *   PLUGINS_PG_TEST_URL=postgresql://... npx vitest run --no-file-parallelism scripts/backfill-rbac-legacy-overrides.pg.integration.test.ts
 * Without the variable it is skipped. It refuses a database that already holds users unless
 * that database carries the pg-integration marker table.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'
import { KEEP_ACTION, MARKER_ACTION, backfillRbacLegacyOverrides } from './backfill-rbac-legacy-overrides.mjs'
import { REMOVE_ACTION } from './backfill-rbac-legacy-grants.mjs'

const URL = process.env.PLUGINS_PG_TEST_URL
const MARKER = 'plugins_pg_integration_test_marker'
const db = URL ? new PrismaClient({ datasources: { db: { url: URL } } }) : (null as unknown as PrismaClient)
const ON = { RBAC_IDENTITY_ENABLED: 'true', RBAC_PERMISSIONS_ENABLED: 'true' } as unknown as NodeJS.ProcessEnv
const PW = '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42'
const DAY = 86_400_000
const T0 = Date.parse('2026-11-12T08:00:00.000Z')

async function account(id: string, role: string, legacyGrants: string[]) {
  await db.user.create({
    data: { id, name: id, email: `${id}@example.invalid`, role, password: PW, legacyGrants, updatedAt: new Date(T0 - 30 * DAY) },
  })
}
async function decide(action: string, targetId: string, grant: string, at: number) {
  await db.auditLog.create({
    data: { action, actorId: 'adm', targetType: 'user', targetId, after: { grant }, source: 'api', createdAt: new Date(at) },
  })
}
const overrides = () => db.userPermissionOverride.findMany({
  orderBy: [{ userId: 'asc' }, { permission: 'asc' }],
  select: { userId: true, permission: true, effect: true, reason: true, expiresAt: true, grantedById: true },
})

describe.skipIf(!URL)('backfillRbacLegacyOverrides on a real Postgres (PLUGINS_PG_TEST_URL)', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(async () => {
    await db.$executeRawUnsafe('TRUNCATE audit_log, user_permission_overrides, users CASCADE')
    await account('adm', 'admin', ['kali_terminal'])
    await account('m-kept', 'standard', ['kali_terminal', 'shell_sessions', 'tunnels'])
    await account('m-undecided', 'standard', ['kali_terminal', 'shell_sessions'])
    await account('m-removed', 'standard', ['shell_sessions'])
    await decide(KEEP_ACTION, 'm-kept', 'kali_terminal', T0 - 3 * DAY)
    await decide(KEEP_ACTION, 'm-kept', 'tunnels', T0 - 3 * DAY)
    await decide(KEEP_ACTION, 'm-removed', 'kali_terminal', T0 - 3 * DAY)
    await decide(REMOVE_ACTION, 'm-removed', 'kali_terminal', T0 - 2 * DAY)
    await decide(KEEP_ACTION, 'adm', 'kali_terminal', T0 - 3 * DAY)
  })

  afterAll(async () => {
    await db?.$disconnect()
  })

  test('kept → override with the reason and the end; undecided and removed → nothing; the column untouched', async () => {
    const before = await db.user.findMany({ orderBy: { id: 'asc' }, select: { id: true, legacyGrants: true, updatedAt: true } })
    const out = await backfillRbacLegacyOverrides(db, ON, { now: () => new Date(T0) })
    expect(out).toMatchObject({ ran: true, marker: true, converted: 2, lapsed: 4, kali_terminal: 1, shell_sessions: 0, tunnels: 1 })
    const ends = new Date(T0 + 90 * DAY)
    expect(await overrides()).toEqual([
      { userId: 'm-kept', permission: 'platform:kali_terminal', effect: 'grant', reason: 'kept from 7.7.x', expiresAt: ends, grantedById: 'adm' },
      { userId: 'm-kept', permission: 'platform:tunnels', effect: 'grant', reason: 'kept from 7.7.x', expiresAt: ends, grantedById: 'adm' },
    ])
    expect(await db.user.findMany({ orderBy: { id: 'asc' }, select: { id: true, legacyGrants: true, updatedAt: true } })).toEqual(before)
    const markers = await db.auditLog.findMany({ where: { action: MARKER_ACTION } })
    expect(markers.map((m) => [m.targetType, m.source, (m.after as Record<string, unknown>).converted])).toEqual([['system', 'system', 2]])
  })

  test('three webapp copies booting together convert once', async () => {
    const copies = [1, 2, 3].map(() => new PrismaClient({ datasources: { db: { url: URL } } }))
    try {
      const results = await Promise.all(copies.map((c) => backfillRbacLegacyOverrides(c, ON, { now: () => new Date(T0) })))
      expect(results.map((r) => r.converted).sort()).toEqual([0, 0, 2])
      expect(await db.userPermissionOverride.count()).toBe(2)
      expect(await db.auditLog.count({ where: { action: MARKER_ACTION } })).toBe(1)
    } finally {
      await Promise.all(copies.map((c) => c.$disconnect()))
    }
  })

  test('a downgrade dropped the overrides: the next boot writes them again, ending when the first ones did', async () => {
    await backfillRbacLegacyOverrides(db, ON, { now: () => new Date(T0) })
    await db.$executeRawUnsafe('TRUNCATE user_permission_overrides')
    const again = await backfillRbacLegacyOverrides(db, ON, { now: () => new Date(T0 + 20 * DAY) })
    expect(again).toMatchObject({ marker: true, converted: 2 })
    expect((await overrides()).map((o) => o.expiresAt)).toEqual([new Date(T0 + 90 * DAY), new Date(T0 + 90 * DAY)])
  })

  test('switch off → nothing read or written', async () => {
    expect(await backfillRbacLegacyOverrides(db, { RBAC_IDENTITY_ENABLED: 'true' } as unknown as NodeJS.ProcessEnv)).toEqual({ ran: false })
    expect(await db.userPermissionOverride.count()).toBe(0)
    expect(await db.auditLog.count({ where: { action: MARKER_ACTION } })).toBe(0)
  })
})
