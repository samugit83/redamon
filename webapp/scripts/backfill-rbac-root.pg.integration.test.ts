/**
 * The boot-time Root recognition (step 2.5, ID-09, ID-02, DV-26) on a real Postgres: the
 * oldest admin with a password becomes the automatic, unconfirmed Root with its
 * `system.rbac_root_assigned` row; three copies booting together, and the host's
 * create-admin claim taking the same lock, never make two; a stale Root id is chosen again.
 *
 * Needs a DISPOSABLE database holding the webapp schema (`prisma db push`); it empties
 * `audit_log`, `instance_settings` and `users` (CASCADE) between tests. Run:
 *   PLUGINS_PG_TEST_URL=postgresql://... npx vitest run --no-file-parallelism scripts/backfill-rbac-root.pg.integration.test.ts
 * Without the variable it is skipped. It refuses a database that already holds users
 * unless that database carries the pg-integration marker table.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'
import { ASSIGNED_ACTION, backfillRbacRoot } from './backfill-rbac-root.mjs'

const URL = process.env.PLUGINS_PG_TEST_URL
const MARKER = 'plugins_pg_integration_test_marker'
const db = URL ? new PrismaClient({ datasources: { db: { url: URL } } }) : (null as unknown as PrismaClient)

const PW = '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42'
const T = (day: number) => new Date(Date.UTC(2026, 0, day, 9))

async function user(id: string, role: string, createdAt: Date, password = PW) {
  await db.user.create({ data: { id, name: id, email: `${id}@example.invalid`, role, password, createdAt } })
}
const root = async () => db.instanceSettings.findUnique({
  where: { id: 'instance' }, select: { rootUserId: true, rootConfirmedAt: true, rootAssignedBy: true },
})

describe.skipIf(!URL)('backfillRbacRoot on a real Postgres (PLUGINS_PG_TEST_URL)', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(async () => {
    await db.$executeRawUnsafe('TRUNCATE audit_log, instance_settings, users CASCADE')
    await user('adm-young', 'admin', T(9))
    await user('adm-old', 'admin', T(2))
    await user('adm-nopw', 'admin', T(1), '')
    await user('mem', 'standard', T(1))
  })

  afterAll(async () => {
    await db?.$disconnect()
  })

  test('the oldest admin with a password becomes the automatic, unconfirmed Root, with its row', async () => {
    expect(await backfillRbacRoot(db)).toEqual({ assigned: true, userId: 'adm-old', rule: 'oldest_admin', candidateCount: 2 })
    expect(await root()).toEqual({ rootUserId: 'adm-old', rootConfirmedAt: null, rootAssignedBy: 'automatic' })
    const rows = await db.auditLog.findMany({ where: { action: ASSIGNED_ACTION } })
    expect(rows.map((r) => [r.targetId, r.source, r.after])).toEqual([
      ['adm-old', 'system', { userId: 'adm-old', rule: 'oldest_admin', candidateCount: 2 }],
    ])
  })

  test('three webapp copies booting together choose one Root (lock + conditional update)', async () => {
    const copies = [1, 2, 3].map(() => new PrismaClient({ datasources: { db: { url: URL } } }))
    try {
      const results = await Promise.all(copies.map((c) => backfillRbacRoot(c)))
      expect(results.filter((r) => r.assigned)).toHaveLength(1)
      expect(await db.auditLog.count({ where: { action: ASSIGNED_ACTION } })).toBe(1)
      expect((await root())?.rootUserId).toBe('adm-old')
    } finally {
      await Promise.all(copies.map((c) => c.$disconnect()))
    }
  })

  test("a boot racing the host's create-admin claim (same lock) never makes a second Root", async () => {
    const host = new PrismaClient({ datasources: { db: { url: URL } } })
    try {
      // create-admin.mjs's claim, in its own transaction under the same key; the boot starts
      // once the claim holds the lock.
      let held!: () => void
      const locked = new Promise<void>((r) => { held = r })
      const claim = host.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('rbac-root'))`
        held()
        await tx.$executeRaw`
          INSERT INTO instance_settings (id, root_user_id, root_confirmed_at, root_assigned_by, updated_at)
          VALUES ('instance', 'adm-young', now(), 'install', now())
          ON CONFLICT (id) DO UPDATE SET root_user_id = EXCLUDED.root_user_id, root_confirmed_at = now(),
            root_assigned_by = 'install', updated_at = now()
          WHERE instance_settings.root_user_id IS NULL`
        await new Promise((r) => setTimeout(r, 300))
      })
      await locked
      const boot = await backfillRbacRoot(db)
      await claim
      expect(boot).toEqual({ assigned: false, rootUserId: 'adm-young' })
      expect(await root()).toMatchObject({ rootUserId: 'adm-young', rootAssignedBy: 'install' })
      expect(await db.auditLog.count({ where: { action: ASSIGNED_ACTION } })).toBe(0)
    } finally {
      await host.$disconnect()
    }
  })

  test('a Root id that names no account is chosen again; a second boot changes nothing', async () => {
    await db.instanceSettings.create({ data: { id: 'instance', rootUserId: 'gone', rootAssignedBy: 'host', rootConfirmedAt: T(3) } })
    expect((await backfillRbacRoot(db)).userId).toBe('adm-old')
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: 'adm-old' })
    const rows = await db.auditLog.findMany({ where: { action: ASSIGNED_ACTION } })
    expect(rows.map((r) => r.after)).toEqual([{ userId: 'adm-old', rule: 'oldest_admin', candidateCount: 2, previousRootUserId: 'gone' }])
  })

  test('only passwordless admins: no Root and no row', async () => {
    await db.$executeRawUnsafe(`UPDATE users SET password = '' WHERE role = 'admin'`)
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: null, candidateCount: 0 })
    expect(await root()).toBeNull()
    expect(await db.auditLog.count()).toBe(0)
  })
})
