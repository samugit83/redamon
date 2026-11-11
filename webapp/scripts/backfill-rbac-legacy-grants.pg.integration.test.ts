/**
 * The one-time legacy-grants backfill of the RBAC hardening (HD-28, DV-26), on a real
 * Postgres.
 *
 * Every non-admin account with a password that existed when the hardened code first
 * started keeps the Kali terminal and the shell sessions; one whose settings configure a
 * tunnel (an ngrok token, or a chisel URL with or without auth) keeps tunnels too. Admins,
 * passwordless accounts and accounts created after the cutoff get nothing. `updated_at`
 * does not move. The marker is an AuditLog row written in the grants' transaction, under
 * an advisory lock; the backfill skips only when the marker AND the grants exist, so a
 * downgrade that dropped the column is followed by a re-derivation that leaves out every
 * grant an admin removed.
 *
 * Needs a DISPOSABLE database holding the webapp schema (`prisma db push`); it empties
 * `audit_log`, `user_settings` and `users` (CASCADE) between tests and drops and re-adds
 * `users.legacy_grants` in one of them. Run:
 *   PLUGINS_PG_TEST_URL=postgresql://... npx vitest run --no-file-parallelism scripts/backfill-rbac-legacy-grants.pg.integration.test.ts
 * Without the variable it is skipped. It refuses a database that already holds users
 * unless that database carries the pg-integration marker table.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'
import {
  CUTOFF_ACTION, MARKER_ACTION, REMOVE_ACTION, backfillRbacLegacyGrants,
} from './backfill-rbac-legacy-grants.mjs'

const URL = process.env.PLUGINS_PG_TEST_URL
const MARKER = 'plugins_pg_integration_test_marker'
const db = URL ? new PrismaClient({ datasources: { db: { url: URL } } }) : (null as unknown as PrismaClient)

const T0 = new Date('2026-01-01T00:00:00.000Z')
const PW = '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42'
const TERMINAL_AND_SESSIONS = ['kali_terminal', 'shell_sessions']
const ALL = ['kali_terminal', 'shell_sessions', 'tunnels']

async function user(id: string, role: string, password: string, createdAt = T0) {
  await db.user.create({ data: { id, name: id, email: `${id}@example.invalid`, role, password, createdAt } })
  // A known past updated_at, so a write that moved it is visible.
  await db.$executeRaw`UPDATE users SET updated_at = ${T0} WHERE id = ${id}`
}

const grantsOf = async (id: string) => (await db.user.findUniqueOrThrow({ where: { id }, select: { legacyGrants: true } })).legacyGrants
const updatedAt = async (id: string) => (await db.user.findUniqueOrThrow({ where: { id }, select: { updatedAt: true } })).updatedAt

describe.skipIf(!URL)('backfillRbacLegacyGrants on a real Postgres (PLUGINS_PG_TEST_URL)', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(async () => {
    await db.$executeRawUnsafe('TRUNCATE audit_log, user_settings, users CASCADE')
    await user('admin', 'admin', PW)
    await user('alice', 'standard', PW)
    await user('ngrok', 'standard', PW)
    await user('chisel', 'standard', PW)
    await user('managed', 'standard', '')
    await db.userSettings.createMany({
      data: [
        { userId: 'admin', ngrokAuthtoken: 'fake-ngrok-admin' },
        { userId: 'alice', chiselAuth: 'fake-user:fake-pass' },
        { userId: 'ngrok', ngrokAuthtoken: 'fake-ngrok-0001' },
        { userId: 'chisel', chiselServerUrl: 'https://chisel.example.invalid:8443' },
        { userId: 'managed', ngrokAuthtoken: 'fake-ngrok-0002' },
      ],
    })
  })

  afterAll(async () => {
    await db?.$disconnect()
  })

  test('members with a password get terminal and sessions; tunnel holders tunnels; admins and passwordless nothing', async () => {
    await backfillRbacLegacyGrants(db)
    expect(await grantsOf('alice')).toEqual(TERMINAL_AND_SESSIONS)
    expect(await grantsOf('ngrok')).toEqual(ALL)
    expect(await grantsOf('chisel')).toEqual(ALL)
    expect(await grantsOf('admin')).toEqual([])
    expect(await grantsOf('managed')).toEqual([])
  })

  test('updated_at never moves: a grant is not an edit of the account', async () => {
    await backfillRbacLegacyGrants(db)
    for (const id of ['admin', 'alice', 'ngrok', 'chisel', 'managed']) {
      expect((await updatedAt(id)).toISOString(), id).toBe(T0.toISOString())
    }
  })

  test('the marker row records how many accounts hold each grant, and the result says the same', async () => {
    const result = await backfillRbacLegacyGrants(db)
    expect(result).toEqual({ done: true, kali_terminal: 3, shell_sessions: 3, tunnels: 2, usersChanged: 3 })
    const markers = await db.auditLog.findMany({ where: { action: MARKER_ACTION } })
    expect(markers).toHaveLength(1)
    expect(markers[0]).toMatchObject({
      action: 'system.rbac_legacy_grants_backfill', targetType: 'system', source: 'system', actorId: null,
      after: { kali_terminal: 3, shell_sessions: 3, tunnels: 2 },
    })
  })

  test('a user created after the cutoff gets nothing', async () => {
    await user('late', 'standard', PW, new Date(Date.now() + 86_400_000))
    await backfillRbacLegacyGrants(db)
    expect(await grantsOf('late')).toEqual([])
    const cutoff = await db.auditLog.findFirstOrThrow({ where: { action: CUTOFF_ACTION } })
    expect(cutoff.createdAt.getTime()).toBeLessThan(Date.now() + 86_400_000)
  })

  test('a second run changes nothing: no write, no second marker, one cutoff', async () => {
    await backfillRbacLegacyGrants(db)
    const after1 = await db.user.findMany({ select: { id: true, legacyGrants: true, updatedAt: true }, orderBy: { id: 'asc' } })
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: false })
    const after2 = await db.user.findMany({ select: { id: true, legacyGrants: true, updatedAt: true }, orderBy: { id: 'asc' } })
    expect(after2).toEqual(after1)
    expect(await db.auditLog.count({ where: { action: MARKER_ACTION } })).toBe(1)
    expect(await db.auditLog.count({ where: { action: CUTOFF_ACTION } })).toBe(1)
  })

  test('three webapp copies booting together grant once (the advisory lock)', async () => {
    const results = await Promise.all([backfillRbacLegacyGrants(db), backfillRbacLegacyGrants(db), backfillRbacLegacyGrants(db)])
    expect(results.filter((r) => r.done)).toHaveLength(1)
    expect(results.filter((r) => !r.done)).toHaveLength(2)
    expect(await db.auditLog.count({ where: { action: MARKER_ACTION } })).toBe(1)
    expect(await db.auditLog.count({ where: { action: CUTOFF_ACTION } })).toBe(1)
    expect(await grantsOf('ngrok')).toEqual(ALL)
  })

  test('a downgrade that dropped the column: the re-upgrade grants again, minus what an admin removed', async () => {
    await backfillRbacLegacyGrants(db)
    await db.auditLog.create({
      data: { action: REMOVE_ACTION, targetType: 'user', targetId: 'ngrok', after: { grant: 'tunnels' }, source: 'api' },
    })
    // What the 7.7.x entrypoint's `db push --accept-data-loss` and the next upgrade's push do.
    await db.$executeRawUnsafe('ALTER TABLE users DROP COLUMN legacy_grants')
    await db.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN legacy_grants TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[]`)
    expect(await grantsOf('alice')).toEqual([])

    expect(await backfillRbacLegacyGrants(db)).toMatchObject({ done: true, kali_terminal: 3, tunnels: 1 })
    expect(await grantsOf('alice')).toEqual(TERMINAL_AND_SESSIONS)
    expect(await grantsOf('ngrok')).toEqual(TERMINAL_AND_SESSIONS)
    expect(await grantsOf('chisel')).toEqual(ALL)
    expect(await db.auditLog.count({ where: { action: MARKER_ACTION } })).toBe(2)
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: false })
  })

  test('an existing marker with grants still held means the backfill never runs', async () => {
    await db.auditLog.create({ data: { action: MARKER_ACTION, targetType: 'system', source: 'system', after: { kali_terminal: 1, shell_sessions: 1, tunnels: 0 } } })
    await db.user.update({ where: { id: 'alice' }, data: { legacyGrants: ['kali_terminal'] } })
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: false })
    expect(await grantsOf('ngrok')).toEqual([])
  })
})
