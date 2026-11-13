/**
 * The upgrade preview of the RBAC hardening (HD-31, DV-32) on a real Postgres: its one
 * transaction is read-only, it leaves every row as it found it, it reads no secret, it runs
 * on the 7.7.x schema (no `users.legacy_grants`, no `instance_settings`), the grants it lists
 * are the ones the legacy-grants backfill then writes, and it names Root from the instance
 * settings row (step 2.13). Its `--downgrade` report (step 7.2) reads the full schema read-only,
 * counts every table and column a downgrade to 7.7.2 drops, and its `instance/` model reset runs.
 *
 * Needs a DISPOSABLE database holding the webapp schema (`prisma db push`); it empties
 * `audit_log`, `user_settings`, `users` (CASCADE) and `instance_settings` between tests, drops and
 * re-adds `users.legacy_grants` in one of them and renames `instance_settings` away and back in
 * another. Run:
 *   PLUGINS_PG_TEST_URL=postgresql://... npx vitest run --no-file-parallelism scripts/rbac-upgrade-preview.pg.integration.test.ts
 * Without the variable it is skipped. It refuses a database that already holds users
 * unless that database carries the pg-integration marker table.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'
import { backfillRbacLegacyGrants } from './backfill-rbac-legacy-grants.mjs'
import {
  instanceModelResetSql, previewRbacDowngrade, previewRbacUpgrade, readDowngradeState, readUpgradeState,
} from './rbac-upgrade-preview.mjs'

const URL = process.env.PLUGINS_PG_TEST_URL
const MARKER = 'plugins_pg_integration_test_marker'
const db = URL ? new PrismaClient({ datasources: { db: { url: URL } } }) : (null as unknown as PrismaClient)

const T0 = new Date('2026-01-01T00:00:00.000Z')
const PW = '$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42'
const SECRETS = ['fake-ngrok-pg-0001', 'fake-user:fake-pass-pg', 'fake-bearer-pg-0001', 'fake-env-value-pg', PW]
const ENV = { SCANNER_API_KEY: 'b'.repeat(64) }

async function user(id: string, role: string, password: string) {
  await db.user.create({ data: { id, name: id, email: `${id}@example.invalid`, role, password, createdAt: T0 } })
}

/** Every row of the three tables the preview reads, as text, in a fixed order. */
async function snapshot() {
  return db.$queryRawUnsafe<{ t: string }[]>(
    `SELECT 'u' || row_to_json(u)::text AS t FROM users u
     UNION ALL SELECT 's' || row_to_json(s)::text FROM user_settings s
     UNION ALL SELECT 'a' || row_to_json(a)::text FROM audit_log a
     UNION ALL SELECT 'i' || row_to_json(i)::text FROM instance_settings i
     ORDER BY 1`,
  )
}

const grantsOf = async (id: string) => (await db.user.findUniqueOrThrow({ where: { id }, select: { legacyGrants: true } })).legacyGrants
const predicted = (r: { grants: { id: string; grants: string[] }[] }) =>
  Object.fromEntries(r.grants.map((a) => [a.id, a.grants]))

describe.skipIf(!URL)('the RBAC upgrade preview on a real Postgres (PLUGINS_PG_TEST_URL)', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(async () => {
    await db.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS legacy_grants text[] NOT NULL DEFAULT '{}'`)
    await db.$executeRawUnsafe('TRUNCATE audit_log, user_settings, users, instance_settings CASCADE')
    await user('admin', 'admin', PW)
    await user('alice', 'standard', PW)
    await user('tunnel', 'standard', PW)
    await user('managed', 'standard', '')
    await db.userSettings.createMany({
      data: [
        { userId: 'admin', chiselAuth: SECRETS[1] },
        { userId: 'tunnel', tunnelsEnabled: true, ngrokAuthtoken: SECRETS[0] },
        {
          userId: 'managed',
          mcpServers: [
            { id: 'local', name: 'local', transport: 'stdio', command: 'true', env: { K: SECRETS[3] } },
            { id: 'exfil', name: 'exfil', transport: 'sse', url: 'https://mcp.example.invalid/sse', auth: { type: 'bearer', token_env_var: 'INTERNAL_API_KEY' } },
            { id: 'literal', name: 'literal', transport: 'sse', url: 'https://mcp.example.invalid/sse', auth: { type: 'bearer', token: SECRETS[2] } },
          ],
        },
      ],
    })
  })

  afterAll(async () => {
    await db?.$executeRawUnsafe(`ALTER TABLE users ADD COLUMN IF NOT EXISTS legacy_grants text[] NOT NULL DEFAULT '{}'`)
    await db?.$executeRawUnsafe(
      `DO $$ BEGIN IF to_regclass('instance_settings_hidden') IS NOT NULL THEN ALTER TABLE instance_settings_hidden RENAME TO instance_settings; END IF; END $$`,
    )
    await db?.$disconnect()
  })

  test('opens a read-only transaction: a write inside it is refused', async () => {
    let refusal: unknown = null
    const probe = {
      $transaction: (fn: (tx: unknown) => Promise<unknown>, opts: unknown) => db.$transaction(async (tx) => {
        const state = await fn(tx)
        refusal = await tx.$executeRawUnsafe(`UPDATE users SET name = name`).then(() => null, (e: Error) => e.message)
        return state
      }, opts as { timeout: number }),
    }
    await readUpgradeState(probe)
    expect(String(refusal)).toMatch(/read-only transaction/)
  })

  test('leaves every row as it found it', async () => {
    await db.$executeRawUnsafe(`INSERT INTO instance_settings (id, root_user_id, updated_at) VALUES ('instance', 'admin', now())`)
    const before = await snapshot()
    await previewRbacUpgrade(db, { env: ENV, templateFiles: 0 })
    expect(await snapshot()).toEqual(before)
  })

  test('reads no secret value', async () => {
    const state = JSON.stringify(await readUpgradeState(db))
    for (const s of SECRETS) expect(state).not.toContain(s)
    const r = await previewRbacUpgrade(db, { env: ENV, templateFiles: 0 })
    for (const s of SECRETS) expect(r.text).not.toContain(s)
    expect(r.text).toMatch(/managed@example\.invalid\s+local/)
    expect(r.text).toMatch(/managed@example\.invalid\s+exfil \(INTERNAL_API_KEY\)/)
  })

  test('works when the new columns are absent (the 7.7.x schema)', async () => {
    await db.$executeRawUnsafe('ALTER TABLE users DROP COLUMN legacy_grants')
    const r = await previewRbacUpgrade(db, { env: ENV, templateFiles: 0 })
    expect(predicted(r)).toEqual({
      alice: ['kali_terminal', 'shell_sessions'],
      tunnel: ['kali_terminal', 'shell_sessions', 'tunnels'],
    })
    expect(r.review).toBe(true)
  })

  test('lists grants exactly as the backfill writes them, then reports the hardening in place', async () => {
    const r = await previewRbacUpgrade(db, { env: ENV, templateFiles: 0 })
    await backfillRbacLegacyGrants(db)
    for (const id of ['admin', 'alice', 'tunnel', 'managed']) {
      expect(await grantsOf(id), id).toEqual(predicted(r)[id] ?? [])
    }
    const again = await previewRbacUpgrade(db, { env: ENV, templateFiles: 0 })
    expect(again.applied).toBe(true)
    expect(again.review).toBe(false)
  })

  test('names Root and the instance settings sources, from instance_settings and without that table', async () => {
    const before = await previewRbacUpgrade(db, { env: ENV, templateFiles: 0 })
    expect(before.text).toMatch(/Root: admin@example\.invalid, the only admin with a password, chosen automatically/)
    expect(before.text).toMatch(/tunnel\s+tunnel@example\.invalid \(member\), saved \d{4}-\d{2}-\d{2}/)
    expect(before.text).toMatch(/TrafficMind, egress, SCA\s+admin@example\.invalid, saved/)

    await db.$executeRawUnsafe(
      `INSERT INTO instance_settings (id, root_user_id, root_confirmed_at, updated_at) VALUES ('instance', 'admin', now(), now())`,
    )
    expect((await previewRbacUpgrade(db, { env: ENV, templateFiles: 0 })).text).toMatch(/Root: admin@example\.invalid \(confirmed\)\./)

    await db.$executeRawUnsafe('ALTER TABLE instance_settings RENAME TO instance_settings_hidden')
    try {
      const old = await previewRbacUpgrade(db, { env: ENV, templateFiles: 0 })
      expect(old.text).toMatch(/Root: admin@example\.invalid, the only admin with a password/)
    } finally {
      await db.$executeRawUnsafe('ALTER TABLE instance_settings_hidden RENAME TO instance_settings')
    }
  })

  test('the downgrade report: read-only, every dropped table and column counted, the instance models; the reset leaves none', async () => {
    const MODEL = 'instance/prov-pg/gpt-x'
    await db.$executeRawUnsafe(
      `INSERT INTO instance_settings (id, root_user_id, default_member_set_id, updated_at) VALUES ('instance', 'admin', 'builtin:recon-operator', now())`,
    )
    await db.$executeRawUnsafe(`UPDATE users SET status = 'disabled', password_on_hold = $1, session_version = 1 WHERE id = 'managed'`, PW)
    await db.$executeRawUnsafe(`INSERT INTO user_permission_sets (user_id, set_id) VALUES ('alice', 'builtin:read-only-analyst')`)
    await db.$executeRawUnsafe(
      `INSERT INTO user_sessions (id, user_id, session_version, expires_at, revoked_at) VALUES ('pg-s1', 'alice', 0, now() + interval '1 day', now())`,
    )
    await db.project.create({ data: { id: 'pg-p1', name: 'Instance project', userId: 'alice', agentOpenaiModel: MODEL } })
    await db.userProjectPreset.create({ data: { userId: 'alice', name: 'Fast', settings: { agentOpenaiModel: MODEL, naabuThreads: 10 } } })
    await db.userTradecraftResource.create({ data: { userId: 'alice', name: 'blog', slug: 'blog', url: 'https://blog.example.invalid', llmModel: MODEL } })
    const rows = async () => db.$queryRawUnsafe<{ t: string }[]>(
      `SELECT 'p' || row_to_json(p)::text AS t FROM projects p
       UNION ALL SELECT 'r' || row_to_json(r)::text FROM user_project_presets r
       UNION ALL SELECT 'c' || row_to_json(c)::text FROM user_tradecraft_resources c
       UNION ALL SELECT 's' || row_to_json(s)::text FROM user_sessions s ORDER BY 1`,
    )
    const before = [await snapshot(), await rows()]

    let refusal: unknown = null
    const probe = {
      $transaction: (fn: (tx: unknown) => Promise<unknown>, opts: unknown) => db.$transaction(async (tx) => {
        const state = await fn(tx)
        refusal = await tx.$executeRawUnsafe(`UPDATE users SET name = name`).then(() => null, (e: Error) => e.message)
        return state
      }, opts as { timeout: number }),
    }
    await readDowngradeState(probe)
    expect(String(refusal)).toMatch(/read-only transaction/)

    const r = await previewRbacDowngrade(db, { env: { RBAC_IDENTITY_ENABLED: 'true', RBAC_PERMISSIONS_ENABLED: 'true' } })
    expect([await snapshot(), await rows()]).toEqual(before)
    for (const s of SECRETS) expect(r.text).not.toContain(s)
    expect(r.review).toBe(true)
    expect(r.text).not.toMatch(/not in this database/)
    expect(r.text).toMatch(/instance_settings\s+1 row\s/)
    expect(r.text).toMatch(/user_sessions\s+1 row\s/)
    expect(r.text).toMatch(/quota_usage\s+0 rows\s/)
    expect(r.text).toMatch(/users\.status\s+1 row\s/)
    expect(r.text).toMatch(/users\.password_on_hold\s+1 row\s/)
    expect(r.text).toMatch(/projects\.naabu_run_timeout\s+0 rows\s/)
    expect(r.text).toMatch(/alice@example\.invalid\s+permission set Read-only analyst/)
    expect(r.text).toMatch(/tunnel@example\.invalid\s+the instance default set Recon operator/)
    expect(r.text).toMatch(/managed@example\.invalid\s+disabled/)
    expect(r.text).toMatch(/1 device session revoked/)
    expect(r.text).toMatch(/Instance project \(alice@example\.invalid\)\s+agent model/)
    expect(r.text).toMatch(/1 tradecraft resource/)
    expect(r.text).toMatch(/1 saved preset: Fast/)

    for (const sql of instanceModelResetSql()) await db.$executeRawUnsafe(sql)
    const fresh = await db.project.create({ data: { id: 'pg-p2', name: 'Fresh', userId: 'alice' } })
    const reset = await db.project.findUniqueOrThrow({ where: { id: 'pg-p1' } })
    expect(reset.agentOpenaiModel).toBe(fresh.agentOpenaiModel)
    const [preset] = await db.userProjectPreset.findMany({ where: { userId: 'alice' } })
    expect(preset.settings).toEqual({ naabuThreads: 10 })
    const [resource] = await db.userTradecraftResource.findMany({ where: { userId: 'alice' } })
    expect(resource.llmModel).toBe('')
    expect((await previewRbacDowngrade(db, { env: {} })).sections.map((s: { id: string }) => s.id)).not.toContain('instance_models')
  })
})
