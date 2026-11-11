/**
 * The one-time Nuclei template owner backfill of the RBAC hardening (HD-08, T18), on a
 * real Postgres.
 *
 * Every template file present at the upgrade gets an instance row (no owner); the marker
 * is an AuditLog row written in the rows' transaction, under an advisory lock, so several
 * webapp copies booting together record once; the backfill skips only when the marker AND
 * a row exist, so a downgrade that dropped the table is followed by a second recording,
 * and rows that survived are never changed (`skipDuplicates`).
 *
 * Needs a DISPOSABLE database holding the webapp schema (`prisma db push`); it empties
 * `audit_log` and `nuclei_templates` between tests. Run:
 *   PLUGINS_PG_TEST_URL=postgresql://... npx vitest run --no-file-parallelism scripts/backfill-nuclei-template-owners.pg.integration.test.ts
 * Without the variable it is skipped. It refuses a database that already holds users
 * unless that database carries the pg-integration marker table.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { mkdir, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { PrismaClient } from '@prisma/client'
import { MARKER_ACTION, backfillNucleiTemplateOwners } from './backfill-nuclei-template-owners.mjs'

const URL = process.env.PLUGINS_PG_TEST_URL
const MARKER = 'plugins_pg_integration_test_marker'
const db = URL ? new PrismaClient({ datasources: { db: { url: URL } } }) : (null as unknown as PrismaClient)
const ROOT = `${process.env.TMPDIR || '/tmp'}/redamon-nuclei-backfill-pg-${process.pid}-${Date.now()}`
const template = (id: string) => `id: ${id}\ninfo:\n  name: ${id}\n  severity: low\n`

const owners = async () => (await db.nucleiTemplate.findMany({ orderBy: { path: 'asc' }, select: { path: true, ownerUserId: true } }))
  .map(r => [r.path, r.ownerUserId])
const markers = () => db.auditLog.count({ where: { action: MARKER_ACTION } })

describe.skipIf(!URL)('backfillNucleiTemplateOwners on a real Postgres (PLUGINS_PG_TEST_URL)', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(async () => {
    await db.$executeRawUnsafe('TRUNCATE audit_log, nuclei_templates')
    await rm(ROOT, { recursive: true, force: true })
    await mkdir(path.join(ROOT, 'team'), { recursive: true })
    await writeFile(path.join(ROOT, 'springboot.yaml'), template('springboot'))
    await writeFile(path.join(ROOT, 'team', 'xss.yaml'), template('xss'))
    await writeFile(path.join(ROOT, 'old.yml'), template('old'))
  })

  afterAll(async () => {
    await rm(ROOT, { recursive: true, force: true })
    await db?.$disconnect()
  })

  test('every file present at the upgrade becomes an instance template, with the marker', async () => {
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: true, files: 3, rowsCreated: 3 })
    expect(await owners()).toEqual([['old.yml', null], ['springboot.yaml', null], ['team/xss.yaml', null]])
    const row = await db.nucleiTemplate.findUniqueOrThrow({ where: { path: 'springboot.yaml' } })
    expect(row.sizeBytes).toBe(template('springboot').length)
    expect(row.sha256).toMatch(/^[0-9a-f]{64}$/)
    const marker = await db.auditLog.findFirstOrThrow({ where: { action: MARKER_ACTION } })
    expect(marker).toMatchObject({ targetType: 'system', source: 'system', after: { files: 3, rowsCreated: 3 } })
  })

  test('a second boot is a no-op, and a member\'s later upload is never touched', async () => {
    await backfillNucleiTemplateOwners(db, ROOT)
    await writeFile(path.join(ROOT, 'member.yaml'), template('member'))
    await db.nucleiTemplate.create({ data: { path: 'member.yaml', ownerUserId: 'member-a' } })
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: false })
    expect(await markers()).toBe(1)
    expect((await db.nucleiTemplate.findUniqueOrThrow({ where: { path: 'member.yaml' } })).ownerUserId).toBe('member-a')
  })

  test('three copies booting together record once', async () => {
    const copies = [1, 2, 3].map(() => new PrismaClient({ datasources: { db: { url: URL } } }))
    try {
      const results = await Promise.all(copies.map(c => backfillNucleiTemplateOwners(c, ROOT)))
      expect(results.filter(r => r.done)).toHaveLength(1)
      expect(await markers()).toBe(1)
      expect(await db.nucleiTemplate.count()).toBe(3)
    } finally {
      await Promise.all(copies.map(c => c.$disconnect()))
    }
  })

  test('rows gone under a surviving marker (a downgrade dropped the table) are recorded again, once', async () => {
    await backfillNucleiTemplateOwners(db, ROOT)
    await db.$executeRawUnsafe('TRUNCATE nuclei_templates')
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: true, files: 3, rowsCreated: 3 })
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: false })
    expect(await markers()).toBe(2)
  })

  test('a row that survived keeps its owner; only the missing files are added', async () => {
    await db.nucleiTemplate.create({ data: { path: 'springboot.yaml', ownerUserId: 'member-a', sha256: 'kept' } })
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: true, files: 3, rowsCreated: 2 })
    expect(await db.nucleiTemplate.findUniqueOrThrow({ where: { path: 'springboot.yaml' } }))
      .toMatchObject({ ownerUserId: 'member-a', sha256: 'kept' })
  })
})
