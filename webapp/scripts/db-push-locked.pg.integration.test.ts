/**
 * The boot `prisma db push` behind its advisory lock (scripts/db-push-locked.mjs), on a real
 * Postgres with the real Prisma CLI: two webapp copies booting together over an older
 * database must both come up.
 *
 * Without the lock, two pushes of a schema that adds columns both ALTER the same table and
 * one fails with "column ... already exists" (or "relation ... already exists"), which the
 * entrypoint turns into a container exit. With it, the second copy waits, then finds the
 * schema in sync and pushes nothing.
 *
 * Each run creates a THROWAWAY database next to the one PLUGINS_PG_TEST_URL names (the
 * role needs CREATEDB), pushes a small schema of its own into it, and drops it after: the
 * database the variable names is never pushed to. Run:
 *   PLUGINS_PG_TEST_URL=postgresql://... npx vitest run --no-file-parallelism scripts/db-push-locked.pg.integration.test.ts
 * Without the variable it is skipped. Needs webapp/node_modules (the Prisma CLI).
 *
 * @vitest-environment node
 */
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'
import { LOCK_NAME, singleConnectionUrl } from './db-push-locked.mjs'

const URL_ = process.env.PLUGINS_PG_TEST_URL
const WEBAPP = path.resolve(__dirname, '..')
const DB_NAME = `db_push_lock_${process.pid}_${Date.now().toString(36)}`

const DATASOURCE = 'datasource db {\n  provider = "postgresql"\n  url      = env("DATABASE_URL")\n}\n'
// What the new image's schema adds over the database: three columns and a table.
const NEW_SCHEMA = `${DATASOURCE}
model Probe {
  id    Int      @id
  name  String
  note  String?
  score Int      @default(0)
  tags  String[] @default([])
  @@map("probe")
}
model ProbeEvent {
  id      Int    @id @default(autoincrement())
  probeId Int    @map("probe_id")
  kind    String
  @@index([probeId])
  @@map("probe_event")
}
`
// A push Prisma refuses: a required column with no default over a table holding a row.
const REFUSED_SCHEMA = `${DATASOURCE}
model Probe {
  id       Int    @id
  name     String
  required String
  @@map("probe")
}
`

let admin: PrismaClient
let db: PrismaClient
let holder: PrismaClient
let dbUrl = ''
let dir = ''
let newSchema = ''
let refusedSchema = ''

type Run = { code: number | null; out: string }

/** One webapp copy's boot push: the wrapper as the startup list runs it. */
function bootPush(schema: string): Promise<Run> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath,
      ['scripts/db-push-locked.mjs', 'db', 'push', '--skip-generate', '--accept-data-loss', '--schema', schema],
      { cwd: WEBAPP, env: { ...process.env, DATABASE_URL: dbUrl, CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1' } })
    let out = ''
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { out += d })
    child.on('close', (code) => resolve({ code, out }))
  })
}

async function columns(table: string) {
  const rows = await db.$queryRaw<{ c: string }[]>`SELECT column_name AS c FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = ${table} ORDER BY 1`
  return rows.map((r) => r.c)
}

async function advisoryLocks(granted: boolean) {
  const [{ n }] = await admin.$queryRaw<{ n: number }[]>`SELECT count(*)::int AS n FROM pg_locks l
    JOIN pg_database d ON d.oid = l.database
    WHERE l.locktype = 'advisory' AND l.granted = ${granted} AND d.datname = ${DB_NAME}`
  return n
}

const UPGRADED = ['id', 'name', 'note', 'score', 'tags']

describe.skipIf(!URL_)('db-push-locked on a real Postgres (PLUGINS_PG_TEST_URL)', () => {
  beforeAll(async () => {
    const u = new URL(URL_!)
    u.pathname = `/${DB_NAME}`
    if (u.searchParams.has('schema')) u.searchParams.delete('schema')
    dbUrl = u.toString()
    if (dbUrl === URL_) throw new Error('Refusing to run: the throwaway database URL equals PLUGINS_PG_TEST_URL')

    admin = new PrismaClient({ datasources: { db: { url: URL_ } } })
    await admin.$executeRawUnsafe(`CREATE DATABASE ${DB_NAME}`)
    db = new PrismaClient({ datasources: { db: { url: dbUrl } } })
    // Another copy mid-push: a session of its own holding the wrapper's lock.
    holder = new PrismaClient({ datasources: { db: { url: singleConnectionUrl(dbUrl) } } })

    dir = mkdtempSync(path.join(os.tmpdir(), 'db-push-lock-'))
    newSchema = path.join(dir, 'new.prisma')
    refusedSchema = path.join(dir, 'refused.prisma')
    writeFileSync(newSchema, NEW_SCHEMA)
    writeFileSync(refusedSchema, REFUSED_SCHEMA)
  }, 30_000)

  beforeEach(async () => {
    // The older database: the table without the new columns, holding one row.
    await db.$executeRawUnsafe('DROP SCHEMA IF EXISTS public CASCADE')
    await db.$executeRawUnsafe('CREATE SCHEMA public')
    await db.$executeRawUnsafe('CREATE TABLE probe (id integer PRIMARY KEY, name text NOT NULL)')
    await db.$executeRawUnsafe(`INSERT INTO probe VALUES (1, 'kept')`)
  })

  afterAll(async () => {
    await holder?.$disconnect()
    await db?.$disconnect()
    if (admin) {
      await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS ${DB_NAME} WITH (FORCE)`)
      await admin.$disconnect()
    }
    if (dir) rmSync(dir, { recursive: true, force: true })
  }, 30_000)

  test('two copies pushing new columns at once both exit 0; the columns arrive and the row stays', async () => {
    // A bare push loses this race often but not always, so it runs three times.
    for (let round = 1; round <= 3; round++) {
      if (round > 1) {
        await db.$executeRawUnsafe('DROP TABLE IF EXISTS probe_event')
        await db.$executeRawUnsafe('ALTER TABLE probe DROP COLUMN IF EXISTS note, DROP COLUMN IF EXISTS score, DROP COLUMN IF EXISTS tags')
      }
      const [a, b] = await Promise.all([bootPush(newSchema), bootPush(newSchema)])
      expect({ round, a: a.code, b: b.code }, `${a.out}\n----\n${b.out}`).toEqual({ round, a: 0, b: 0 })
      expect(await columns('probe')).toEqual(UPGRADED)
      expect(await columns('probe_event')).toEqual(['id', 'kind', 'probe_id'])
      expect(await db.$queryRaw`SELECT id, name FROM probe`).toEqual([{ id: 1, name: 'kept' }])
      expect(await advisoryLocks(true)).toBe(0)
    }
  }, 120_000)

  test('a copy that finds the lock held waits for it, pushing nothing meanwhile, then finds the schema in sync', async () => {
    await holder.$executeRaw`SELECT pg_advisory_lock(hashtext(${LOCK_NAME}))`
    const runs = [bootPush(newSchema), bootPush(newSchema)]
    try {
      let waiting = 0
      for (let i = 0; i < 120 && waiting < 2; i++) {
        waiting = await advisoryLocks(false)
        if (waiting < 2) await new Promise((r) => setTimeout(r, 250))
      }
      expect(waiting, 'both copies wait on the lock the holder has').toBe(2)
      expect(await columns('probe')).toEqual(['id', 'name'])
    } finally {
      await holder.$queryRaw`SELECT pg_advisory_unlock(hashtext(${LOCK_NAME}))`
      // Also on a failed assertion: two pushes left running would race the next test.
      await Promise.allSettled(runs)
    }
    const [a, b] = await Promise.all(runs)
    expect([a.code, b.code], `${a.out}\n----\n${b.out}`).toEqual([0, 0])
    for (const r of [a, b]) expect(r.out).toMatch(/\[db-push\] another webapp copy is pushing the schema; waiting/)
    // One of them pushed; the other found nothing left to do.
    expect([a.out, b.out].filter((o) => /already in sync/i.test(o))).toHaveLength(1)
    expect(await columns('probe')).toEqual(UPGRADED)
    expect(await advisoryLocks(true)).toBe(0)
  }, 120_000)

  test('a push that fails exits non-zero and leaves the lock free for the next copy', async () => {
    const refused = await bootPush(refusedSchema)
    expect(refused.code, refused.out).not.toBe(0)
    expect(refused.out).toMatch(/required column `required`/)
    expect(await advisoryLocks(true)).toBe(0)
    expect(await columns('probe')).toEqual(['id', 'name'])

    const next = await bootPush(newSchema)
    expect(next.code, next.out).toBe(0)
    expect(next.out).not.toMatch(/waiting/)
    expect(await columns('probe')).toEqual(UPGRADED)
  }, 120_000)
})
