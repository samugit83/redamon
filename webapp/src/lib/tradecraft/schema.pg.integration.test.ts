/**
 * The Tradecraft 2.0 schema on a real Postgres (T1.1): the search objects exist after the
 * push and scripts/apply-tradecraft-search.mjs, the trigger fills the vectors, a second push
 * keeps everything (EX-1), the script is idempotent and safe to run twice at once, and the
 * cascades leave nothing behind (§7.1, R-063, R-087, R-209, R-211, AC-25).
 *
 * Run through the disposable harness, on the session's own database (a copy of the
 * template the harness pushed and ran the script on):
 *   TC_PG_DB=tc_<session> tooling/scripts/tradecraft_pg_testdb.sh web src/lib/tradecraft/schema.pg.integration.test.ts
 * Without TRADECRAFT_PG_TEST_URL (or PLUGINS_PG_TEST_URL) it is skipped. It refuses a
 * database that holds users without the harness's marker table, and its second push runs
 * the real Prisma CLI of webapp/node_modules against that database only.
 *
 * @vitest-environment node
 */
import { spawn } from 'node:child_process'
import path from 'node:path'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { PrismaClient } from '@prisma/client'
import {
  applyTradecraftSearch, ENTRY_TRIGGER, SECTION_TRIGGER, VECTOR_INPUT_MAX_CHARS,
} from '../../../scripts/apply-tradecraft-search.mjs'

const URL_ = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL
const MARKER = 'plugins_pg_integration_test_marker'
const WEBAPP = path.resolve(__dirname, '../../..')
const RUN = `tcs${process.pid}${Date.now().toString(36)}`

const db = URL_ ? new PrismaClient({ datasources: { db: { url: URL_ } } }) : (null as unknown as PrismaClient)

const TABLES_BY_RESOURCE = [
  'tradecraft_ingestion_jobs', 'tradecraft_page_ids', 'tradecraft_entries', 'tradecraft_sections',
  'tradecraft_tree_nodes', 'tradecraft_curations', 'tradecraft_project_choices',
]
const TABLES_BY_USER = ['tradecraft_ingestion_jobs', 'tradecraft_entries', 'tradecraft_sections', 'tradecraft_tree_nodes',
  'tradecraft_user_settings', 'user_tradecraft_resources']

async function count(table: string, column: string, value: string): Promise<number> {
  const rows = await db.$queryRawUnsafe<{ n: number }[]>(`SELECT count(*)::int AS n FROM ${table} WHERE ${column} = $1`, value)
  return rows[0].n
}

async function indexDefs(table: string): Promise<string[]> {
  const rows = await db.$queryRaw<{ indexdef: string }[]>`SELECT indexdef FROM pg_indexes WHERE tablename = ${table}`
  return rows.map(r => r.indexdef)
}

async function triggers(): Promise<string[]> {
  const rows = await db.$queryRaw<{ tgname: string }[]>`
    SELECT tgname FROM pg_trigger WHERE NOT tgisinternal AND tgname IN (${ENTRY_TRIGGER}, ${SECTION_TRIGGER}) ORDER BY tgname`
  return rows.map(r => r.tgname)
}

async function matches(entryId: bigint, query: string): Promise<boolean> {
  const rows = await db.$queryRaw<{ ok: boolean }[]>`
    SELECT search_vector @@ plainto_tsquery('english', ${query}) AS ok FROM tradecraft_entries WHERE id = ${entryId}`
  return rows[0].ok
}

/** A user with one resource, its page IDs, entries, sections, tree, curation, job, settings and a project choice. */
async function seedLibrary(tag: string) {
  const userId = `${RUN}-${tag}-u`
  const projectId = `${RUN}-${tag}-p`
  await db.user.create({ data: { id: userId, name: tag, email: `${userId}@example.invalid` } })
  await db.project.create({ data: { id: projectId, userId, name: tag } })
  await db.tradecraftUserSettings.create({ data: { userId, v2Enabled: true } })
  const resource = await db.userTradecraftResource.create({
    data: { userId, name: tag, slug: `lib-${tag}`, url: `https://${tag}.example.invalid/`, storageMode: 'stored', generation: 1 },
  })
  const page = await db.tradecraftPageId.create({ data: { resourceId: resource.id, url: `https://${tag}.example.invalid/sqli` } })
  const entry = await db.tradecraftEntry.create({
    data: {
      userId, resourceId: resource.id, generation: 1, pageId: page.id, url: page.url, title: 'Kerberoasting attacks',
      breadcrumb: ['Windows', 'Active Directory'], headings: [{ level: 2, text: 'Time based injection' }],
      description: 'Payloads for PostgreSQL', topics: ['active_directory'], entities: ['CVE-2024-23897'],
      storedText: 'fake stored page text', storedBytes: 21,
    },
  })
  await db.tradecraftSection.create({
    data: { entryId: entry.id, resourceId: resource.id, userId, generation: 1, ord: 0, level: 2, heading: 'pg_sleep alternatives', text: 'generate_series heavy query delays' },
  })
  await db.tradecraftTreeNode.create({
    data: { resourceId: resource.id, userId, generation: 1, path: 'Windows/', parentPath: '', label: 'Windows', pageCount: 1 },
  })
  await db.tradecraftCuration.create({ data: { resourceId: resource.id, url: page.url, pinned: true } })
  const job = await db.tradecraftIngestionJob.create({
    data: { userId, resourceId: resource.id, kind: 'refresh', leaseUntil: new Date(Date.now() + 60_000), actorUserId: userId },
  })
  await db.tradecraftIngestionJob.create({ data: { userId, kind: 'convert' } })
  await db.tradecraftProjectChoice.create({ data: { projectId, resourceId: resource.id, createdById: userId } })
  return { userId, projectId, resourceId: resource.id, pageId: page.id, entryId: entry.id, jobId: job.id }
}

function prismaPush(): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath,
      [path.join(WEBAPP, 'node_modules/prisma/build/index.js'), 'db', 'push', '--skip-generate', '--accept-data-loss', '--schema', 'prisma/schema.prisma'],
      { cwd: WEBAPP, env: { ...process.env, DATABASE_URL: URL_, CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1' } })
    let out = ''
    child.stdout.on('data', (d) => { out += d })
    child.stderr.on('data', (d) => { out += d })
    child.on('close', (code) => resolve({ code, out }))
  })
}

describe.skipIf(!URL_)('the Tradecraft 2.0 schema on a real Postgres', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    if (!marked) await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  afterAll(async () => {
    await db?.$executeRawUnsafe(`DELETE FROM users WHERE id LIKE '${RUN}-%'`)
    await db?.$disconnect()
  })

  test('the push and the script created pg_trgm, the GIN and trigram indexes and both triggers', async () => {
    const [{ trgm }] = await db.$queryRaw<{ trgm: boolean }[]>`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') AS trgm`
    expect(trgm).toBe(true)
    const entries = await indexDefs('tradecraft_entries')
    expect(entries.some(d => /USING gin \(search_vector\)/.test(d))).toBe(true)
    expect(entries.some(d => /USING gin \(title gin_trgm_ops\)/.test(d))).toBe(true)
    expect(entries.some(d => /USING gin \(topics\)/.test(d))).toBe(true)
    expect(entries.some(d => /USING gin \(entities\)/.test(d))).toBe(true)
    expect((await indexDefs('tradecraft_sections')).some(d => /USING gin \(search_vector\)/.test(d))).toBe(true)
    expect(await triggers()).toEqual([ENTRY_TRIGGER, SECTION_TRIGGER].sort())
  })

  test('the trigger fills the vectors on insert and on update, with English stemming', async () => {
    const { entryId } = await seedLibrary('fill')
    expect(await matches(entryId, 'kerberoast')).toBe(true)
    expect(await matches(entryId, 'active directory')).toBe(true)
    expect(await matches(entryId, 'time based')).toBe(true)
    expect(await matches(entryId, 'postgresql')).toBe(true)
    expect(await matches(entryId, 'smuggling')).toBe(false)
    await db.tradecraftEntry.update({ where: { id: entryId }, data: { title: 'HTTP request smuggling' } })
    expect(await matches(entryId, 'smuggling')).toBe(true)
    const [section] = await db.$queryRaw<{ ok: boolean }[]>`
      SELECT search_vector @@ plainto_tsquery('english', 'generate series') AS ok FROM tradecraft_sections WHERE entry_id = ${entryId}`
    expect(section.ok).toBe(true)
  })

  test('a section of unique tokens longer than the vector limit is still stored', async () => {
    const { entryId, resourceId, userId } = await seedLibrary('long')
    const text = Array.from({ length: 60_000 }, (_, i) => `tok${i.toString(36)}x${(i * 7919).toString(36)}`).join(' ')
    expect(text.length).toBeGreaterThan(VECTOR_INPUT_MAX_CHARS)
    await db.tradecraftSection.create({ data: { entryId, resourceId, userId, generation: 1, ord: 1, level: 2, text } })
    expect(await db.tradecraftSection.count({ where: { entryId } })).toBe(2)
  })

  test('the script is idempotent, also twice at the same time: a matching trigger is left alone', async () => {
    const other = new PrismaClient({ datasources: { db: { url: URL_ } } })
    try {
      await applyTradecraftSearch(db)
      const both = await Promise.all([applyTradecraftSearch(db), applyTradecraftSearch(other)])
      expect(both).toEqual([[], []])
    } finally {
      await other.$disconnect()
    }
    expect(await triggers()).toEqual([ENTRY_TRIGGER, SECTION_TRIGGER].sort())
  })

  test('an ordinary start takes no lock on the tables: it does not wait for a long write', async () => {
    const { entryId, resourceId, userId } = await seedLibrary('busy')
    const writer = new PrismaClient({ datasources: { db: { url: URL_ } } })
    let release!: () => void
    const held = new Promise<void>((r) => { release = r })
    try {
      // An ingestion writing a generation: a transaction holding ROW EXCLUSIVE on both tables.
      const writing = writer.$transaction(async (tx) => {
        await tx.tradecraftSection.create({ data: { entryId, resourceId, userId, generation: 1, ord: 7, level: 2, text: 'held' } })
        await tx.tradecraftEntry.update({ where: { id: entryId }, data: { title: 'held title' } })
        await held
      }, { timeout: 60_000 })
      await new Promise((r) => setTimeout(r, 300))
      const started = Date.now()
      expect(await applyTradecraftSearch(db)).toEqual([])
      expect(Date.now() - started).toBeLessThan(2_000)
      release()
      await writing
    } finally {
      release?.()
      await writer.$disconnect()
    }
  }, 60_000)

  test('a trigger to restore on a busy table gives up after the lock timeout, and reads never queue behind it', async () => {
    const { entryId, resourceId, userId } = await seedLibrary('defer')
    await db.$executeRawUnsafe(`DROP TRIGGER ${SECTION_TRIGGER} ON tradecraft_sections`)
    const writer = new PrismaClient({ datasources: { db: { url: URL_ } } })
    const reader = new PrismaClient({ datasources: { db: { url: URL_ } } })
    let release!: () => void
    const held = new Promise<void>((r) => { release = r })
    try {
      const writing = writer.$transaction(async (tx) => {
        await tx.tradecraftSection.create({ data: { entryId, resourceId, userId, generation: 1, ord: 8, level: 2, text: 'held' } })
        await held
      }, { timeout: 60_000 })
      await new Promise((r) => setTimeout(r, 300))
      const started = Date.now()
      const applying = applyTradecraftSearch(db).then(() => 'applied', (e: { code?: string; message?: string }) => `refused ${e?.code ?? e?.message}`)
      await new Promise((r) => setTimeout(r, 500))
      // The waiting CREATE OR REPLACE TRIGGER does not stop a read of the table.
      const readStart = Date.now()
      expect(await reader.tradecraftSection.count({ where: { resourceId } })).toBeGreaterThan(0)
      expect(Date.now() - readStart).toBeLessThan(1_500)
      const outcome = await applying
      expect(outcome).toMatch(/^refused/)
      expect(Date.now() - started).toBeLessThan(15_000)
      release()
      await writing
      // With the table free, the next start restores it.
      expect(await applyTradecraftSearch(db)).toEqual([SECTION_TRIGGER])
      expect(await triggers()).toEqual([ENTRY_TRIGGER, SECTION_TRIGGER].sort())
    } finally {
      release?.()
      await writer.$disconnect()
      await reader.$disconnect()
    }
  }, 60_000)

  test('a second push keeps the vectors, the indexes, the extension and the triggers', async () => {
    const { entryId, resourceId, userId, pageId } = await seedLibrary('push')
    const before = await indexDefs('tradecraft_entries')
    const run = await prismaPush()
    // The push drops tables the schema does not declare, the harness's marker among them.
    await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
    expect(run.code, run.out).toBe(0)
    expect(await indexDefs('tradecraft_entries')).toEqual(expect.arrayContaining(before))
    expect(await triggers()).toEqual([ENTRY_TRIGGER, SECTION_TRIGGER].sort())
    expect(await matches(entryId, 'kerberoast')).toBe(true)
    const page = await db.tradecraftPageId.create({ data: { resourceId, url: 'https://push.example.invalid/second' } })
    const fresh = await db.tradecraftEntry.create({ data: { userId, resourceId, generation: 2, pageId: page.id, url: page.url, title: 'Golden ticket' } })
    expect(await matches(fresh.id, 'golden ticket')).toBe(true)
    expect(pageId).toBeLessThan(page.id)
  }, 180_000)

  test('a resource delete removes its entries, sections, tree, page IDs, curations, jobs and project choices', async () => {
    const lib = await seedLibrary('rdel')
    for (const t of TABLES_BY_RESOURCE) expect(await count(t, 'resource_id', lib.resourceId), t).toBeGreaterThan(0)
    await db.userTradecraftResource.delete({ where: { id: lib.resourceId } })
    for (const t of TABLES_BY_RESOURCE) expect(await count(t, 'resource_id', lib.resourceId), t).toBe(0)
    // The account's own job (a conversion) and the project stay.
    expect(await count('tradecraft_ingestion_jobs', 'user_id', lib.userId)).toBe(1)
    expect(await db.project.count({ where: { id: lib.projectId } })).toBe(1)
  })

  test('a job that ends after its resource was deleted can write nothing', async () => {
    const lib = await seedLibrary('late')
    await db.userTradecraftResource.delete({ where: { id: lib.resourceId } })
    await expect(db.$executeRaw`
      INSERT INTO tradecraft_page_ids (resource_id, url) VALUES (${lib.resourceId}, 'https://late.example.invalid/x')`).rejects.toThrow()
    const swapped = await db.$executeRaw`
      UPDATE user_tradecraft_resources SET generation = 2, updated_at = now() WHERE id = ${lib.resourceId} AND user_id = ${lib.userId}`
    expect(swapped).toBe(0)
  })

  test('a user delete removes every tradecraft row with their id', async () => {
    const lib = await seedLibrary('udel')
    const other = await seedLibrary('keep')
    await db.user.delete({ where: { id: lib.userId } })
    for (const t of TABLES_BY_USER) expect(await count(t, 'user_id', lib.userId), t).toBe(0)
    for (const t of TABLES_BY_RESOURCE) expect(await count(t, 'resource_id', lib.resourceId), t).toBe(0)
    // Another account with the same shape is untouched.
    for (const t of TABLES_BY_RESOURCE) expect(await count(t, 'resource_id', other.resourceId), t).toBeGreaterThan(0)
  })

  test('a project delete removes its choices and keeps the resources (R-209)', async () => {
    const lib = await seedLibrary('pdel')
    await db.project.delete({ where: { id: lib.projectId } })
    expect(await count('tradecraft_project_choices', 'project_id', lib.projectId)).toBe(0)
    expect(await db.userTradecraftResource.count({ where: { id: lib.resourceId } })).toBe(1)
    expect(await count('tradecraft_entries', 'resource_id', lib.resourceId)).toBe(1)
  })

  test('two users can store the same URL; page IDs are unique per resource and URL', async () => {
    const a = await seedLibrary('same-a')
    const b = await seedLibrary('same-b')
    const url = 'https://shared.example.invalid/page'
    const pa = await db.tradecraftPageId.create({ data: { resourceId: a.resourceId, url } })
    const pb = await db.tradecraftPageId.create({ data: { resourceId: b.resourceId, url } })
    expect(pa.id).not.toBe(pb.id)
    await expect(db.tradecraftPageId.create({ data: { resourceId: a.resourceId, url } })).rejects.toThrow()
  })
})
