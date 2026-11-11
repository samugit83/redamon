/**
 * The one-time backfill that records every custom Nuclei template present at the
 * upgrade as an instance template (scripts/backfill-nuclei-template-owners.mjs, HD-08,
 * T18): one row per file with no owner, a marker in the same transaction under an
 * advisory lock, a second boot that changes nothing unless the rows are gone (a
 * downgrade dropped the table), and a failure that leaves nothing and never stops the
 * boot.
 *
 * The filesystem is real (a throwaway folder); Prisma is an in-memory double whose
 * `pg_advisory_xact_lock` serializes two transactions and whose transaction rolls back
 * its own writes when the callback throws (the real-Postgres twin:
 * scripts/backfill-nuclei-template-owners.pg.integration.test.ts).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/nucleiTemplateOwners.backfill.test.ts
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import { mkdir, rm, symlink, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { describe, test, expect, beforeEach, afterAll, vi } from 'vitest'
import {
  LOCK_KEY, MARKER_ACTION, backfillNucleiTemplateOwners, listTemplateFiles, run,
} from '../../scripts/backfill-nuclei-template-owners.mjs'

type TemplateRow = { id: string; path: string; ownerUserId: string | null; sha256: string | null; sizeBytes: number | null }
type AuditRow = { action: string; targetType: string; source: string; after: unknown; createdAt: Date }

const ROOT = `${process.env.TMPDIR || '/tmp'}/redamon-nuclei-backfill-${process.pid}-${Date.now()}`
const template = (id: string) => `id: ${id}\ninfo:\n  name: ${id}\n  severity: low\n`

class FakeDb {
  templates: TemplateRow[] = []
  audit: AuditRow[] = []
  locks: string[] = []
  failCreateMany = false
  private lockTail = new Map<string, Promise<void>>()
  private seq = 0
  private clock = 0

  async $transaction<T>(fn: (tx: unknown) => Promise<T>): Promise<T> {
    const snapshot = { templates: this.templates.map(r => ({ ...r })), audit: [...this.audit] }
    const releases: (() => void)[] = []
    const tx = {
      $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
        expect(strings.join('?')).toBe('SELECT pg_advisory_xact_lock(hashtext(?))')
        const key = String(values[0])
        this.locks.push(key)
        const prev = this.lockTail.get(key) ?? Promise.resolve()
        let release!: () => void
        const held = new Promise<void>(r => { release = r })
        this.lockTail.set(key, prev.then(() => held))
        releases.push(release)
        await prev
        return 1
      },
      auditLog: {
        findFirst: async ({ where }: { where: { action: string } }) =>
          [...this.audit].reverse().find(r => r.action === where.action) ?? null,
        create: async ({ data }: { data: Omit<AuditRow, 'createdAt'> }) => {
          const row = { ...data, createdAt: new Date(++this.clock) }
          this.audit.push(row)
          return row
        },
      },
      nucleiTemplate: {
        findFirst: async () => (this.templates[0] ? { id: this.templates[0].id } : null),
        createMany: async ({ data, skipDuplicates }: { data: Omit<TemplateRow, 'id'>[]; skipDuplicates?: boolean }) => {
          // Let a second transaction run up to its lock in between.
          await new Promise(r => setTimeout(r, 5))
          if (this.failCreateMany) throw Object.assign(new Error('relation "nuclei_templates" does not exist'), { code: 'P2021' })
          let count = 0
          for (const row of data) {
            if (this.templates.some(r => r.path === row.path)) {
              if (!skipDuplicates) throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' })
              continue
            }
            this.templates.push({ id: `t${++this.seq}`, ...row })
            count++
          }
          return { count }
        },
      },
    }
    try {
      return await fn(tx)
    } catch (err) {
      this.templates = snapshot.templates
      this.audit = snapshot.audit
      throw err
    } finally {
      for (const r of releases) r()
    }
  }
}

let db: FakeDb
const markers = () => db.audit.filter(r => r.action === MARKER_ACTION)

async function seedFolder() {
  await mkdir(path.join(ROOT, 'team', 'web'), { recursive: true })
  await writeFile(path.join(ROOT, 'springboot.yaml'), template('springboot'))
  await writeFile(path.join(ROOT, 'old.yml'), template('old'))
  await writeFile(path.join(ROOT, 'team', 'web', 'xss.yaml'), template('xss'))
  await writeFile(path.join(ROOT, '.gitkeep'), '')
  await writeFile(path.join(ROOT, 'notes.txt'), 'not a template')
  await symlink(path.join(ROOT, 'springboot.yaml'), path.join(ROOT, 'link.yaml'))
}

beforeEach(async () => {
  db = new FakeDb()
  await rm(ROOT, { recursive: true, force: true })
  await mkdir(ROOT, { recursive: true })
})
afterAll(async () => { await rm(ROOT, { recursive: true, force: true }) })

describe('backfillNucleiTemplateOwners', () => {
  test('exports the lock key and the marker action', () => {
    expect(LOCK_KEY).toBe('system.nuclei_template_owners')
    expect(MARKER_ACTION).toBe('system.nuclei_template_owners_backfill')
  })

  test('every file becomes instance: one ownerless row per template, with its hash and size', async () => {
    await seedFolder()
    const r = await backfillNucleiTemplateOwners(db, ROOT)
    expect(r).toEqual({ done: true, files: 3, rowsCreated: 3 })
    expect(db.templates.map(t => [t.path, t.ownerUserId])).toEqual([
      ['old.yml', null], ['springboot.yaml', null], ['team/web/xss.yaml', null],
    ])
    const sb = db.templates.find(t => t.path === 'springboot.yaml')!
    expect(sb.sizeBytes).toBe(template('springboot').length)
    expect(sb.sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(markers()).toEqual([expect.objectContaining({ targetType: 'system', source: 'system', after: { files: 3, rowsCreated: 3 } })])
    expect(db.locks).toEqual([LOCK_KEY])
  })

  test('idempotent: a second boot writes nothing and no second marker', async () => {
    await seedFolder()
    await backfillNucleiTemplateOwners(db, ROOT)
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: false })
    expect(db.templates).toHaveLength(3)
    expect(markers()).toHaveLength(1)
  })

  test('a template a member uploaded after the upgrade is left alone by a later boot', async () => {
    await seedFolder()
    await backfillNucleiTemplateOwners(db, ROOT)
    await writeFile(path.join(ROOT, 'member.yaml'), template('member'))
    db.templates.push({ id: 'm', path: 'member.yaml', ownerUserId: 'member-a', sha256: null, sizeBytes: null })
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: false })
    expect(db.templates.find(t => t.path === 'member.yaml')?.ownerUserId).toBe('member-a')
  })

  test('two copies booting together record once', async () => {
    await seedFolder()
    const [a, b] = await Promise.all([backfillNucleiTemplateOwners(db, ROOT), backfillNucleiTemplateOwners(db, ROOT)])
    expect([a, b].filter(r => r.done)).toHaveLength(1)
    expect(db.templates).toHaveLength(3)
    expect(markers()).toHaveLength(1)
  })

  test('a marker whose rows are gone (a downgrade dropped the table) records the files again, once', async () => {
    await seedFolder()
    await backfillNucleiTemplateOwners(db, ROOT)
    db.templates = []
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: true, files: 3, rowsCreated: 3 })
    expect(markers()).toHaveLength(2)
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: false })
  })

  test('rows that survived are never changed; only the missing files are added', async () => {
    await seedFolder()
    db.templates.push({ id: 'kept', path: 'springboot.yaml', ownerUserId: 'member-a', sha256: 'x', sizeBytes: 1 })
    const r = await backfillNucleiTemplateOwners(db, ROOT)
    expect(r).toEqual({ done: true, files: 3, rowsCreated: 2 })
    expect(db.templates.find(t => t.path === 'springboot.yaml')).toMatchObject({ ownerUserId: 'member-a', sha256: 'x' })
  })

  test('an empty or missing folder records zero files, and that marker is final', async () => {
    expect(await backfillNucleiTemplateOwners(db, path.join(ROOT, 'absent'))).toEqual({ done: true, files: 0, rowsCreated: 0 })
    expect(markers()[0].after).toEqual({ files: 0, rowsCreated: 0 })
    await seedFolder()
    expect(await backfillNucleiTemplateOwners(db, ROOT)).toEqual({ done: false })
    expect(db.templates).toEqual([])
  })

  test('a failure rolls back every row and writes no marker; the next boot records them', async () => {
    await seedFolder()
    db.failCreateMany = true
    await expect(backfillNucleiTemplateOwners(db, ROOT)).rejects.toThrow()
    expect(db.templates).toEqual([])
    expect(markers()).toEqual([])
    db.failCreateMany = false
    expect((await backfillNucleiTemplateOwners(db, ROOT)).done).toBe(true)
  })

  test('the entrypoint call never throws: it logs the retry and the boot goes on', async () => {
    await seedFolder()
    db.failCreateMany = true
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    await expect(run(db, ROOT)).resolves.toBeUndefined()
    expect(error.mock.calls[0].map(String)).toEqual([
      '[rbac] could not record the nuclei template owners (retried next boot):', 'P2021',
    ])
    db.failCreateMany = false
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    await run(db, ROOT)
    expect(log.mock.calls.map(c => String(c[0]))).toEqual([
      '[rbac] nuclei template owners recorded: 3 file(s) present at the upgrade are instance templates (3 row(s) written).',
    ])
  })

  test('the file list matches what the templates route lists: regular .yaml/.yml files, posix paths', async () => {
    await seedFolder()
    expect((await listTemplateFiles(ROOT)).map(f => f.path)).toEqual(['old.yml', 'springboot.yaml', 'team/web/xss.yaml'])
  })
})

describe('the startup lists', () => {
  const dockerfile = readFileSync(path.resolve(__dirname, '../../Dockerfile'), 'utf8')

  test('the entrypoint runs it after db push and the legacy-grants backfill, before the server, never fatally', () => {
    const entry = dockerfile.split('\n').find(l => l.startsWith('RUN printf') && l.includes('entrypoint'))!
    const push = entry.indexOf('db push')
    const grants = entry.indexOf('backfill-rbac-legacy-grants.mjs')
    const ours = entry.indexOf('backfill-nuclei-template-owners.mjs')
    const server = entry.indexOf('exec node server.js')
    expect(push).toBeGreaterThan(0)
    expect(grants).toBeGreaterThan(push)
    expect(ours).toBeGreaterThan(grants)
    expect(server).toBeGreaterThan(ours)
    expect(entry).toMatch(/\\nnode scripts\/backfill-nuclei-template-owners\.mjs 2>&1\\n/)
  })

  test('the dev command runs it in the same place', () => {
    const dev = readFileSync(path.resolve(__dirname, '../../../docker-compose.dev.yml'), 'utf8')
    const lines = dev.split('\n').map(l => l.trim())
    const grants = lines.indexOf('node scripts/backfill-rbac-legacy-grants.mjs')
    expect(grants).toBeGreaterThan(0)
    expect(lines[grants + 1]).toBe('node scripts/backfill-nuclei-template-owners.mjs')
  })
})
