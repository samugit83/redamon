/**
 * AU-05: a privileged change writes its audit row inside its own transaction, and a
 * failed row undoes the change: no row, no change. `writeAuditTx` is that writer; the
 * best-effort `writeAudit` stays for everything else and never throws. AU-01: both
 * write the new columns (the person acted for, the project, the permission used, the
 * actor's email snapshot), and an entry without them writes the row exactly as before.
 *
 * The transaction is the in-memory Prisma of the plugin tests, whose `$transaction`
 * undoes its own writes when the callback throws, as Postgres does.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/auditOrFail.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'

let db: FakePrisma
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (db as never)[k] }) }))

import { writeAudit, writeAuditTx } from '@/lib/audit'

const ENTRY = {
  actorId: 'admin-1',
  action: 'user.role_changed',
  targetType: 'user',
  targetId: 'member-1',
  before: { role: 'standard' },
  after: { role: 'admin' },
}

/** The transaction client with an audit table that refuses every insert. */
function auditDown(tx: FakePrisma): FakePrisma {
  const refusing = { create: async () => { throw new Error('audit_log is locked') } }
  return new Proxy(tx, { get: (t, k) => (k === 'auditLog' ? refusing : (t as never)[k]) })
}

const role = () => db.rows('user').find((u) => u.id === 'member-1')!.role

beforeEach(() => {
  db = createFakePrisma()
  db.seed('user', [{ id: 'member-1', name: 'm', email: 'member-1@e2e.local', role: 'standard', password: 'h' }])
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => vi.restoreAllMocks())

describe('writeAuditTx: no row, no change', () => {
  test('a failing audit write rolls back the change', async () => {
    await expect(db.$transaction(async (tx) => {
      await tx.user.update({ where: { id: 'member-1' }, data: { role: 'admin' } })
      await writeAuditTx(auditDown(tx), ENTRY)
    })).rejects.toThrow('audit_log is locked')
    expect(role()).toBe('standard')
    expect(db.rows('auditLog')).toEqual([])
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('[audit] failed to persist user.role_changed'), expect.anything())
  })

  test('the change and its row commit together', async () => {
    await db.$transaction(async (tx) => {
      await tx.user.update({ where: { id: 'member-1' }, data: { role: 'admin' } })
      await writeAuditTx(tx, ENTRY)
    })
    expect(role()).toBe('admin')
    expect(db.rows('auditLog')).toEqual([expect.objectContaining({ ...ENTRY, source: 'api' })])
  })

  test('the row is written through the transaction it is given, not the global client', async () => {
    const outside = vi.spyOn(db.auditLog, 'create')
    await db.$transaction(async (tx) => writeAuditTx(tx, ENTRY))
    expect(outside).not.toHaveBeenCalled()
    expect(db.rows('auditLog')).toHaveLength(1)
  })

  test('the same failure through writeAudit is swallowed and the change stays (best effort)', async () => {
    await db.$transaction(async (tx) => {
      await tx.user.update({ where: { id: 'member-1' }, data: { role: 'admin' } })
    })
    db.auditLog.create = async () => { throw new Error('audit_log is locked') }
    await expect(writeAudit(ENTRY)).resolves.toBeUndefined()
    expect(role()).toBe('admin')
  })
})

describe('the new columns', () => {
  const COLUMNS = {
    onBehalfOfUserId: 'member-1',
    projectId: 'project-1',
    permission: 'users:manage',
    actorEmail: 'admin-1@e2e.local',
  }

  test('writes the new columns (writeAuditTx)', async () => {
    await db.$transaction(async (tx) => writeAuditTx(tx, { ...ENTRY, ...COLUMNS }))
    expect(db.rows('auditLog')[0]).toMatchObject({ ...ENTRY, ...COLUMNS })
  })

  test('writes the new columns (writeAudit)', async () => {
    await writeAudit({ ...ENTRY, ...COLUMNS })
    expect(db.rows('auditLog')[0]).toMatchObject({ ...ENTRY, ...COLUMNS })
  })

  test('an entry without them writes exactly the columns it wrote before', async () => {
    const create = vi.fn(async (_args: { data: Record<string, unknown> }) => ({}))
    db.auditLog.create = create as never
    await writeAudit(ENTRY)
    await writeAuditTx({ auditLog: { create } }, ENTRY)
    expect(create).toHaveBeenCalledTimes(2)
    for (const [args] of create.mock.calls) {
      expect(Object.keys(args.data).sort()).toEqual(['action', 'actorId', 'after', 'before', 'source', 'targetId', 'targetType'])
    }
  })

  test('an empty column is left out rather than written as null', async () => {
    const create = vi.fn(async (_args: { data: Record<string, unknown> }) => ({}))
    db.auditLog.create = create as never
    await writeAudit({ ...ENTRY, onBehalfOfUserId: null, actorEmail: null, projectId: undefined, permission: '' })
    const data = create.mock.calls[0][0].data
    for (const column of ['onBehalfOfUserId', 'actorEmail', 'projectId', 'permission']) expect(data).not.toHaveProperty(column)
  })
})
