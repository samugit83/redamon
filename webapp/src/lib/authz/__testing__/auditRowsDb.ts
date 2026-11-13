/**
 * An in-memory stand-in for the Prisma client, for the audit viewer, export and retention tests
 * (step 6.6): the three audit tables (`auditLog`, `actAsAudit`, `fireteamSettingsAudit`), the
 * accounts and projects they name, and the instance settings row, with the semantics those readers
 * and the retention sweep rely on:
 *
 * - `where` is evaluated, not compared as text: `AND` / `OR` / `NOT` (an object or an array), and per
 *   field equality, `null`, `{equals, mode: 'insensitive'}`, `{in}`, `{notIn}`, `{startsWith}`,
 *   `{not}`, `{isEmpty}` on a list, `{gt, gte, lt, lte}` on dates and strings. A query that asks a
 *   filter wrongly finds the wrong rows;
 * - `findMany` honours `orderBy` (an array of `{field: 'asc' | 'desc'}`), `take` and `select`;
 *   `count`, `findUnique`, `findFirst`, `deleteMany` (atomic, as a Postgres DELETE), `create`,
 *   `update` / `updateMany` (the instance row; `Prisma.DbNull` stores null);
 * - `$transaction` runs one at a time, as the advisory lock every retention writer takes makes them;
 * - `$transaction(fn)` rolls back the audit rows and the instance row when `fn` throws;
 * - `failAudit` makes the next audit insert throw, as a lost database would; every call is counted in
 *   `calls` so a test can prove a table was not read.
 */
import { Prisma } from '@prisma/client'

export type Row = Record<string, unknown>

type Where = Record<string, unknown>

const isPlain = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date)

const same = (a: unknown, b: unknown): boolean =>
  a instanceof Date && b instanceof Date ? a.getTime() === b.getTime() : a === b

function fieldMatches(value: unknown, cond: unknown): boolean {
  if (cond === null) return value === null || value === undefined
  if (!isPlain(cond)) return same(value, cond)
  const insensitive = cond.mode === 'insensitive'
  const norm = (v: unknown) => (insensitive && typeof v === 'string' ? v.toLowerCase() : v)
  for (const [op, arg] of Object.entries(cond)) {
    if (op === 'mode') continue
    if (op === 'equals' && !same(norm(value), norm(arg))) return false
    if (op === 'in' && !(arg as unknown[]).some((a) => same(norm(value), norm(a)))) return false
    if (op === 'notIn' && (arg as unknown[]).some((a) => same(norm(value), norm(a)))) return false
    if (op === 'startsWith' && !(typeof value === 'string' && String(norm(value)).startsWith(String(norm(arg))))) return false
    if (op === 'not' && fieldMatches(value, arg)) return false
    if (op === 'isEmpty' && !(Array.isArray(value) && (value.length === 0) === arg)) return false
    // Dates by instant, strings (a keyset cursor's id) by code unit, as Postgres' C collation does.
    const order = (v: unknown) => (v instanceof Date ? v.getTime() : typeof v === 'string' ? v : null)
    const x = order(value)
    const y = order(arg)
    const comparable = x !== null && y !== null && typeof x === typeof y
    if (op === 'gt' && !(comparable && x > y)) return false
    if (op === 'gte' && !(comparable && x >= y)) return false
    if (op === 'lt' && !(comparable && x < y)) return false
    if (op === 'lte' && !(comparable && x <= y)) return false
  }
  return true
}

export function matches(row: Row, where: Where | undefined): boolean {
  if (!where) return true
  return Object.entries(where).every(([key, cond]) => {
    if (key === 'AND') return (cond as Where[]).every((w) => matches(row, w))
    if (key === 'OR') return (cond as Where[]).some((w) => matches(row, w))
    if (key === 'NOT') return (Array.isArray(cond) ? cond : [cond]).every((w) => !matches(row, w as Where))
    return fieldMatches(row[key], cond)
  })
}

function ordered(rows: Row[], orderBy: unknown): Row[] {
  const keys = (Array.isArray(orderBy) ? orderBy : orderBy ? [orderBy] : []) as Array<Record<string, 'asc' | 'desc'>>
  if (!keys.length) return rows
  const value = (v: unknown) => (v instanceof Date ? v.getTime() : v as number | string)
  return [...rows].sort((a, b) => {
    for (const k of keys) {
      const [field, dir] = Object.entries(k)[0]
      const x = value(a[field])
      const y = value(b[field])
      if (x === y) continue
      return (x < y ? -1 : 1) * (dir === 'desc' ? -1 : 1)
    }
    return 0
  })
}

const picked = (row: Row, select: unknown): Row =>
  isPlain(select) ? Object.fromEntries(Object.keys(select).filter((k) => select[k]).map((k) => [k, row[k]])) : { ...row }

export interface AuditRowsState {
  audit: Row[]
  actAs: Row[]
  fireteam: Row[]
  users: Row[]
  projects: Row[]
  instance: Row | null
  failAudit: boolean
  calls: string[]
}

const stored = (data: Row): Row =>
  Object.fromEntries(Object.entries(data).map(([k, v]) => [k, v === Prisma.DbNull || v === Prisma.JsonNull ? null : v]))

/** `clock` stamps the rows `create` adds (the database's `now()`). */
export function auditRowsDb(state: AuditRowsState, clock: () => Date = () => new Date()) {
  let nextId = 1
  let queue: Promise<unknown> = Promise.resolve()
  const table = (name: string, rows: () => Row[], set: (r: Row[]) => void) => ({
    findMany: async (a: { where?: Where; orderBy?: unknown; take?: number; select?: unknown } = {}) => {
      state.calls.push(`${name}.findMany`)
      await Promise.resolve()
      let out = ordered(rows().filter((r) => matches(r, a.where)), a.orderBy)
      if (a.take !== undefined) out = out.slice(0, a.take)
      return out.map((r) => picked(r, a.select))
    },
    findFirst: async (a: { where?: Where; orderBy?: unknown; select?: unknown } = {}) => {
      state.calls.push(`${name}.findFirst`)
      const row = ordered(rows().filter((r) => matches(r, a.where)), a.orderBy)[0]
      return row ? picked(row, a.select) : null
    },
    findUnique: async (a: { where: Where; select?: unknown }) => {
      state.calls.push(`${name}.findUnique`)
      const row = rows().find((r) => matches(r, a.where))
      return row ? picked(row, a.select) : null
    },
    count: async (a: { where?: Where } = {}) => {
      state.calls.push(`${name}.count`)
      return rows().filter((r) => matches(r, a.where)).length
    },
    deleteMany: async (a: { where?: Where } = {}) => {
      state.calls.push(`${name}.deleteMany`)
      const before = rows().length
      set(rows().filter((r) => !matches(r, a.where)))
      return { count: before - rows().length }
    },
    create: async ({ data }: { data: Row }) => {
      state.calls.push(`${name}.create`)
      if (name === 'auditLog' && state.failAudit) throw Object.assign(new Error('audit insert failed'), { code: 'P1001' })
      const row = { id: `new-${nextId++}`, createdAt: clock(), ...data }
      set([...rows(), row])
      return { ...row }
    },
  })
  const client = {
    auditLog: table('auditLog', () => state.audit, (r) => { state.audit = r }),
    actAsAudit: table('actAsAudit', () => state.actAs, (r) => { state.actAs = r }),
    fireteamSettingsAudit: table('fireteamSettingsAudit', () => state.fireteam, (r) => { state.fireteam = r }),
    user: table('user', () => state.users, (r) => { state.users = r }),
    project: table('project', () => state.projects, (r) => { state.projects = r }),
    instanceSettings: {
      findUnique: async (a: { select?: unknown } = {}) => {
        state.calls.push('instanceSettings.findUnique')
        return state.instance ? picked(state.instance, a.select) : null
      },
      updateMany: async ({ where, data }: { where?: Where; data: Row }) => {
        state.calls.push('instanceSettings.updateMany')
        if (!state.instance || !matches(state.instance, where)) return { count: 0 }
        state.instance = { ...state.instance, ...stored(data) }
        return { count: 1 }
      },
      update: async ({ data }: { where: Where; data: Row }) => {
        state.calls.push('instanceSettings.update')
        if (!state.instance) throw Object.assign(new Error('Record to update not found'), { code: 'P2025' })
        state.instance = { ...state.instance, ...stored(data) }
        return { ...state.instance }
      },
    },
    $executeRaw: async () => 0,
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      const turn = queue.then(async () => {
        const snapshot = { audit: [...state.audit], instance: state.instance ? { ...state.instance } : null }
        try {
          return await fn(client)
        } catch (err) {
          state.audit = snapshot.audit
          state.instance = snapshot.instance
          throw err
        }
      })
      queue = turn.catch(() => undefined)
      return turn
    },
  }
  return client
}

export function emptyAuditRowsState(): AuditRowsState {
  return { audit: [], actAs: [], fireteam: [], users: [], projects: [], instance: null, failAudit: false, calls: [] }
}
