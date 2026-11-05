/**
 * An in-memory stand-in for the Prisma client, covering the four plugin tables and the
 * core rows the plugin platform reads (`project`, `user`, `userSettings`,
 * `conversation`, `chatMessage`), with the semantics the plugin stores rely on:
 *
 * - `updateMany` / `deleteMany` return `{count}` and apply atomically, so a
 *   compare-and-swap test sees exactly one winner;
 * - a `where` key whose value is `undefined` is ignored, as Prisma does, so a store
 *   that builds `{operationId: undefined}` matches every row here too;
 * - `startsWith` / `contains` are SQL `LIKE` patterns, as Prisma 6 sends them to
 *   Postgres: it does NOT escape `_` and `%`, so `startsWith: '__'` matches any value of
 *   two or more characters. A store must escape its own patterns (likePrefix);
 * - a JSON path filter (`{path: [field], equals: v}`) follows jsonb: a missing path never
 *   matches, `Prisma.JsonNull` matches a JSON null, a boolean never equals a number, and an
 *   object or array never equals a scalar;
 * - unique keys raise the real `PrismaClientKnownRequestError` P2002, missing rows P2025;
 * - `$transaction(fn)` rolls back only its own writes when `fn` throws, and
 *   `SELECT pg_advisory_xact_lock(hashtext(<key>))` through `$executeRaw` takes a real
 *   (async) lock held until the transaction ends, so two interleaved transactions
 *   serialize exactly where Postgres would and nowhere else; the only other raw
 *   statement is the purge's removal of a `feature_models` key;
 * - `$queryRaw` answers only the two user-skill name queries of userSkillNames.ts (found
 *   by their marker comment), with an ASCII-whitespace key that approximates Postgres's;
 *   userSkillNames.pg.integration.test.ts runs the real one;
 * - a unique key with a NULL in it never collides, as in Postgres;
 * - `@default(cuid())`, `@default(now())` and `@updatedAt` are applied, with the
 *   platform clock.
 *
 * It does NOT enforce the partial one-active index or the CHECK constraints of
 * apply-plugin-constraints.mjs: the stores must hold those invariants by themselves
 * (tests/plugins_db_test.sh proves the database wall).
 */
import { randomUUID } from 'crypto'
import { Prisma } from '@prisma/client'
import { now } from '../clock'

export type Row = Record<string, unknown>
type Where = Record<string, unknown>

export type TableName =
  | 'pluginInstall'
  | 'pluginData'
  | 'pluginOverride'
  | 'pluginPlatformState'
  | 'project'
  | 'user'
  | 'userSettings'
  | 'conversation'
  | 'chatMessage'
  | 'userAttackSkill'
  | 'userProjectPreset'
  | 'userLlmProvider'
  | 'auditLog'

interface TableSpec {
  pk: string
  uniques: Record<string, string[]>
  defaults: () => Row
  relations?: Record<string, { table: TableName; from: string; to: string }>
}

const TABLES: Record<TableName, TableSpec> = {
  pluginInstall: {
    pk: 'pluginId',
    uniques: {},
    defaults: () => ({
      enabled: false,
      status: 'available',
      activeVersion: null,
      previousVersion: null,
      pendingVersion: null,
      dataVersion: 0,
      previousDataVersion: null,
      grantedPermissions: [],
      manifest: null,
      catalogEntry: null,
      installedBy: null,
      installedAt: null,
      operationId: null,
      operationKind: null,
      operationArgs: null,
      leaseExpiresAt: null,
      lastError: null,
      revokedReason: null,
    }),
  },
  pluginData: {
    pk: 'id',
    uniques: {
      pluginId_namespace_ownerType_ownerId_collection_key: [
        'pluginId', 'namespace', 'ownerType', 'ownerId', 'collection', 'key',
      ],
    },
    defaults: () => ({ namespace: 'live', userId: null, projectId: null, expiresAt: null }),
  },
  pluginOverride: {
    pk: 'id',
    uniques: {},
    defaults: () => ({
      userId: null,
      projectId: null,
      revision: null,
      status: 'proposed',
      note: null,
      meta: null,
      decidedBy: null,
      decidedAt: null,
    }),
    relations: { plugin: { table: 'pluginInstall', from: 'pluginId', to: 'pluginId' } },
  },
  pluginPlatformState: { pk: 'key', uniques: {}, defaults: () => ({}) },
  project: { pk: 'id', uniques: {}, defaults: () => ({}) },
  user: { pk: 'id', uniques: { email: ['email'] }, defaults: () => ({ name: '', password: '', role: 'standard' }) },
  userSettings: { pk: 'id', uniques: { userId: ['userId'] }, defaults: () => ({ featureModels: {} }) },
  conversation: {
    pk: 'id',
    uniques: { sessionId: ['sessionId'] },
    defaults: () => ({
      title: '',
      status: 'active',
      agentRunning: false,
      currentPhase: 'informational',
      iterationCount: 0,
      activeSkillId: '',
    }),
  },
  chatMessage: { pk: 'id', uniques: {}, defaults: () => ({ memberIdKey: null, fireteamIdKey: null }) },
  userAttackSkill: {
    pk: 'id',
    uniques: { originChangeSetId: ['originChangeSetId'] },
    defaults: () => ({
      description: null,
      derivedFromId: null,
      lineageRootId: null,
      version: null,
      originChangeSetId: null,
      originPluginId: null,
      originPluginVersion: null,
      originChain: [],
      quarantinedAt: null,
      quarantineReason: null,
      quarantinedFor: null,
      releasedFor: [],
    }),
  },
  userProjectPreset: { pk: 'id', uniques: {}, defaults: () => ({ description: '' }) },
  userLlmProvider: { pk: 'id', uniques: {}, defaults: () => ({}) },
  auditLog: { pk: 'id', uniques: {}, defaults: () => ({ actorId: null, targetId: null, before: null, after: null, source: 'api' }) },
}
const HAS_UPDATED_AT: TableName[] = [
  'pluginInstall', 'pluginData', 'pluginOverride', 'pluginPlatformState', 'conversation', 'userSettings', 'userAttackSkill',
]
const HAS_CREATED_AT: TableName[] = [
  'pluginInstall', 'pluginData', 'pluginOverride', 'conversation', 'chatMessage', 'userAttackSkill', 'userLlmProvider', 'auditLog',
]

/** The name key of userSkillNames.ts (NFC, JavaScript's whitespace set), for tests. */
export function fakeNameKey(name: string): string {
  return name.normalize('NFC').replace(/\s+/gu, ' ').replace(/^ | $/g, '').toLowerCase()
}

const clone = <T>(v: T): T => (v === undefined ? v : structuredClone(v))

function known(code: 'P2002' | 'P2025', message: string, meta?: Record<string, unknown>) {
  return new Prisma.PrismaClientKnownRequestError(message, { code, clientVersion: 'fake', meta })
}

function storable(v: unknown): unknown {
  if (v === Prisma.DbNull || v === Prisma.JsonNull) return null
  return clone(v)
}

function eq(a: unknown, b: unknown): boolean {
  if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime()
  if (a === null || a === undefined) return b === null || b === undefined
  if (typeof a === 'object' || typeof b === 'object') return JSON.stringify(a) === JSON.stringify(b)
  return a === b
}

const cmp = (a: unknown, b: unknown): number => {
  const x = a instanceof Date ? a.getTime() : (a as number | string)
  const y = b instanceof Date ? b.getTime() : (b as number | string)
  return x < y ? -1 : x > y ? 1 : 0
}

const OPERATORS = new Set(['equals', 'in', 'notIn', 'lt', 'lte', 'gt', 'gte', 'not', 'startsWith', 'contains', 'has', 'hasSome'])

/** Postgres LIKE: `_` is one character, `%` any run, a backslash escapes the next one. */
function like(value: unknown, pattern: string): boolean {
  if (typeof value !== 'string') return false
  let re = '^'
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]
    if (ch === '\\' && i + 1 < pattern.length) re += pattern[++i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    else if (ch === '_') re += '.'
    else if (ch === '%') re += '.*'
    else re += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }
  return new RegExp(re + '$', 's').test(value)
}

function isOperatorObject(v: unknown): v is Record<string, unknown> {
  if (!v || typeof v !== 'object' || v instanceof Date || Array.isArray(v)) return false
  const keys = Object.keys(v)
  return keys.length > 0 && keys.every((k) => OPERATORS.has(k))
}

function jsonPathEquals(value: unknown, path: unknown[], expected: unknown): boolean {
  let at: unknown = value
  for (const key of path) {
    if (!at || typeof at !== 'object' || Array.isArray(at) || !Object.hasOwn(at as object, String(key))) return false
    at = (at as Record<string, unknown>)[String(key)]
  }
  if (expected === Prisma.JsonNull) return at === null
  if (expected === null || typeof expected === 'object') throw new Error('fakePrisma: JSON path equals takes a scalar or JsonNull')
  return typeof at === typeof expected && at === expected
}

function matchField(value: unknown, cond: unknown): boolean {
  if (cond === undefined) return true
  if (cond && typeof cond === 'object' && Array.isArray((cond as Record<string, unknown>).path)) {
    const { path, equals } = cond as { path: unknown[]; equals: unknown }
    return jsonPathEquals(value, path, equals)
  }
  if (!isOperatorObject(cond)) return eq(value, cond)
  for (const [op, arg] of Object.entries(cond)) {
    if (arg === undefined) continue
    switch (op) {
      case 'equals': if (!eq(value, arg)) return false; break
      case 'in': if (!(arg as unknown[]).some((a) => eq(value, a))) return false; break
      case 'notIn': if ((arg as unknown[]).some((a) => eq(value, a))) return false; break
      // Postgres comparisons with NULL are never true.
      case 'lt': if (value == null || cmp(value, arg) >= 0) return false; break
      case 'lte': if (value == null || cmp(value, arg) > 0) return false; break
      case 'gt': if (value == null || cmp(value, arg) <= 0) return false; break
      case 'gte': if (value == null || cmp(value, arg) < 0) return false; break
      case 'not': if (isOperatorObject(arg) ? matchField(value, arg) : eq(value, arg)) return false; break
      case 'startsWith': if (!like(value, `${arg}%`)) return false; break
      case 'contains': if (!like(value, `%${arg}%`)) return false; break
      // Scalar lists (String[]).
      case 'has': if (!Array.isArray(value) || !value.some((v) => eq(v, arg))) return false; break
      case 'hasSome': if (!Array.isArray(value) || !(arg as unknown[]).some((a) => value.some((v) => eq(v, a)))) return false; break
    }
  }
  return true
}

function expandUnique(spec: TableSpec, where: Where): Where {
  const out: Where = {}
  for (const [k, v] of Object.entries(where)) {
    if (spec.uniques[k] && v && typeof v === 'object') Object.assign(out, v)
    else out[k] = v
  }
  return out
}

function matches(spec: TableSpec, row: Row, where: Where | undefined): boolean {
  if (!where) return true
  for (const [k, v] of Object.entries(expandUnique(spec, where))) {
    if (v === undefined) continue
    if (k === 'AND') {
      const all = Array.isArray(v) ? v : [v]
      if (!all.every((w) => matches(spec, row, w as Where))) return false
    } else if (k === 'OR') {
      if (!(v as Where[]).some((w) => matches(spec, row, w))) return false
    } else if (k === 'NOT') {
      const all = Array.isArray(v) ? v : [v]
      if (all.some((w) => matches(spec, row, w as Where))) return false
    } else if (!matchField(row[k], v)) {
      return false
    }
  }
  return true
}

type OrderBy = Record<string, 'asc' | 'desc'> | Record<string, 'asc' | 'desc'>[]

function sortRows(rows: Row[], orderBy: OrderBy | undefined): Row[] {
  if (!orderBy) return rows
  const keys = (Array.isArray(orderBy) ? orderBy : [orderBy]).flatMap((o) => Object.entries(o))
  return [...rows].sort((a, b) => {
    for (const [k, dir] of keys) {
      const c = a[k] == null ? (b[k] == null ? 0 : -1) : b[k] == null ? 1 : cmp(a[k], b[k])
      if (c !== 0) return dir === 'desc' ? -c : c
    }
    return 0
  })
}

class Mutex {
  private tail = new Map<string, Promise<void>>()
  async acquire(key: string): Promise<() => void> {
    const prev = this.tail.get(key) ?? Promise.resolve()
    let release!: () => void
    const next = new Promise<void>((r) => (release = r))
    const chained = prev.then(() => next)
    this.tail.set(key, chained)
    await prev
    return () => {
      release()
      if (this.tail.get(key) === chained) this.tail.delete(key)
    }
  }
}

type UndoEntry = { table: TableName; pk: unknown; before: Row | null }

interface Context {
  undo: UndoEntry[] | null
  locks: (() => void)[] | null
}

type Args = {
  where?: Where
  data?: Row | Row[]
  create?: Row
  update?: Row
  select?: Row
  include?: Row
  orderBy?: OrderBy
  take?: number
  skip?: number
  skipDuplicates?: boolean
  _count?: unknown
  _sum?: Record<string, boolean>
}

/** The Prisma delegate methods the plugin stores use, on plain rows. */
export interface FakeDelegate {
  findUnique(a: Args): Promise<Row | null>
  findFirst(a?: Args): Promise<Row | null>
  findMany(a?: Args): Promise<Row[]>
  count(a?: Args): Promise<number>
  aggregate(a: Args): Promise<Row>
  create(a: Args): Promise<Row>
  createMany(a: Args): Promise<{ count: number }>
  update(a: Args): Promise<Row>
  updateMany(a: Args): Promise<{ count: number }>
  upsert(a: Args): Promise<Row>
  delete(a: Args): Promise<Row>
  deleteMany(a?: Args): Promise<{ count: number }>
}

export interface FakePrisma extends Record<TableName, FakeDelegate> {
  $transaction<T>(fn: (tx: FakePrisma) => Promise<T>): Promise<T>
  $executeRaw(strings: TemplateStringsArray, ...values: unknown[]): Promise<number>
  $queryRaw(query: { sql: string; values: unknown[] }): Promise<unknown[]>
  /** Every raw statement, with its values, in order (for assertions). */
  rawCalls: { sql: string; values: unknown[] }[]
  /** Tables, keyed by primary key. */
  tables: Record<TableName, Map<unknown, Row>>
  seed: (table: TableName, rows: Row[]) => void
  rows: (table: TableName) => Row[]
  transactions: number
}

export function createFakePrisma(): FakePrisma {
  const tables = Object.fromEntries(
    (Object.keys(TABLES) as TableName[]).map((t) => [t, new Map<unknown, Row>()]),
  ) as Record<TableName, Map<unknown, Row>>
  const mutex = new Mutex()
  const rawCalls: { sql: string; values: unknown[] }[] = []
  let transactions = 0

  function write(ctx: Context, table: TableName, pk: unknown, row: Row | null) {
    const map = tables[table]
    const before = map.get(pk) ?? null
    if (ctx.undo) ctx.undo.push({ table, pk, before: before && clone(before) })
    if (row) map.set(pk, row)
    else map.delete(pk)
  }

  function checkUnique(table: TableName, row: Row, selfPk: unknown) {
    const spec: TableSpec = TABLES[table]
    for (const [pkOther, other] of tables[table]) {
      if (pkOther === selfPk) continue
      if (eq(other[spec.pk], row[spec.pk])) {
        throw known('P2002', `Unique constraint failed on ${spec.pk}`, { target: [spec.pk] })
      }
      for (const [name, fields] of Object.entries(spec.uniques)) {
        if (fields.some((f) => row[f] === null || row[f] === undefined)) continue
        if (fields.every((f) => eq(other[f], row[f]))) {
          throw known('P2002', `Unique constraint failed on ${name}`, { target: fields })
        }
      }
    }
  }

  function applyData(row: Row, data: Row) {
    for (const [k, v] of Object.entries(data)) {
      if (v === undefined) continue
      if (v && typeof v === 'object' && !(v instanceof Date) && 'increment' in (v as Row)) {
        row[k] = (row[k] as number) + ((v as Row).increment as number)
      } else if (v && typeof v === 'object' && !(v instanceof Date) && 'set' in (v as Row)) {
        row[k] = storable((v as Row).set)
      } else {
        row[k] = storable(v)
      }
    }
  }

  function shape(table: TableName, row: Row, args: { select?: Row; include?: Row }): Row {
    const spec: TableSpec = TABLES[table]
    let out: Row = clone(row)
    if (args.select) {
      out = Object.fromEntries(Object.keys(args.select).filter((k) => args.select![k]).map((k) => [k, clone(row[k])]))
    }
    for (const [rel, on] of Object.entries(args.include ?? {})) {
      const r = spec.relations?.[rel]
      if (!on || !r) continue
      const target = [...tables[r.table].values()].find((x) => eq(x[r.to], row[r.from]))
      out[rel] = target ? clone(target) : null
    }
    return out
  }

  function delegate(table: TableName, ctx: Context) {
    const spec: TableSpec = TABLES[table]
    const all = () => [...tables[table].values()]
    const find = (where?: Where) => all().filter((r) => matches(spec, r, where))

    function create(data: Row): Row {
      const t = now()
      const row: Row = { ...spec.defaults() }
      if (spec.pk === 'id') row.id = `c${randomUUID().replace(/-/g, '').slice(0, 24)}`
      if (HAS_CREATED_AT.includes(table)) row.createdAt = t
      if (HAS_UPDATED_AT.includes(table)) row.updatedAt = t
      applyData(row, data)
      checkUnique(table, row, undefined)
      write(ctx, table, row[spec.pk], row)
      return row
    }

    function update(row: Row, data: Row): Row {
      const next = clone(row)
      applyData(next, data)
      if (HAS_UPDATED_AT.includes(table) && data.updatedAt === undefined) next.updatedAt = now()
      checkUnique(table, next, row[spec.pk])
      if (next[spec.pk] !== row[spec.pk]) write(ctx, table, row[spec.pk], null)
      write(ctx, table, next[spec.pk], next)
      return next
    }

    return {
      findUnique: async (a: { where: Where; select?: Row; include?: Row }) => {
        const r = find(a.where)[0]
        return r ? shape(table, r, a) : null
      },
      findFirst: async (a: { where?: Where; orderBy?: OrderBy; select?: Row; include?: Row } = {}) => {
        const r = sortRows(find(a.where), a.orderBy)[0]
        return r ? shape(table, r, a) : null
      },
      findMany: async (a: { where?: Where; orderBy?: OrderBy; take?: number; skip?: number; select?: Row; include?: Row } = {}) => {
        let rows = sortRows(find(a.where), a.orderBy)
        if (a.skip) rows = rows.slice(a.skip)
        if (a.take !== undefined) rows = rows.slice(0, a.take)
        return rows.map((r) => shape(table, r, a))
      },
      count: async (a: { where?: Where } = {}) => find(a.where).length,
      aggregate: async (a: { where?: Where; _count?: unknown; _sum?: Record<string, boolean> }) => {
        const rows = find(a.where)
        const out: Row = {}
        if (a._count) out._count = a._count === true ? rows.length : { _all: rows.length }
        if (a._sum) {
          out._sum = Object.fromEntries(
            Object.keys(a._sum).map((k) => [k, rows.length ? rows.reduce((s, r) => s + (r[k] as number), 0) : null]),
          )
        }
        return out
      },
      create: async (a: { data: Row; select?: Row }) => shape(table, create(a.data), a),
      createMany: async (a: { data: Row[]; skipDuplicates?: boolean }) => {
        let count = 0
        for (const d of a.data) {
          try {
            create(d)
            count++
          } catch (e) {
            if (!(a.skipDuplicates && e instanceof Prisma.PrismaClientKnownRequestError)) throw e
          }
        }
        return { count }
      },
      update: async (a: { where: Where; data: Row; select?: Row }) => {
        const r = find(a.where)[0]
        if (!r) throw known('P2025', 'Record to update not found.')
        return shape(table, update(r, a.data), a)
      },
      updateMany: async (a: { where?: Where; data: Row }) => {
        const rows = find(a.where)
        for (const r of rows) update(r, a.data)
        return { count: rows.length }
      },
      upsert: async (a: { where: Where; create: Row; update: Row; select?: Row }) => {
        const r = find(a.where)[0]
        return shape(table, r ? update(r, a.update) : create(a.create), a)
      },
      delete: async (a: { where: Where }) => {
        const r = find(a.where)[0]
        if (!r) throw known('P2025', 'Record to delete does not exist.')
        write(ctx, table, r[spec.pk], null)
        return clone(r)
      },
      deleteMany: async (a: { where?: Where } = {}) => {
        const rows = find(a.where)
        for (const r of rows) write(ctx, table, r[spec.pk], null)
        return { count: rows.length }
      },
      createNow: create,
    }
  }

  function client(ctx: Context): FakePrisma {
    const c: Record<string, unknown> = {}
    for (const t of Object.keys(TABLES) as TableName[]) c[t] = delegate(t, ctx)
    c.$executeRaw = async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const sql = strings.join('?')
      rawCalls.push({ sql, values })
      if (/pg_advisory_xact_lock\(hashtext\(\?\)\)/.test(sql)) {
        // Outside a transaction the lock would end with its own statement.
        if (ctx.locks) ctx.locks.push(await mutex.acquire(String(values[0])))
        return 1
      }
      // The purge's removal of one plugin's model choice from every user (TD-10).
      if (sql === 'UPDATE "user_settings" SET "feature_models" = "feature_models" - ? WHERE jsonb_exists("feature_models", ?)') {
        const key = String(values[0])
        let count = 0
        for (const row of [...tables.userSettings.values()]) {
          const fm = row.featureModels
          if (!fm || typeof fm !== 'object' || Array.isArray(fm) || !Object.hasOwn(fm, key)) continue
          const next = clone(row)
          delete (next.featureModels as Row)[key]
          next.updatedAt = now()
          write(ctx, 'userSettings', row.id, next)
          count++
        }
        return count
      }
      // A migration's data swap (dataStore.swapNamespace): a move that keeps updated_at.
      if (sql === 'UPDATE "plugin_data" SET "namespace" = ? WHERE "plugin_id" = ? AND "namespace" = ? AND "collection" NOT LIKE ?') {
        const [to, pluginId, from, pattern] = values.map(String)
        if (pattern !== '\\_\\_%') throw new Error(`fakePrisma: unexpected reserved pattern ${pattern}`)
        let count = 0
        for (const row of [...tables.pluginData.values()]) {
          if (row.pluginId !== pluginId || row.namespace !== from || String(row.collection).startsWith('__')) continue
          const next = { ...clone(row), namespace: to }
          checkUnique('pluginData', next, row.id)
          write(ctx, 'pluginData', row.id, next)
          count++
        }
        return count
      }
      throw new Error(`fakePrisma: raw SQL not supported: ${sql}`)
    }
    c.$queryRaw = async (query: { sql?: string; values?: unknown[] }) => {
      const sql = String(query?.sql ?? '')
      const values = query?.values ?? []
      rawCalls.push({ sql, values })
      if (sql.includes('/* user_skill_name_taken */')) {
        // values: userId, the whitespace pattern, the name, the pattern again, the excepted id.
        const [userId, , name, , exceptId] = values as string[]
        const key = fakeNameKey(name)
        const taken = [...tables.userAttackSkill.values()].some(
          (r) => r.userId === userId && r.id !== exceptId && fakeNameKey(String(r.name)) === key,
        )
        return [{ taken }]
      }
      if (sql.includes('/* user_skill_name_keys */')) {
        const names = values[1] as string[]
        return names.map((n, i) => ({ i: i + 1, k: fakeNameKey(n) }))
      }
      throw new Error(`fakePrisma: raw query not supported: ${sql}`)
    }
    c.$transaction = async (arg: unknown) => {
      if (Array.isArray(arg)) return Promise.all(arg)
      transactions++
      const tx: Context = { undo: [], locks: [] }
      try {
        return await (arg as (t: FakePrisma) => Promise<unknown>)(client(tx))
      } catch (e) {
        for (const u of tx.undo!.reverse()) {
          if (u.before) tables[u.table].set(u.pk, u.before)
          else tables[u.table].delete(u.pk)
        }
        throw e
      } finally {
        for (const release of tx.locks!) release()
      }
    }
    c.rawCalls = rawCalls
    c.tables = tables
    c.seed = (table: TableName, rows: Row[]) => {
      const d = delegate(table, { undo: null, locks: null })
      for (const r of rows) d.createNow(r)
    }
    c.rows = (table: TableName) => [...tables[table].values()].map((r) => clone(r))
    Object.defineProperty(c, 'transactions', { get: () => transactions })
    return c as unknown as FakePrisma
  }

  return client({ undo: null, locks: null })
}
