/**
 * An in-memory double of the Prisma client for the Tradecraft modules and routes: the tables
 * they read and write, the `where` shapes they use, `select` projection, unique keys, the
 * cascades of `schema.prisma`, and interactive transactions that run one at a time and roll
 * back on a throw (what the resource row lock gives in Postgres). Raw statements are recorded;
 * a `... FOR UPDATE` on `user_tradecraft_resources` answers the matching row ids.
 *
 *   const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
 *   vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as never)[k] }) }))
 *   beforeEach(() => { h.db = createTradecraftDb() })
 */
type Row = Record<string, unknown>
type Where = Record<string, unknown>

const DEFAULTS: Record<string, () => Row> = {
  userTradecraftResource: () => ({
    enabled: true, resourceType: 'agentic-crawl', summary: '', sitemap: {}, crawlStoppedBecause: '', crawlStats: {},
    llmModel: '', githubTokenOverride: '', cacheTtlSec: 0, lastVerifiedAt: null, lastRefreshedAt: null, lastError: '',
    storageMode: 'live', forcedType: '', overrides: {}, typeOptions: {}, focus: {}, credentials: {}, hasLogin: false,
    summarySource: 'generated', summaryLocked: false, settingsSnapshot: {}, settingsHash: '', ingestionReport: {},
    mapVersion: 1, legacyMapHash: '', generation: 0, activeJobId: null, priority: 'normal', presetKey: '',
  }),
  tradecraftIngestionJob: () => ({
    resourceId: null, status: 'queued', stage: '', progress: {}, errorCode: '', cancelRequested: false, leaseUntil: null,
    ownerInstance: '', bulkId: null, targetGeneration: 0, actorUserId: null, realActorUserId: null, startedAt: null,
    finishedAt: null,
  }),
  tradecraftUserSettings: () => ({
    v2Enabled: false, v2EnabledAt: null, ingestion: {}, search: {}, recipes: [], synonyms: [], bulkRefreshOfferedAt: null,
  }),
  tradecraftProjectChoice: () => ({ createdById: null }),
  tradecraftEntry: () => ({
    title: '', status: 'kept', storedText: null, storedBytes: 0, topics: [], kinds: [], technologies: [], entities: [],
  }),
  tradecraftSection: () => ({}),
  tradecraftCuration: () => ({ pinned: false, blocked: false, renamedTitle: null, restoredFromDrop: false, createdById: null }),
  tradecraftPageId: () => ({}),
  tradecraftTreeNode: () => ({}),
  userSettings: () => ({ githubAccessToken: '' }),
  project: () => ({}),
  user: () => ({}),
  userAttackSkill: () => ({ description: null, content: '', quarantinedAt: null, lineageRootId: null, version: 1 }),
  // The rows `writeAuditTx` writes inside a write's transaction: rolled back with it.
  auditLog: () => ({}),
}

/** Unique keys per table, as `schema.prisma` declares them (the id is always one). */
const UNIQUE: Record<string, string[][]> = {
  userTradecraftResource: [['userId', 'url'], ['userId', 'slug']],
  tradecraftUserSettings: [['userId']],
  tradecraftProjectChoice: [['projectId', 'resourceId']],
  userSettings: [['userId']],
  tradecraftCuration: [['resourceId', 'url']],
  tradecraftEntry: [['resourceId', 'generation', 'pageId']],
}

/** `schema.prisma`'s onDelete: Cascade, child table -> its foreign key, per parent table. */
const CASCADES: Record<string, [string, string][]> = {
  user: [['userTradecraftResource', 'userId'], ['tradecraftIngestionJob', 'userId'], ['tradecraftUserSettings', 'userId'],
    ['tradecraftEntry', 'userId'], ['userSettings', 'userId'], ['project', 'userId']],
  userTradecraftResource: [['tradecraftIngestionJob', 'resourceId'], ['tradecraftPageId', 'resourceId'],
    ['tradecraftEntry', 'resourceId'], ['tradecraftSection', 'resourceId'], ['tradecraftTreeNode', 'resourceId'],
    ['tradecraftCuration', 'resourceId'], ['tradecraftProjectChoice', 'resourceId']],
  project: [['tradecraftProjectChoice', 'projectId']],
}

const UPDATED_AT = new Set(['userTradecraftResource', 'tradecraftIngestionJob', 'tradecraftUserSettings', 'tradecraftEntry', 'tradecraftCuration'])

function isPlain(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v) && !(v instanceof Date)
}

function eq(a: unknown, b: unknown): boolean {
  if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime()
  return a === b
}

function cmp(a: unknown, b: unknown): number {
  const x = a instanceof Date ? a.getTime() : (a as number)
  const y = b instanceof Date ? b.getTime() : (b as number)
  return x < y ? -1 : x > y ? 1 : 0
}

function matchesField(value: unknown, cond: unknown): boolean {
  if (cond === null) return value === null || value === undefined
  if (!isPlain(cond)) return eq(value, cond)
  const insensitive = cond.mode === 'insensitive'
  for (const [op, arg] of Object.entries(cond)) {
    switch (op) {
      case 'mode': break
      case 'contains': {
        if (typeof value !== 'string') return false
        const [v, a] = insensitive ? [value.toLowerCase(), String(arg).toLowerCase()] : [value, String(arg)]
        if (!v.includes(a)) return false
        break
      }
      case 'equals': if (!matchesField(value, arg)) return false; break
      case 'in': if (!(arg as unknown[]).some(a => eq(a, value))) return false; break
      case 'notIn': if ((arg as unknown[]).some(a => eq(a, value))) return false; break
      case 'not': if (matchesField(value, arg)) return false; break
      case 'lt': if (value === null || value === undefined || cmp(value, arg) >= 0) return false; break
      case 'lte': if (value === null || value === undefined || cmp(value, arg) > 0) return false; break
      case 'gt': if (value === null || value === undefined || cmp(value, arg) <= 0) return false; break
      case 'gte': if (value === null || value === undefined || cmp(value, arg) < 0) return false; break
      case 'has': if (!Array.isArray(value) || !value.includes(arg)) return false; break
      default: throw new Error(`tradecraftDb: unsupported filter ${op}`)
    }
  }
  return true
}

export function matches(row: Row, where: Where | undefined): boolean {
  if (!where) return true
  for (const [key, cond] of Object.entries(where)) {
    if (cond === undefined) continue
    if (key === 'OR') { if (!(cond as Where[]).some(w => matches(row, w))) return false; continue }
    if (key === 'AND') { if (!(cond as Where[]).every(w => matches(row, w))) return false; continue }
    if (key === 'NOT') { if (matches(row, cond as Where)) return false; continue }
    // A compound unique key (`userId_slug: { userId, slug }`) is the conjunction of its parts.
    if (key.includes('_') && isPlain(cond) && Object.keys(cond).every(k => key.split('_').includes(k))) {
      if (!matches(row, cond)) return false
      continue
    }
    if (!matchesField(row[key], cond)) return false
  }
  return true
}

function project(row: Row, select: Record<string, unknown> | undefined): Row {
  const copy = structuredClone(row)
  if (!select) return copy
  const out: Row = {}
  for (const [k, on] of Object.entries(select)) if (on) out[k] = copy[k]
  return out
}

function applyData(row: Row, data: Row): void {
  for (const [k, v] of Object.entries(data)) {
    if (isPlain(v) && ('increment' in v || 'set' in v)) {
      row[k] = 'increment' in v ? (row[k] as number) + (v.increment as number) : v.set
    } else {
      row[k] = v
    }
  }
}

class PrismaError extends Error {
  constructor(message: string, readonly code: string) { super(message) }
}

export interface TradecraftDb {
  tables: Record<string, Row[]>
  /** Every raw statement's text (placeholders as `$n`) with its values. */
  raw: { sql: string; values: unknown[] }[]
  /** Every delegate call, `model.op`, in order. */
  calls: string[]
  /** The next call of `model.op` throws this error. */
  failNext(op: string, err: Error): void
  seed(model: string, row: Row): Row
  rows(model: string, where?: Where): Row[]
  prisma: Record<string, unknown>
  /** Moves the clock the double stamps createdAt/updatedAt with. */
  clock: { now: () => Date }
}

export function createTradecraftDb(): TradecraftDb {
  const tables: Record<string, Row[]> = Object.fromEntries(Object.keys(DEFAULTS).map(k => [k, []]))
  const raw: { sql: string; values: unknown[] }[] = []
  const calls: string[] = []
  const failures = new Map<string, Error>()
  const clock = { now: () => new Date('2026-11-16T10:00:00Z') }
  let nextId = 1
  let txChain: Promise<unknown> = Promise.resolve()

  function fail(op: string): void {
    calls.push(op)
    const err = failures.get(op)
    if (err) { failures.delete(op); throw err }
  }

  function checkUnique(model: string, row: Row, self?: Row): void {
    for (const key of [['id'], ...(UNIQUE[model] ?? [])]) {
      const clash = tables[model].find(r => r !== self && key.every(k => eq(r[k], row[k])) && key.every(k => row[k] !== undefined))
      if (clash) throw new PrismaError(`Unique constraint failed on the fields: (${key.join(',')})`, 'P2002')
    }
  }

  function insert(model: string, data: Row): Row {
    const at = clock.now()
    const row: Row = { ...DEFAULTS[model](), createdAt: at, ...(UPDATED_AT.has(model) ? { updatedAt: at } : {}), ...structuredClone(data) }
    if (row.id === undefined && model !== 'tradecraftProjectChoice') row.id = `${model.slice(0, 3)}-${nextId++}`
    checkUnique(model, row)
    tables[model].push(row)
    return row
  }

  function remove(model: string, row: Row): void {
    tables[model] = tables[model].filter(r => r !== row)
    for (const [child, fk] of CASCADES[model] ?? []) {
      for (const c of tables[child].filter(r => r[fk] === row.id)) remove(child, c)
    }
  }

  function sortRows(rows: Row[], orderBy: unknown): Row[] {
    const orders = (Array.isArray(orderBy) ? orderBy : orderBy ? [orderBy] : []) as Record<string, 'asc' | 'desc'>[]
    return [...rows].sort((a, b) => {
      for (const o of orders) {
        const [k, dir] = Object.entries(o)[0]
        const c = cmp(a[k], b[k])
        if (c !== 0) return dir === 'desc' ? -c : c
      }
      return 0
    })
  }

  function delegate(model: string) {
    return {
      findUnique: async ({ where, select }: { where: Where; select?: Row }) => {
        fail(`${model}.findUnique`)
        const r = tables[model].find(x => matches(x, where))
        return r ? project(r, select) : null
      },
      findFirst: async ({ where, select, orderBy }: { where?: Where; select?: Row; orderBy?: unknown }) => {
        fail(`${model}.findFirst`)
        const r = sortRows(tables[model].filter(x => matches(x, where)), orderBy)[0]
        return r ? project(r, select) : null
      },
      findMany: async ({ where, select, orderBy, distinct, take }: { where?: Where; select?: Row; orderBy?: unknown; distinct?: string[]; take?: number } = {}) => {
        fail(`${model}.findMany`)
        let rows = sortRows(tables[model].filter(x => matches(x, where)), orderBy)
        if (distinct) {
          const seen = new Set<string>()
          rows = rows.filter(r => { const k = distinct.map(d => String(r[d])).join('|'); if (seen.has(k)) return false; seen.add(k); return true })
        }
        if (take !== undefined) rows = rows.slice(0, take)
        return rows.map(r => project(r, select))
      },
      count: async ({ where }: { where?: Where } = {}) => {
        fail(`${model}.count`)
        return tables[model].filter(x => matches(x, where)).length
      },
      groupBy: async ({ by, where }: { by: string[]; where?: Where; _count?: unknown }) => {
        fail(`${model}.groupBy`)
        const groups = new Map<string, Row>()
        for (const r of tables[model].filter(x => matches(x, where))) {
          const k = by.map(b => String(r[b])).join('|')
          const g = groups.get(k) ?? { ...Object.fromEntries(by.map(b => [b, r[b]])), _count: { _all: 0 } }
          ;(g._count as { _all: number })._all += 1
          groups.set(k, g)
        }
        return [...groups.values()]
      },
      create: async ({ data, select }: { data: Row; select?: Row }) => {
        fail(`${model}.create`)
        return project(insert(model, data), select)
      },
      createMany: async ({ data, skipDuplicates }: { data: Row[]; skipDuplicates?: boolean }) => {
        fail(`${model}.createMany`)
        let count = 0
        for (const row of data) {
          try {
            insert(model, row)
            count += 1
          } catch (err) {
            if (!(skipDuplicates && err instanceof PrismaError && err.code === 'P2002')) throw err
          }
        }
        return { count }
      },
      update: async ({ where, data, select }: { where: Where; data: Row; select?: Row }) => {
        fail(`${model}.update`)
        const r = tables[model].find(x => matches(x, where))
        if (!r) throw new PrismaError('Record to update not found.', 'P2025')
        const next = { ...r }
        applyData(next, structuredClone(data))
        if (UPDATED_AT.has(model)) next.updatedAt = clock.now()
        checkUnique(model, next, r)
        Object.assign(r, next)
        return project(r, select)
      },
      updateMany: async ({ where, data }: { where?: Where; data: Row }) => {
        fail(`${model}.updateMany`)
        const rows = tables[model].filter(x => matches(x, where))
        for (const r of rows) {
          applyData(r, structuredClone(data))
          if (UPDATED_AT.has(model)) r.updatedAt = clock.now()
        }
        return { count: rows.length }
      },
      upsert: async ({ where, create, update }: { where: Where; create: Row; update: Row }) => {
        fail(`${model}.upsert`)
        const r = tables[model].find(x => matches(x, where))
        if (!r) return project(insert(model, create), undefined)
        applyData(r, structuredClone(update))
        return project(r, undefined)
      },
      delete: async ({ where }: { where: Where }) => {
        fail(`${model}.delete`)
        const r = tables[model].find(x => matches(x, where))
        if (!r) throw new PrismaError('Record to delete does not exist.', 'P2025')
        remove(model, r)
        return structuredClone(r)
      },
      deleteMany: async ({ where }: { where?: Where } = {}) => {
        fail(`${model}.deleteMany`)
        const rows = tables[model].filter(x => matches(x, where))
        for (const r of rows) remove(model, r)
        return { count: rows.length }
      },
    }
  }

  function rawCall(strings: TemplateStringsArray, values: unknown[]): unknown[] {
    const sql = strings.reduce((acc, s, i) => acc + s + (i < values.length ? `$${i + 1}` : ''), '').replace(/\s+/g, ' ').trim()
    raw.push({ sql, values })
    fail('$raw')
    const lock = /FROM user_tradecraft_resources WHERE id = \$1 AND user_id = \$2 FOR UPDATE/.exec(sql)
    if (lock) {
      return tables.userTradecraftResource.filter(r => r.id === values[0] && r.userId === values[1]).map(r => ({ id: r.id, generation: r.generation }))
    }
    return []
  }

  const client: Record<string, unknown> = {
    $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => rawCall(strings, values),
    $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => rawCall(strings, values).length,
  }
  for (const model of Object.keys(DEFAULTS)) client[model] = delegate(model)

  client.$transaction = async (arg: unknown) => {
    if (Array.isArray(arg)) return Promise.all(arg)
    // One transaction at a time, as the row lock serializes the writers of one resource.
    const run = txChain.then(async () => {
      const before = structuredClone(tables)
      try {
        return await (arg as (tx: unknown) => Promise<unknown>)(client)
      } catch (err) {
        for (const k of Object.keys(tables)) tables[k] = before[k]
        throw err
      }
    })
    txChain = run.catch(() => undefined)
    return run
  }

  return {
    tables,
    raw,
    calls,
    clock,
    failNext: (op, err) => { failures.set(op, err) },
    seed: (model, row) => insert(model, row),
    rows: (model, where) => tables[model].filter(r => matches(r, where)),
    prisma: client,
  }
}
