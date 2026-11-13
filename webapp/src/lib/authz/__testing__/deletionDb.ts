/**
 * An in-memory stand-in for the Prisma client, for the user deletion and its plan (step 5.13): any
 * table by name (`db.<table>`), with the query shapes the deletion, the plan, the ownership transfer
 * and the revocation path send.
 *
 * - `where`: equality (`null` included), `{in}`, `{not}` (a value, `null` or a nested filter), `{gt}`,
 *   `{lt}`, `{lte}`, `OR`, `AND`, `NOT`, the compound `projectId_userId`, and the relations the readers
 *   use: `project` and `user` (a row's `projectId` / `userId`), and a project's `collaborators: {some}`;
 * - `select` picks the keys and follows `project` and `user` with their own `select`; `orderBy`
 *   on `createdAt` (asc or desc); `take`;
 * - `$transaction(fn)` rolls every write of `fn` back when it throws (the state restored from a
 *   snapshot); `$executeRaw` (the advisory locks) answers 1;
 * - deleting a user cascades as the schema does into the rows whose `userId` names it (its projects,
 *   shares, conversations, MCP tokens, device sessions), and a project into its rows;
 * - `failNext(table, op)` makes the next such write throw (P1017), as a lost database would.
 */
type Row = Record<string, unknown>
type Where = Row

/** The rows the schema deletes with a user (`onDelete: Cascade` on `userId`). */
const USER_CASCADE = ['project', 'projectCollaborator', 'conversation', 'mcpAccessToken', 'userSession']
/** The rows the schema deletes with a project. */
const PROJECT_CASCADE = ['projectCollaborator', 'jobQueue', 'scanSchedule', 'conversation', 'projectTransfer', 'triageRun']

export interface DeletionDb {
  tables: Record<string, Row[]>
  rows(table: string): Row[]
  seed(tables: Record<string, Row[]>): void
  failNext(table: string, op: 'create' | 'update' | 'delete'): void
  [table: string]: unknown
}

export function createDeletionDb(): DeletionDb {
  const state = { tables: {} as Record<string, Row[]>, seq: 0, fail: null as null | { table: string; op: string } }
  const rows = (table: string) => (state.tables[table] ??= [])

  function relation(row: Row, key: string): Row | null {
    if (key === 'project') return rows('project').find((p) => p.id === row.projectId) ?? null
    if (key === 'user') return rows('user').find((u) => u.id === row.userId) ?? null
    return null
  }

  function scalar(value: unknown, cond: unknown): boolean {
    if (cond !== null && typeof cond === 'object' && !(cond instanceof Date) && !Array.isArray(cond)) {
      const c = cond as Row
      return Object.entries(c).every(([op, arg]) => {
        if (op === 'in') return (arg as unknown[]).includes(value)
        if (op === 'not') {
          if (arg === null) return value !== null && value !== undefined
          if (arg !== null && typeof arg === 'object' && !(arg instanceof Date)) return !scalar(value, arg)
          return value !== arg
        }
        const time = (v: unknown) => (v instanceof Date ? v.getTime() : Number.NaN)
        if (op === 'gt') return time(value) > time(arg)
        if (op === 'lt') return time(value) < time(arg)
        if (op === 'lte') return time(value) <= time(arg)
        if (op === 'gte') return time(value) >= time(arg)
        throw new Error(`deletionDb: unsupported operator ${op}`)
      })
    }
    if (value instanceof Date && cond instanceof Date) return value.getTime() === cond.getTime()
    return (value ?? null) === (cond ?? null)
  }

  function matches(table: string, row: Row, where: Where | undefined): boolean {
    if (!where) return true
    return Object.entries(where).every(([key, cond]) => {
      if (key === 'OR') return (cond as Where[]).some((w) => matches(table, row, w))
      if (key === 'AND') return (cond as Where[]).every((w) => matches(table, row, w))
      if (key === 'NOT') return !matches(table, row, cond as Where)
      if (key === 'projectId_userId') return matches(table, row, cond as Where)
      if ((key === 'project' || key === 'user') && !(key in row)) {
        const related = relation(row, key)
        return !!related && matches(key, related, cond as Where)
      }
      if (key === 'collaborators' && table === 'project') {
        const some = (cond as { some?: Where }).some
        return rows('projectCollaborator').some((c) => c.projectId === row.id && matches('projectCollaborator', c, some))
      }
      return scalar(row[key], cond)
    })
  }

  function pick(row: Row, select?: Row): Row {
    if (!select) return { ...row }
    const out: Row = {}
    for (const [key, sel] of Object.entries(select)) {
      if (!sel) continue
      if (sel !== true && (key === 'project' || key === 'user')) {
        const related = relation(row, key)
        out[key] = related ? pick(related, (sel as { select?: Row }).select) : null
      } else {
        out[key] = row[key]
      }
    }
    return out
  }

  function guard(table: string, op: string) {
    if (state.fail && state.fail.table === table && state.fail.op === op) {
      state.fail = null
      throw Object.assign(new Error(`write to ${table} failed`), { code: 'P1017' })
    }
  }

  function deleteRows(table: string, doomed: Row[]) {
    state.tables[table] = rows(table).filter((r) => !doomed.includes(r))
    for (const row of doomed) {
      if (table === 'user') {
        for (const t of USER_CASCADE) deleteRows(t, rows(t).filter((r) => r.userId === row.id))
      }
      if (table === 'project') {
        for (const t of PROJECT_CASCADE) deleteRows(t, rows(t).filter((r) => r.projectId === row.id))
      }
    }
  }

  function sorted(found: Row[], orderBy?: Row | Row[]): Row[] {
    const order = Array.isArray(orderBy) ? orderBy[0] : orderBy
    const dir = order?.createdAt
    if (!dir) return found
    const t = (r: Row) => (r.createdAt instanceof Date ? r.createdAt.getTime() : 0)
    return [...found].sort((a, b) => (dir === 'asc' ? t(a) - t(b) : t(b) - t(a)))
  }

  function table(name: string) {
    const find = (where?: Where) => rows(name).filter((r) => matches(name, r, where))
    return {
      findUnique: async ({ where, select }: { where: Where; select?: Row }) => {
        const r = find(where)[0]
        return r ? pick(r, select) : null
      },
      findFirst: async ({ where, select, orderBy }: { where?: Where; select?: Row; orderBy?: Row } = {}) => {
        const r = sorted(find(where), orderBy)[0]
        return r ? pick(r, select) : null
      },
      findMany: async ({ where, select, orderBy, take }: { where?: Where; select?: Row; orderBy?: Row; take?: number } = {}) =>
        sorted(find(where), orderBy).slice(0, take ?? undefined).map((r) => pick(r, select)),
      count: async ({ where }: { where?: Where } = {}) => find(where).length,
      create: async ({ data, select }: { data: Row; select?: Row }) => {
        guard(name, 'create')
        const row: Row = { id: `${name}-${++state.seq}`, createdAt: new Date(Date.UTC(2026, 10, 13) + state.seq), ...data }
        rows(name).push(row)
        return pick(row, select)
      },
      update: async ({ where, data, select }: { where: Where; data: Row; select?: Row }) => {
        guard(name, 'update')
        const r = find(where)[0]
        if (!r) throw Object.assign(new Error('Record to update not found.'), { code: 'P2025' })
        Object.assign(r, data)
        return pick(r, select)
      },
      updateMany: async ({ where, data }: { where?: Where; data: Row }) => {
        guard(name, 'update')
        const hit = find(where)
        for (const r of hit) Object.assign(r, data)
        return { count: hit.length }
      },
      delete: async ({ where }: { where: Where }) => {
        guard(name, 'delete')
        const r = find(where)[0]
        if (!r) throw Object.assign(new Error('Record to delete does not exist.'), { code: 'P2025' })
        deleteRows(name, [r])
        return { ...r }
      },
      deleteMany: async ({ where }: { where?: Where } = {}) => {
        guard(name, 'delete')
        const hit = find(where)
        deleteRows(name, hit)
        return { count: hit.length }
      },
    }
  }

  const tables = new Map<string, ReturnType<typeof table>>()
  const base: Row = {
    get tables() { return state.tables },
    rows,
    seed(seedTables: Record<string, Row[]>) {
      state.tables = structuredClone(seedTables)
      state.seq = 0
      state.fail = null
    },
    failNext(t: string, op: string) { state.fail = { table: t, op } },
    $executeRaw: async () => 1,
  }
  const db: DeletionDb = new Proxy(base, {
    get(target, prop: string) {
      if (prop in target) return target[prop]
      if (prop === '$transaction') {
        return async (fn: (tx: unknown) => Promise<unknown>) => {
          const snapshot = structuredClone(state.tables)
          try {
            return await fn(db)
          } catch (err) {
            state.tables = snapshot
            throw err
          }
        }
      }
      if (prop === 'then' || typeof prop !== 'string' || prop.startsWith('$')) return undefined
      if (!tables.has(prop)) tables.set(prop, table(prop))
      return tables.get(prop)
    },
  }) as DeletionDb
  return db
}
