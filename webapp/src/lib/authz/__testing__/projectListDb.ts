/**
 * An in-memory Prisma double for tests of the lists that show "my projects" (step 4.5): the project
 * list, the reports and the scan activity view. It evaluates the `where` shapes those routes and
 * visibleProjects.ts build (columns, `in`, `not`, `gt`, `OR`, `NOT`, the share relation filter
 * `collaborators: {some}` with its account and expiry, a `project` relation filter) and shapes the
 * `select` they ask for (scalars, a to-one relation's `select`, the person's own share of a row),
 * so a test asserts which rows come back, not which arguments were passed. The instance row holds
 * the sharing policy; every other model is absent.
 *
 *   const h = vi.hoisted(() => ({ db: null as unknown }))
 *   vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db as Record<string, unknown>)[k as string] }) }))
 *   beforeEach(() => { h.db = projectListPrisma(state) })
 */

type Row = Record<string, unknown>
type Where = Record<string, unknown>

export interface ProjectListState {
  projects: Row[]
  users: Row[]
  /** `{projectId, userId, access, rawData, expiresAt}` */
  shares: Row[]
  reports: Row[]
  jobQueue: Row[]
  scanJobs: Row[]
  /** The stored sharing policy (the instance row's JSON). */
  policy: unknown
}

export function emptyProjectListState(): ProjectListState {
  return { projects: [], users: [], shares: [], reports: [], jobQueue: [], scanJobs: [], policy: { enabled: true } }
}

type Table = 'project' | 'user' | 'share' | 'report' | 'jobQueue' | 'scanJob'

interface Relation {
  table: Table
  many: boolean
  of: (row: Row, state: ProjectListState) => Row[]
}

const RELATIONS: Partial<Record<Table, Record<string, Relation>>> = {
  project: {
    user: { table: 'user', many: false, of: (r, s) => s.users.filter((u) => u.id === r.userId) },
    collaborators: { table: 'share', many: true, of: (r, s) => s.shares.filter((c) => c.projectId === r.id) },
  },
  share: { user: { table: 'user', many: false, of: (r, s) => s.users.filter((u) => u.id === r.userId) } },
  report: { project: { table: 'project', many: false, of: (r, s) => s.projects.filter((p) => p.id === r.projectId) } },
  jobQueue: { project: { table: 'project', many: false, of: (r, s) => s.projects.filter((p) => p.id === r.projectId) } },
  scanJob: { project: { table: 'project', many: false, of: (r, s) => s.projects.filter((p) => p.id === r.projectId) } },
}

const OPERATORS = new Set(['in', 'notIn', 'not', 'gt', 'gte', 'lt', 'lte', 'equals'])

function isOperatorObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || value instanceof Date || Array.isArray(value)) return false
  const keys = Object.keys(value)
  return keys.length > 0 && keys.every((k) => OPERATORS.has(k))
}

const time = (v: unknown): unknown => (v instanceof Date ? v.getTime() : v)

function fieldMatches(value: unknown, filter: unknown): boolean {
  if (!isOperatorObject(filter)) return time(value) === time(filter)
  return Object.entries(filter).every(([op, arg]) => {
    switch (op) {
      case 'in': return (arg as unknown[]).some((a) => time(a) === time(value))
      case 'notIn': return !(arg as unknown[]).some((a) => time(a) === time(value))
      case 'not': return !fieldMatches(value, arg)
      case 'equals': return time(value) === time(arg)
      case 'gt': return value !== null && value !== undefined && (time(value) as number) > (time(arg) as number)
      case 'gte': return value !== null && value !== undefined && (time(value) as number) >= (time(arg) as number)
      case 'lt': return value !== null && value !== undefined && (time(value) as number) < (time(arg) as number)
      case 'lte': return value !== null && value !== undefined && (time(value) as number) <= (time(arg) as number)
      default: throw new Error(`projectListDb: operator ${op} not modelled`)
    }
  })
}

function matches(table: Table, row: Row, where: Where | undefined, state: ProjectListState): boolean {
  if (!where) return true
  return Object.entries(where).every(([key, value]) => {
    if (value === undefined) return true
    if (key === 'OR') return (value as Where[]).some((w) => matches(table, row, w, state))
    if (key === 'AND') return (value as Where[]).every((w) => matches(table, row, w, state))
    if (key === 'NOT') return !(Array.isArray(value) ? value : [value]).some((w) => matches(table, row, w as Where, state))
    const relation = RELATIONS[table]?.[key]
    if (relation) {
      const related = relation.of(row, state)
      if (!relation.many) return related.length === 1 && matches(relation.table, related[0], value as Where, state)
      const { some, ...rest } = value as { some?: Where }
      if (Object.keys(rest).length > 0 || !some) throw new Error(`projectListDb: list filter ${Object.keys(rest)} not modelled`)
      return related.some((r) => matches(relation.table, r, some, state))
    }
    return fieldMatches(row[key], value)
  })
}

function shape(table: Table, row: Row, select: Record<string, unknown> | undefined, state: ProjectListState): Row {
  if (!select) return { ...row }
  const out: Row = {}
  for (const [key, spec] of Object.entries(select)) {
    if (!spec) continue
    const relation = RELATIONS[table]?.[key]
    if (!relation) {
      out[key] = row[key]
      continue
    }
    const args = (spec === true ? {} : spec) as { where?: Where; select?: Record<string, unknown> }
    const related = relation.of(row, state).filter((r) => matches(relation.table, r, args.where, state))
    out[key] = relation.many
      ? related.map((r) => shape(relation.table, r, args.select, state))
      : (related[0] ? shape(relation.table, related[0], args.select, state) : null)
  }
  return out
}

type OrderBy = Record<string, 'asc' | 'desc'> | Array<Record<string, 'asc' | 'desc'>> | undefined

function sorted(rows: Row[], orderBy: OrderBy): Row[] {
  const keys = (Array.isArray(orderBy) ? orderBy : orderBy ? [orderBy] : []).flatMap((o) => Object.entries(o))
  return [...rows].sort((a, b) => {
    for (const [key, dir] of keys) {
      const x = time(a[key]) as number
      const y = time(b[key]) as number
      if (x === y) continue
      if (x === null || x === undefined) return 1
      if (y === null || y === undefined) return -1
      return (x < y ? -1 : 1) * (dir === 'desc' ? -1 : 1)
    }
    return 0
  })
}

interface FindArgs { where?: Where; select?: Record<string, unknown>; orderBy?: OrderBy; take?: number }

function model(table: Table, rows: (s: ProjectListState) => Row[], state: ProjectListState) {
  const found = (a: FindArgs = {}) => sorted(rows(state).filter((r) => matches(table, r, a.where, state)), a.orderBy)
  return {
    findMany: async (a: FindArgs = {}) => found(a).slice(0, a.take ?? Infinity).map((r) => shape(table, r, a.select, state)),
    count: async (a: { where?: Where } = {}) => found(a).length,
    groupBy: async (a: { by: string[]; where?: Where }) => {
      const groups = new Map<string, Row>()
      for (const r of found(a)) {
        const key = JSON.stringify(a.by.map((k) => r[k] ?? null))
        const g = groups.get(key) ?? { ...Object.fromEntries(a.by.map((k) => [k, r[k] ?? null])), _count: { _all: 0 } }
        ;(g._count as { _all: number })._all += 1
        groups.set(key, g)
      }
      return [...groups.values()]
    },
  }
}

/** The Prisma client the list routes read, over `state` (mutate `state` between requests). */
export function projectListPrisma(state: ProjectListState) {
  return {
    project: model('project', (s) => s.projects, state),
    user: model('user', (s) => s.users, state),
    report: model('report', (s) => s.reports, state),
    jobQueue: model('jobQueue', (s) => s.jobQueue, state),
    scanJob: model('scanJob', (s) => s.scanJobs, state),
    instanceSettings: { findUnique: async () => ({ id: 'instance', sharingPolicy: state.policy }) },
  }
}
