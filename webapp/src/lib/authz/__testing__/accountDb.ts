/**
 * An in-memory stand-in for the Prisma client, for the account-status tests (step 2.3): the
 * `users`, `mcp_access_tokens` and `audit_log` rows those routes touch, and the instance
 * settings row whose Root the Root protections read (step 2.5), with the semantics they rely on:
 *
 * - `$transaction(fn)` runs one at a time and rolls back every write of `fn` when it throws
 *   (state restored from a snapshot), so "the audit write failed, so nothing changed" is real;
 * - `SELECT pg_advisory_xact_lock(...)` through `$executeRaw` is accepted (transactions
 *   already run one at a time here);
 * - `where` matches equality, `{not}`, `{in}` and `null`; `data` applies `{increment}`;
 *   `update` of a missing row raises P2025; `@updatedAt` moves on every update;
 * - `failAudit(action)` makes the audit insert of that action throw, as a lost database would;
 * - (step 2.6) the instance row is written by `update` / `updateMany`, accounts are created and
 *   deleted, and an account's deletion reads no project and hands over no template here;
 * - (step 2.9) the `user_invites` rows (deleted with their account, as the schema's cascade),
 *   `where` also matches `{gt}` / `{lt}` on dates, `user.deleteMany`, `project.count` (seeded
 *   by `seedProjects`), and the one raw read `emailTakenByAnother` sends;
 * - (step 2.10) every account carries `pendingNotices` (`[]`, the schema default);
 * - (step 3.11) the `permission_sets`, `user_permission_sets` and `user_permission_overrides`
 *   rows (an account's assignments and overrides go with it, as the schema's cascade), the
 *   account's nested `permissionSets` / `permissionOverrides` select the principal makes, a
 *   unique set name (P2002), and `orderBy` ignored (callers sort);
 * - (step 3.14) the act-as log read newest first (`findFirst` / `findMany` with `take`, rows
 *   ordered by `createdAt`, then by insertion), and the conditional raw write of an account's
 *   notices (`appendNotice`), which writes only when the stored list is still the one it read.
 */
import { Prisma } from '@prisma/client'

export type Row = Record<string, unknown>

export interface AccountSeed {
  id: string
  name?: string
  email?: string
  role?: string
  password?: string
  status?: string
  sessionVersion?: number
  passwordOnHold?: string
  legacyGrants?: string[]
  lastLoginAt?: Date | null
  pendingNotices?: unknown[]
  adminProfileId?: string | null
}

function matches(row: Row, where: Row = {}): boolean {
  for (const [k, cond] of Object.entries(where)) {
    if (cond === undefined) continue
    const v = row[k]
    if (cond !== null && typeof cond === 'object' && !(cond instanceof Date)) {
      const c = cond as Row
      if ('not' in c && v === c.not) return false
      if ('in' in c && !(c.in as unknown[]).includes(v)) return false
      if ('gt' in c && !(v instanceof Date && v.getTime() > (c.gt as Date).getTime())) return false
      if ('lt' in c && !(v instanceof Date && v.getTime() < (c.lt as Date).getTime())) return false
      continue
    }
    if (cond === null ? v !== null && v !== undefined : v !== cond) return false
  }
  return true
}

function apply(row: Row, data: Row): void {
  for (const [k, v] of Object.entries(data)) {
    if (v && typeof v === 'object' && !(v instanceof Date) && 'increment' in (v as Row)) {
      row[k] = (row[k] as number) + ((v as Row).increment as number)
    } else {
      row[k] = v
    }
  }
  row.updatedAt = new Date()
}

function pick(row: Row, select?: Row): Row {
  if (!select) return { ...row }
  return Object.fromEntries(Object.keys(select).filter((k) => select[k]).map((k) => [k, row[k]]))
}

function notFound(): Error {
  return new Prisma.PrismaClientKnownRequestError('Record to update not found.', { code: 'P2025', clientVersion: 'fake' })
}

export function createAccountDb() {
  const state = {
    users: [] as Row[],
    tokens: [] as Row[],
    audit: [] as Row[],
    actAs: [] as Row[],
    instance: null as Row | null,
    invites: [] as Row[],
    projectCounts: {} as Record<string, number>,
    sets: [] as Row[],
    assignments: [] as Row[],
    overrides: [] as Row[],
  }
  const failing = new Set<string>()
  const rawCalls: string[] = []
  const rawValues: unknown[][] = []
  let queue: Promise<unknown> = Promise.resolve()
  let transactions = 0

  const RELATIONS = { permissionSets: () => state.assignments, permissionOverrides: () => state.overrides } as const
  const withRelations = (r: Row, select?: Row): Row => {
    const out = pick(r, select)
    for (const [k, rows] of Object.entries(RELATIONS)) {
      const nested = select?.[k] as { select?: Row } | undefined
      if (nested) out[k] = rows().filter((x) => x.userId === r.id).map((x) => pick(x, nested.select))
    }
    return out
  }
  const user = {
    findUnique: async (a: { where: Row; select?: Row }) => {
      const r = state.users.find((u) => matches(u, a.where))
      return r ? withRelations(r, a.select) : null
    },
    findMany: async (a: { where?: Row; select?: Row } = {}) =>
      state.users.filter((u) => matches(u, a.where)).map((u) => pick(u, a.select)),
    count: async (a: { where?: Row } = {}) => state.users.filter((u) => matches(u, a.where)).length,
    update: async (a: { where: Row; data: Row; select?: Row }) => {
      const r = state.users.find((u) => matches(u, a.where))
      if (!r) throw notFound()
      apply(r, a.data)
      return pick(r, a.select)
    },
    updateMany: async (a: { where?: Row; data: Row }) => {
      const rows = state.users.filter((u) => matches(u, a.where))
      for (const r of rows) apply(r, a.data)
      return { count: rows.length }
    },
    create: async (a: { data: Row; select?: Row }) => {
      if (state.users.some((u) => u.email === a.data.email)) {
        throw new Prisma.PrismaClientKnownRequestError('Unique constraint failed', { code: 'P2002', clientVersion: 'fake' })
      }
      const r: Row = {
        id: `user-${state.users.length + 1}`, role: 'standard', password: '', status: 'active', sessionVersion: 0,
        passwordOnHold: '', mustChangePassword: false, adminProfileId: null, lastLoginAt: null, legacyGrants: [],
        pendingNotices: [], createdAt: new Date(), updatedAt: new Date(), ...a.data,
      }
      state.users.push(r)
      return pick(r, a.select)
    },
    delete: async (a: { where: Row }) => {
      const i = state.users.findIndex((u) => matches(u, a.where))
      if (i < 0) throw notFound()
      const [r] = state.users.splice(i, 1)
      state.invites = state.invites.filter((v) => v.userId !== r.id)
      state.assignments = state.assignments.filter((v) => v.userId !== r.id)
      state.overrides = state.overrides.filter((v) => v.userId !== r.id)
      return r
    },
    deleteMany: async (a: { where?: Row } = {}) => {
      const gone = state.users.filter((u) => matches(u, a.where))
      state.users = state.users.filter((u) => !gone.includes(u))
      const ids = new Set(gone.map((u) => u.id))
      state.invites = state.invites.filter((v) => !ids.has(v.userId))
      state.assignments = state.assignments.filter((v) => !ids.has(v.userId))
      state.overrides = state.overrides.filter((v) => !ids.has(v.userId))
      return { count: gone.length }
    },
  }
  const project = {
    findMany: async () => [] as Row[],
    count: async (a: { where?: Row } = {}) => state.projectCounts[String(a.where?.userId)] ?? 0,
  }
  let inviteSeq = 0
  const withUser = (r: Row, select?: Row): Row => {
    const out = pick(r, select)
    const nested = select?.user as { select?: Row } | undefined
    if (nested) {
      const u = state.users.find((x) => x.id === r.userId)
      out.user = u ? pick(u, nested.select) : null
    }
    return out
  }
  const userInvite = {
    create: async (a: { data: Row; select?: Row }) => {
      if (state.invites.some((v) => v.tokenHash === a.data.tokenHash)) {
        throw new Prisma.PrismaClientKnownRequestError('Unique constraint failed', { code: 'P2002', clientVersion: 'fake' })
      }
      const r: Row = { id: `invite-${++inviteSeq}`, usedAt: null, cancelledAt: null, reason: null, createdAt: new Date(), ...a.data }
      state.invites.push(r)
      return pick(r, a.select)
    },
    findUnique: async (a: { where: Row; select?: Row }) => {
      const r = state.invites.find((v) => matches(v, a.where))
      return r ? withUser(r, a.select) : null
    },
    findMany: async (a: { where?: Row; select?: Row } = {}) =>
      state.invites.filter((v) => matches(v, a.where)).map((v) => withUser(v, a.select)),
    updateMany: async (a: { where?: Row; data: Row }) => {
      const rows = state.invites.filter((v) => matches(v, a.where))
      for (const r of rows) Object.assign(r, a.data)
      return { count: rows.length }
    },
  }
  const $queryRaw = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?')
    if (!/^\s*SELECT id FROM users WHERE lower\(email\) = lower\(\?\)\s*$/.test(sql)) {
      throw new Error(`accountDb: raw SQL not supported: ${sql}`)
    }
    const email = String(values[0]).toLowerCase()
    return state.users.filter((u) => String(u.email).toLowerCase() === email).map((u) => ({ id: u.id }))
  }
  const nucleiTemplate = { updateMany: async () => ({ count: 0 }) }
  const mcpAccessToken = {
    updateMany: async (a: { where?: Row; data: Row }) => {
      const rows = state.tokens.filter((t) => matches(t, a.where))
      for (const r of rows) Object.assign(r, a.data)
      return { count: rows.length }
    },
    findMany: async (a: { where?: Row; select?: Row } = {}) =>
      state.tokens.filter((t) => matches(t, a.where)).map((t) => pick(t, a.select)),
    findUnique: async (a: { where: Row; select?: Row }) => {
      const r = state.tokens.find((t) => matches(t, a.where))
      return r ? pick(r, a.select) : null
    },
    update: async (a: { where: Row; data: Row; select?: Row }) => {
      const r = state.tokens.find((t) => matches(t, a.where))
      if (!r) throw notFound()
      Object.assign(r, a.data)
      return pick(r, a.select)
    },
    delete: async (a: { where: Row }) => {
      const i = state.tokens.findIndex((t) => matches(t, a.where))
      if (i < 0) throw notFound()
      return state.tokens.splice(i, 1)[0]
    },
  }
  const auditLog = {
    create: async (a: { data: Row }) => {
      if (failing.has(String(a.data.action))) throw new Error('audit insert failed')
      state.audit.push({ ...a.data })
      return a.data
    },
  }
  let actAsSeq = 0
  const newestActAs = (where?: Row): Row[] => state.actAs
    .map((r, i) => ({ r, i }))
    .filter(({ r }) => matches(r, where))
    .sort((a, b) => ((b.r.createdAt as Date).getTime() - (a.r.createdAt as Date).getTime()) || b.i - a.i)
    .map(({ r }) => r)
  const actAsAudit = {
    create: async (a: { data: Row }) => {
      const r: Row = { id: `actas-${++actAsSeq}`, createdAt: new Date(), reason: null, durationMinutes: null, endedBy: null, ...a.data }
      state.actAs.push(r)
      return { ...r }
    },
    findFirst: async (a: { where?: Row; select?: Row } = {}) => {
      const r = newestActAs(a.where)[0]
      return r ? pick(r, a.select) : null
    },
    findMany: async (a: { where?: Row; select?: Row; take?: number } = {}) =>
      newestActAs(a.where).slice(0, a.take ?? Infinity).map((r) => pick(r, a.select)),
  }
  const $executeRaw = async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?')
    rawCalls.push(sql)
    rawValues.push(values)
    if (/UPDATE users SET pending_notices = \?::jsonb WHERE id = \? AND pending_notices = \?::jsonb/.test(sql)) {
      const u = state.users.find((x) => x.id === values[1])
      if (!u || JSON.stringify(u.pendingNotices) !== values[2]) return 0
      u.pendingNotices = JSON.parse(String(values[0]))
      return 1
    }
    if (!/pg_advisory_xact_lock/.test(sql)) throw new Error(`accountDb: raw SQL not supported: ${sql}`)
    return 1
  }
  const instanceSettings = {
    findUnique: async (a: { where: Row; select?: Row }) =>
      state.instance && matches(state.instance, a.where) ? pick(state.instance, a.select) : null,
    update: async (a: { where: Row; data: Row; select?: Row }) => {
      if (!state.instance || !matches(state.instance, a.where)) throw notFound()
      apply(state.instance, a.data)
      return pick(state.instance, a.select)
    },
    updateMany: async (a: { where?: Row; data: Row }) => {
      if (!state.instance || !matches(state.instance, a.where)) return { count: 0 }
      apply(state.instance, a.data)
      return { count: 1 }
    },
  }
  let setSeq = 0
  const unique = () => new Prisma.PrismaClientKnownRequestError('Unique constraint failed', { code: 'P2002', clientVersion: 'fake' })
  const permissionSet = {
    findUnique: async (a: { where: Row; select?: Row }) => {
      const r = state.sets.find((x) => matches(x, a.where))
      return r ? pick(r, a.select) : null
    },
    findMany: async (a: { where?: Row; select?: Row } = {}) =>
      state.sets.filter((x) => matches(x, a.where)).map((x) => pick(x, a.select)),
    create: async (a: { data: Row; select?: Row }) => {
      if (state.sets.some((x) => x.name === a.data.name)) throw unique()
      const r: Row = {
        id: `set-${++setSeq}`, description: null, clonedFrom: null, createdAt: new Date(), updatedAt: new Date(), ...a.data,
        permissions: [...(a.data.permissions as string[])],
      }
      state.sets.push(r)
      return pick(r, a.select)
    },
    update: async (a: { where: Row; data: Row; select?: Row }) => {
      const r = state.sets.find((x) => matches(x, a.where))
      if (!r) throw notFound()
      if (a.data.name !== undefined && state.sets.some((x) => x !== r && x.name === a.data.name)) throw unique()
      apply(r, a.data)
      return pick(r, a.select)
    },
    delete: async (a: { where: Row }) => {
      const i = state.sets.findIndex((x) => matches(x, a.where))
      if (i < 0) throw notFound()
      return state.sets.splice(i, 1)[0]
    },
  }
  const rowsOf = (key: 'assignments' | 'overrides') => ({
    findMany: async (a: { where?: Row; select?: Row } = {}) =>
      state[key].filter((x) => matches(x, a.where)).map((x) => pick(x, a.select)),
    count: async (a: { where?: Row } = {}) => state[key].filter((x) => matches(x, a.where)).length,
    deleteMany: async (a: { where?: Row } = {}) => {
      const gone = state[key].filter((x) => matches(x, a.where))
      state[key] = state[key].filter((x) => !gone.includes(x))
      return { count: gone.length }
    },
    createMany: async (a: { data: Row[] }) => {
      const id = (x: Row) => key === 'assignments' ? `${x.userId}|${x.setId}` : `${x.userId}|${x.permission}`
      for (const d of a.data) {
        if (state[key].some((x) => id(x) === id(d))) throw unique()
        state[key].push(key === 'assignments'
          ? { createdAt: new Date(), ...d }
          : { expiresAt: null, reason: null, createdAt: new Date(), ...d })
      }
      return { count: a.data.length }
    },
  })
  const userPermissionSet = rowsOf('assignments')
  const userPermissionOverride = rowsOf('overrides')
  const client = {
    user, mcpAccessToken, auditLog, actAsAudit, instanceSettings, project, nucleiTemplate, userInvite,
    permissionSet, userPermissionSet, userPermissionOverride, $executeRaw, $queryRaw,
  }

  async function $transaction<T>(fn: ((tx: typeof client) => Promise<T>) | Promise<unknown>[]): Promise<T> {
    // The array form: its writes already started, in order, as Prisma's batch would send them.
    if (Array.isArray(fn)) return Promise.all(fn) as Promise<T>
    const run = queue.then(async () => {
      transactions++
      const snapshot = structuredClone(state)
      try {
        return await fn(client)
      } catch (e) {
        state.users = snapshot.users
        state.tokens = snapshot.tokens
        state.audit = snapshot.audit
        state.actAs = snapshot.actAs
        state.instance = snapshot.instance
        state.invites = snapshot.invites
        state.sets = snapshot.sets
        state.assignments = snapshot.assignments
        state.overrides = snapshot.overrides
        throw e
      }
    })
    queue = run.catch(() => undefined)
    return run
  }

  return {
    ...client,
    $transaction,
    seedUsers(rows: AccountSeed[]) {
      for (const r of rows) {
        state.users.push({
          name: r.id, email: `${r.id}@e2e.local`, role: 'standard', password: '$2a$12$hash-of-' + r.id,
          status: 'active', sessionVersion: 0, passwordOnHold: '', mustChangePassword: false,
          adminProfileId: null, lastLoginAt: null, legacyGrants: [], pendingNotices: [], createdAt: new Date(0),
          updatedAt: new Date(0), ...r,
        })
      }
    },
    /** The instance settings row (null: none), its Root and transfer columns empty unless given. */
    seedInstance(row: Row | null) {
      state.instance = row && {
        id: 'instance', rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null,
        pendingRootTransferTo: null, pendingRootTransferExpires: null, ...row,
      }
    },
    /** The instance row as it is now (a copy), or null. */
    instance(): Row | null {
      return state.instance && { ...state.instance }
    },
    seedToken(row: { id: string; userId: string; revokedAt?: Date | null } & Row) {
      state.tokens.push({ revokedAt: null, ...row })
    },
    account(id: string): Row | undefined {
      const r = state.users.find((u) => u.id === id)
      return r && { ...r }
    },
    tokens: () => state.tokens.map((t) => ({ ...t })),
    /** The invite and reset link rows as they are now (copies). */
    invites: () => state.invites.map((v) => ({ ...v })),
    seedInvite(row: { id: string; userId: string; kind: string; tokenHash: string; expiresAt: Date } & Row) {
      state.invites.push({ usedAt: null, cancelledAt: null, createdById: 'admin-1', reason: null, createdAt: new Date(0), ...row })
    },
    seedProjects(userId: string, count: number) {
      state.projectCounts[userId] = count
    },
    audit: () => state.audit.map((a) => ({ ...a })),
    actAs: () => state.actAs.map((a) => ({ ...a })),
    /** An act-as log row as an earlier run wrote it (`createdAt` sets its place in time). */
    seedActAs(row: { adminId: string; targetUserId: string; event: string; createdAt: Date } & Row) {
      state.actAs.push({ id: `actas-${++actAsSeq}`, source: 'api', reason: null, durationMinutes: null, endedBy: null, ...row })
    },
    /** A stored permission set or admin profile (`kind`), its other columns defaulted. */
    seedSet(row: { id: string; kind: string; name: string; permissions: string[] } & Row) {
      state.sets.push({ description: null, clonedFrom: null, createdById: 'root-1', createdAt: new Date(0), updatedAt: new Date(0), ...row })
    },
    /** The account's set assignment rows. */
    seedAssignment(userId: string, ...setIds: string[]) {
      for (const setId of setIds) state.assignments.push({ userId, setId, createdAt: new Date(0) })
    },
    seedOverride(row: { userId: string; permission: string; effect: string } & Row) {
      state.overrides.push({ expiresAt: null, reason: null, grantedById: 'root-1', createdAt: new Date(0), ...row })
    },
    sets: () => state.sets.map((x): Row => ({ ...x, permissions: [...(x.permissions as string[])] })),
    assignments: () => state.assignments.map((x) => ({ ...x })),
    overrides: () => state.overrides.map((x) => ({ ...x })),
    failAudit(action: string | null) {
      failing.clear()
      if (action) failing.add(action)
    },
    reset() {
      state.users = []
      state.tokens = []
      state.audit = []
      state.actAs = []
      state.instance = null
      state.invites = []
      state.projectCounts = {}
      state.sets = []
      state.assignments = []
      state.overrides = []
      inviteSeq = 0
      setSeq = 0
      actAsSeq = 0
      failing.clear()
      rawCalls.length = 0
      rawValues.length = 0
      transactions = 0
    },
    rawCalls,
    /** The bound values of each raw call, in order (the advisory lock's key). */
    rawValues,
    get transactions() { return transactions },
  }
}

export type AccountDb = ReturnType<typeof createAccountDb>
