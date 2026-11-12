/**
 * An in-memory stand-in for the Prisma client, for the account-status tests (step 2.3): the
 * `users`, `mcp_access_tokens` and `audit_log` rows those routes touch, with the semantics
 * they rely on:
 *
 * - `$transaction(fn)` runs one at a time and rolls back every write of `fn` when it throws
 *   (state restored from a snapshot), so "the audit write failed, so nothing changed" is real;
 * - `SELECT pg_advisory_xact_lock(...)` through `$executeRaw` is accepted (transactions
 *   already run one at a time here);
 * - `where` matches equality, `{not}`, `{in}` and `null`; `data` applies `{increment}`;
 *   `update` of a missing row raises P2025; `@updatedAt` moves on every update;
 * - `failAudit(action)` makes the audit insert of that action throw, as a lost database would.
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
}

function matches(row: Row, where: Row = {}): boolean {
  for (const [k, cond] of Object.entries(where)) {
    if (cond === undefined) continue
    const v = row[k]
    if (cond !== null && typeof cond === 'object' && !(cond instanceof Date)) {
      const c = cond as Row
      if ('not' in c && v === c.not) return false
      if ('in' in c && !(c.in as unknown[]).includes(v)) return false
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
  }
  const failing = new Set<string>()
  const rawCalls: string[] = []
  let queue: Promise<unknown> = Promise.resolve()
  let transactions = 0

  const user = {
    findUnique: async (a: { where: Row; select?: Row }) => {
      const r = state.users.find((u) => matches(u, a.where))
      return r ? pick(r, a.select) : null
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
  }
  const mcpAccessToken = {
    updateMany: async (a: { where?: Row; data: Row }) => {
      const rows = state.tokens.filter((t) => matches(t, a.where))
      for (const r of rows) Object.assign(r, a.data)
      return { count: rows.length }
    },
  }
  const auditLog = {
    create: async (a: { data: Row }) => {
      if (failing.has(String(a.data.action))) throw new Error('audit insert failed')
      state.audit.push({ ...a.data })
      return a.data
    },
  }
  const $executeRaw = async (strings: TemplateStringsArray) => {
    const sql = strings.join('?')
    rawCalls.push(sql)
    if (!/pg_advisory_xact_lock/.test(sql)) throw new Error(`accountDb: raw SQL not supported: ${sql}`)
    return 1
  }
  const client = { user, mcpAccessToken, auditLog, $executeRaw }

  async function $transaction<T>(fn: (tx: typeof client) => Promise<T>): Promise<T> {
    const run = queue.then(async () => {
      transactions++
      const snapshot = structuredClone(state)
      try {
        return await fn(client)
      } catch (e) {
        state.users = snapshot.users
        state.tokens = snapshot.tokens
        state.audit = snapshot.audit
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
          adminProfileId: null, lastLoginAt: null, legacyGrants: [], createdAt: new Date(0), updatedAt: new Date(0),
          ...r,
        })
      }
    },
    seedToken(row: { id: string; userId: string; revokedAt?: Date | null }) {
      state.tokens.push({ revokedAt: null, ...row })
    },
    account(id: string): Row | undefined {
      const r = state.users.find((u) => u.id === id)
      return r && { ...r }
    },
    tokens: () => state.tokens.map((t) => ({ ...t })),
    audit: () => state.audit.map((a) => ({ ...a })),
    failAudit(action: string | null) {
      failing.clear()
      if (action) failing.add(action)
    },
    reset() {
      state.users = []
      state.tokens = []
      state.audit = []
      failing.clear()
      rawCalls.length = 0
      transactions = 0
    },
    rawCalls,
    get transactions() { return transactions },
  }
}

export type AccountDb = ReturnType<typeof createAccountDb>
