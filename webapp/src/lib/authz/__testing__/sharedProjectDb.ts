/**
 * A Prisma double for tests of what a person reaches on a project shared with them (step 4.8):
 * the rows the real projectAccess(), can() and capability code read (the project, its shares and
 * break-glass rows, the instance row with the sharing policy enabled, the accounts), and every other
 * model readable and empty unless the test seeds a method, every write recorded. Nothing past the
 * authorization is decided here: the test asserts what reached the graph, the database or the agent.
 *
 *   const h = vi.hoisted(() => ({
 *     identity: null as unknown,
 *     db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
 *   }))
 *   vi.mock('@/lib/session', async (orig) => ({
 *     ...(await orig<typeof import('@/lib/session')>()),
 *     ...(await import('@/lib/authz/__testing__/sharedProjectDb')).sessionOf(h),
 *   }))
 *   vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
 *
 *   import '@/lib/authz/guards'   // first: see below
 *
 * vi.hoisted runs before any import, so the empty state is written inline there (the type import is
 * erased); `resetSharedProjectDb` empties it between tests. The real session module imports the
 * guards, which import the session: imported first, the guards bind the doubled session; reached
 * from inside the session's factory (the cycle), they bind the real one and every request is a 500.
 */

export const OWNER = 'alice'
export const SHARED_PROJECT = 'P-alice'
export const COLLABORATOR = 'bob'
/** An admin with no profile: Full admin, which holds `projects:oversee` (OQ-03). */
export const OVERSEER = 'admin-1'
export const STRANGER = 'carol'

export interface ShareRow {
  access: string
  rawData: boolean
  expiresAt: Date | null
  status?: string
  /** The Read + Write toggles (step 5.2): read by projectAccess() only with write sharing in force. */
  runScans?: boolean
  useAgent?: boolean
  exploit?: boolean
  manage?: boolean
}

type Method = (...args: unknown[]) => unknown

export interface SharedProjectDb {
  /** `${projectId}|${userId}` -> the share. */
  shares: Map<string, ShareRow>
  /** `${projectId}|${userId}` -> the break-glass row's expiry. */
  breakGlass: Map<string, Date>
  /** The stored sharing policy (the instance row's JSON). */
  policy: unknown
  /** A test's own answers for a model's methods, e.g. `{nodeFilterRun: {findFirst: () => row}}`. */
  models: Record<string, Record<string, Method>>
  /** Every create, update, upsert, delete and raw statement, in order. */
  writes: Array<{ model: string; method: string }>
}

export function resetSharedProjectDb(db: SharedProjectDb): void {
  db.shares.clear()
  db.breakGlass.clear()
  db.policy = { enabled: true }
  for (const k of Object.keys(db.models)) delete db.models[k]
  db.writes.length = 0
}

export function shareWith(db: SharedProjectDb, userId: string, row: Partial<ShareRow> = {}): void {
  db.shares.set(`${SHARED_PROJECT}|${userId}`, { access: 'read', rawData: false, expiresAt: null, ...row })
}

/** An account as loadPrincipal reads it; `admin-*` ids are admins with no profile (Full admin). */
export function account(id: string, over: Record<string, unknown> = {}) {
  return {
    id, email: `${id}@example.test`, name: id, role: id.startsWith('admin') ? 'admin' : 'standard', password: 'hash',
    createdAt: new Date('2026-09-01T00:00:00Z'), legacyGrants: [] as string[], status: 'active', sessionVersion: 0,
    mustChangePassword: false, adminProfileId: null, lastLoginAt: null, hasPassword: true, pendingNotices: [],
    permissionSets: [] as string[], permissionOverrides: [], ...over,
  }
}

/** The identity the guard reads for `userId`, signed in as themself. */
export function identityOf(userId: string) {
  const principal = account(userId)
  return { session: { userId: principal.id, role: principal.role }, principal, actingAs: null }
}

/** `getAuthzIdentity` and `getEffectiveUser` over a hoisted `identity`. */
export function sessionOf(h: { identity: unknown }) {
  return {
    getAuthzIdentity: async () => h.identity,
    getEffectiveUser: async () => {
      const identity = h.identity as { principal: { id: string } } | null
      return identity ? { userId: identity.principal.id } : null
    },
  }
}

const PROJECT_ROW = Object.freeze({
  id: SHARED_PROJECT, userId: OWNER, name: 'rbac-shared', cypherfixDefaultRepo: '', triageReviewBudget: 0,
})

const WRITE = /^(create|createMany|update|updateMany|upsert|delete|deleteMany|\$executeRaw|\$executeRawUnsafe|\$transaction)$/

const EMPTY: Record<string, unknown> = {
  findMany: [], findFirst: null, findUnique: null, count: 0, groupBy: [], aggregate: { _count: {} },
}

function model(db: SharedProjectDb, name: string, known: Record<string, Method> = {}): unknown {
  return new Proxy({}, {
    get: (_t, method) => {
      if (typeof method !== 'string') return undefined
      const own = db.models[name]?.[method] ?? known[method]
      if (own) return async (...args: unknown[]) => own(...args)
      return async () => {
        if (WRITE.test(method)) {
          db.writes.push({ model: name, method })
          return {}
        }
        if (method in EMPTY) return EMPTY[method]
        throw new Error(`sharedProjectDb: ${name}.${method} is not doubled`)
      }
    },
  })
}

export function sharedProjectPrisma(h: { db: SharedProjectDb }): unknown {
  const db = () => h.db
  const known: Record<string, Record<string, Method>> = {
    project: {
      findUnique: (args) => {
        const { where } = args as { where: { id: string } }
        return where.id === SHARED_PROJECT ? { ...PROJECT_ROW } : null
      },
    },
    projectCollaborator: {
      findUnique: (args) => {
        const { where } = args as { where: { projectId_userId: { projectId: string; userId: string } } }
        const row = db().shares.get(`${where.projectId_userId.projectId}|${where.projectId_userId.userId}`)
        if (!row) return null
        const { status, ...share } = row
        return { ...share, user: { status: status ?? 'active' } }
      },
    },
    projectBreakGlass: {
      findFirst: (args) => {
        const { where } = args as { where: { projectId: string; userId: string } }
        const expiresAt = db().breakGlass.get(`${where.projectId}|${where.userId}`)
        return expiresAt ? { expiresAt } : null
      },
    },
    instanceSettings: {
      findUnique: () => ({
        sharingPolicy: db().policy, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null,
      }),
    },
    user: { findUnique: (args) => account((args as { where: { id: string } }).where.id) },
  }
  return new Proxy({}, {
    get: (_t, prop) => {
      if (typeof prop !== 'string' || prop === 'then') return undefined
      if (prop.startsWith('$')) {
        return async () => {
          db().writes.push({ model: '$client', method: prop })
          return []
        }
      }
      return model(db(), prop, known[prop])
    },
  })
}
