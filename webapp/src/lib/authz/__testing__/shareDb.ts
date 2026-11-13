/**
 * An in-memory stand-in for the Prisma client, for the share routes (step 4.4): the accounts,
 * projects, shares (`project_collaborators`), break-glass rows, audit rows and the instance row
 * that projectAccess(), can() and the share writers read, with the semantics they rely on:
 *
 * - `$transaction(fn)` runs one at a time (two at once wait, as Postgres makes the second writer of
 *   a key wait) and rolls back every write of `fn` when it throws (state restored from a snapshot),
 *   so "the audit write failed, so nothing changed" is real;
 * - a share is keyed by (projectId, userId): `create` of an existing pair raises the real P2002,
 *   `updateMany` / `deleteMany` answer `{count}`; `where` matches equality and `{lte}` / `{gt}` on
 *   dates; a read returns the row with its `user` (`select` and `include` are not applied);
 * - `$queryRaw` answers only the recipient lookup (`lower(email) = lower($1)`); `$executeRaw` takes
 *   the advisory locks (`locks()` lists their keys) and the notice update is not doubled;
 * - `user.findMany` matches `{id: {in}}` (the share answers' account types, step 4.12);
 * - break-glass rows can be created, listed and deleted (step 4.14); an audit row gets its
 *   `createdAt` from the clock, and `auditLog.findFirst` matches equality and `{gte, lt}` dates;
 * - queued jobs, scan schedules and triage runs (step 5.9: what a revocation cancels, pauses or
 *   stops) are listed by equality / `{in}` and changed by `updateMany`, rolled back with the rest;
 * - `failAudit(action)` makes the audit insert of that action throw, as a lost database would;
 *   `failRead()` makes the next share read throw; `raceCreate()` makes the next share insert raise
 *   P2002, as another copy's insert between the read and the write would.
 */
import { Prisma } from '@prisma/client'

export interface ShareAccount {
  id: string
  email: string
  name: string
  role: string
  status: string
  password: string
  createdAt: Date
  legacyGrants: string[]
  sessionVersion: number
  mustChangePassword: boolean
  adminProfileId: string | null
  lastLoginAt: Date | null
  hasPassword: boolean
  permissionSets: unknown[]
  permissionOverrides: unknown[]
}

export interface ShareRow {
  projectId: string
  userId: string
  access: string
  runScans: boolean
  useAgent: boolean
  exploit: boolean
  rawData: boolean
  manage: boolean
  expiresAt: Date | null
  note: string | null
  grantedById: string
  createdAt: Date
  updatedAt: Date
}

export interface AuditRow {
  action: string
  actorId: string | null
  projectId?: string | null
  targetId?: string | null
  before?: unknown
  after?: unknown
  [k: string]: unknown
}

export function shareAccount(id: string, over: Partial<ShareAccount> = {}): ShareAccount {
  return {
    id, email: `${id}@example.test`, name: `Name ${id}`, role: 'standard', status: 'active', password: 'hash',
    createdAt: new Date('2026-09-01T00:00:00Z'), legacyGrants: [], sessionVersion: 0, mustChangePassword: false,
    adminProfileId: null, lastLoginAt: null, hasPassword: true, permissionSets: [], permissionOverrides: [], ...over,
  }
}

type Where = Record<string, unknown>

function matches(row: Record<string, unknown>, where: Where): boolean {
  return Object.entries(where).every(([k, cond]) => {
    if (cond === undefined) return true
    if (k === 'OR') return (cond as Where[]).some(w => matches(row, w))
    const v = row[k]
    if (cond instanceof Date) return v instanceof Date && v.getTime() === cond.getTime()
    if (cond && typeof cond === 'object') {
      const c = cond as { lte?: Date; gt?: Date; gte?: Date; lt?: Date; in?: unknown[] }
      if (c.in) return c.in.includes(v)
      if (!(v instanceof Date)) return false
      if (c.lte && !(v.getTime() <= c.lte.getTime())) return false
      if (c.gt && !(v.getTime() > c.gt.getTime())) return false
      if (c.gte && !(v.getTime() >= c.gte.getTime())) return false
      if (c.lt && !(v.getTime() < c.lt.getTime())) return false
      return true
    }
    return v === cond
  })
}

export interface QueuedJobRow {
  id: string
  projectId: string
  userId: string
  kind: string
  payload: unknown
  status: string
  blockedCode?: string | null
  blockedReason?: string | null
  finishedAt?: Date | null
}

export interface ScheduleRow {
  id: string
  projectId: string
  userId: string
  label: string
  scanMode: string
  enabled: boolean
  pausedReason: string | null
}

export interface TriageRunRow {
  id: string
  projectId: string
  actorUserId: string
  status: string
  startedAt: Date
  heartbeatAt: Date | null
}

export interface BreakGlassRow {
  id: string
  projectId: string
  userId: string
  reason: string
  expiresAt: Date
  createdAt: Date
}

function p2002(): Error {
  return new Prisma.PrismaClientKnownRequestError('Unique constraint failed', { code: 'P2002', clientVersion: 'test' })
}

export function createShareDb(clock: () => Date = () => new Date()) {
  let users = new Map<string, ShareAccount>()
  let projects = new Map<string, { id: string; userId: string; name: string }>()
  let shares = new Map<string, ShareRow>()
  let breakGlass: BreakGlassRow[] = []
  let jobs: QueuedJobRow[] = []
  let schedules: ScheduleRow[] = []
  const triageRuns: TriageRunRow[] = []
  let glassSeq = 0
  const locks: string[] = []
  let audit: AuditRow[] = []
  let policy: unknown = { enabled: true }
  let root: { userId: string | null; confirmedAt: Date | null } = { userId: null, confirmedAt: null }
  const failing = new Set<string>()
  let readFails = false
  let createRaces = false
  let queue: Promise<unknown> = Promise.resolve()

  const key = (projectId: string, userId: string) => `${projectId}|${userId}`
  const withUser = (row: ShareRow) => ({ ...row, user: users.get(row.userId) ?? null })
  const shareRead = () => {
    if (readFails) {
      readFails = false
      throw new Error('connection lost')
    }
  }

  const client = {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => users.get(where.id) ?? null,
      findMany: async ({ where }: { where: Where }) => [...users.values()].filter(u => matches(u as never, where)),
    },
    project: {
      findUnique: async ({ where }: { where: { id: string } }) => projects.get(where.id) ?? null,
      findMany: async () => [...projects.values()].map(p => ({ ...p, user: users.get(p.userId) ?? null })),
    },
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) => {
        shareRead()
        const row = shares.get(key(where.projectId_userId.projectId, where.projectId_userId.userId))
        return row ? withUser(row) : null
      },
      findMany: async ({ where }: { where: Where }) => {
        shareRead()
        return [...shares.values()].filter(r => matches(r as never, where))
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime()).map(withUser)
      },
      create: async ({ data }: { data: Partial<ShareRow> & { projectId: string; userId: string; grantedById: string } }) => {
        const k = key(data.projectId, data.userId)
        if (createRaces) {
          createRaces = false
          throw p2002()
        }
        if (shares.has(k)) throw p2002()
        const at = clock()
        const row: ShareRow = {
          access: 'read', runScans: false, useAgent: false, exploit: false, rawData: false, manage: false,
          expiresAt: null, note: null, createdAt: at, updatedAt: at, ...data,
        }
        shares.set(k, row)
        return withUser(row)
      },
      updateMany: async ({ where, data }: { where: Where; data: Partial<ShareRow> }) => {
        let count = 0
        for (const [k, row] of shares) {
          if (!matches(row as never, where)) continue
          shares.set(k, { ...row, ...data, updatedAt: clock() })
          count += 1
        }
        return { count }
      },
      deleteMany: async ({ where }: { where: Where }) => {
        let count = 0
        for (const [k, row] of [...shares]) {
          if (!matches(row as never, where)) continue
          shares.delete(k)
          count += 1
        }
        return { count }
      },
    },
    projectBreakGlass: {
      findFirst: async ({ where }: { where: { projectId: string; userId: string; expiresAt: { gt: Date } } }) =>
        breakGlass.find(b => b.projectId === where.projectId && b.userId === where.userId && b.expiresAt > where.expiresAt.gt) ?? null,
      findMany: async ({ where }: { where: Where }) => breakGlass.filter(b => matches(b as never, where)),
      create: async ({ data }: { data: Omit<BreakGlassRow, 'id' | 'createdAt'> }) => {
        glassSeq += 1
        const row: BreakGlassRow = { id: `bg${glassSeq}`, createdAt: clock(), ...data }
        breakGlass.push(row)
        return row
      },
      deleteMany: async ({ where }: { where: Where }) => {
        const before = breakGlass.length
        breakGlass = breakGlass.filter(b => !matches(b as never, where))
        return { count: before - breakGlass.length }
      },
    },
    jobQueue: {
      findMany: async ({ where }: { where: Where }) => jobs.filter(j => matches(j as never, where)).map(j => ({ ...j })),
      updateMany: async ({ where, data }: { where: Where; data: Partial<QueuedJobRow> }) => {
        const hit = jobs.filter(j => matches(j as never, where))
        jobs = jobs.map(j => (hit.includes(j) ? { ...j, ...data } : j))
        return { count: hit.length }
      },
    },
    scanSchedule: {
      findMany: async ({ where }: { where: Where }) => schedules.filter(r => matches(r as never, where)).map(r => ({ ...r })),
      updateMany: async ({ where, data }: { where: Where; data: Partial<ScheduleRow> }) => {
        const hit = schedules.filter(r => matches(r as never, where))
        schedules = schedules.map(r => (hit.includes(r) ? { ...r, ...data } : r))
        return { count: hit.length }
      },
    },
    triageRun: {
      findMany: async ({ where }: { where: Where }) => triageRuns.filter(r => matches(r as never, where)).map(r => ({ ...r })),
      updateMany: async () => ({ count: 0 }),
    },
    instanceSettings: {
      findUnique: async () => ({
        id: 'instance', sharingPolicy: policy, rootUserId: root.userId, rootConfirmedAt: root.confirmedAt,
        rootAssignedBy: root.userId ? 'install' : null, defaultMemberSetId: null,
      }),
    },
    permissionSet: { findMany: async () => [] },
    auditLog: {
      create: async ({ data }: { data: AuditRow }) => {
        if (failing.has(data.action)) throw new Error('audit insert failed')
        const row = { createdAt: clock(), ...data }
        audit.push(row)
        return row
      },
      findFirst: async ({ where }: { where?: Where } = {}) => (where ? audit.find(r => matches(r, where)) ?? null : null),
    },
    $executeRaw: async (_strings: TemplateStringsArray, ...values: unknown[]) => {
      locks.push(String(values[0]))
      return 1
    },
    $queryRaw: async (_strings: TemplateStringsArray, ...values: unknown[]) => {
      const email = String(values[0]).toLowerCase()
      return [...users.values()].filter(u => u.email.toLowerCase() === email)
        .map(u => ({ id: u.id, name: u.name, email: u.email, status: u.status }))
    },
    $transaction: <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => {
      const run = async () => {
        const snapshot = {
          users: new Map(users), projects: new Map(projects), shares: new Map(shares), breakGlass: [...breakGlass], audit: [...audit],
          jobs: [...jobs], schedules: [...schedules],
        }
        try {
          return await fn(client)
        } catch (err) {
          ;({ users, projects, shares, breakGlass, audit, jobs, schedules } = snapshot)
          throw err
        }
      }
      const result = queue.then(run, run)
      queue = result.catch(() => undefined)
      return result
    },
  }

  return {
    client,
    addUser(account: ShareAccount) { users.set(account.id, account) },
    addProject(id: string, userId: string) { projects.set(id, { id, userId, name: id }) },
    addShare(row: Partial<ShareRow> & { projectId: string; userId: string }) {
      const at = clock()
      shares.set(key(row.projectId, row.userId), {
        access: 'read', runScans: false, useAgent: false, exploit: false, rawData: false, manage: false,
        expiresAt: null, note: null, grantedById: 'owner', createdAt: at, updatedAt: at, ...row,
      })
    },
    addBreakGlass(projectId: string, userId: string, expiresAt: Date) {
      glassSeq += 1
      breakGlass.push({ id: `bg${glassSeq}`, projectId, userId, expiresAt, reason: 'seeded', createdAt: clock() })
    },
    breakGlassRows: () => breakGlass,
    addJob(row: Partial<QueuedJobRow> & { id: string; projectId: string; userId: string }) {
      jobs.push({ kind: 'full_recon', payload: { mode: 'new' }, status: 'queued', ...row })
    },
    job: (id: string) => jobs.find(j => j.id === id),
    addSchedule(row: Partial<ScheduleRow> & { id: string; projectId: string; userId: string }) {
      schedules.push({ label: row.id, scanMode: 'new', enabled: true, pausedReason: null, ...row })
    },
    schedule: (id: string) => schedules.find(r => r.id === id),
    /** A live triage run that `actorUserId` started; its heartbeat is fresh by the real clock, which triageRun.ts reads. */
    addTriageRun(row: Partial<TriageRunRow> & { id: string; projectId: string; actorUserId: string }) {
      triageRuns.push({ status: 'running', startedAt: clock(), heartbeatAt: new Date(), ...row })
    },
    locks: () => locks,
    share(projectId: string, userId: string): ShareRow | undefined { return shares.get(key(projectId, userId)) },
    shareCount: () => shares.size,
    audit: () => audit,
    setPolicy(stored: unknown) { policy = stored },
    /** The instance's Root, confirmed at `confirmedAt` (null: unconfirmed). */
    setRoot(userId: string, confirmedAt: Date | null) { root = { userId, confirmedAt } },
    failAudit(action: string) { failing.add(action) },
    failRead() { readFails = true },
    raceCreate() { createRaces = true },
  }
}

export type ShareDb = ReturnType<typeof createShareDb>
