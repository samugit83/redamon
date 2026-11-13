/**
 * The read waves' route tests (step 4.6 and after; SH-07): behind the real guard, can() and
 * projectAccess(), a route answers a read collaborator what it answers the owner, and refuses its
 * writes with the 403 naming their permission.
 *
 * The test file declares the doubles (vi.mock is per file), all reading one hoisted state:
 *
 *   const h = vi.hoisted(() => ({ identity: vi.fn(), shares: new Map(), policy: { enabled: true } as unknown, models: {} as Record<string, unknown>, refused: vi.fn() }))
 *   vi.mock('@/lib/session', () => ({ getAuthzIdentity: (...a: unknown[]) => h.identity(...a), mayActAs: async () => false }))
 *   vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedReads')).sharedReadPrisma(h) }))
 *
 * The session double is a whole module: session.ts imports guards.ts, so a partial one
 * (importOriginal) leaves the guard holding the real getAuthzIdentity. Add `getEffectiveUser` for a
 * route that reads it. Plus a double of each upstream the route calls (the graph, the agent). Prisma answers the reads
 * the guard makes (the project, the share, break-glass, the instance row, the permission sets),
 * then the route's own models from `h.models`; any other model rejects and is recorded in
 * `h.refused`.
 *
 * This module is imported by the Prisma mock's factory, so it imports nothing that reads
 * '@/lib/prisma' at load (the factory would wait on itself): the authz modules whose caches it
 * clears are imported when the reset runs.
 */
import type { Mock } from 'vitest'
import type { Principal } from '@/lib/authz/principal'
import { principal } from './routePermissionCases'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyMock = Mock<(...args: any[]) => any>

export interface ShareRow {
  access: string
  rawData: boolean
  expiresAt: Date | null
  user: { status: string }
}

export interface SharedReadState {
  identity: AnyMock
  /** `<projectId>|<userId>` -> the collaborator row projectAccess reads. */
  shares: Map<string, ShareRow>
  /** The stored `instance_settings.sharing_policy`. */
  policy: unknown
  /** The route's own Prisma models (read past the guard). */
  models: Record<string, unknown>
  refused: AnyMock
}

export const OWNER = 'alice'
export const SHARED_PROJECT = 'P-alice'
/** Holds a Read share on SHARED_PROJECT, without Raw data & files. */
export const COLLABORATOR = 'bob'
/** Holds a Read share on SHARED_PROJECT with Raw data & files. */
export const RAW_COLLABORATOR = 'dave'
export const STRANGER = 'carol'
/** An admin without a profile (Full admin): `projects:oversee`. */
export const OVERSEER = 'admin-1'

/** The owner's project row: the guard reads `{id, userId}`, a route may read more (Insights activity). */
export const SHARED_PROJECT_ROW = Object.freeze({
  id: SHARED_PROJECT, userId: OWNER, name: 'rbac-shared', targetDomain: 'rbac.test', ipMode: false, scanModules: [],
  createdAt: new Date('2026-11-01T00:00:00Z'), updatedAt: new Date('2026-11-02T00:00:00Z'), targetIps: [], subdomainList: [],
  domainBatchMode: false, domainBatchHosts: [],
})

export const ACTORS: Readonly<Record<string, Principal>> = Object.freeze({
  [OWNER]: principal(OWNER),
  [COLLABORATOR]: principal(COLLABORATOR),
  [RAW_COLLABORATOR]: principal(RAW_COLLABORATOR),
  [STRANGER]: principal(STRANGER),
  [OVERSEER]: principal(OVERSEER, { role: 'admin' }),
})

const GUARD_MODELS = new Set(['project', 'projectCollaborator', 'projectBreakGlass', 'instanceSettings', 'permissionSet', 'auditLog', 'user'])

export function sharedReadPrisma(h: SharedReadState): unknown {
  const refused = (model: string) => new Proxy({}, {
    get: (_t, method) => (...args: unknown[]) => {
      h.refused(model, String(method), ...args)
      return Promise.reject(Object.assign(new Error(`no ${model} table in this test`), { code: 'TEST_NO_TABLE' }))
    },
  })
  const guard: Record<string, unknown> = {
    project: {
      findUnique: async ({ where }: { where: { id: string } }) => (where.id === SHARED_PROJECT ? { ...SHARED_PROJECT_ROW } : null),
    },
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) =>
        h.shares.get(`${where.projectId_userId.projectId}|${where.projectId_userId.userId}`) ?? null,
    },
    projectBreakGlass: { findFirst: async () => null },
    instanceSettings: {
      findUnique: async () => ({
        sharingPolicy: h.policy, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null,
      }),
    },
    permissionSet: { findMany: async () => [] },
    auditLog: { findFirst: async () => null },
    user: { findUnique: async () => null },
  }
  return new Proxy(guard, {
    get: (target, prop: string) => {
      if (Object.hasOwn(h.models, prop)) return h.models[prop]
      if (GUARD_MODELS.has(prop)) return target[prop]
      return prop === 'then' ? undefined : refused(prop)
    },
  })
}

/** Every switch on, the policy enabled, the two shares in place, caches empty. Await in beforeEach. */
export async function resetSharedReads(h: SharedReadState): Promise<void> {
  h.identity.mockReset()
  h.refused.mockReset()
  h.shares.clear()
  for (const k of Object.keys(h.models)) delete h.models[k]
  h.policy = { enabled: true }
  h.shares.set(`${SHARED_PROJECT}|${COLLABORATOR}`, { access: 'read', rawData: false, expiresAt: null, user: { status: 'active' } })
  h.shares.set(`${SHARED_PROJECT}|${RAW_COLLABORATOR}`, { access: 'read', rawData: true, expiresAt: null, user: { status: 'active' } })
  await setFlags({ identity: true, permissions: true, sharing: true })
}

/** Sets the switches and empties every authorization cache, so the next request reads them anew. */
export async function setFlags(values: { identity: boolean; permissions: boolean; sharing: boolean } | null): Promise<void> {
  ;(await import('@/lib/authz/flags')).setFlagsForTests(values)
  await clearCaches()
}

export async function clearCaches(): Promise<void> {
  ;(await import('@/lib/authz/sharingPolicy')).clearSharingPolicyCacheForTests()
  ;(await import('@/lib/authz/capabilities')).clearCapabilityCachesForTests()
  ;(await import('@/lib/authz/root')).clearInstanceRootCacheForTests()
  ;(await import('@/lib/authz/principal')).clearPrincipalCacheForTests()
  ;(await import('@/lib/authz/sharedTools')).resetSharedToolsForTests()
}

export async function endSharedReads(): Promise<void> {
  ;(await import('@/lib/authz/flags')).setFlagsForTests(null)
}

export function signInAs(h: SharedReadState, who: string): void {
  const p = ACTORS[who]
  if (!p) throw new Error(`no actor ${who}`)
  h.identity.mockResolvedValue({ session: { userId: p.id, role: p.role }, principal: p, actingAs: null })
}

/** Whether `value` appears anywhere in `data` (a query's parameters, a request body). */
export function mentions(data: unknown, value: string): boolean {
  if (data === value) return true
  if (Array.isArray(data)) return data.some(d => mentions(d, value))
  if (data && typeof data === 'object') return Object.values(data as Record<string, unknown>).some(d => mentions(d, value))
  return false
}

/** The project-id parameter of a graph query, whichever name the route gave it. */
export function queriedProject(params: unknown): unknown {
  const p = (params ?? {}) as Record<string, unknown>
  return p.pid ?? p.projectId ?? p.project_id
}
