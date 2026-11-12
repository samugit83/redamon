/**
 * The route families' permission tests (step 3.8 and after; PE-19, PE-22): each route, with the real
 * guard, the real can() and the real registry, refuses an owner who lacks its permission with the
 * 403 naming it, before anything past the guard runs, and lets an owner on *Default member* through.
 *
 * The test file declares the doubles (vi.mock is per file), all reading one hoisted state:
 *
 *   const h = vi.hoisted(() => ({ identity: vi.fn(), projects: new Map(), downstream: vi.fn(), upstream: vi.fn(), models: {} }))
 *   vi.mock('@/lib/session', async (orig) => ({ ...(await orig<typeof import('@/lib/session')>()), getAuthzIdentity: (...a: unknown[]) => h.identity(...a) }))
 *   vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
 *   vi.mock('@/lib/authz/guards', async (orig) => { const real = await orig<typeof import('@/lib/authz/guards')>(); return { ...real, requirePermission: vi.fn(real.requirePermission) } })
 *
 * plus a double of each upstream the family's routes call (the orchestrator, the graph) that
 * records into `h.upstream`; `fetch` is stubbed to it too. Prisma answers the reads the guard makes
 * (the project, the permission sets, the instance row) and refuses every other model, recording it
 * in `h.downstream`: past the guard a route meets that refusal (a 500), which is fine for an
 * "allowed" case, decided by what requirePermission answered.
 */
import { describe, test, expect, vi, beforeEach, afterEach, type Mock } from 'vitest'
import { NextRequest } from 'next/server'
import type { Principal } from '@/lib/authz/principal'
import type { PermissionId } from '@/lib/authz/permissions'
import type { PermissionContext } from '@/lib/authz/guards'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyMock = Mock<(...args: any[]) => any>

export interface RouteCaseState {
  identity: AnyMock
  projects: Map<string, { id: string; userId: string }>
  downstream: AnyMock
  upstream: AnyMock
  /** Models a route reads BEFORE its guard (a job row naming its project), set by a case's `arrange`. */
  models: Record<string, unknown>
}

/** A route handler; its context is `{params}` with the route's own param names. */
type Handler = (request: NextRequest, context: never) => Promise<Response>

export interface RouteCase {
  /** `METHOD /api/...`, as the manifest names the route. */
  route: string
  handler: () => Promise<Handler>
  permission: PermissionId
  /** The route's params; the project the guard is asked about must be OWNED_PROJECT. */
  params: Record<string, string>
  /** A JSON body; only the request's shape, nothing past the guard runs on a refusal. */
  body?: unknown
  /** The query string, for a route that reads its project from it (`?projectId=`). */
  query?: Record<string, string>
  /**
   * The project the route names when it is not a param (a job row's project); null for an
   * instance permission checked with no project (project create, import).
   */
  projectId?: string | null
  /** Runs before the request: the rows a route reads before its guard, in `h.models`. */
  arrange?: (h: RouteCaseState) => void
}

export const OWNER = 'alice'
export const OWNED_PROJECT = 'P-alice'
export const OTHERS_PROJECT = 'P-bob'

const AUTH_MODELS = new Set(['project', 'permissionSet', 'instanceSettings', 'user', 'auditLog'])

/** The Prisma double: the guard's reads, and a recorded refusal for every other model. */
export function authPrisma(h: RouteCaseState): unknown {
  const refused = (model: string) => new Proxy({}, {
    get: (_t, method) => (...args: unknown[]) => {
      h.downstream(model, String(method), ...args)
      return Promise.reject(Object.assign(new Error(`no ${model} table in this test`), { code: 'TEST_NO_TABLE' }))
    },
  })
  const known: Record<string, unknown> = {
    project: {
      findUnique: async ({ where, select }: { where: { id: string }; select?: Record<string, unknown> }) => {
        const row = h.projects.get(where.id)
        // The guard reads {id, userId}; any other read is the route's own, past the guard.
        if (!select || Object.keys(select).some(k => k !== 'id' && k !== 'userId')) h.downstream('project', 'findUnique', { where, select })
        return row ? { ...row } : null
      },
    },
    permissionSet: { findMany: async () => [] },
    instanceSettings: { findUnique: async () => null },
    user: { findUnique: async () => null },
    auditLog: { findFirst: async () => null },
  }
  return new Proxy(known, {
    get: (target, prop: string) => {
      if (AUTH_MODELS.has(prop)) return target[prop]
      if (Object.hasOwn(h.models, prop)) return h.models[prop]
      return prop === 'then' ? undefined : refused(prop)
    },
  })
}

export function principal(id: string, over: Partial<Principal> = {}): Principal {
  return {
    id, email: `${id}@e2e.local`, name: id, role: 'standard', status: 'active', sessionVersion: 0, mustChangePassword: false,
    adminProfileId: null, hasPassword: true, createdAt: new Date(0), lastLoginAt: null, legacyGrants: [],
    permissionSets: [], permissionOverrides: [], ...over,
  }
}

export function denying(id: string, permission: PermissionId): Principal {
  return principal(id, { permissionOverrides: [{ permission, effect: 'deny', expiresAt: null, reason: null }] })
}

function requestFor(c: RouteCase): NextRequest {
  const [method, path] = c.route.split(' ')
  const query = c.query ? `?${new URLSearchParams(c.query)}` : ''
  const url = 'http://localhost:3000' + path.replace(/\[(\w+)\]/g, (_m, k: string) => c.params[k] ?? k) + query
  const init: { method: string; headers?: Record<string, string>; body?: string } = { method }
  if (c.body !== undefined) {
    init.headers = { 'content-type': 'application/json', origin: 'http://localhost:3000' }
    init.body = JSON.stringify(c.body)
  }
  return new NextRequest(url, init)
}

async function run(h: RouteCaseState, c: RouteCase, who: Principal): Promise<{ res: Response | null; guard: unknown }> {
  h.identity.mockResolvedValue({ session: { userId: who.id, role: who.role }, principal: who, actingAs: null })
  c.arrange?.(h)
  const guards = await import('@/lib/authz/guards')
  const spy = vi.mocked(guards.requirePermission)
  spy.mockClear()
  const handler = await c.handler()
  const res = await handler(requestFor(c), { params: Promise.resolve(c.params) } as never).catch(() => null)
  const first = spy.mock.results[0]
  return { res, guard: first ? await first.value : undefined }
}

export interface FamilyOptions {
  setFlags: (values: { identity: boolean; permissions: boolean } | null) => void
  clearCaches: () => void
}

/**
 * One `refused without <permission>` and one `allowed with Default member` test per route, the
 * stranger's 404 on the first route whose project is a param, the switch-off answer on the first.
 */
export function describeRoutePermissions(family: string, cases: RouteCase[], h: RouteCaseState, opts: FamilyOptions): void {
  describe(`${family}: each route asks for its permission (step 3.8)`, () => {
    beforeEach(() => {
      h.identity.mockReset()
      h.downstream.mockReset()
      h.upstream.mockReset()
      h.upstream.mockRejectedValue(Object.assign(new Error('no upstream in this test'), { code: 'ECONNREFUSED' }))
      h.projects.clear()
      for (const k of Object.keys(h.models)) delete h.models[k]
      h.projects.set(OWNED_PROJECT, { id: OWNED_PROJECT, userId: OWNER })
      h.projects.set(OTHERS_PROJECT, { id: OTHERS_PROJECT, userId: 'bob' })
      vi.stubGlobal('fetch', (...a: unknown[]) => h.upstream(...a))
      opts.setFlags({ identity: true, permissions: true })
      vi.stubEnv('MCP_SERVER_ENABLED', 'true')
      vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
      opts.clearCaches()
      vi.spyOn(console, 'error').mockImplementation(() => {})
      vi.spyOn(console, 'warn').mockImplementation(() => {})
    })
    afterEach(() => {
      opts.setFlags(null)
      vi.unstubAllGlobals()
      vi.unstubAllEnvs()
      vi.restoreAllMocks()
    })

    for (const c of cases) {
      const projectId = c.projectId === undefined ? OWNED_PROJECT : c.projectId
      const guardArgs = projectId === null ? [c.permission] : [c.permission, { projectId }]
      test(`${c.route} refused without ${c.permission}: 403 naming it, nothing past the guard runs`, async () => {
        const { res, guard } = await run(h, c, denying(OWNER, c.permission))
        expect(res?.status).toBe(403)
        expect(await res!.json()).toMatchObject({ code: 'forbidden', permission: c.permission })
        expect(guard).toBeInstanceOf(Response)
        const guards = await import('@/lib/authz/guards')
        expect(vi.mocked(guards.requirePermission).mock.calls[0].slice(1)).toEqual(guardArgs)
        expect(h.upstream).not.toHaveBeenCalled()
        expect(h.downstream).not.toHaveBeenCalled()
      })

      test(`${c.route} allowed with Default member`, async () => {
        const { guard } = await run(h, c, principal(OWNER))
        expect(guard).not.toBeInstanceOf(Response)
        expect((guard as PermissionContext).permission).toBe(c.permission)
        expect((guard as PermissionContext).access?.project ?? null).toEqual(projectId === null ? null : { id: projectId, userId: OWNER })
      })
    }

    const first = cases[0]
    const onProject = cases.find(c => c.projectId === undefined)
    if (onProject) {
      test(`${onProject.route}: a project the caller cannot see answers 404 whatever they hold`, async () => {
        const query = onProject.query && retarget({ ...onProject, params: onProject.query })
        const { res } = await run(h, { ...onProject, params: retarget(onProject), query }, principal('bob-friend'))
        expect(res?.status).toBe(404)
        expect(h.upstream).not.toHaveBeenCalled()
      })
    }

    test(`${first.route}: with RBAC_PERMISSIONS_ENABLED off an owner passes whatever an override says (today's answer)`, async () => {
      opts.setFlags({ identity: true, permissions: false })
      opts.clearCaches()
      const { guard } = await run(h, first, denying(OWNER, first.permission))
      expect(guard).not.toBeInstanceOf(Response)
    })
  })
}

function retarget(c: RouteCase): Record<string, string> {
  return Object.fromEntries(Object.entries(c.params).map(([k, v]) => [k, v === OWNED_PROJECT ? OTHERS_PROJECT : v]))
}
