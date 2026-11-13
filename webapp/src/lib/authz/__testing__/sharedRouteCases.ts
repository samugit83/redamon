/**
 * The route families' shared-project tests (step 4.7; the later read waves reuse it): with sharing in
 * force (RBAC_SHARING_ENABLED on, the instance policy enabled), each route, with the real guard, the
 * real can(), projectAccess() and registry, answers a collaborator holding a Read share of the owner's
 * project as its case's `reach` says:
 *
 *   read   passes with or without Raw data & files, on the owner's project: the context's access is
 *          the share's (level `read`, `via: 'share'`, the owner as `project.userId`, the tenant);
 *   raw    without Raw data & files refused 403 naming the route's permission and `level: 'R*'`
 *          (requireLevel), before anything past the check runs; with it, it passes;
 *   write  refused at read, Raw data or not: 403 naming the permission, nothing past the guard runs;
 *   rawPermission  the route's own permission is at `R*` (traffic, workspace; step 4.9): without Raw data
 *          & files the guard refuses (403 naming the permission), nothing past it runs; with it, it
 *          passes on the owner's project, as `read` does.
 *
 * Once per family, with sharing not in force the same collaborator gets 404, as before sharing
 * (sharing.flags.off.test.ts proves that no share is then read).
 *
 * The test file declares the doubles as routePermissionCases.ts describes, with `shares` in the
 * hoisted state and this file's Prisma double (which answers the guard's share, break-glass and
 * policy reads, and delegates every other model to `authPrisma`):
 *
 *   const h = vi.hoisted(() => ({ identity: vi.fn(), projects: new Map(), shares: new Map(), downstream: vi.fn(), upstream: vi.fn(), models: {} }))
 *   vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedRouteCases')).sharingPrisma(h) }))
 *
 * plus the session double, the requirePermission spy and the upstream doubles of that file. Take OWNER
 * and OWNED_PROJECT from routePermissionCases.ts: this module is first loaded by the Prisma factory.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import type { PermissionContext } from '@/lib/authz/guards'
import type { Principal } from '@/lib/authz/principal'
import { authPrisma, principal, OWNER, OWNED_PROJECT, type RouteCase, type RouteCaseState } from './routePermissionCases'


/** The collaborator every case signs in as, on *Default member* (it holds every member permission). */
export const COLLABORATOR = 'carol'

export interface ShareRow {
  access: string
  rawData: boolean
  expiresAt: Date | null
  user: { status: string }
}

export interface SharedRouteState extends RouteCaseState {
  /** `${projectId}|${userId}` -> the share row projectAccess() reads. */
  shares: Map<string, ShareRow>
}

export type SharedReach = 'read' | 'raw' | 'write' | 'rawPermission'

export interface SharedRouteCase extends RouteCase {
  reach: SharedReach
}

/** authPrisma, plus the share, break-glass and instance policy reads of projectAccess(). */
export function sharingPrisma(h: SharedRouteState): unknown {
  const base = authPrisma(h) as Record<string | symbol, unknown>
  const own: Record<string, unknown> = {
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) => {
        const row = h.shares.get(`${where.projectId_userId.projectId}|${where.projectId_userId.userId}`)
        return row ? { ...row } : null
      },
    },
    projectBreakGlass: { findFirst: async () => null },
    instanceSettings: {
      findUnique: async () => ({
        sharingPolicy: { enabled: true }, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null,
      }),
    },
  }
  return new Proxy(own, { get: (target, prop) => (typeof prop === 'string' && Object.hasOwn(target, prop) ? target[prop] : base[prop]) })
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

async function run(h: SharedRouteState, c: RouteCase, who: Principal): Promise<{ res: Response | null; guard: unknown }> {
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

export interface SharedFamilyOptions {
  setFlags: (values: { identity: boolean; permissions: boolean; sharing: boolean } | null) => void
  clearCaches: () => void
}

const share = (rawData: boolean): ShareRow => ({ access: 'read', rawData, expiresAt: null, user: { status: 'active' } })

export function describeSharedAccess(family: string, cases: SharedRouteCase[], h: SharedRouteState, opts: SharedFamilyOptions): void {
  describe(`${family}: a read collaborator of the owner's project (step 4.7)`, () => {
    beforeEach(async () => {
      h.identity.mockReset()
      h.downstream.mockReset()
      h.upstream.mockReset()
      h.upstream.mockRejectedValue(Object.assign(new Error('no upstream in this test'), { code: 'ECONNREFUSED' }))
      h.projects.clear()
      h.shares.clear()
      for (const k of Object.keys(h.models)) delete h.models[k]
      h.projects.set(OWNED_PROJECT, { id: OWNED_PROJECT, userId: OWNER })
      vi.stubGlobal('fetch', (...a: unknown[]) => h.upstream(...a))
      opts.setFlags({ identity: true, permissions: true, sharing: true })
      vi.stubEnv('MCP_SERVER_ENABLED', 'true')
      vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
      opts.clearCaches()
      // Imported here, not at the top: this file is loaded by the test's Prisma mock factory, and the
      // policy reader imports Prisma, which would wait on that factory for ever.
      const { clearSharingPolicyCacheForTests } = await import('@/lib/authz/sharingPolicy')
      clearSharingPolicyCacheForTests()
      vi.spyOn(console, 'error').mockImplementation(() => {})
      vi.spyOn(console, 'warn').mockImplementation(() => {})
    })
    afterEach(() => {
      opts.setFlags(null)
      vi.unstubAllGlobals()
      vi.unstubAllEnvs()
      vi.restoreAllMocks()
    })

    const collaborator = principal(COLLABORATOR)
    const projectOf = (c: RouteCase) => (c.projectId === undefined ? OWNED_PROJECT : c.projectId)

    for (const c of cases) {
      if (c.reach === 'read') {
        test.each([[false], [true]])(`${c.route} passes at read (Raw data %s), on the owner's project`, async (rawData) => {
          h.shares.set(`${projectOf(c)}|${COLLABORATOR}`, share(rawData))
          const { res, guard } = await run(h, c, collaborator)
          expect(guard).not.toBeInstanceOf(Response)
          const access = (guard as PermissionContext).access
          expect(access).toMatchObject({ project: { id: projectOf(c), userId: OWNER }, level: 'read', via: 'share', toggles: { rawData } })
          expect(res?.status).not.toBe(403)
        })
      }

      if (c.reach === 'raw') {
        test(`${c.route} without Raw data & files: 403 naming ${c.permission} and R*, nothing past the check runs`, async () => {
          h.shares.set(`${projectOf(c)}|${COLLABORATOR}`, share(false))
          const { res, guard } = await run(h, c, collaborator)
          expect(guard).not.toBeInstanceOf(Response)
          expect(res?.status).toBe(403)
          if (c.route.startsWith('HEAD ')) return
          expect(await res!.json()).toMatchObject({ code: 'forbidden', permission: c.permission, level: 'R*' })
          expect(h.downstream).not.toHaveBeenCalled()
          expect(h.upstream).not.toHaveBeenCalled()
        })

        test(`${c.route} with Raw data & files passes`, async () => {
          h.shares.set(`${projectOf(c)}|${COLLABORATOR}`, share(true))
          const { res, guard } = await run(h, c, collaborator)
          expect((guard as PermissionContext).access).toMatchObject({ level: 'read', toggles: { rawData: true } })
          expect(res?.status).not.toBe(403)
        })
      }

      if (c.reach === 'rawPermission') {
        test(`${c.route} without Raw data & files: the guard refuses, 403 naming ${c.permission}, nothing past it runs`, async () => {
          h.shares.set(`${projectOf(c)}|${COLLABORATOR}`, share(false))
          const { res, guard } = await run(h, c, collaborator)
          expect(guard).toBeInstanceOf(Response)
          expect(res?.status).toBe(403)
          expect(await res!.json()).toMatchObject({ code: 'forbidden', permission: c.permission })
          expect(h.downstream).not.toHaveBeenCalled()
          expect(h.upstream).not.toHaveBeenCalled()
        })

        test(`${c.route} with Raw data & files passes, on the owner's project`, async () => {
          h.shares.set(`${projectOf(c)}|${COLLABORATOR}`, share(true))
          const { res, guard } = await run(h, c, collaborator)
          expect(guard).not.toBeInstanceOf(Response)
          expect((guard as PermissionContext).access).toMatchObject({
            project: { id: projectOf(c), userId: OWNER }, level: 'read', via: 'share', toggles: { rawData: true },
          })
          expect(res?.status).not.toBe(403)
        })
      }

      if (c.reach === 'write') {
        test(`${c.route} refused at read, Raw data or not: 403 naming ${c.permission}, nothing past the guard runs`, async () => {
          for (const rawData of [false, true]) {
            h.downstream.mockClear()
            h.shares.set(`${projectOf(c)}|${COLLABORATOR}`, share(rawData))
            const { res, guard } = await run(h, c, collaborator)
            expect(guard).toBeInstanceOf(Response)
            expect(res?.status).toBe(403)
            expect(await res!.json()).toMatchObject({ code: 'forbidden', permission: c.permission })
            expect(h.downstream).not.toHaveBeenCalled()
            expect(h.upstream).not.toHaveBeenCalled()
          }
        })
      }
    }

    const first = cases.find(c => c.reach === 'read') ?? cases[0]
    test(`${first.route}: with RBAC_SHARING_ENABLED off the collaborator gets 404, as before sharing`, async () => {
      opts.setFlags({ identity: true, permissions: true, sharing: false })
      opts.clearCaches()
      h.shares.set(`${projectOf(first)}|${COLLABORATOR}`, share(true))
      const { res } = await run(h, first, collaborator)
      expect(res?.status).toBe(404)
      expect(h.upstream).not.toHaveBeenCalled()
    })
  })
}
