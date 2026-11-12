/**
 * Doubles of '@/lib/authz/guards' for route tests written before their route asked for a
 * permission, which decide who passes by doubling the owner helpers of '@/lib/access'.
 *
 * Step 3.8 moved the project, recon and scan routes from `guardProject` /
 * `requireEffectiveUser` + `requireProjectAccess` to `requirePermission`, whose project check is
 * the same `projectAccess()` rule. With these doubles such a test keeps its own access doubles
 * (or the real helpers over its session and Prisma doubles): `requirePermission` answers what
 * those helpers answer, so the test still proves what the route does past the guard and that a
 * refusal stops it. The context holds every permission, as an owner on *Default member* does; the
 * permission each route asks for is proved by its family's `*.permissions.test.ts`, with the real
 * guard and the real `can()`. Everything else (`requireAlso`, `forbiddenResponse`) is the real one.
 *
 *   vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
 */
import { vi } from 'vitest'
import { NextResponse } from 'next/server'
import type { PermissionContext, RequirePermissionOptions } from '@/lib/authz/guards'
import type { Capabilities } from '@/lib/authz/capabilities'
import { PERMISSION_IDS, assertKnownPermission, type PermissionId } from '@/lib/authz/permissions'
import type { EffectiveUser } from '@/lib/session'

type Guards = typeof import('@/lib/authz/guards')
type RequirePermission = Guards['requirePermission']

const HOLDS_ALL: Capabilities = Object.freeze({
  userId: '',
  accountType: 'member',
  enforced: false,
  sets: Object.freeze([]),
  missingSets: Object.freeze([]),
  held: PERMISSION_IDS,
  has: (permission: PermissionId) => {
    assertKnownPermission(permission)
    return true
  },
  explain: (permission: PermissionId) => Object.freeze({ permission, held: true, reasons: Object.freeze([]) }),
  explainAll: () => Object.freeze(PERMISSION_IDS.map(p => Object.freeze({ permission: p, held: true, reasons: Object.freeze([]) }))),
}) as unknown as Capabilities

function context(permission: PermissionId, effective: EffectiveUser, project: { id: string; userId: string } | null): PermissionContext {
  return {
    session: { userId: effective.userId, role: 'standard' },
    principal: null,
    actingAs: null,
    effective,
    permission,
    capabilities: { ...HOLDS_ALL, userId: effective.userId } as Capabilities,
    access: project ? { project, level: 'owner' } : null,
  } as unknown as PermissionContext
}

const isResponse = (value: unknown): value is Response => value instanceof Response

/** A refusal as the real guard returns it: some tests double a helper with a plain Response. */
const asNextResponse = (res: Response): NextResponse => (res instanceof NextResponse ? res : new NextResponse(res.body, res))

async function withDouble(requirePermission: RequirePermission): Promise<Guards> {
  const real = await vi.importActual<Guards>('@/lib/authz/guards')
  return { ...real, requirePermission }
}

/**
 * For a test that doubles `guardProject`: the project check is `guardProject(projectId)`. The
 * effective user is not in the context (the routes it serves read it themselves).
 */
export function overGuardProject(): Promise<Guards> {
  return withDouble(async (_request: Request, permission: PermissionId, opts: RequirePermissionOptions = {}) => {
    assertKnownPermission(permission)
    if (!('projectId' in opts)) throw new Error('overGuardProject doubles project checks only')
    const { guardProject } = await import('@/lib/access')
    const denied = await guardProject(opts.projectId ?? '')
    if (denied) return asNextResponse(denied)
    return context(permission, { userId: '' }, { id: opts.projectId ?? '', userId: '' })
  })
}

/**
 * For a test that doubles `requireEffectiveUser` (and `requireProjectAccess` when the route names a
 * project): the context's effective user is the one `requireEffectiveUser` answers, its access the
 * project `requireProjectAccess` answers.
 */
export function overEffectiveUser(): Promise<Guards> {
  return withDouble(async (_request: Request, permission: PermissionId, opts: RequirePermissionOptions = {}) => {
    assertKnownPermission(permission)
    const access = await import('@/lib/access')
    const eff = await access.requireEffectiveUser()
    if (isResponse(eff)) return asNextResponse(eff)
    if (!('projectId' in opts)) return context(permission, eff, null)
    const allowed = await access.requireProjectAccess(eff, opts.projectId ?? '')
    if (isResponse(allowed)) return asNextResponse(allowed)
    return context(permission, eff, allowed.project)
  })
}
