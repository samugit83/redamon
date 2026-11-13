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
    principal: { id: effective.userId, role: 'standard' },
    actingAs: null,
    effective,
    permission,
    capabilities: { ...HOLDS_ALL, userId: effective.userId } as Capabilities,
    access: project ? { project, level: 'owner', toggles: { rawData: true }, via: 'owner' } : null,
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
    const allowed: unknown = await access.requireProjectAccess(eff, opts.projectId ?? '')
    if (isResponse(allowed)) return asNextResponse(allowed)
    // Some tests double the helper as "allowed" with no row (null): the project is then the caller's.
    const project = (allowed as { project?: { id: string; userId: string } } | null)?.project
    return context(permission, eff, project ?? { id: opts.projectId ?? '', userId: eff.userId })
  })
}

/**
 * For a test of a triage or mute-rule route (step 3.9), which decided who passes through
 * `requireProjectOwner` (triageClient.ts, real or doubled): the context's project is the caller it
 * answers, the project's owner as its user.
 */
export function overProjectOwner(): Promise<Guards> {
  return withDouble(async (_request: Request, permission: PermissionId, opts: RequirePermissionOptions = {}) => {
    assertKnownPermission(permission)
    if (!('projectId' in opts)) throw new Error('overProjectOwner doubles project checks only')
    const { requireProjectOwner } = await import('@/lib/triageClient')
    const caller = await requireProjectOwner(opts.projectId)
    if (isResponse(caller)) return asNextResponse(caller)
    return context(permission, { userId: caller.userId }, { id: caller.projectId, userId: caller.userId })
  })
}

/**
 * For a test of a conversation route (step 3.9), which decided who passes through the conversation
 * guard (`requireEffectiveUser` + `requireConversationAccess[BySession]`, doubled): the route then
 * asks `agent:chat` on the conversation's project, which that guard already found the caller's.
 * The context's effective user is the one `requireEffectiveUser` answers, its project the one named.
 */
export function overConversation(): Promise<Guards> {
  return withDouble(async (_request: Request, permission: PermissionId, opts: RequirePermissionOptions = {}) => {
    assertKnownPermission(permission)
    if (!('projectId' in opts)) throw new Error('overConversation doubles project checks only')
    const access = await import('@/lib/access')
    const eff = await access.requireEffectiveUser()
    if (isResponse(eff)) return asNextResponse(eff)
    return context(permission, eff, { id: opts.projectId ?? '', userId: eff.userId })
  })
}

/**
 * For a test that doubles `guardProject` of a route that also asks a permission with no project
 * (`/api/agent/files` without a projectId, step 3.9): a project check is `guardProject(projectId)`,
 * a capability alone passes holding every permission, as an owner on *Default member* does.
 */
export function overGuardProjectOrCapability(): Promise<Guards> {
  return withDouble(async (_request: Request, permission: PermissionId, opts: RequirePermissionOptions = {}) => {
    assertKnownPermission(permission)
    if (!('projectId' in opts)) return context(permission, { userId: '' }, null)
    const { guardProject } = await import('@/lib/access')
    const denied = await guardProject(opts.projectId ?? '')
    if (denied) return asNextResponse(denied)
    return context(permission, { userId: '' }, { id: opts.projectId ?? '', userId: '' })
  })
}

/**
 * For a test of a plugin route (step 3.9) that doubles `getEffectiveUser` of '@/lib/session': the
 * route asks `plugins:use` or `plugins:approve_overrides`, a capability with no project; no
 * effective user answers the 401, anyone else passes holding every permission, as an owner on
 * *Default member* does.
 */
export function overSessionEffectiveUser(): Promise<Guards> {
  // One import shared by every call: two requests at once (a concurrency test) each importing the
  // session module can be handed the real one while the test's async mock factory still runs.
  let session: Promise<typeof import('@/lib/session')> | null = null
  return withDouble(async (_request: Request, permission: PermissionId, opts: RequirePermissionOptions = {}) => {
    assertKnownPermission(permission)
    if ('projectId' in opts) throw new Error('overSessionEffectiveUser doubles capability checks only')
    const { getEffectiveUser } = await (session ??= import('@/lib/session'))
    const eff = await getEffectiveUser()
    if (!eff) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    return context(permission, eff, null)
  })
}

/**
 * A double of '@/lib/authz/selfService' for a self-service route test written before its route
 * asked `self:*` (step 3.9): the route's account rule (requireUserAccess, doubled or real) decides
 * who passes, and the person holds the catalog's permission, as an owner on *Default member* does.
 * The permission each route asks is proved by `users/[id]/selfService.permissions.test.ts`.
 *
 *   vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
 */
export async function overSelfService(): Promise<typeof import('@/lib/authz/selfService')> {
  return {
    requireSelfPermission: async (_request: unknown, _accountId: string, permission: PermissionId) => {
      assertKnownPermission(permission)
      return null
    },
  } as unknown as typeof import('@/lib/authz/selfService')
}

/**
 * For a test that doubles `getAuthzIdentity` of '@/lib/session' (and `requireProjectAccess` of
 * '@/lib/access' when the route names a project), of a route that reads the person through the
 * guard (the WebSocket ticket, step 3.9): no identity answers the 401, the project check is that
 * helper's answer, and the context carries the identity the double answers, holding every
 * permission, as an owner on *Default member* does.
 */
export function overAuthzIdentity(): Promise<Guards> {
  return withDouble(async (_request: Request, permission: PermissionId, opts: RequirePermissionOptions = {}) => {
    assertKnownPermission(permission)
    const { getAuthzIdentity } = await import('@/lib/session')
    const identity = await getAuthzIdentity(opts.fresh ? { fresh: true } : {})
    if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const effective = { userId: (identity.actingAs ?? identity.principal).id }
    let project: { id: string; userId: string } | null = null
    if ('projectId' in opts) {
      const access = await import('@/lib/access')
      const allowed: unknown = await access.requireProjectAccess(effective, opts.projectId ?? '')
      if (isResponse(allowed)) return asNextResponse(allowed)
      project = (allowed as { project?: { id: string; userId: string } } | null)?.project ?? { id: opts.projectId ?? '', userId: effective.userId }
    }
    return { ...context(permission, effective, project), session: identity.session, principal: identity.principal, actingAs: identity.actingAs }
  })
}
