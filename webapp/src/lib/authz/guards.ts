/**
 * Route guards over the policy function (master plan §9.8): the session first, then `can()`.
 *
 *   const auth = await requirePermission(request, 'recon:scan', { projectId })
 *   if (auth instanceof NextResponse) return auth
 *
 *   export const GET = withRouteErrors('Could not load X',
 *     withPermission('recon:read', handler, { projectId: async (_r, { params }) => (await params).id }))
 *
 * Answers: 401 `{error: 'Unauthorized'}` without a valid session; 400 `{error: 'projectId is
 * required'}` for a project named but empty; 404 `{error: 'Not found'}` for a project the caller
 * cannot see, the body of a project that does not exist; 403 `{error, code: 'forbidden',
 * permission}` for a permission the caller does not hold or does not reach on the project; a
 * coded 500 (`internalError`) when a read fails, never a pass.
 *
 * Name the project in the options whenever the route acts on one: the route manifest classes a
 * call with a literal `projectId` option as a project guard (scripts/gen-route-manifest.mjs).
 */
import { NextResponse } from 'next/server'
import { getAuthzIdentity, type AuthzIdentity, type EffectiveUser } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { can, type CanDecision } from './can'
import type { Capabilities } from './capabilities'
import { assertKnownPermission, type PermissionId } from './permissions'
import type { ProjectAccess } from './projectAccess'

export interface PermissionContext extends AuthzIdentity {
  /** Whose data the request touches: the account acted as, else the signed-in account. */
  effective: EffectiveUser
  permission: PermissionId
  /** The signed-in account's. */
  capabilities: Capabilities
  /** The caller's access to the project the check named, else null. */
  access: ProjectAccess | null
}

export interface RequirePermissionOptions {
  /** The project the action is on; see `CanOptions.projectId` (a key present but empty answers 400). */
  projectId?: string | null
  /** A critical path (step 2.2): the account and the capabilities are read from the database. */
  fresh?: boolean
}

/** The 403 of every permission check (master plan §9.8, DV-07). */
export function forbiddenResponse(permission: PermissionId): NextResponse {
  assertKnownPermission(permission)
  return NextResponse.json(
    { error: `You do not hold the permission this action needs (${permission}).`, code: 'forbidden', permission },
    { status: 403 },
  )
}

export async function requirePermission(
  _request: Request,
  permission: PermissionId,
  opts: RequirePermissionOptions = {},
): Promise<PermissionContext | NextResponse> {
  assertKnownPermission(permission)
  const fresh = opts.fresh === true
  let identity: AuthzIdentity | null
  try {
    identity = await getAuthzIdentity({ fresh })
  } catch (err) {
    return internalError(err, 'Could not read the signed-in account')
  }
  if (!identity) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  let decision: CanDecision
  try {
    decision = await can(identity.principal, permission, {
      ...('projectId' in opts ? { projectId: opts.projectId } : {}),
      actingAs: identity.actingAs,
      fresh,
    })
  } catch (err) {
    return internalError(err, 'Could not check the permission')
  }
  if (decision.allowed) {
    return {
      ...identity,
      effective: { userId: (identity.actingAs ?? identity.principal).id },
      permission,
      capabilities: decision.capabilities,
      access: decision.access,
    }
  }
  if (decision.status === 400) return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  if (decision.status === 404) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  return forbiddenResponse(permission)
}

export interface WithPermissionOptions<C> {
  /** The project the route acts on, from its request or params. */
  projectId?: (request: Request, context: C) => string | null | undefined | Promise<string | null | undefined>
  fresh?: boolean
}

/**
 * A route handler that runs only when `requirePermission` allows, with the context as its third
 * argument. The permission is checked when the route module loads, so a typo fails at once.
 */
export function withPermission<C = unknown, R extends Request = Request>(
  permission: PermissionId,
  handler: (request: R, context: C, auth: PermissionContext) => Promise<Response>,
  opts: WithPermissionOptions<C> = {},
): (request: R, context: C) => Promise<Response> {
  assertKnownPermission(permission)
  return async (request: R, context: C) => {
    const auth = await requirePermission(request, permission, {
      ...(opts.projectId ? { projectId: await opts.projectId(request, context) } : {}),
      fresh: opts.fresh,
    })
    if (auth instanceof NextResponse) return auth
    return handler(request, context, auth)
  }
}
