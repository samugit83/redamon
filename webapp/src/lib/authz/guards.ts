/**
 * Route guards over the policy function (master plan §9.8): the session first, then the route's
 * project id, then `can()`.
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
 * Oversight and break-glass (step 4.14) are a person's own: under act-as, a project the account acted
 * as reaches only by its own oversight or break-glass answers 404 (can() already keeps the acting
 * admin's own out, D-22). A request an admin's oversight allowed writes the day's `project.oversee`
 * audit row first (oversight.ts); when that row cannot be written the answer is a coded 500, never an
 * unaudited read.
 *
 * Name the project in the options whenever the route acts on one: the route manifest classes a
 * call as a project guard when it passes the permission as a string literal, the permission acts
 * on a project, and a literal options object has a `projectId` key (scripts/gen-route-manifest.mjs
 * refuses a `projectId` given with any other permission: can() ignores it). The key decides, not
 * its value: `{projectId: undefined}` is a project named but empty (400).
 */
import { NextResponse } from 'next/server'
import { getAuthzIdentity, type AuthzIdentity, type EffectiveUser } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { actsOnProject, can, type CanDecision } from './can'
import type { Capabilities } from './capabilities'
import { PERMISSIONS, assertKnownPermission, type PermissionId, type ProjectLevel } from './permissions'
import { meetsLevel, type ProjectAccess } from './projectAccess'
import { auditOversightRead } from './oversight'

export interface PermissionContext extends AuthzIdentity {
  /** Whose data the request touches: the account acted as, else the signed-in account. */
  effective: EffectiveUser
  permission: PermissionId
  /**
   * What the request may use, as can() applied it: the signed-in account's, or under act-as the
   * member permissions both people hold and the administration ones the real person holds (§4.7),
   * so a second check on this field cannot reach past the act-as rule.
   */
  capabilities: Capabilities
  /** The caller's access to the project the check named, else null. */
  access: ProjectAccess | null
}

export interface RequirePermissionOptions {
  /** The project the action is on; see `CanOptions.projectId` (a key present but empty answers 400). */
  projectId?: string | null
  /**
   * A critical path (step 2.2): both accounts (getAuthzIdentity), the Root, the sets and the
   * instance default are read from the database (`CanOptions.fresh`).
   */
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

/** The session check every guard makes first: 401 without one, a coded 500 when it cannot be read. */
async function signedIn(fresh: boolean): Promise<AuthzIdentity | NextResponse> {
  try {
    return (await getAuthzIdentity({ fresh })) ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  } catch (err) {
    return internalError(err, 'Could not read the signed-in account')
  }
}

async function decide(
  identity: AuthzIdentity,
  permission: PermissionId,
  project: Pick<RequirePermissionOptions, 'projectId'>,
  fresh: boolean,
): Promise<PermissionContext | NextResponse> {
  let decision: CanDecision
  try {
    decision = await can(identity.principal, permission, { ...project, actingAs: identity.actingAs, fresh })
  } catch (err) {
    return internalError(err, 'Could not check the permission')
  }
  if (decision.allowed) {
    const via = decision.access?.via
    if (identity.actingAs && (via === 'oversight' || via === 'break_glass')) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    if (via === 'oversight') {
      try {
        await auditOversightRead(identity, decision.access, permission)
      } catch (err) {
        return internalError(err, 'Could not record the oversight read')
      }
    }
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

export async function requirePermission(
  _request: Request,
  permission: PermissionId,
  opts: RequirePermissionOptions = {},
): Promise<PermissionContext | NextResponse> {
  assertKnownPermission(permission)
  const fresh = opts.fresh === true
  const identity = await signedIn(fresh)
  if (identity instanceof NextResponse) return identity
  return decide(identity, permission, 'projectId' in opts ? { projectId: opts.projectId } : {}, fresh)
}

/**
 * A second permission the same request needs because of what it asks for (an overwrite run, a
 * scope change inside a settings save, the kind of scan a queued job will start), decided on the
 * context the route's requirePermission answered, as can() would decide it on the same project,
 * reading nothing again: the capabilities can() applied (under act-as, what both people hold) and,
 * on the project the context checked, the access level the permission needs. Answers null when
 * held, else the 403 naming it.
 *
 * A permission that acts on a project, on a context that checked none, throws: the level could not
 * be decided, so the route must name the project in its requirePermission first.
 */
export function requireAlso(auth: PermissionContext, permission: PermissionId): NextResponse | null {
  assertKnownPermission(permission)
  if (actsOnProject(permission) && !auth.access) {
    throw new Error(`[rbac] requireAlso('${permission}') needs a context that checked a project`)
  }
  if (!auth.capabilities.has(permission)) return forbiddenResponse(permission)
  const level = PERMISSIONS[permission].level
  if (auth.access && level !== null && !meetsLevel(auth.access, level)) return forbiddenResponse(permission)
  return null
}

/**
 * A project level the request needs beyond the one its permission names, decided on the access the
 * route's requirePermission answered, reading nothing again (step 4.7). For a route whose
 * permission is a read but whose answer is raw data: the six scan-result downloads and the AI
 * attack-surface transcript keep `recon:read` (the owner and the Read-only analyst unchanged) and
 * add `requireLevel(auth, 'R*')`, so a read collaborator without Raw data & files is refused.
 *
 *   const auth = await requirePermission(request, 'recon:read', { projectId })
 *   if (auth instanceof NextResponse) return auth
 *   const raw = requireLevel(auth, 'R*')
 *   if (raw) return raw
 *
 * Answers null when the access reaches the level (`meetsLevel`), else the 403 of §9.8 naming the
 * route's permission and the level: `{error, code: 'forbidden', permission, level}`. A context that
 * checked no project throws: the route must name its project in requirePermission first.
 */
export function requireLevel(auth: PermissionContext, level: ProjectLevel): NextResponse | null {
  if (!auth.access) throw new Error(`[rbac] requireLevel('${level}') needs a context that checked a project`)
  if (meetsLevel(auth.access, level)) return null
  const error = level === 'R*'
    ? `This needs Raw data & files on this project (${auth.permission}).`
    : `Your access to this project does not reach this action (${auth.permission}, level ${level}).`
  return NextResponse.json({ error, code: 'forbidden', permission: auth.permission, level }, { status: 403 })
}

type ProjectIdExtractor<C> = (request: Request, context: C) => string | null | undefined | Promise<string | null | undefined>

export interface WithPermissionOptions<C> {
  /**
   * The project the route acts on, from its request or params. It runs after the session check,
   * on a copy of the request, so reading the body leaves it to the handler; a throw propagates
   * (wrap the route in `withRouteErrors`). The key decides: present without a function is a
   * project named but empty (400).
   */
  projectId?: ProjectIdExtractor<C>
  fresh?: boolean
}

/**
 * Runs the extractor on a copy of the request. A copy it leaves unread is cancelled, so the body is
 * not buffered twice (an upload); not awaited, since a branch's cancel settles only when the
 * handler has read the other one.
 */
async function projectIdOf<C>(extract: ProjectIdExtractor<C>, request: Request, context: C): Promise<string | null | undefined> {
  const copy = request.clone()
  try {
    return await extract(copy, context)
  } finally {
    if (copy.body && !copy.bodyUsed) copy.body.cancel().catch(() => {})
  }
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
  const fresh = opts.fresh === true
  const namesProject = 'projectId' in opts
  const extract = opts.projectId
  return async (request: R, context: C) => {
    const identity = await signedIn(fresh)
    if (identity instanceof NextResponse) return identity
    const project = namesProject ? { projectId: extract ? await projectIdOf(extract, request, context) : undefined } : {}
    const auth = await decide(identity, permission, project, fresh)
    if (auth instanceof NextResponse) return auth
    return handler(request, context, auth)
  }
}
