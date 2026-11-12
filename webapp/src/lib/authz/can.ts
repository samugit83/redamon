/**
 * The one policy function (feature document §4.2; PE-04, PE-06, PE-23): may this person do this,
 * here? `allowed = capability ∧ project access ≥ the level the permission needs`; the project
 * policy (RoE, engagement authorization, phase gates) stays with the routes that enforce it today.
 *
 *   - A permission that acts on a project (a project permission, or `project:share` /
 *     `plugins:approve_overrides` given a project) first asks `projectAccess()`: a project the
 *     person cannot see answers 404 whatever they hold, so a refusal never tells a stranger the
 *     project exists. Then the capability, then the level: each missing one answers 403 naming the
 *     permission.
 *   - An instance permission stops at the capability and never reads a project.
 *   - A project permission given no project is the capability alone ("may this person use X at
 *     all"). A project named but empty is a 400, never that: a route that meant a project and lost
 *     its id must not fall back to the capability.
 *
 * Under act-as (`actingAs`, an admin acting as an account): the act-as rule (session.ts
 * `mayActAs`) is checked first, and an `actingAs` it refuses throws `ActAsNotAllowedError` (a
 * caller that built one without the rule is a bug, never a refusal to show). The project is the
 * account acted as, as `getEffectiveUser` answers today; a member permission needs both people to
 * hold it (§4.7: the admin uses only what both may do); an administration or platform permission
 * stays the real person's (user administration, plugins, platform tools read the real session).
 *
 * With RBAC_PERMISSIONS_ENABLED off, the capabilities are the account type's default
 * (capabilities.ts), so every answer is the one the owner checks and admin checks give today.
 *
 * An unknown permission throws (PE-02); a failed read throws, it never reads as allowed.
 */
import { mayActAs } from '@/lib/session'
import {
  resolveCapabilities,
  type Capabilities,
  type CapabilityPrincipal,
  type PermissionExplanation,
} from './capabilities'
import { PERMISSIONS, PERMISSION_IDS, assertKnownPermission, type PermissionId } from './permissions'
import { meetsLevel, projectAccess, type ProjectAccess } from './projectAccess'

export interface CanOptions {
  /**
   * The project the action is on. Leave the key out for a capability-only check; a key that is
   * present but empty (an id the route could not read) answers 400.
   */
  projectId?: string | null
  /**
   * The account an admin acts as (session.ts `getAuthzIdentity`), or null. It must pass the act-as
   * rule (`mayActAs`), else can() throws `ActAsNotAllowedError`.
   */
  actingAs?: CapabilityPrincipal | null
  /**
   * A critical check: what can() reads is read from the database again, not from the cache (the
   * Root, the custom sets and the instance default set of both people, the Root again for the
   * act-as rule; the project is never cached). The people themselves are values: their role,
   * status, sets and overrides are those of the caller's read, because can() reads no account
   * (DV-25: a request reads its account once, and the decision is about the account the session
   * check accepted). For a critical check read them fresh first: `requirePermission({fresh})` does
   * (getAuthzIdentity reads both accounts fresh); another caller uses `loadPrincipal(id, {fresh})`.
   */
  fresh?: boolean
}

export type CanDecision =
  | { allowed: true; permission: PermissionId; capabilities: Capabilities; access: ProjectAccess | null }
  /** `capability`: the person (or, acting as someone, either person) does not hold it. `project_level`: their access to the project does not reach it. */
  | { allowed: false; status: 403; reason: 'capability' | 'project_level'; permission: PermissionId; capabilities: Capabilities }
  | { allowed: false; status: 404; reason: 'project_not_visible'; permission: PermissionId }
  | { allowed: false; status: 400; reason: 'project_required'; permission: PermissionId }

/**
 * can() was handed an `actingAs` the act-as rule refuses. The route answers a coded 500
 * (`internalError` through the guards or `withRouteErrors`): the message is for the log.
 */
export class ActAsNotAllowedError extends Error {
  constructor(actorId: string, targetId: string) {
    super(`[rbac] act_as_refused: account ${actorId} may not act as account ${targetId}`)
    this.name = 'ActAsNotAllowedError'
  }
}

/** Whether the permission is checked against a project when one is named (§5 legend). */
export function actsOnProject(permission: PermissionId): boolean {
  const meta = PERMISSIONS[permission]
  return meta.scope === 'project' || meta.level !== null
}

/**
 * What a person may use while acting as another (§4.7): a member permission when both hold it, an
 * administration one when the real person does. The other fields describe the real person; the
 * reasons for a member permission the account acted as lacks are that account's.
 */
function actingCapabilities(own: Capabilities, target: Capabilities): Capabilities {
  const holds = (p: PermissionId): boolean => own.has(p) && (PERMISSIONS[p].kind === 'admin' || target.has(p))
  const held = Object.freeze(own.held.filter(holds))
  const heldSet = new Set<PermissionId>(held)
  const explain = (p: PermissionId): PermissionExplanation => {
    const mine = own.explain(p)
    if (!mine.held || heldSet.has(p)) return mine
    return Object.freeze({ permission: p, held: false, reasons: target.explain(p).reasons })
  }
  return Object.freeze({
    userId: own.userId,
    accountType: own.accountType,
    enforced: own.enforced,
    sets: own.sets,
    missingSets: own.missingSets,
    held,
    has(permission: PermissionId): boolean {
      assertKnownPermission(permission)
      return heldSet.has(permission)
    },
    explain,
    explainAll: () => Object.freeze(PERMISSION_IDS.map(explain)),
  })
}

export async function can(principal: CapabilityPrincipal, permission: PermissionId, opts: CanOptions = {}): Promise<CanDecision> {
  assertKnownPermission(permission)
  const meta = PERMISSIONS[permission]
  const fresh = opts.fresh === true
  const actingAs = opts.actingAs && opts.actingAs.id !== principal.id ? opts.actingAs : null
  if (actingAs && !(await mayActAs(principal, actingAs, { fresh }))) throw new ActAsNotAllowedError(principal.id, actingAs.id)
  const onProject = actsOnProject(permission) && 'projectId' in opts

  let access: ProjectAccess | null = null
  if (onProject) {
    if (!opts.projectId) return Object.freeze({ allowed: false, status: 400, reason: 'project_required', permission })
    access = await projectAccess({ userId: (actingAs ?? principal).id }, opts.projectId)
    if (!access) return Object.freeze({ allowed: false, status: 404, reason: 'project_not_visible', permission })
  }

  const own = await resolveCapabilities(principal, { fresh })
  const capabilities = actingAs ? actingCapabilities(own, await resolveCapabilities(actingAs, { fresh })) : own
  if (!capabilities.has(permission)) return Object.freeze({ allowed: false, status: 403, reason: 'capability', permission, capabilities })
  if (access && meta.level !== null && !meetsLevel(access, meta.level)) {
    return Object.freeze({ allowed: false, status: 403, reason: 'project_level', permission, capabilities })
  }
  return Object.freeze({ allowed: true, permission, capabilities, access })
}
