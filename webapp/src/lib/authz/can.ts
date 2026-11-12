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
 * Under act-as (`actingAs`, an admin acting as an account): the project is the account acted as,
 * as `getEffectiveUser` answers today; a member permission needs both people to hold it (§4.7: the
 * admin uses only what both may do); an administration or platform permission stays the real
 * person's (user administration, plugins, platform tools read the real session).
 *
 * With RBAC_PERMISSIONS_ENABLED off, the capabilities are the account type's default
 * (capabilities.ts), so every answer is the one the owner checks and admin checks give today.
 *
 * An unknown permission throws (PE-02); a failed read throws, it never reads as allowed.
 */
import { resolveCapabilities, type Capabilities, type CapabilityPrincipal } from './capabilities'
import { PERMISSIONS, assertKnownPermission, type PermissionId } from './permissions'
import { meetsLevel, projectAccess, type ProjectAccess } from './projectAccess'

export interface CanOptions {
  /**
   * The project the action is on. Leave the key out for a capability-only check; a key that is
   * present but empty (an id the route could not read) answers 400.
   */
  projectId?: string | null
  /** The account an admin acts as (session.ts `getAuthzIdentity`), or null. */
  actingAs?: CapabilityPrincipal | null
  /** A critical check: the capabilities' cached reads are made again (resolveCapabilities). */
  fresh?: boolean
}

export type CanDecision =
  | { allowed: true; permission: PermissionId; capabilities: Capabilities; access: ProjectAccess | null }
  /** `capability`: the person (or, acting as someone, either person) does not hold it. `project_level`: their access to the project does not reach it. */
  | { allowed: false; status: 403; reason: 'capability' | 'project_level'; permission: PermissionId; capabilities: Capabilities }
  | { allowed: false; status: 404; reason: 'project_not_visible'; permission: PermissionId }
  | { allowed: false; status: 400; reason: 'project_required'; permission: PermissionId }

/** Whether the permission is checked against a project when one is named (§5 legend). */
export function actsOnProject(permission: PermissionId): boolean {
  const meta = PERMISSIONS[permission]
  return meta.scope === 'project' || meta.level !== null
}

export async function can(principal: CapabilityPrincipal, permission: PermissionId, opts: CanOptions = {}): Promise<CanDecision> {
  assertKnownPermission(permission)
  const meta = PERMISSIONS[permission]
  const actingAs = opts.actingAs && opts.actingAs.id !== principal.id ? opts.actingAs : null
  const onProject = actsOnProject(permission) && 'projectId' in opts

  let access: ProjectAccess | null = null
  if (onProject) {
    if (!opts.projectId) return Object.freeze({ allowed: false, status: 400, reason: 'project_required', permission })
    access = await projectAccess({ userId: (actingAs ?? principal).id }, opts.projectId)
    if (!access) return Object.freeze({ allowed: false, status: 404, reason: 'project_not_visible', permission })
  }

  const capabilities = await resolveCapabilities(principal, { fresh: opts.fresh })
  let held = capabilities.has(permission)
  if (held && actingAs && meta.kind === 'member') {
    held = (await resolveCapabilities(actingAs, { fresh: opts.fresh })).has(permission)
  }
  if (!held) return Object.freeze({ allowed: false, status: 403, reason: 'capability', permission, capabilities })
  if (access && meta.level !== null && !meetsLevel(access, meta.level)) {
    return Object.freeze({ allowed: false, status: 403, reason: 'project_level', permission, capabilities })
  }
  return Object.freeze({ allowed: true, permission, capabilities, access })
}
